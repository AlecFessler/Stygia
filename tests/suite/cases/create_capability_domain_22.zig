// Spec §[create_capability_domain] create_capability_domain — test 22.
//
// "[test 22] on success, the new domain's handle table contains an IDC
//  handle to itself at slot 2 with caps = the passed `cridc_ceiling`."
//
// FIDELITY NOTE — DEGRADED SMOKE VARIANT
//   A faithful assertion of test 22 requires reading the new domain's
//   slot 2 from inside the new domain. The new domain's cap table is
//   mapped read-only into its own address space — the *parent* (this
//   test) cannot reach across domain boundaries to read the child's
//   slot 2 directly. The spec exposes no syscall that lets one domain
//   peek at another's table contents (even `acquire_ecs` / `acquire_vars`
//   only mint EC/VAR handles into the caller's table; they don't
//   inspect the target's slots). To run a faithful assertion the child
//   ELF would have to read its own slot-2 cap, compare caps() to the
//   `cridc_ceiling` it was created with, and report the result back
//   over the result port; that requires constructing a second ELF in
//   this file and embedding it as a separate cargo, which the v0
//   manifest pipeline does not support (the build embeds one ELF per
//   test file via @embedFile, not nested ELFs).
//
//   Until the spec gains a cross-domain table introspection syscall
//   (or the runner gains a "child probes its own table" harness), this
//   test degrades to a smoke check on the success path: it stages a
//   well-formed inputs bundle whose `cridc_ceiling` is a known strict
//   subset of the parent's, calls create_capability_domain, and
//   asserts the call succeeded (i.e. vreg 1 carries a handle word, not
//   an error). The kernel's correctness on slot-2 caps remains an
//   internal property covered by §[capability_domain] cridc_ceiling
//   prose; redteam coverage and integration tests are the right
//   long-term home for the cross-domain readback.
//
// Strategy
//   The runner spawns this test with self-handle caps that include
//   `crcd`/`crec`/`crpf`/`crpt`/... and ceilings derived from
//   runner/primary.zig's `ceilings_inner = 0x001C_011F_3F01_FFFF` and
//   `ceilings_outer = 0x0000_003F_03FE_FFFF` templates. We mirror
//   those templates verbatim so the subset/ceiling/restart-policy
//   checks in tests 02-12 cannot fire — leaving the success path
//   open.
//
//   For the ELF input, the kernel needs a valid ELF header (test 15
//   guards malformed; test 16 guards size mismatch). We do not have a
//   second ELF to load in this file, so we construct a *minimal valid*
//   x86-64 ELF64 header in a 4 KiB page frame, with an entry point and
//   one zero-sized PT_LOAD segment so size validation passes. The
//   smoke test does not require the child to actually run any
//   instructions for test 22's spec assertion (the assertion is about
//   the slot-2 entry being present at create-time); but a kernel that
//   schedules the child immediately is welcome to do so — the entry
//   point lands in the page itself with a `hlt` instruction so the
//   child halts cleanly if started.
//
//   Even so, this is the minimum-viable success-path setup. If a
//   future kernel rejects this ELF for a reason orthogonal to test 22
//   (e.g., requires PT_LOAD segments to be present in the file), the
//   smoke check will fail at assertion 4 and a follow-up patch will
//   need to expand the staged ELF.
//
//   Passed handles: we pass the result port (slot 3) with bind+xfer so
//   the call shape mirrors what the runner does for every other test;
//   that branch exercises the passed_handles path without taking us
//   off the success path.
//
// Action
//   1. create_page_frame(1 page)                       — must succeed
//   2. create_var(r|w) and map the page frame          — must succeed
//   3. write a minimal valid ELF64 header into the var — best effort
//   4. delete the var (mirrors runner's reclaim pattern)
//   5. call create_capability_domain with valid ceilings — must succeed
//
// Assertions
//   1: create_page_frame returned an error word
//   2: create_var returned an error word
//   3: map_pf returned an error word
//   4: create_capability_domain returned an error word (spec §[error_codes]
//      values 1..15) instead of an IDC handle to the new domain
//
// FIDELITY GAP (logged):
//   This test does not assert that the new domain's slot 2 has caps =
//   the passed `cridc_ceiling`. See "FIDELITY NOTE" above for why; a
//   future faithful variant should be added once the harness can run
//   a child-side probe.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Mirror runner/primary.zig's known-valid ceiling templates so subset
// and ceiling checks pass cleanly.
const VALID_CEILINGS_INNER: u64 = 0x001C_011F_3F01_FFFF;
const VALID_CEILINGS_OUTER: u64 = 0x0000_003F_03FE_FFFF;

// Minimum-viable x86-64 ELF64 image. Layout per System V ABI / ELF-64
// gABI: 16-byte e_ident, 2-byte e_type, 2-byte e_machine, 4-byte
// e_version, 8-byte e_entry, 8-byte e_phoff, 8-byte e_shoff, 4-byte
// e_flags, 2-byte e_ehsize, 2-byte e_phentsize, 2-byte e_phnum,
// 2-byte e_shentsize, 2-byte e_shnum, 2-byte e_shstrndx. Followed by
// one PT_LOAD program header so the kernel's elfImageSpan / loader
// have at least one loadable segment to work with.
const SIZEOF_EHDR64: usize = 64;
const SIZEOF_PHDR64: usize = 56;
const PAGE_SIZE: usize = 4096;

fn writeU16(dst: [*]volatile u8, off: usize, v: u16) void {
    dst[off + 0] = @truncate(v & 0xFF);
    dst[off + 1] = @truncate((v >> 8) & 0xFF);
}

fn writeU32(dst: [*]volatile u8, off: usize, v: u32) void {
    dst[off + 0] = @truncate(v & 0xFF);
    dst[off + 1] = @truncate((v >> 8) & 0xFF);
    dst[off + 2] = @truncate((v >> 16) & 0xFF);
    dst[off + 3] = @truncate((v >> 24) & 0xFF);
}

fn writeU64(dst: [*]volatile u8, off: usize, v: u64) void {
    var i: usize = 0;
    while (i < 8) {
        dst[off + i] = @truncate((v >> @as(u6, @intCast(i * 8))) & 0xFF);
        i += 1;
    }
}

fn writeMinimalElf64(dst: [*]volatile u8) void {
    var i: usize = 0;
    while (i < PAGE_SIZE) {
        dst[i] = 0;
        i += 1;
    }
    // e_ident
    dst[0] = 0x7F; // EI_MAG0
    dst[1] = 'E'; // EI_MAG1
    dst[2] = 'L'; // EI_MAG2
    dst[3] = 'F'; // EI_MAG3
    dst[4] = 2; // EI_CLASS = ELFCLASS64
    dst[5] = 1; // EI_DATA  = ELFDATA2LSB (little-endian)
    dst[6] = 1; // EI_VERSION = EV_CURRENT
    dst[7] = 0; // EI_OSABI = ELFOSABI_NONE

    const entry_off: u64 = SIZEOF_EHDR64 + SIZEOF_PHDR64;

    writeU16(dst, 0x10, 3); // e_type = ET_DYN
    writeU16(dst, 0x12, 62); // e_machine = EM_X86_64
    writeU32(dst, 0x14, 1); // e_version
    writeU64(dst, 0x18, entry_off); // e_entry
    writeU64(dst, 0x20, SIZEOF_EHDR64); // e_phoff
    writeU64(dst, 0x28, 0); // e_shoff
    writeU32(dst, 0x30, 0); // e_flags
    writeU16(dst, 0x34, SIZEOF_EHDR64); // e_ehsize
    writeU16(dst, 0x36, SIZEOF_PHDR64); // e_phentsize
    writeU16(dst, 0x38, 1); // e_phnum
    writeU16(dst, 0x3A, 0); // e_shentsize
    writeU16(dst, 0x3C, 0); // e_shnum
    writeU16(dst, 0x3E, 0); // e_shstrndx

    // Program header at offset 64 (one PT_LOAD covering the page).
    const ph: usize = SIZEOF_EHDR64;
    writeU32(dst, ph + 0x00, 1); // PT_LOAD
    writeU32(dst, ph + 0x04, 4 | 1); // p_flags = PF_R | PF_X
    writeU64(dst, ph + 0x08, 0); // p_offset
    writeU64(dst, ph + 0x10, 0); // p_vaddr
    writeU64(dst, ph + 0x18, 0); // p_paddr
    writeU64(dst, ph + 0x20, PAGE_SIZE); // p_filesz
    writeU64(dst, ph + 0x28, PAGE_SIZE); // p_memsz
    writeU64(dst, ph + 0x30, PAGE_SIZE); // p_align

    // Single hlt instruction at e_entry so a scheduled child halts cleanly.
    dst[entry_off] = 0xF4;
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Stage one 4 KiB page frame for the ELF image.
    const pf_caps = caps.PfCap{ .move = true, .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1,
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const pf_handle: u12 = @truncate(cpf.v1 & 0xFFF);

    // Map the page frame into a temporary VAR so we can write the
    // minimal ELF header into byte offset 0 of the page frame.
    const var_caps_word = caps.VarCap{ .r = true, .w = true };
    const cvar = syscall.createVar(
        @as(u64, var_caps_word.toU16()),
        0b011, // cur_rwx = r|w
        1,
        0, // preferred_base = kernel chooses
        0, // device_region = none
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(2);
        return;
    }
    const var_handle: u12 = @truncate(cvar.v1 & 0xFFF);
    const var_base: u64 = cvar.v2;

    const map_result = syscall.mapPf(var_handle, &.{ 0, pf_handle });
    if (map_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Write the minimal valid ELF64 header into the staged page frame.
    // volatile so ReleaseSmall doesn't optimize away the writes (the
    // kernel reads through a different VA after we delete the staging VAR).
    const dst: [*]volatile u8 = @ptrFromInt(var_base);
    writeMinimalElf64(dst);

    // Reclaim the staging VAR (mirrors runner/primary.zig's pattern).
    _ = syscall.delete(var_handle);

    // SelfCap subset of what the runner granted us. Strict subset so
    // [test 02] (E_PERM if self_caps not subset) cannot fire.
    const child_self = caps.SelfCap{
        .crcd = true,
        .crec = true,
        .crpf = true,
        .crpt = true,
    };
    const self_caps_word: u64 = @as(u64, child_self.toU16());

    // Pass the result port handle so the parent retains a reference.
    // We use copy semantics (move = false) so this test domain keeps
    // its own port handle for the suspend that reports our verdict.
    const port_slot: u12 = caps.SLOT_FIRST_PASSED;
    const passed: [1]u64 = .{
        (caps.PassedHandle{
            .id = port_slot,
            .caps = (caps.PortCap{ .bind = true, .xfer = true }).toU16(),
            .move = false,
        }).toU64(),
    };

    const result = syscall.createCapabilityDomain(self_caps_word, VALID_CEILINGS_INNER, VALID_CEILINGS_OUTER, pf_handle, 0, // initial_ec_affinity
        passed[0..]);

    // Smoke check: any error code in the §[error_codes] range (1..15)
    // means the success path didn't take. The post-condition test 22
    // asserts (slot-2 cap caps == cridc_ceiling) cannot be checked
    // from the parent — see FIDELITY NOTE at the top of this file.
    if (testing.isHandleError(result.v1)) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
