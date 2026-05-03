// Spec §[create_capability_domain] — test 19.
//
// "[test 19] on success, the caller receives an IDC handle to the new
//  domain with caps = the caller's `cridc_ceiling`."
//
// Strategy
//   The post-condition concerns the caller-side IDC handle that
//   `create_capability_domain` returns in vreg 1. Per the spec text
//   immediately above the test list and §[cridc_ceiling], that handle
//   is minted with caps = the caller's `cridc_ceiling`, which lives at
//   bits 24-31 of the caller's slot-0 self-handle field0.
//
//   The test therefore:
//     1. Reads the caller's self-handle to extract the authoritative
//        `cridc_ceiling` value (no hardcoding — the runner's spawn
//        config is the only ground truth and may evolve).
//     2. Stages a minimal-but-valid ELF image into a page frame so
//        the create call has a parsable ELF and reaches the success
//        path rather than tripping E_INVAL (test 15/16).
//     3. Calls `create_capability_domain` with ceilings that are
//        strict subsets of the caller's ceilings — every E_PERM
//        check (tests 01-12) and every E_INVAL/E_BADCAP setup check
//        (tests 13-18) must be cleared so the kernel reaches the
//        success path.
//     4. Reads the cap-table slot of the returned IDC handle and
//        asserts its caps field equals the caller's `cridc_ceiling`.
//
//   Minimal ELF construction: one ELF64 little-endian executable
//   header, one program header of type PT_LOAD covering the single
//   page that holds a `hlt` instruction at `e_entry`. That is the
//   smallest layout the kernel's ELF parser can succeed on without
//   triggering E_INVAL (malformed) or running off the end of the
//   page frame (E_INVAL size).
//
// SPEC AMBIGUITY: the kernel-side handle ABI in §[capabilities] places
// the cap field at bits 48-63 of word 0; libz's `caps.Cap.caps()` reads
// that slice. The post-condition is checked against that field as
// observed via the read-only cap table. If the kernel surfaces caps
// only via the returned vreg (not via the table) the readCap branch
// would need replacing with a vreg-derived check; we follow the same
// convention every other on-success cap test in this suite uses.
//
// SPEC AMBIGUITY: an inline-built minimal ELF has no executable text;
// the page following the header bytes is zero-filled. The new domain's
// initial EC will fault on first instruction. The spec lists no
// success precondition that the EC "execute usefully" — only that the
// caller observe its returned handle's caps. So this test passes as
// long as `create_capability_domain` itself succeeds and mints the
// handle correctly. If the kernel decides "ELF parse OK but no
// executable text" should be E_INVAL, this test must adopt the
// embedded-test pattern (mirror of `runner/primary.zig`'s
// `stageElfIntoPageFrame`) which embeds a real test ELF via a build
// step. That is not yet wired; degraded smoke noted here.
//
// Action
//   1. readCap(slot 0) — extract caller's cridc_ceiling
//   2. create_page_frame(1 page, r|w|x) — staging area for the ELF
//   3. create_var(r|w, 1 page) and map_pf — get a writable mapping
//   4. write minimal ELF64 header into the page
//   5. delete the staging VAR (mirrors primary.zig — kernel re-reads
//      the page frame independently)
//   6. create_capability_domain(...) with strict-subset ceilings
//   7. readCap(returned slot) — verify caps == cridc_ceiling
//
// Assertions
//   1: readCap of slot 0 produced a non-self-handle type (sanity)
//   2: create_page_frame returned an error word
//   3: create_var returned an error word
//   4: map_pf returned non-OK
//   5: create_capability_domain returned an error word in vreg 1
//   6: returned IDC handle's type tag is not `capability_domain`
//   7: returned IDC handle's caps field != caller's cridc_ceiling

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const Cap = caps.Cap;
const HandleId = caps.HandleId;
const HandleType = caps.HandleType;
const IdcCap = caps.IdcCap;
const PassedHandle = caps.PassedHandle;
const PfCap = caps.PfCap;
const SelfCap = caps.SelfCap;
const VarCap = caps.VarCap;

// Minimal ELF64 header constants. Spec source: System V ABI / ELF-64
// Object File Format. Field offsets / sizes from elf.h equivalents.
const EI_NIDENT: usize = 16;
const ELF_MAG0: u8 = 0x7F;
const ELF_MAG1: u8 = 'E';
const ELF_MAG2: u8 = 'L';
const ELF_MAG3: u8 = 'F';
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;
const ELFOSABI_NONE: u8 = 0;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

const SIZEOF_EHDR64: usize = 64;
const SIZEOF_PHDR64: usize = 56;
const PAGE_SIZE: usize = 4096;

// Lay down a minimal but valid ELF64 image at `dst`. Returns the total
// bytes written. The image declares one PT_LOAD segment that covers
// the entire page frame (header + tail) starting at vaddr 0; e_entry
// points just past the header so the first instruction the kernel sees
// is whatever sits at offset SIZEOF_EHDR64 + SIZEOF_PHDR64 in the
// page. We write a single 0xF4 (`hlt`) byte there so a domain that
// successfully launches will halt rather than fault on undefined ops.
//
// `dst` is `volatile` because the kernel re-reads the page frame
// through a different VA (physmap) after the staging VAR is dropped;
// without volatile, ReleaseSmall optimizes away the stores (see
// project memory `project_zig_shm_readtable_bug.md` — same class of
// bug as the runner's stageElfIntoPageFrame which also uses volatile).
fn writeMinimalElf(dst: [*]volatile u8) usize {
    var i: usize = 0;
    while (i < PAGE_SIZE) {
        dst[i] = 0;
        i += 1;
    }

    // e_ident
    dst[0] = ELF_MAG0;
    dst[1] = ELF_MAG1;
    dst[2] = ELF_MAG2;
    dst[3] = ELF_MAG3;
    dst[4] = ELFCLASS64;
    dst[5] = ELFDATA2LSB;
    dst[6] = EV_CURRENT;
    dst[7] = ELFOSABI_NONE;
    // bytes 8-15 already zero

    const entry_off: u64 = SIZEOF_EHDR64 + SIZEOF_PHDR64;

    writeU16(dst, 0x10, ET_DYN); // e_type — kernel requires PIE (ET_DYN)
    writeU16(dst, 0x12, EM_X86_64); // e_machine
    writeU32(dst, 0x14, EV_CURRENT); // e_version
    writeU64(dst, 0x18, entry_off); // e_entry — vaddr of first insn
    writeU64(dst, 0x20, SIZEOF_EHDR64); // e_phoff
    writeU64(dst, 0x28, 0); // e_shoff
    writeU32(dst, 0x30, 0); // e_flags
    writeU16(dst, 0x34, SIZEOF_EHDR64); // e_ehsize
    writeU16(dst, 0x36, SIZEOF_PHDR64); // e_phentsize
    writeU16(dst, 0x38, 1); // e_phnum
    writeU16(dst, 0x3A, 0); // e_shentsize
    writeU16(dst, 0x3C, 0); // e_shnum
    writeU16(dst, 0x3E, 0); // e_shstrndx

    // Program header at offset SIZEOF_EHDR64 (one PT_LOAD).
    const ph: usize = SIZEOF_EHDR64;
    writeU32(dst, ph + 0x00, PT_LOAD);
    writeU32(dst, ph + 0x04, PF_R | PF_X); // p_flags
    writeU64(dst, ph + 0x08, 0); // p_offset (whole image from byte 0)
    writeU64(dst, ph + 0x10, 0); // p_vaddr
    writeU64(dst, ph + 0x18, 0); // p_paddr
    writeU64(dst, ph + 0x20, PAGE_SIZE); // p_filesz
    writeU64(dst, ph + 0x28, PAGE_SIZE); // p_memsz
    writeU64(dst, ph + 0x30, PAGE_SIZE); // p_align

    // Single hlt instruction at e_entry so the domain halts cleanly.
    dst[entry_off] = 0xF4; // hlt

    return PAGE_SIZE;
}

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

pub fn main(cap_table_base: u64) void {
    // 1. Read caller's self-handle to extract cridc_ceiling.
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    if (self_cap.handleType() != .capability_domain_self) {
        testing.fail(1);
        return;
    }
    // §[capability_domain] Self handle field0: cridc_ceiling at bits 24-31.
    const caller_cridc_ceiling: u16 = @truncate((self_cap.field0 >> 24) & 0xFF);

    // 2. Create a 1-page page frame to hold the ELF.
    const pf_caps = PfCap{
        .move = true,
        .copy = true,
        .r = true,
        .w = true,
        .x = true,
    };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props.sz = 0 (4 KiB)
        1,
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(2);
        return;
    }
    const pf_handle: HandleId = @truncate(cpf.v1 & 0xFFF);

    // 3. Create a writable VAR and install the page frame at offset 0.
    const var_caps = VarCap{ .r = true, .w = true };
    const cvar = syscall.createVar(
        @as(u64, var_caps.toU16()),
        0b011, // cur_rwx = r|w
        1, // pages
        0, // preferred_base = kernel chooses
        0, // device_region = none
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(3);
        return;
    }
    const var_handle: HandleId = @truncate(cvar.v1 & 0xFFF);
    const var_base: u64 = cvar.v2;

    const map = syscall.mapPf(var_handle, &.{ 0, pf_handle });
    if (map.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }

    // 4. Stage a minimal valid ELF into the page frame.
    const dst: [*]volatile u8 = @ptrFromInt(var_base);
    _ = writeMinimalElf(dst);

    // 5. Drop the staging VAR. The kernel re-reads the page frame
    //    independently of any caller-held mapping.
    _ = syscall.delete(var_handle);

    // 6. Build ceilings as strict subsets of the caller's. Mirror of
    //    `runner/primary.zig` spawnOne — every reserved bit zeroed,
    //    every per-type ceiling set within what the runner granted us.
    //    The actual values must satisfy E_PERM checks tests 02-12;
    //    using the exact caller ceilings (read from self-handle) keeps
    //    the test robust against runner-spawn changes.
    //
    //    self_caps in [1] bits 0-15 plus idc_rx in bits 16-23.
    const new_self = SelfCap{
        .crcd = false,
        .crec = true,
        .crvr = true,
        .crpf = true,
        .crpt = true,
    };
    const idc_rx_byte: u64 = (self_cap.field0 >> 32) & 0xFF;
    const caps_word: u64 = @as(u64, new_self.toU16()) | (idc_rx_byte << 16);

    // ceilings_inner ([2] arg layout): build from the caller's field0
    // (which uses §[capability_domain] Self handle layout — idc_rx at
    // bits 32-39 between cridc and pf). Copy bits 0-31 verbatim
    // (ec/var/cridc) and shift bits 40-63 (pf/vm/port) down by 8 to
    // place them at [2]-layout bits 32-55.
    const field0_low: u64 = self_cap.field0 & 0x0000_0000_FFFF_FFFF;
    const field0_pf_vm_port: u64 = (self_cap.field0 >> 40) & 0x0000_0000_00FF_FFFF;
    const ceilings_inner: u64 = field0_low | (field0_pf_vm_port << 32);

    // ceilings_outer: ec_outer in bits 0-7, var_outer in bits 8-15,
    // restart_policy_ceiling in 16-31, fut_wait_max in 32-37 — all
    // straight from the caller's field1 (already a valid bit pattern).
    const ceilings_outer: u64 = self_cap.field1;

    // 7. Issue create_capability_domain. We pass zero `passed_handles`
    //    — adding any introduces additional reserved-bit / source-id
    //    checks irrelevant to test 19's post-condition.
    const passed: [0]u64 = .{};

    const result = syscall.createCapabilityDomain(caps_word, ceilings_inner, ceilings_outer, pf_handle, 0, // initial_ec_affinity
        passed[0..]);
    if (testing.isHandleError(result.v1)) {
        testing.fail(5);
        return;
    }

    // 8. The returned handle id is in vreg 1 bits 0-11. Confirm the
    //    type tag is `capability_domain` (IDC handles to other domains
    //    use this type per §[capabilities] HandleType table).
    const idc_handle: HandleId = @truncate(result.v1 & 0xFFF);
    const idc_cap = caps.readCap(cap_table_base, idc_handle);
    if (idc_cap.handleType() != .capability_domain) {
        testing.fail(6);
        return;
    }

    // 9. The post-condition: caps field equals caller's cridc_ceiling.
    //    cridc_ceiling is an 8-bit value; the IDC cap field is 16 bits
    //    wide. Per §[cridc_ceiling] the minted caps are exactly the
    //    caller's cridc_ceiling, zero-extended into the cap field.
    const got: u16 = idc_cap.caps();
    const expected: u16 = @as(u16, caller_cridc_ceiling);
    if (got != expected) {
        testing.fail(7);
        return;
    }

    testing.pass();
}
