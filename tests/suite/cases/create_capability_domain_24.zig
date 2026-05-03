// Spec §[create_capability_domain] create_capability_domain — test 24.
//
// "[test 24] a passed handle entry with `move = 1` is removed from the
//  caller's handle table after the call."
//
// Strategy
//   Pre-condition: this test runs as a child capability domain spawned
//   by the runner primary. The runner grants the child enough rights
//   for the setup we need: `crcd` (so create_capability_domain itself
//   doesn't return E_PERM via test 01), `crpt` (to mint a donor port),
//   and ceilings broad enough to satisfy tests 02-12.
//
//   To exercise test 24 we need a passed-handle entry whose source
//   handle:
//     - exists in the caller's table (avoids E_BADCAP / test 14),
//     - has `move` in its current caps (otherwise the kernel rejects
//       a `move = 1` transfer per §[handle_attachments] test 04),
//     - has caps that are a strict superset of (or equal to) the
//       caps requested in the entry (test 03 of handle_attachments).
//
//   A freshly-created port with `{move, copy, xfer, bind}` satisfies
//   all three. We request the entry with caps `{xfer, bind}` and
//   `move = 1` so it sits cleanly inside test 24's sweet spot.
//
//   We then issue `create_capability_domain`. On a working kernel the
//   call succeeds and §[create_capability_domain] test 24 mandates
//   that the donor port slot is released from our table. We probe the
//   slot with `restrict(donor, 0)`:
//     - new caps = 0 is a subset of any prior caps, so no E_PERM,
//     - reserved bits are clean, so no E_INVAL,
//     - the slot is the only state restrict touches,
//   leaving E_BADCAP as the spec-mandated post-condition for a
//   released slot (cf. §[capabilities] delete test 03, which uses the
//   same probe pattern).
//
// DEGRADED — ELF body unavailable in v0
//   The runner stages each test's own ELF via build-time @embedFile
//   into the primary's manifest, but a test ELF cannot embed a second
//   inner ELF without recursive build coupling that does not yet
//   exist. We provision an `elf_page_frame` of plausible size with
//   uninitialized backing pages; on a real kernel that page frame's
//   bytes do not parse as an ELF header and the call short-circuits
//   to E_INVAL via §[create_capability_domain] test 15 before any
//   handle-table mutation happens.
//
//   The spec line under test only fires on a *successful* call, so
//   the assertion this test wants to make is unreachable until the
//   harness can supply a valid inner ELF. Until then, we still issue
//   the call so the syscall path is exercised end-to-end, and we
//   defensively assert the post-condition that the working-kernel
//   path requires. On the v0 kernel (which fails the call) this test
//   reports a fail at assertion id 3; that is the expected degraded
//   behavior and matches the same "needs full kernel" gating other
//   complete-success tests will share.
//
// Action
//   1. create_port(caps = {move, copy, xfer, bind}) — must succeed
//   2. create_page_frame(2 pages of 4 KiB)          — must succeed
//        (sized to comfortably exceed an ELF header so test 16's
//        size-mismatch path is not what fires; isolates failure to
//        test 15's malformed-header path on the v0 stub kernel)
//   3. create_capability_domain(
//        self_caps   = a strict subset of the runner-granted self caps,
//        ceilings_in = subset of the caller's inner ceilings,
//        ceilings_out= subset of the caller's outer ceilings,
//        elf_pf      = pf from step 2,
//        passed[0]   = { id = port, caps = {xfer, bind}, move = 1 },
//      )                                             — must succeed
//   4. restrict(port, 0)                             — must return E_BADCAP
//
// Assertions
//   1: create_port returned an error word (donor setup failed)
//   2: create_page_frame returned an error word (ELF carrier failed)
//   3: create_capability_domain did not return success in vreg 1
//      (DEGRADED: fires on v0 due to missing inner ELF; see note above)
//   4: post-call restrict on the donor port did not return E_BADCAP,
//      i.e., the kernel did not remove the `move = 1` source from
//      the caller's table

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

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

fn writeMinimalElf(dst: [*]volatile u8) void {
    var i: usize = 0;
    while (i < PAGE_SIZE) {
        dst[i] = 0;
        i += 1;
    }
    dst[0] = 0x7F;
    dst[1] = 'E';
    dst[2] = 'L';
    dst[3] = 'F';
    dst[4] = 2; // ELFCLASS64
    dst[5] = 1; // ELFDATA2LSB
    dst[6] = 1; // EV_CURRENT
    dst[7] = 0;

    const entry_off: u64 = SIZEOF_EHDR64 + SIZEOF_PHDR64;

    writeU16(dst, 0x10, 3); // ET_DYN
    writeU16(dst, 0x12, 62); // EM_X86_64
    writeU32(dst, 0x14, 1);
    writeU64(dst, 0x18, entry_off);
    writeU64(dst, 0x20, SIZEOF_EHDR64); // e_phoff
    writeU64(dst, 0x28, 0);
    writeU32(dst, 0x30, 0);
    writeU16(dst, 0x34, SIZEOF_EHDR64);
    writeU16(dst, 0x36, SIZEOF_PHDR64);
    writeU16(dst, 0x38, 1); // e_phnum
    writeU16(dst, 0x3A, 0);
    writeU16(dst, 0x3C, 0);
    writeU16(dst, 0x3E, 0);

    const ph: usize = SIZEOF_EHDR64;
    writeU32(dst, ph + 0x00, 1); // PT_LOAD
    writeU32(dst, ph + 0x04, 4 | 1); // PF_R | PF_X
    writeU64(dst, ph + 0x08, 0);
    writeU64(dst, ph + 0x10, 0);
    writeU64(dst, ph + 0x18, 0);
    writeU64(dst, ph + 0x20, PAGE_SIZE);
    writeU64(dst, ph + 0x28, PAGE_SIZE);
    writeU64(dst, ph + 0x30, PAGE_SIZE);

    dst[entry_off] = 0xF4; // hlt
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1 — donor port with full move + xfer caps.
    const donor_caps = caps.PortCap{
        .move = true,
        .copy = true,
        .xfer = true,
        .bind = true,
    };
    const cp = syscall.createPort(@as(u64, donor_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const donor: caps.HandleId = @truncate(cp.v1 & 0xFFF);

    // Step 2 — page frame to act as elf_page_frame. One 4 KiB page is
    // sufficient for a minimal valid ELF (Ehdr + one Phdr + entry).
    const pf_caps = caps.PfCap{ .move = true, .copy = true, .r = true, .w = true, .x = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props.sz = 0 (4 KiB)
        1,
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(2);
        return;
    }
    const elf_pf: caps.HandleId = @truncate(cpf.v1 & 0xFFF);

    // Stage the ELF into a writable VAR mapping of the page frame
    // (the kernel reads the page frame contents through physmap).
    const stage_var_caps = caps.VarCap{ .r = true, .w = true };
    const cvar = syscall.createVar(
        @as(u64, stage_var_caps.toU16()),
        0b011,
        1,
        0,
        0,
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(2);
        return;
    }
    const stage_var: caps.HandleId = @truncate(cvar.v1 & 0xFFF);
    const stage_base: u64 = cvar.v2;
    const map = syscall.mapPf(stage_var, &.{ 0, elf_pf });
    if (map.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }
    const dst: [*]volatile u8 = @ptrFromInt(stage_base);
    writeMinimalElf(dst);
    _ = syscall.delete(stage_var);

    // Step 3 — child self caps. Subset of what the runner grants this
    // test domain (see runner/primary.zig spawnOne).
    const child_self = caps.SelfCap{
        .crpt = true,
    };
    const self_caps_word: u64 = @as(u64, child_self.toU16());

    // ceilings_inner (field0) — subset of the runner-granted ceilings.
    //   bits  0-7   ec_inner_ceiling   = 0x00 (no EC ops needed)
    //   bits  8-23  var_inner_ceiling  = 0x0000
    //   bits 24-31  cridc_ceiling      = 0x00
    //   bits 32-39  pf_ceiling         = 0x00
    //   bits 40-47  vm_ceiling         = 0x00
    //   bits 48-55  port_ceiling       = 0x1C (xfer/recv/bind)
    //   bits 56-63  _reserved          = 0
    const ceilings_inner: u64 = 0x001C_0000_0000_0000;

    // ceilings_outer (field1) — also a clean subset.
    //   bits  0-7   ec_outer_ceiling          = 0
    //   bits  8-15  var_outer_ceiling         = 0
    //   bits 16-31  restart_policy_ceiling    = 0
    //   bits 32-37  fut_wait_max              = 0
    //   bits 38-63  _reserved                 = 0
    const ceilings_outer: u64 = 0;

    // The passed-handle entry we are exercising. PassedHandle's u64
    // bit layout matches §[create_capability_domain] [4+] verbatim.
    const passed_entry = caps.PassedHandle{
        .id = donor,
        .caps = (caps.PortCap{ .xfer = true, .bind = true }).toU16(),
        .move = true,
    };
    const passed: [1]u64 = .{passed_entry.toU64()};

    const ccd = syscall.createCapabilityDomain(self_caps_word, ceilings_inner, ceilings_outer, elf_pf, 0, // initial_ec_affinity
        passed[0..]);

    // On a working kernel with a valid ELF body this is OK. On the
    // v0 stub kernel with no ELF body it is E_INVAL (test 15).
    // Either way the test 24 assertion below is what we are after.
    if (testing.isHandleError(ccd.v1)) {
        testing.fail(3);
        return;
    }

    // Step 4 — probe the donor slot. After a successful call with
    // `move = 1`, the donor's slot must be released; restrict on a
    // released slot returns E_BADCAP (cf. §[capabilities] delete
    // test 03).
    const probe = syscall.restrict(donor, 0);
    if (probe.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
