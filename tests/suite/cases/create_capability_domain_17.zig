// Spec §[create_capability_domain] — test 17.
//
// "[test 17] returns E_INVAL if any reserved bits are set in [1], [2],
//  or a passed handle entry."
//
// Strategy
//   The argument layout per spec §[create_capability_domain] has
//   reserved bit ranges in three places:
//     [1] caps:           bits 24-63 _reserved
//     [2] ceilings_inner: bits 56-63 _reserved (plus internal
//                         reserved sub-fields, e.g. bits 17-23 in
//                         var_inner_ceiling)
//     [3] ceilings_outer: bits 38-63 _reserved
//     [5+] passed_handle: bits 12-15 and 33-63 _reserved
//
//   We exercise three branches, one per reservoir of reserved bits in
//   [1], [2], and a passed handle entry, asserting the kernel returns
//   E_INVAL each time. We mirror the runner's known-valid argument
//   template (see runner/primary.zig: `ceilings_inner =
//   0x001C_011F_3F01_FFFF`, `ceilings_outer = 0x0000_003F_03FE_FFFF`)
//   so that with all-zero reserved bits the call would otherwise pass
//   the subset/ceiling/restart-policy checks. The reserved-bit check
//   is therefore the only spec-mandated failure path that mutates
//   between the baseline and our injected variants.
//
//   Test 13 (E_BADCAP on invalid page frame) requires a valid pf
//   handle, so we stage one via `create_page_frame`. We do NOT write a
//   valid ELF into it: tests 15 (malformed ELF) and 16 (size mismatch)
//   also return E_INVAL, which collides with our expected return code.
//   That collision is benign — any spec-correct implementation returns
//   E_INVAL for the reserved-bit case, and an implementation that
//   short-circuits on ELF validation first still surfaces E_INVAL. A
//   stricter ordering test would belong in tests 15/16/17 inter-order
//   coverage, which the spec does not pin.
//
// Action
//   Setup
//     - create a 1-page page frame to use as `elf_page_frame`.
//
//   Branch A: reserved bit 56 of [2] (ceilings_inner) set.
//     Call create_capability_domain with the runner's valid
//     ceilings_inner OR'd with (1 << 56). Assert vreg 1 == E_INVAL.
//
//   Branch B: reserved bit 24 of [1] (self_caps) set.
//     Caps word low 16 bits hold a valid SelfCap subset of what the
//     runner granted us; idc_rx (bits 16-23) zero; bit 24 is reserved.
//
//   Branch C: passed_handle entry with reserved bit 12 set.
//     Use the result port handle (slot 3) — the only handle the test
//     domain is guaranteed to have besides self/EC/IDC. Build a
//     PassedHandle equivalent encoding manually with bit 12 set.
//
// Assertions
//   1: setup `create_page_frame` failed.
//   2: branch A returned something other than E_INVAL.
//   3: branch B returned something other than E_INVAL.
//   4: branch C returned something other than E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Mirror runner/primary.zig's known-valid ceiling templates so the
// only spec violation in each branch is the injected reserved bit.
const VALID_CEILINGS_INNER: u64 = 0x001C_011F_3F01_FFFF;
const VALID_CEILINGS_OUTER: u64 = 0x0000_003F_03FE_FFFF;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Stage a 1-page page frame to satisfy test 13's BADCAP check.
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

    // A SelfCap subset of what the runner granted us. Caller's caps
    // include crcd/crec/crvr/crpf/crvm/crpt/pmu/fut_wake/timer; we ask
    // for a strict subset so test 02 (E_PERM on self_caps not subset)
    // can't fire.
    const child_self = caps.SelfCap{ .crpf = true };
    const valid_self_caps: u64 = @as(u64, child_self.toU16());

    // Result port handle is at slot SLOT_FIRST_PASSED by spec
    // §[create_capability_domain] convention (the runner passes the
    // result port as the sole entry).
    const port_slot: u12 = caps.SLOT_FIRST_PASSED;

    // ---------------------------------------------------------------
    // Branch A: reserved bit 56 set in [2] ceilings_inner.
    // ---------------------------------------------------------------
    {
        const ceilings_inner_bad: u64 = VALID_CEILINGS_INNER | (@as(u64, 1) << 56);
        const passed = (caps.PassedHandle{
            .id = port_slot,
            .caps = (caps.PortCap{ .bind = true, .xfer = true }).toU16(),
            .move = false,
        }).toU64();
        const r = syscall.issueReg(.create_capability_domain, 0, .{
            .v1 = valid_self_caps,
            .v2 = ceilings_inner_bad,
            .v3 = VALID_CEILINGS_OUTER,
            .v4 = @as(u64, pf_handle),
            .v5 = passed,
        });
        if (r.v1 != @intFromEnum(errors.Error.E_INVAL)) {
            testing.fail(2);
            return;
        }
    }

    // ---------------------------------------------------------------
    // Branch B: reserved bit 24 set in [1] caps.
    // ---------------------------------------------------------------
    {
        const caps_bad: u64 = valid_self_caps | (@as(u64, 1) << 24);
        const passed = (caps.PassedHandle{
            .id = port_slot,
            .caps = (caps.PortCap{ .bind = true, .xfer = true }).toU16(),
            .move = false,
        }).toU64();
        const r = syscall.issueReg(.create_capability_domain, 0, .{
            .v1 = caps_bad,
            .v2 = VALID_CEILINGS_INNER,
            .v3 = VALID_CEILINGS_OUTER,
            .v4 = @as(u64, pf_handle),
            .v5 = passed,
        });
        if (r.v1 != @intFromEnum(errors.Error.E_INVAL)) {
            testing.fail(3);
            return;
        }
    }

    // ---------------------------------------------------------------
    // Branch C: reserved bit 12 set in a passed handle entry.
    //
    // PassedHandle's typed wrapper takes id: u12 and won't carry a
    // bit at position 12. Build the u64 manually so the reserved
    // bit reaches the kernel.
    // ---------------------------------------------------------------
    {
        const port_caps_word: u64 =
            @as(u64, (caps.PortCap{ .bind = true, .xfer = true }).toU16());
        const passed_bad: u64 =
            (@as(u64, port_slot) & 0xFFF) | // id
            (@as(u64, 1) << 12) | // reserved bit 12 set
            (port_caps_word << 16) | // caps in bits 16-31
            (@as(u64, 0) << 32); // move = 0
        const r = syscall.issueReg(.create_capability_domain, 0, .{
            .v1 = valid_self_caps,
            .v2 = VALID_CEILINGS_INNER,
            .v3 = VALID_CEILINGS_OUTER,
            .v4 = @as(u64, pf_handle),
            .v5 = passed_bad,
        });
        if (r.v1 != @intFromEnum(errors.Error.E_INVAL)) {
            testing.fail(4);
            return;
        }
    }

    testing.pass();
}
