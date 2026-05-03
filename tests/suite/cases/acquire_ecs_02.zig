// Spec §[acquire_ecs] acquire_ecs — test 02.
//
// "[test 02] returns E_PERM if [1] does not have the `aqec` cap."
//
// Strategy
//   The kernel populates the new domain's slot 2 with a self-IDC
//   handle whose caps are taken from the parent's `cridc_ceiling`.
//   The runner passes `cridc_ceiling = 0x3F` (all 6 IDC bits set,
//   §[capability_domain] / §[create_capability_domain]), so the
//   child's slot-2 self-IDC starts with `aqec` set.
//
//   To prove the spec's E_PERM gate fires when `aqec` is absent we
//   use restrict to drop just that bit: §[capabilities] restrict
//   test 07 establishes the canonical "drop a cap, then exercise
//   the gated syscall and observe E_PERM" shape and we follow it
//   verbatim here.
//
//   IDC caps use only bitwise-subset semantics — bit 5
//   (`restart_policy`) is a single bool, not the EC/VAR 2-bit numeric
//   field — so restrict on an IDC handle has no numeric corner. Other
//   IDC cap bits (`move`, `copy`, `crec`, `aqvr`, `restart_policy`)
//   are preserved across the restrict so dropping `aqec` is the only
//   change visible to acquire_ecs.
//
// Action
//   1. restrict(self_idc, IdcCap{ all bits except aqec })  — succeed
//   2. acquire_ecs(self_idc)                                — E_PERM
//
// Assertions
//   1: restrict returned a non-OK error word (setup failed)
//   2: acquire_ecs returned something other than E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const self_idc: u12 = caps.SLOT_SELF_IDC;

    // Drop `aqec` while preserving every other IDC cap bit so the
    // restrict itself is a strict subset of slot 2's starting caps
    // (= cridc_ceiling = 0x3F, bits 0-5 all set).
    const reduced = caps.IdcCap{
        .move = true,
        .copy = true,
        .crec = true,
        .aqec = false,
        .aqvr = true,
        .restart_policy = true,
    };
    const new_caps_word: u64 = @as(u64, reduced.toU16());
    const restrict_result = syscall.restrict(self_idc, new_caps_word);
    if (restrict_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    const result = syscall.acquireEcs(self_idc);
    if (result.regs.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
