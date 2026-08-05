// Spec §[snapshot] — test 03.
//
// "[test 03] returns E_INVAL if [1].caps.restart_policy is not 3 (snapshot)."
//
// Strategy
//   The §[snapshot] gate order is:
//     test 01 — [1] BADCAP
//     test 02 — [2] BADCAP
//     test 03 — [1].caps.restart_policy != 3
//     test 04 — [2].caps.restart_policy != 2
//   To isolate test 03's E_INVAL we need [1] and [2] to clear the BADCAP
//   gates, then make only [1].caps.restart_policy invalid for snapshot.
//   The target VMAR uses caps = {r, w}, which leaves restart_policy at
//   the default 0 (= free), while the distinct source VMAR uses
//   restart_policy = 2 (= preserve) so test 04's precondition is valid.
//
//   §[var] specifies the VmarCap layout: bits 9-10 hold restart_policy.
//   `caps.VmarCap{ .r = true, .w = true }` leaves restart_policy at its
//   default of 0 (= free), exactly the target-side violation this test
//   wants. The source uses the same size/properties with restart_policy
//   set to preserve.
//
// Action
//   1. createVmar(caps={r,w}, props=0b011, pages=1) — target VMAR with
//      restart_policy = 0 (assertion 2 guards this precondition).
//   2. createVmar(caps={r,w,restart_policy=2}, props=0b011, pages=1) —
//      valid source VMAR (assertion 3 guards this precondition).
//   3. snapshot(target, source) — must return E_INVAL because
//      [1].caps.restart_policy is 0, not 3.
//
// Assertions
//   1: vreg 1 was not E_INVAL (the spec assertion under test).
//   2: target createVmar returned an error code — the success-path
//      precondition is broken so we cannot proceed.
//   3: source createVmar returned an error code — the source-side
//      preserve-policy precondition is broken so we cannot proceed.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const target_caps = caps.VmarCap{ .r = true, .w = true };
    const source_caps = caps.VmarCap{
        .r = true,
        .w = true,
        .restart_policy = 2, // preserve
    };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0

    const ctarget = syscall.createVmar(
        @as(u64, target_caps.toU16()),
        props,
        1, // pages = 1
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(ctarget.v1)) {
        testing.fail(2);
        return;
    }
    const target_handle: caps.HandleId = @truncate(ctarget.v1 & 0xFFF);

    const csource = syscall.createVmar(
        @as(u64, source_caps.toU16()),
        props,
        1, // pages = 1 (matches target)
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(csource.v1)) {
        testing.fail(3);
        return;
    }
    const source_handle: caps.HandleId = @truncate(csource.v1 & 0xFFF);

    const result = syscall.snapshot(target_handle, source_handle);

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
