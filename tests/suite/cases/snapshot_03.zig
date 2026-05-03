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
//   gates with [1].caps.restart_policy != 3. The simplest way to land
//   there is to mint a single regular VAR handle via `create_var` with
//   caps = {r, w} (default `restart_policy = 0` = free) and reuse it for
//   both arguments. [1].caps.restart_policy = 0, so test 03's gate fires
//   and we don't reach test 04.
//
//   §[var] specifies the VarCap layout: bits 9-10 hold restart_policy.
//   `caps.VarCap{ .r = true, .w = true }` leaves restart_policy at its
//   default of 0 (= free), exactly the precondition the test wants.
//
// Action
//   1. createVar(caps={r,w}, props=0b011, pages=1) — must return a VAR
//      handle in vreg 1 (assertion 2 guards this precondition).
//   2. snapshot(var, var) — must return E_INVAL because
//      [1].caps.restart_policy is 0, not 3.
//
// Assertions
//   1: vreg 1 was not E_INVAL (the spec assertion under test).
//   2: createVar returned an error code — the success-path precondition
//      is broken so we cannot proceed to verify the snapshot E_INVAL
//      path.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const var_caps = caps.VarCap{ .r = true, .w = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0

    const cv = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        1, // pages = 1
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cv.v1)) {
        testing.fail(2);
        return;
    }

    const var_handle: caps.HandleId = @truncate(cv.v1 & 0xFFF);

    const result = syscall.snapshot(var_handle, var_handle);

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
