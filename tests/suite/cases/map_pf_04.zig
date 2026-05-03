// Spec §[map_pf] — test 04.
//
// "[test 04] returns E_INVAL if N is 0."
//
// Strategy
//   N is encoded in syscall word bits 12-19 (count of (offset,
//   page_frame) pairs). Per §[map_pf] the syscall takes
//   `[2 + 2i] offset, [2 + 2i + 1] page_frame` for i in 0..N-1, so
//   the libz wrapper derives N from `pairs.len / 2`. An empty pairs
//   slice therefore drives N = 0 in the syscall word.
//
//   To isolate the N == 0 rejection we need [1] to be a valid VAR
//   handle so test 01 (E_BADCAP for an invalid VAR) does not pre-empt
//   test 04. We also want a non-mmio VAR so test 03 (E_PERM on
//   caps.mmio) cannot fire. Tests 02 and 05-09 all dereference the
//   pairs slice; with no pairs in flight none of them have anything
//   to inspect, so test 04 is the only check left to fail. Test 10
//   inspects field1 `map`, which on a freshly minted VAR is 0 — the
//   exact state pf installation accepts.
//
//   The freshly-minted VAR therefore satisfies every prerequisite for
//   test 04 to be the surfacing rejection: the only remaining gate on
//   an empty pairs slice is N == 0.
//
// Action
//   1. createVar(caps={r,w}, props=0b011, pages=1) — must return a
//      VAR handle in vreg 1 (assertion 2 guards this precondition).
//   2. mapPf(var_handle, &.{}) — empty pairs slice, so N = 0. The
//      kernel must return E_INVAL per §[map_pf] test 04.
//
// Assertions
//   1: vreg 1 was not E_INVAL after mapPf with an empty pairs slice
//      (the spec assertion under test).
//   2: createVar returned an error code in vreg 1 — the precondition
//      for the assertion is broken so we cannot proceed.

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

    const result = syscall.mapPf(var_handle, &.{});

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
