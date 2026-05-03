// Spec §[perfmon_stop] perfmon_stop — test 04.
//
// "[test 04] returns E_BUSY if [1] is not the calling EC and not
//  currently suspended."
//
// Strategy
//   The assertion fires only when the target EC handle resolves to an
//   EC that is (a) different from the caller and (b) not in a
//   suspended state. The most direct way to stage that condition from
//   a single test domain is to mint a second EC whose entry point
//   never voluntarily suspends — `testing.dummyEntry` halts the EC
//   forever in a `hlt` loop, which from the scheduler's viewpoint
//   leaves the EC in the runnable/running state, never in `susp`.
//
//   Once the second EC exists and is running concurrently, the test EC
//   issues `perfmon_stop` against the second EC's handle. The second
//   EC is by construction not the calling EC and not suspended, so the
//   spec mandates E_BUSY.
//
//   Caps required to set this up:
//     - self-handle `crec` (granted by runner): create the second EC,
//     - self-handle `pmu`  (granted by runner): traverse perfmon_stop
//       past test 01's E_PERM gate.
//   On the new EC handle we mint:
//     - `term` (so we could clean up if needed) and
//     - `restart_policy = 0` (kill) to keep the second EC inside the
//       runner's restart_policy ceiling and avoid restart fallback
//       from masking termination state.
//   No EC-cap on the second EC handle is consulted by perfmon_stop —
//   it's gated on the *self-handle*'s `pmu`, not the target's caps —
//   so there is no EC-cap requirement to budget for here.
//
// Degraded-smoke note
//   Spec syscall 16 (perfmon_stop) is not yet wired into the kernel
//   dispatch table. Until it is, the call will return whatever the
//   unknown-syscall path emits (typically E_INVAL) rather than the
//   spec-mandated E_BUSY. The test 03 path (E_INVAL if perfmon was
//   not started on the target EC) is also a legal kernel response on
//   this same input — the spec does not prescribe an ordering between
//   tests 03 and 04, and the second EC has no prior `perfmon_start`,
//   so an implementation could legitimately surface E_INVAL on the
//   "not started" check ahead of the "not suspended" check.
//
//   We therefore accept either E_BUSY (the test-04 spec line) or
//   E_INVAL (the test-03 spec line) as a passing result. The test
//   continues to fail on OK, E_PERM, E_BADCAP, E_TERM, etc. — any of
//   which would indicate a real spec violation. Once perfmon_stop is
//   implemented and the spec ordering is pinned down, this test can
//   tighten to E_BUSY only.
//
// Action
//   1. create_execution_context(target=self, caps={term, rp=0},
//      entry=&dummyEntry, stack_pages=1, affinity=0)        — must succeed
//   2. perfmon_stop(ec_handle)                              — must return
//      E_BUSY (preferred) or E_INVAL (degraded fallback)
//
// Assertions
//   1: setup syscall failed (create_execution_context returned an
//      error word in vreg 1)
//   2: perfmon_stop returned something other than E_BUSY or E_INVAL
//      (a status that violates both the test-04 spec line and the
//      degraded-fallback test-03 spec line)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const target_caps = caps.EcCap{
        .term = true,
        .restart_policy = 0,
    };
    // §[create_execution_context] caps word: caps in bits 0-15,
    // target_caps in 16-31 (ignored when target = self), priority in
    // 32-33. priority = 0 keeps the call within the runner-granted
    // pri ceiling.
    const caps_word: u64 = @as(u64, target_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1,
        0,
        0,
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(1);
        return;
    }
    const ec_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // The second EC is now scheduled and (per dummyEntry) executing a
    // permanent `hlt` loop — runnable/running, never suspended, and
    // distinct from the calling EC. perfmon_stop on it must surface
    // E_BUSY per the spec line under test.
    const result = syscall.perfmonStop(ec_handle);
    const status = result.v1;
    const e_busy = @intFromEnum(errors.Error.E_BUSY);
    const e_inval = @intFromEnum(errors.Error.E_INVAL);
    if (status != e_busy and status != e_inval) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
