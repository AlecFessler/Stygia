// Spec §[suspend] suspend — test 07.
//
// "[test 07] returns E_INVAL if [1] is already suspended."
//
// Strategy
//   The "already suspended" branch fires only when every preceding
//   gate (tests 01..06) is inert and the kernel resolves [1] to an EC
//   that is currently in the suspended state. The plan is to mint a
//   helper EC + a destination port, drive a *first* `suspend(target,
//   port)` to land the helper in the suspended state, then issue a
//   *second* `suspend(target, port)` and assert E_INVAL.
//
//   Failure-path neutralization (§[suspend] tests 01..07):
//     - test 01 (E_BADCAP if [1] not a valid EC handle): the helper
//       handle id comes from a successful create_execution_context, so
//       it remains a valid EC handle for both suspend calls.
//     - test 02 (E_BADCAP if [2] not a valid port handle): the port
//       handle id comes from a successful create_port, so it remains
//       valid for both calls.
//     - test 03 (E_PERM if [1] lacks `susp`): the helper is minted
//       with `susp = true`.
//     - test 04 (E_PERM if [2] lacks `bind`): the port is minted
//       with `bind = true`.
//     - test 05 (E_INVAL reserved bits): `syscall.suspendEc` packs
//       target / port through u12, so vreg 1 / vreg 2 cannot carry
//       reserved bits; pair_count = 0 so no high-vreg pair entry
//       reserved bits.
//     - test 06 (E_INVAL [1] is a vCPU): the helper is a plain EC.
//
//   Why the helper EC, not self
//     Suspending the calling EC blocks until something resumes it (a
//     receiver picks up the event, replies). The test EC has no peer
//     wired up to drain the port and reply, so suspending self would
//     deadlock the test. Spawning a helper EC and suspending *it*
//     leaves the calling EC running so we can issue the second
//     `suspend` and observe its return value.
//
//   Why the helper does not need to be readable / writable
//     Tests 10/11 (read/write cap gating of event_state) are
//     orthogonal: this test only cares about the kernel's suspended-
//     state discriminator, not what the event payload exposes. The
//     helper's EC handle in this domain carries the minimum caps
//     needed to drive `suspend` past the cap gates (just `susp`).
//
//   Why a fresh port, not the result port at SLOT_FIRST_PASSED
//     The result port is owned by the runner's primary EC and used
//     by the testing helpers (`pass()` / `fail()`) to report this
//     test's outcome. Queuing extra senders on it could perturb the
//     primary's recv ordering. A fresh port created here gives the
//     test exclusive control over the suspension queue. The port has
//     `bind` so the cap gate stays inert; nothing in the test ever
//     calls `recv` on this port, so it accumulates two queued senders
//     across the two suspend attempts (well, one — the second call
//     returns E_INVAL and never queues), which is fine since the
//     port is local to the test domain and gets cleaned up at domain
//     teardown.
//
// Action
//   1. createPort(caps={bind})                                  — must succeed
//   2. createExecutionContext(target=self, caps={susp},
//      entry=&dummyEntry, stack_pages=1, affinity=0)            — must succeed
//   3. suspendEc(helper_ec, port, &.{})                         — first suspend;
//      must return OK (the helper is now suspended on the port).
//   4. suspendEc(helper_ec, port, &.{})                         — second suspend;
//      must return E_INVAL because the helper is already suspended.
//
// Assertions
//   1: setup syscall failed (createPort returned an error word in v1).
//   2: setup syscall failed (createExecutionContext returned an error
//      word in v1).
//   3: first suspend did not return OK (the precondition for test 07
//      — that the helper EC is in the suspended state — could not be
//      established).
//   4: second suspend returned something other than E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: destination port with `bind` so suspend's [2] cap gate
    // (test 04) stays inert. No other caps are load-bearing for this
    // test; the port never receives a `recv`, so its sender queue
    // simply holds the helper EC across the second call.
    const port_caps = caps.PortCap{ .bind = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: helper EC with `susp` so suspend's [1] cap gate (test
    // 03) stays inert. `restart_policy = 0` keeps the call within the
    // runner's restart_policy_ceiling. The helper begins executing at
    // dummyEntry (an infinite hlt) — running, not suspended — so the
    // first suspend has a runnable target to land in the suspended
    // state.
    const ec_caps = caps.EcCap{
        .susp = true,
        .restart_policy = 0,
    };
    // §[create_execution_context] caps word: caps in bits 0-15,
    // target_caps in 16-31 (ignored when target=self), priority in
    // 32-33. priority=0 stays within the child's pri ceiling.
    const caps_word: u64 = @as(u64, ec_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages
        0, // target = self
        0, // affinity = any core
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(2);
        return;
    }
    const helper_ec: u12 = @truncate(cec.v1 & 0xFFF);

    // Step 3: first suspend. With every prelude gate inert and the
    // helper running, this must succeed (returning OK) and leave the
    // helper EC in the suspended state on `port_handle`.
    const first = syscall.suspendEc(helper_ec, port_handle, &.{});
    if (first.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Step 4: second suspend on the now-suspended helper. Tests 01,
    // 02, 03, 04, 05, 06 are still inert (handles unchanged, caps
    // unchanged, no reserved bits, regular EC), so the only remaining
    // rejection path is the already-suspended discriminator — must
    // return E_INVAL.
    const second = syscall.suspendEc(helper_ec, port_handle, &.{});
    if (second.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
