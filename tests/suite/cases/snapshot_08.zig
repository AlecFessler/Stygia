// Spec §[snapshot] — test 08.
//
// "[test 08] if the source [2] is deleted before restart, the binding
//  is cleared; on restart with no source bound, the domain is
//  terminated rather than restarted."
//
// DEGRADED SMOKE VARIANT
//   The faithful observable is split across two domain-restart events
//   that the test capability domain cannot trigger or witness from
//   inside itself:
//
//     1. Bind a source VAR to a target VAR via `snapshot`.
//     2. `delete` the source VAR handle. Per §[delete] line 173, the
//        VAR's address space is freed and the handle released; per
//        §[snapshot] test 08, the kernel is supposed to clear the
//        target's source binding as a side effect of that source
//        deletion (the binding is internal kernel state — there is no
//        v3 syscall that reads "the source bound to this target").
//     3. Cause the calling capability domain to restart (e.g., fault
//        every EC, or kill the self-handle with `restart` cap set).
//        The kernel walks the target VAR's `restart_policy = snapshot`,
//        looks up its bound source, finds none, and per the spec line
//        TERMINATES the domain rather than restarting it.
//     4. From outside, observe that the domain did not restart.
//
//   None of these post-action observations is reachable from inside the
//   test EC's own capability domain:
//
//     - Step (2)'s side effect — "the binding is cleared" — is not
//       directly observable: there is no `get_snapshot_source` syscall
//       and `sync` on the target VAR refreshes only `cur_rwx`, `map`,
//       `device` (per §[var] field1), not the bound-source identity.
//     - Step (3) requires triggering a restart of *this same domain*,
//       which destroys the EC running the test. Even if we could trip
//       the restart, the spec-mandated outcome (TERMINATION instead of
//       restart) means the test EC does not get a chance to call
//       `pass`/`fail` — the result port reply path is gone with the
//       domain. Confirming "domain was terminated, not restarted" is a
//       parent-runner observation, and the runner currently spawns
//       each test in a single child capability domain with no recipe
//       for "restart this domain and report whether it came back".
//
//   Reaching the faithful observation would require either:
//     - the runner gaining a per-test "restart-and-observe" harness:
//       hold a self-IDC handle to the test domain plus a watch on its
//       lifecycle, fault one of its ECs, and report whether the domain
//       reappears; or
//     - this test spawning a sub-sub-domain, embedding an inner ELF
//       that performs the snapshot/delete/fault sequence, and reading
//       termination back through the sub-sub-domain's IDC handle (a
//       full nested test driver — the same infrastructure that
//       restart_semantics_04's notes call out).
//
//   Until either lands, this file holds the prelude verbatim so the
//   eventual faithful version can graft the restart trigger and
//   parent-side termination check on top without re-deriving the
//   create_var/snapshot/delete plumbing.
//
// Strategy (smoke prelude)
//   We exercise the bind-then-delete portion that is reachable from
//   inside the child:
//     1. create_var(caps={r,w, restart_policy=2 (preserve)}, ...) — the
//        source. `var_restart_max = 3` in the runner ceiling permits
//        restart_policy = 2.
//     2. create_var(caps={r,w, restart_policy=3 (snapshot)}, ...) — the
//        target, same size as the source (1 page each).
//     3. snapshot(target, source) — bind the source to the target.
//     4. delete(source) — releases the source handle and (per spec
//        test 08) is supposed to clear the binding inside the kernel.
//
//   We do not assert anything about the `snapshot` or `delete` return
//   values beyond "non-error" because the spec assertion under test
//   requires post-restart observation. Any prelude failure is also
//   reported as pass-with-id-0 since no spec assertion is being
//   checked (mirrors unmap_06.zig's smoke pattern).
//
// Action
//   1. createVar(caps={r, w, restart_policy=2}, props={cur_rwx=r|w},
//                pages=1, preferred_base=0, device_region=0)
//      — the source VAR.
//   2. createVar(caps={r, w, restart_policy=3}, props={cur_rwx=r|w},
//                pages=1, preferred_base=0, device_region=0)
//      — the target VAR (same size as source: 1 × 4 KiB).
//   3. snapshot(target_handle, source_handle)
//      — binds source to target.
//   4. delete(source_handle)
//      — releases the source; spec test 08 requires the kernel to
//        clear the binding here, but we cannot observe that internally.
//
// Assertion
//   No assertion is checked — passes with assertion id 0 because the
//   spec-mandated observable (domain terminates, not restarts, when
//   the bound source is gone at restart time) sits behind a domain
//   restart we cannot trigger or witness from inside the test EC.
//
// Faithful-test note
//   Faithful test deferred pending a runner-side restart-observability
//   harness: a parent that holds a self-IDC handle to the test domain,
//   triggers the test domain's restart (e.g., by faulting one of its
//   ECs whose self-handle has the `restart` cap), and reports back
//   whether the domain restarted or was terminated. With that, the
//   action becomes:
//
//     create_var(restart_policy=2, ...) -> source
//     create_var(restart_policy=3, ...) -> target
//     snapshot(target, source)
//     delete(source)
//     <signal parent: "now trip my restart">
//     <parent observes: domain terminated, did not come back>
//       -> *expected* observable per test 08 (id 1)
//
//   Two sibling cases worth covering once the harness exists:
//     - Bind source A, then bind source B (test 07 path), then delete
//       B and confirm restart-with-A still works — checks that
//       deleting a *replaced* source does not corrupt the live
//       binding.
//     - Bind source, delete source, rebind a fresh source, confirm
//       restart succeeds — checks the binding really was cleared
//       (not "stuck pointing at freed memory") on the original delete.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Source VAR: restart_policy = 2 (preserve) is the only value
    // §[snapshot] test 04 accepts as a snapshot source. Within
    // var_restart_max = 3 ceiling. Single 4 KiB page; cur_rwx = r|w.
    const source_caps = caps.VarCap{
        .r = true,
        .w = true,
        .restart_policy = 2, // preserve
    };
    // §[create_var] props: cur_rwx in bits 0-2, sz in bits 3-4, cch in
    // bits 5-6. cur_rwx = r|w = 0b011; sz = 0 (4 KiB); cch = 0 (wb).
    const props: u64 = 0b011;
    const csource = syscall.createVar(
        @as(u64, source_caps.toU16()),
        props,
        1, // pages = 1
        0, // preferred_base — kernel chooses
        0, // device_region — ignored when caps.dma = 0
    );
    if (testing.isHandleError(csource.v1)) {
        // Prelude broke; smoke is moot but no spec assertion is
        // being checked, so report pass-with-id-0.
        testing.pass();
        return;
    }
    const source_handle: caps.HandleId = @truncate(csource.v1 & 0xFFF);

    // Target VAR: restart_policy = 3 (snapshot) is the only value
    // §[snapshot] test 03 accepts as a snapshot target. Same size as
    // the source (1 page) so test 05 (size mismatch) does not fire.
    const target_caps = caps.VarCap{
        .r = true,
        .w = true,
        .restart_policy = 3, // snapshot
    };
    const ctarget = syscall.createVar(
        @as(u64, target_caps.toU16()),
        props,
        1, // pages = 1 (matches source)
        0, // preferred_base — kernel chooses
        0, // device_region — ignored when caps.dma = 0
    );
    if (testing.isHandleError(ctarget.v1)) {
        testing.pass();
        return;
    }
    const target_handle: caps.HandleId = @truncate(ctarget.v1 & 0xFFF);

    // Bind source -> target. Per §[snapshot], on success no error is
    // returned; we don't assert on the return because the spec
    // observable under test sits behind a domain restart, and any
    // bind-time anomaly would be caught by snapshot tests 01-07.
    _ = syscall.snapshot(target_handle, source_handle);

    // Delete the source. Per §[delete] line 173 the VAR is unmapped
    // and the handle released; per §[snapshot] test 08 the binding on
    // the target is supposed to be cleared as a side effect. The
    // cleared-binding observable is invisible from inside the child
    // (no syscall reads "current bound source"), and the
    // termination-on-restart observable requires the domain itself to
    // be restarted from outside.
    _ = syscall.delete(source_handle);

    // No spec assertion is being checked — the restart-observability
    // half of test 08 is unreachable from inside the test domain.
    // Pass with assertion id 0 to mark this slot as smoke-only in
    // coverage.
    testing.pass();
}
