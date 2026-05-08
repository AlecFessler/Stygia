// Spec §[timer] timer_rearm — test 09.
//
// "[test 09] `timer_rearm` called on a currently-armed timer replaces
//  the prior configuration; the prior pending fire does not occur and
//  field0 reflects the reset to 0 rather than any partial fire."
//
// Strategy
//   The assertion has two halves:
//
//     Half (a) — the immediate post-rearm state: field0 must read 0
//     and the new (deadline_ns, periodic) config must be installed
//     (field1.arm = 1, field1.pd = [3].periodic).
//
//     Half (b) — the no-fire-from-prior-config invariant: across the
//     window where the prior deadline_ns would have elapsed but the
//     new deadline_ns has not yet elapsed, field0 must remain 0; the
//     prior pending fire must not increment the counter.
//
//   Half (a) is observable directly through the holding domain's cap
//   table immediately on return (§[timer] field0 row: kernel-mutable,
//   eagerly propagated to every domain-local copy; §[timer_rearm]:
//   "Resets `field0` to 0").
//
//   Half (b) needs a bounded-delay timing primitive to verify "no
//   fire across the prior-deadline window". `time_monotonic` provides
//   that — same shape as `timer_cancel_08` uses for its
//   "elapsed >= deadline_ns" wait. The choreography:
//
//     1. timer_arm a one-shot with PRIOR_DEADLINE_NS so a fire is
//        pending soon.
//     2. timer_rearm a one-shot with NEW_DEADLINE_NS where
//        NEW_DEADLINE_NS >> PRIOR_DEADLINE_NS, so the window
//        [PRIOR_DEADLINE_NS, NEW_DEADLINE_NS) is non-empty.
//     3. Half (a): readCap immediately — assert field0 == 0,
//        field1.arm == 1, field1.pd == 0.
//     4. Half (b): spin on time_monotonic until elapsed >=
//        SETTLE_NS, where SETTLE_NS > PRIOR_DEADLINE_NS but <<
//        NEW_DEADLINE_NS, so any leaked fire from the prior config
//        would have landed by now. Re-read field0 and assert still 0.
//
//   Sizing:
//     - PRIOR_DEADLINE_NS = 5 ms — well above any plausible
//       per-syscall latency, so the timer is genuinely armed when
//       step 2 issues the rearm.
//     - SETTLE_NS = 50 ms — 10× the prior deadline. If the kernel
//       leaked the prior fire, field0 would be 1 by this point.
//     - NEW_DEADLINE_NS = 60 s — vastly exceeds SETTLE_NS so the
//       new config cannot fire during the observation window;
//       field0 staying at 0 is unambiguously attributable to the
//       cancellation of the prior fire.
//
//   For `timer_rearm` itself we need every error path inert so the
//   success contract is the only path:
//     - test 01 (BADCAP): handle is the freshly-armed timer.
//     - test 02 (PERM): caps={arm} on the minted handle.
//     - test 03 (INVAL deadline=0): NEW_DEADLINE_NS != 0.
//     - test 04 (INVAL reserved bits): handle u12, flags = 0.
//
// Action
//   1. timer_arm(caps={arm, cancel}, deadline_ns=PRIOR_DEADLINE_NS,
//                flags=0) — mint a pending one-shot. cancel cap is
//      not strictly needed here but matches the timer_cancel_08
//      pattern for tidy shutdown if we ever need it.
//   2. readCap(timer) — sanity-check that arm-time field0 = 0 and
//      field1.arm = 1, anchoring later observations to a known
//      state.
//   3. timer_rearm(timer, deadline_ns=NEW_DEADLINE_NS, flags=0) —
//      replace the prior config with a far-future one-shot.
//   4. readCap(timer) — half (a): assert field0 == 0,
//      field1.arm == 1, field1.pd == 0.
//   5. busy-poll time_monotonic until elapsed >= SETTLE_NS.
//   6. readCap(timer) — half (b): assert field0 still == 0; no
//      fire from the prior pending config leaked through.
//
// Assertions
//   1: setup — timer_arm returned an error word in vreg 1.
//   2: setup — post-arm field0 was non-zero (a stale slot or
//      arm-time partial fire would invalidate later observations).
//   3: setup — post-arm field1.arm was 0 (the kernel did not leave
//      the handle armed; nothing for rearm to cancel).
//   4: timer_rearm returned non-OK in vreg 1.
//   5: half (a) — post-rearm field0 != 0 (the rearm reset failed
//      OR a partial fire from the prior config leaked through).
//   6: half (a) — post-rearm field1.arm != 1 (the new config did
//      not install).
//   7: half (a) — post-rearm field1.pd != 0 (flags=0 should leave
//      pd clear).
//   8: setup — time_monotonic returned an error-shaped value (half
//      (b) unobservable).
//   9: half (b) — after SETTLE_NS elapsed (≫ prior deadline,
//      ≪ new deadline), field0 was non-zero — i.e. the kernel
//      delivered the prior pending fire despite the rearm having
//      cancelled it. This is the spec's core invariant: "the prior
//      pending fire does not occur".

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// 5 ms — non-trivial pending fire, deliberately larger than the
// per-syscall latency window so the timer is genuinely armed at the
// moment timer_rearm is issued.
const PRIOR_DEADLINE_NS: u64 = 5_000_000;

// 60 s — far enough out that NEW_DEADLINE_NS cannot expire during
// the SETTLE_NS observation window. Means any non-zero field0 we
// see post-settle must be from a leaked prior fire, not the new
// config firing on schedule.
const NEW_DEADLINE_NS: u64 = 60_000_000_000;

// 50 ms — 10× the prior deadline. If the prior pending fire wasn't
// cancelled, the kernel would deliver it well within this window.
// Comfortably below NEW_DEADLINE_NS so the new config cannot fire
// here by accident.
const SETTLE_NS: u64 = 50_000_000;

pub fn main(cap_table_base: u64) void {
    // §[timer] timer_arm caps word: bit 2 = arm, bit 3 = cancel. arm
    // is required for rearm's cap gate (test 02); cancel is included
    // for symmetry with timer_cancel_08 / timer_rearm_08, though we
    // do not invoke timer_cancel here since the 60 s deadline keeps
    // the timer effectively dormant for the suite's lifetime.
    const timer_caps = caps.TimerCap{ .arm = true, .cancel = true };
    const caps_word: u64 = @as(u64, timer_caps.toU16());

    const arm_result = syscall.timerArm(caps_word, PRIOR_DEADLINE_NS, 0);
    if (testing.isHandleError(arm_result.v1)) {
        testing.fail(1);
        return;
    }
    const timer_handle: u12 = @truncate(arm_result.v1 & 0xFFF);

    // §[timer_arm] [test 06]: field0 = 0 and field1.arm = 1
    // immediately after a successful arm. Anchor the post-rearm
    // comparison to a known initial state.
    const post_arm = caps.readCap(cap_table_base, timer_handle);
    if (post_arm.field0 != 0) {
        testing.fail(2);
        return;
    }
    if ((post_arm.field1 & 0x1) != 1) {
        testing.fail(3);
        return;
    }

    const rearm_result = syscall.timerRearm(timer_handle, NEW_DEADLINE_NS, 0);
    if (rearm_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }

    // Half (a): the immediate post-rearm state. field0 must be 0
    // (any non-zero would indicate a leaked partial fire OR a stale
    // slot the rearm failed to reset); field1.arm == 1 and
    // field1.pd == 0 confirm the new (one-shot) config installed.
    const post_rearm = caps.readCap(cap_table_base, timer_handle);
    if (post_rearm.field0 != 0) {
        testing.fail(5);
        return;
    }
    if ((post_rearm.field1 & 0x1) != 1) {
        testing.fail(6);
        return;
    }
    if ((post_rearm.field1 & 0x2) != 0) {
        testing.fail(7);
        return;
    }

    // Half (b): wait past the prior deadline (and well beyond) but
    // far short of the new deadline, then verify field0 is still 0.
    // Same shape as timer_cancel_08's "elapsed >= deadline_ns" wait.
    const t0 = syscall.timeMonotonic();
    if (t0.v1 != 0 and t0.v1 < 16) {
        // time_monotonic returned an error-shaped value — half (b)
        // unobservable. Fail loudly so the missing dependency
        // surfaces rather than silently passing.
        testing.fail(8);
        return;
    }
    const start_ns: u64 = t0.v1;

    while (true) {
        const tn = syscall.timeMonotonic();
        if (tn.v1 != 0 and tn.v1 < 16) {
            testing.fail(8);
            return;
        }
        const now_ns: u64 = tn.v1;
        // §[time_monotonic] [test 01] — strictly monotonic, so
        // now_ns >= start_ns always. Defensive saturating sub.
        const elapsed: u64 = if (now_ns >= start_ns) now_ns - start_ns else 0;
        if (elapsed >= SETTLE_NS) break;
    }

    // Spec assertion under test (half b): "the prior pending fire
    // does not occur". With SETTLE_NS ≫ PRIOR_DEADLINE_NS but
    // ≪ NEW_DEADLINE_NS, any non-zero field0 here can only be
    // attributed to the prior pending fire leaking through the
    // rearm transition.
    const post_settle = caps.readCap(cap_table_base, timer_handle);
    if (post_settle.field0 != 0) {
        testing.fail(9);
        return;
    }

    testing.pass();
}
