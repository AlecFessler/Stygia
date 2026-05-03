// Spec §[timer] timer_rearm — test 02.
//
// "[test 02] returns E_PERM if [1] does not have the `arm` cap."
//
// Strategy
//   `arm` is the cap that gates `timer_rearm` (§[timer] cap table:
//   bit 2 = arm, "reconfiguring the timer via `timer_rearm`"). Mint a
//   timer with full operational caps including `arm`, then `restrict`
//   the handle down to caps without `arm`. Timer caps use the plain
//   bitwise subset semantics (only `restart_policy` on EC/VAR handles
//   uses the numeric ordering — see §[capabilities]), so dropping a
//   single bit via restrict is well-defined.
//
//   With `arm` cleared, a fresh `timer_rearm` on the same handle must
//   surface E_PERM per the cap-gate rule, independent of the other
//   argument validation paths (deadline_ns is non-zero, no reserved
//   bits, the handle id itself is still valid).
//
//   The test EC's self-handle carries the `timer` cap (the primary
//   grants it on every test domain — see runner/primary.zig), and
//   `restart_policy_ceiling.tm_restart_max` is unrestricted, so the
//   `timer_arm` setup call succeeds without hitting test-02-of-arm
//   (E_PERM via tm_restart_max).
//
// Action
//   1. timer_arm(caps={move,copy,arm,cancel}, deadline=1ms, flags=0)
//        — must succeed and yield a timer handle
//   2. restrict(timer, caps={move,copy,cancel})
//        — must succeed (drops `arm`, keeps others)
//   3. timer_rearm(timer, deadline=1ms, flags=0)
//        — must return E_PERM
//
// Assertions
//   1: timer_arm returned an error word (setup failed)
//   2: restrict returned a non-zero error word (drop arm)
//   3: timer_rearm returned something other than E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const initial = caps.TimerCap{
        .move = true,
        .copy = true,
        .arm = true,
        .cancel = true,
    };
    const arm_caps_word: u64 = @as(u64, initial.toU16());
    const deadline_ns: u64 = 1_000_000;
    const arm_result = syscall.timerArm(arm_caps_word, deadline_ns, 0);
    if (testing.isHandleError(arm_result.v1)) {
        testing.fail(1);
        return;
    }
    const timer_handle: u12 = @truncate(arm_result.v1 & 0xFFF);

    const reduced = caps.TimerCap{
        .move = true,
        .copy = true,
        .cancel = true,
    };
    const reduced_word: u64 = @as(u64, reduced.toU16());
    const restrict_result = syscall.restrict(timer_handle, reduced_word);
    if (restrict_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    const rearm_result = syscall.timerRearm(timer_handle, deadline_ns, 0);
    if (rearm_result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
