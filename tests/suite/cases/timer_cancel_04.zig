// Spec §[timer_cancel] timer_cancel — test 04.
//
// "[test 04] returns E_INVAL if any reserved bits are set in [1]."
//
// Strategy
//   The [1] handle word carries the 12-bit handle id in bits 0-11
//   with bits 12-63 _reserved when used as a syscall input
//   (§[handle_representation], §[syscall_abi]). Setting any bit
//   outside the id field is a spec violation that must surface
//   E_INVAL at the syscall ABI layer.
//
//   To isolate the reserved-bit check we make every other check on
//   timer_cancel pass. timer_cancel's failure paths are:
//     [test 01] E_BADCAP if [1] is not a valid timer handle.
//     [test 02] E_PERM   if [1] lacks the `cancel` cap.
//     [test 03] E_INVAL  if [1].field1.arm = 0.
//     [test 04] E_INVAL  if any reserved bits are set in [1].
//
//   So [1]'s low 12 bits must reference a valid armed timer handle
//   that has the `cancel` cap. We mint one via `timer_arm` with
//   caps={cancel}, restart_policy=0 (no tm_restart_max needed),
//   deadline_ns large enough that the timer cannot fire (and thus
//   transition arm=0) before we reach the timer_cancel call. We
//   choose a one-shot timer (periodic=0) to keep the call shape
//   minimal — the kernel just needs the timer armed at the moment
//   of timer_cancel, and the deadline is picked so the timer is
//   still armed.
//
//   Neutralize timer_arm's own failure paths so setup succeeds:
//     [test 01] caller's self-handle has `timer` cap (granted by
//               primary, see runner/primary.zig).
//     [test 02] [1].caps.restart_policy = 0, so no
//               tm_restart_max requirement.
//     [test 03] deadline_ns != 0.
//     [test 04] caps and flags carry no reserved bits.
//
//   We then dispatch timer_cancel with reserved bit 12 of [1] set
//   while the low 12 bits hold the freshly-minted timer's slot id.
//   The libz `syscall.timerCancel` wrapper takes `timer_handle: u12`,
//   which cannot carry reserved bits in [1]. We bypass that wrapper
//   and dispatch through `syscall.issueReg` directly so we can stuff
//   bit 12 into vreg 1.
//
// Action
//   1. timer_arm(caps={cancel}, deadline_ns=large, flags=0)
//      — must succeed (yields a valid armed timer with `cancel`)
//   2. timer_cancel(handle | (1 << 12))
//      — must return E_INVAL (reserved bit 12 of [1] set; low 12
//        bits hold the valid timer id)
//
// Assertions
//   1: setup syscall failed (timer_arm returned an error word in v1)
//   2: timer_cancel with reserved bit 12 of [1] returned something
//      other than E_INVAL

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const initial = caps.TimerCap{
        .cancel = true,
        .restart_policy = false,
    };
    // §[timer_arm] [1] caps word: caps in bits 0-15, bits 16-63 reserved.
    const caps_word: u64 = @as(u64, initial.toU16());
    // Long deadline so the timer remains armed across the timer_cancel
    // call; this neutralizes test 03 (arm=0) on the cancel side.
    const deadline_ns: u64 = ~@as(u64, 0) >> 1;
    const flags: u64 = 0; // periodic=0; no reserved bits.

    const ta = syscall.timerArm(caps_word, deadline_ns, flags);
    if (testing.isHandleError(ta.v1)) {
        testing.fail(1);
        return;
    }
    const timer_handle: u12 = @truncate(ta.v1 & 0xFFF);

    // Reserved bit 12 of [1] set; low 12 bits hold the valid timer id.
    // Bypass the typed wrapper since it takes u12 and would truncate
    // the reserved bit before it reaches the kernel.
    const handle_with_reserved: u64 = @as(u64, timer_handle) | (@as(u64, 1) << 12);
    const r = syscall.issueReg(.timer_cancel, 0, .{
        .v1 = handle_with_reserved,
    });
    if (r.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
