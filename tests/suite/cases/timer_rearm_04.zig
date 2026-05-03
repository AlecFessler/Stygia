// Spec §[timer] timer_rearm — test 04.
//
// "[test 04] returns E_INVAL if any reserved bits are set in [1] or [3]."
//
// Strategy
//   The timer_rearm syscall encodes [1] as a 12-bit handle id in bits
//   0-11 with bits 12-63 _reserved, and [3] as a flags word with bit 0
//   = periodic and bits 1-63 _reserved. Setting any bit outside the
//   defined fields is a spec violation that must surface E_INVAL.
//
//   To isolate the reserved-bit check we make every other check pass:
//     - the runner mints the test domain's self-handle with `timer`
//       (see runner/primary.zig — child_self.timer = true), so
//       timer_arm is on the success path and yields a valid handle id
//       (so test 01 BADCAP cannot fire),
//     - the minted handle carries `arm` (so test 02 PERM cannot fire),
//     - deadline_ns is non-zero (so test 03 INVAL on [2] cannot fire).
//   That leaves the [1]/[3] reserved-bit check as the only spec-
//   mandated failure path.
//
//   The libz `syscall.timerRearm` wrapper takes `timer_handle: u12`,
//   which cannot carry reserved bits in [1]; it also takes `flags: u64`
//   verbatim, which can carry reserved bits in [3]. To exercise [1]
//   reserved bits we bypass the wrapper and dispatch through
//   `syscall.issueReg` directly so we can stuff bit 12 into vreg 1.
//
// Action
//   1. timer_arm(caps={arm}, deadline_ns=1_000_000, flags=0)
//      — must succeed
//   2. timer_rearm(handle | (1 << 12), 1_000_000, 0)
//      — must return E_INVAL (reserved bit 12 of [1] set)
//   3. timer_rearm(handle, 1_000_000, 1 << 1)
//      — must return E_INVAL (reserved bit 1 of [3] set)
//
// Assertions
//   1: setup syscall failed (timer_arm returned an error word)
//   2: timer_rearm with reserved bit 12 of [1] returned something
//      other than E_INVAL
//   3: timer_rearm with reserved bit 1 of [3] returned something
//      other than E_INVAL

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // §[timer_arm] caps word: caps in bits 0-15, reserved 16-63.
    // `arm` is required so the rearm call's test 02 PERM check cannot
    // fire. deadline_ns = 1_000_000 (1 ms) is non-zero so test 03
    // cannot fire on either timer_arm or timer_rearm. flags = 0 keeps
    // periodic = 0 and all reserved bits clear (test 04 of timer_arm
    // cannot fire on this setup call).
    const timer_caps = caps.TimerCap{ .arm = true };
    const caps_word: u64 = @as(u64, timer_caps.toU16());
    const deadline_ns: u64 = 1_000_000;
    const arm = syscall.timerArm(caps_word, deadline_ns, 0);
    if (testing.isHandleError(arm.v1)) {
        testing.fail(1);
        return;
    }
    const timer_handle: u12 = @truncate(arm.v1 & 0xFFF);

    // Reserved bit 12 of [1] set; low 12 bits hold the valid id.
    // Bypass the typed wrapper since it takes u12 and would truncate
    // the reserved bit before it reaches the kernel.
    const handle_with_reserved: u64 = @as(u64, timer_handle) | (@as(u64, 1) << 12);
    const r1 = syscall.issueReg(.timer_rearm, 0, .{
        .v1 = handle_with_reserved,
        .v2 = deadline_ns,
        .v3 = 0,
    });
    if (r1.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    // Reserved bit 1 of [3] set; bit 0 (periodic) clear, valid handle.
    const flags_with_reserved: u64 = @as(u64, 1) << 1;
    const r2 = syscall.timerRearm(timer_handle, deadline_ns, flags_with_reserved);
    if (r2.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
