const zag = @import("zag");

const capability = zag.caps.capability;
const errors = zag.syscall.errors;
const timer = zag.sched.timer;

const HANDLE_MASK: u64 = 0xFFF;
const CAPS_MASK: u64 = 0xFFFF;
const FLAGS_MASK: u64 = 0x1;

/// Mints a new timer handle with its own counter and arms it. Each call
/// yields an independent timer; previously-minted timers are unaffected.
///
/// ```
/// timer_arm([1] caps, [2] deadline_ns, [3] flags) -> [1] handle
///   syscall_num = 40
///
///   [1] caps: u64 packed as
///     bits  0-15: caps     — caps on the returned timer handle
///     bits 16-63: _reserved
///
///   [2] deadline_ns: nanoseconds until first fire (and period if periodic)
///
///   [3] flags: u64 packed as
///     bit 0:     periodic
///     bits 1-63: _reserved
/// ```
///
/// Self-handle cap required: `timer`.
///
/// On each fire, the kernel atomically increments `field0` of every
/// domain-local copy of the handle (saturating at `u64::MAX − 1`) and
/// issues a futex wake on each copy's `field0` paddr. One-shot timers
/// transition `field1.arm` to 0 after the single fire; periodic timers
/// stay armed until `timer_cancel`.
///
/// Returns E_NOMEM if insufficient kernel memory; returns E_FULL if the
/// caller's handle table has no free slot.
///
/// [test 01] returns E_PERM if the caller's self-handle lacks `timer`.
/// [test 02] returns E_PERM if [1].caps.restart_policy = 1 and the caller's `restart_policy_ceiling.tm_restart_max = 0`.
/// [test 03] returns E_INVAL if [2] deadline_ns is 0.
/// [test 04] returns E_INVAL if any reserved bits are set in [1] or [3].
/// [test 05] on success, the caller receives a timer handle with caps = [1].caps.
/// [test 06] on success, [1].field0 = 0, [1].field1.arm = 1, and [1].field1.pd = [3].periodic.
/// [test 07] on success with [3].periodic = 0, [1].field0 is incremented by 1 once after [2] deadline_ns; [1].field1.arm becomes 0 after the fire.
/// [test 08] on success with [3].periodic = 1, [1].field0 is incremented by 1 every [2] deadline_ns until `timer_cancel` or `timer_rearm`; [1].field1.arm remains 1.
/// [test 09] on each fire, every EC blocked in futex_wait_val keyed on the paddr of any domain-local copy of [1].field0 returns from the call with [1] = the corresponding domain-local vaddr of field0.
/// [test 10] calling `timer_arm` again yields a fresh, independent timer handle; the prior handle's field0 and field1 are unaffected.
pub fn timerArm(caller: *anyopaque, caps: u64, deadline_ns: u64, flags: u64) i64 {
    if (caps & ~CAPS_MASK != 0) return errors.E_INVAL;
    if (flags & ~FLAGS_MASK != 0) return errors.E_INVAL;
    if (deadline_ns == 0) return errors.E_INVAL;
    return timer.timerArm(caller, caps, deadline_ns, flags);
}

/// Reconfigures an existing timer. Resets `field0` to 0, sets
/// `field1.arm = 1`, sets `field1.pd = [3].periodic`, and applies the new
/// `deadline_ns`. Works regardless of whether the timer was armed or
/// disarmed at call time.
///
/// ```
/// timer_rearm([1] timer, [2] deadline_ns, [3] flags) -> void
///   syscall_num = 41
///
///   [1] timer: timer handle
///   [2] deadline_ns: nanoseconds until first fire (and period if periodic)
///   [3] flags: u64 packed as
///     bit 0:     periodic
///     bits 1-63: _reserved
/// ```
///
/// Timer cap required on [1]: `arm`.
///
/// [test 01] returns E_BADCAP if [1] is not a valid timer handle.
/// [test 02] returns E_PERM if [1] does not have the `arm` cap.
/// [test 03] returns E_INVAL if [2] deadline_ns is 0.
/// [test 04] returns E_INVAL if any reserved bits are set in [1] or [3].
/// [test 05] on success, the calling domain's copy of [1] has `field0 = 0` immediately on return; every other domain-local copy returns 0 from a fresh `sync` within a bounded delay.
/// [test 06] on success, [1].field1.arm = 1 and [1].field1.pd = [3].periodic.
/// [test 07] on success with [3].periodic = 0, [1].field0 is incremented by 1 once after [2] deadline_ns and `[1].field1.arm` becomes 0; with [3].periodic = 1, [1].field0 is incremented by 1 every [2] deadline_ns until `timer_cancel` or another `timer_rearm`.
/// [test 08] on success, every EC blocked in futex_wait_val keyed on the paddr of any domain-local copy of [1].field0 returns from the call with [1] = the corresponding domain-local vaddr of field0.
/// [test 09] `timer_rearm` called on a currently-armed timer replaces the prior configuration; the prior pending fire does not occur and field0 reflects the reset to 0 rather than any partial fire.
/// [test 10] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.
pub fn timerRearm(caller: *anyopaque, handle: u64, deadline_ns: u64, flags: u64) i64 {
    // Spec §[timer_rearm] [test 10]: when [1] is a valid handle, the
    // domain-local snapshot must be refreshed regardless of which
    // error path we take. Run the implicit-sync side effect FIRST,
    // before any reserved-bit / deadline / flags rejection — those
    // checks wouldn't otherwise observe the freshly-fired counter on
    // a one-shot timer that fired between arm and rearm. `sync`
    // returns E_BADCAP if the low-12 slot doesn't resolve, which is
    // exactly the test 01 path the spec excludes from "valid handle"
    // gating; we ignore the rc here and let the real validation drive
    // the syscall return value.
    _ = capability.sync(caller, handle & HANDLE_MASK);
    if (handle & ~HANDLE_MASK != 0) return errors.E_INVAL;
    if (flags & ~FLAGS_MASK != 0) return errors.E_INVAL;
    if (deadline_ns == 0) return errors.E_INVAL;
    return timer.timerRearm(caller, handle, deadline_ns, flags);
}

/// Disarms a timer. Returns an error if the timer is not currently armed
/// (e.g., a one-shot that already fired, or one already cancelled). Sets
/// `field0` to `u64::MAX` (the cancellation sentinel), sets `field1.arm =
/// 0`, and wakes futex waiters.
///
/// ```
/// timer_cancel([1] timer) -> void
///   syscall_num = 42
///
///   [1] timer: timer handle
/// ```
///
/// Timer cap required on [1]: `cancel`.
///
/// [test 01] returns E_BADCAP if [1] is not a valid timer handle.
/// [test 02] returns E_PERM if [1] does not have the `cancel` cap.
/// [test 03] returns E_INVAL if [1].field1.arm = 0.
/// [test 04] returns E_INVAL if any reserved bits are set in [1].
/// [test 05] on success, the calling domain's copy of [1] has `field0 = u64::MAX` immediately on return; every other domain-local copy returns u64::MAX from a fresh `sync` within a bounded delay.
/// [test 06] on success, [1].field1.arm becomes 0.
/// [test 07] on success, every EC blocked in futex_wait_val keyed on the paddr of any domain-local copy of [1].field0 returns from the call with [1] = the corresponding domain-local vaddr of field0; subsequent reads observe field0 = u64::MAX.
/// [test 08] on success, after one full prior `deadline_ns` has elapsed, every domain-local copy of [1] still returns `field0 = u64::MAX` from a fresh `sync`.
/// [test 09] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.
pub fn timerCancel(caller: *anyopaque, handle: u64) i64 {
    // Spec §[timer_cancel] [test 09]: implicit-sync side effect on
    // every "valid handle" path including reserved-bit rejection.
    // See `timerRearm` above for the rationale.
    _ = capability.sync(caller, handle & HANDLE_MASK);
    if (handle & ~HANDLE_MASK != 0) return errors.E_INVAL;
    return timer.timerCancel(caller, handle);
}
