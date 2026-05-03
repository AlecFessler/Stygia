// Spec §[timer_rearm] — test 07.
//
// "[test 07] on success with [3].periodic = 0, [1].field0 is
//  incremented by 1 once after [2] deadline_ns and `[1].field1.arm`
//  becomes 0; with [3].periodic = 1, [1].field0 is incremented by 1
//  every [2] deadline_ns until `timer_cancel` or another
//  `timer_rearm`."
//
// Strategy
//   The assertion has two halves.
//
//     Half A: rearm with periodic = 0. Kernel must increment field0
//     to 1 once after deadline_ns elapses, then transition field1.arm
//     from 1 to 0 (one-shot complete). Field0 must stay at 1
//     thereafter — there is no second fire on a one-shot.
//
//     Half B: rearm the same handle with periodic = 1. Kernel must
//     reset field0 to 0 (per the rearm contract), set field1.arm = 1
//     and field1.pd = 1, then increment field0 every deadline_ns
//     while the timer remains armed. Field1.arm must remain 1 across
//     fires.
//
//   Setup mints a fresh timer via `timer_arm` so the rearm path has a
//   live handle to operate on; the initial arm call's deadline is
//   irrelevant to the test (rearm fully replaces the configuration
//   per §[timer_rearm] and §[test 09]).
//
//   field0 lives in the holding domain's cap table at
//     cap_table_base + handle_id * sizeof(Cap) + offsetof(Cap, field0)
//   The handle table is mapped read-only into the holding domain
//   (§[capabilities]), but the kernel mutates the underlying physical
//   page on each fire (§[timer] "eagerly propagated to every
//   domain-local copy"). A volatile pointer prevents the optimizer
//   from caching reads while we spin waiting for the kernel to bump
//   the counter.
//
//   Wait choreography: deadline_ns is set to 5 ms. Spin on field0 with
//   a `pause` and a bounded iteration cap so a stuck kernel surfaces
//   as a fail() rather than a hang. After observing the first fire we
//   re-read field1 to verify field1.arm has cleared (one-shot) or
//   stays set (periodic).
//
//   Cap layout (§[timer]):
//     field0 = u64 counter
//     field1 bit 0 = arm
//     field1 bit 1 = pd (periodic)
//
// Action
//   1. timer_arm(caps={arm,cancel}, deadline_ns=5_000_000, flags=0)
//      — mint a timer handle to operate on.
//   2. timer_rearm(handle, deadline_ns=5_000_000, flags=0)
//      — one-shot reconfigure; resets field0=0, arm=1, pd=0.
//   3. Spin until field0 transitions from 0 to 1 (Half A fire).
//   4. Verify field0 == 1 and field1.arm == 0 post-fire.
//   5. timer_rearm(handle, deadline_ns=5_000_000, flags=1)
//      — periodic reconfigure; resets field0=0, arm=1, pd=1.
//   6. Spin until field0 reaches at least 2 (Half B: multiple fires).
//   7. Verify field1.arm remains 1 while field0 > 0 (still armed).
//   8. timer_cancel(handle) to leave a clean state for shutdown.
//
// Assertions
//   1: timer_arm setup returned an error (no handle to test against)
//   2: first timer_rearm (periodic=0) returned non-OK
//   3: spin timed out before field0 reached 1 (one-shot fire missed)
//   4: post-fire field0 != 1 (kernel double-incremented a one-shot)
//   5: post-fire field1.arm != 0 (one-shot did not clear arm)
//   6: second timer_rearm (periodic=1) returned non-OK
//   7: spin timed out before field0 reached 2 (periodic not firing)
//   8: post-fires field1.arm != 1 (periodic spuriously cleared arm)

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Arch-portable yield-during-spin hint. Issued from a memory-clobber'd
// volatile asm so the compiler keeps the load chain on the spinning
// counter alive across iterations.
inline fn cpuRelax() void {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("pause" ::: .{ .memory = true }),
        .aarch64 => asm volatile ("yield" ::: .{ .memory = true }),
        else => @compileError("unsupported arch"),
    }
}

// 5 ms expressed in nanoseconds. Short enough that the test resolves
// in real time on QEMU+TCG, long enough that scheduling jitter from
// the runner spawning siblings won't flap a periodic fire.
const DEADLINE_NS: u64 = 5_000_000;

// Spin bound for one fire. Sized loosely against the wall-clock
// equivalent of DEADLINE_NS: at modern CPU rates a `pause` iteration
// takes ~10-100 ns, so 100M iterations covers up to ~10 s of wall
// clock — a wide margin over a 5 ms deadline even on slow QEMU TCG.
const SPIN_BOUND: u64 = 100_000_000;

pub fn main(cap_table_base: u64) void {
    // Step 1: mint a timer handle. arm + cancel caps so we can both
    // rearm and clean up on exit. restart_policy stays 0 to dodge
    // §[timer_arm] [test 02]'s tm_restart_max gate.
    const timer_caps = caps.TimerCap{
        .arm = true,
        .cancel = true,
    };
    const arm_caps_word: u64 = @as(u64, timer_caps.toU16());
    const arm_result = syscall.timerArm(arm_caps_word, DEADLINE_NS, 0);
    if (testing.isHandleError(arm_result.v1)) {
        testing.fail(1);
        return;
    }
    const timer_handle: u12 = @truncate(arm_result.v1 & 0xFFF);

    // Volatile pointer to field0 inside the cap table. Cap layout is
    // {word0: u64, field0: u64, field1: u64} per §[capabilities] /
    // libz/caps.zig — field0 sits at offset 8.
    const cap_byte_base: usize = @intCast(cap_table_base);
    const cap_size: usize = @sizeOf(caps.Cap);
    const slot_base: usize = cap_byte_base + (@as(usize, timer_handle) * cap_size);
    const field0_ptr: *volatile u64 = @ptrFromInt(slot_base + 8);
    const field1_ptr: *volatile u64 = @ptrFromInt(slot_base + 16);

    // ---- Half A: periodic = 0 (one-shot) ----
    const rearm_oneshot = syscall.timerRearm(timer_handle, DEADLINE_NS, 0);
    if (rearm_oneshot.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    // Spin until field0 reaches 1 (single fire) or we exhaust the
    // bound. `pause` reduces the load on the bus while waiting; the
    // volatile read forces a fresh load each iteration.
    var iter: u64 = 0;
    while (iter < SPIN_BOUND) {
        if (field0_ptr.* >= 1) break;
        cpuRelax();
        iter += 1;
    }
    if (field0_ptr.* < 1) {
        testing.fail(3);
        return;
    }

    // After the one-shot fire field0 must be exactly 1 (no second
    // increment on a non-periodic timer). Re-read after a brief
    // additional spin so a kernel bug that fires twice in close
    // succession would surface here rather than racing past us.
    var settle: u64 = 0;
    while (settle < SPIN_BOUND / 100) {
        cpuRelax();
        settle += 1;
    }
    if (field0_ptr.* != 1) {
        testing.fail(4);
        return;
    }

    // §[timer_arm]: "One-shot timers transition `field1.arm` to 0
    // after the single fire". Bit 0 of field1 carries arm.
    if ((field1_ptr.* & 1) != 0) {
        testing.fail(5);
        return;
    }

    // ---- Half B: periodic = 1 ----
    // Periodic flag is bit 0 of [3] (§[timer_rearm] flags layout).
    const rearm_periodic = syscall.timerRearm(timer_handle, DEADLINE_NS, 1);
    if (rearm_periodic.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(6);
        return;
    }

    // Wait for at least two fires. Two is the minimum count that
    // distinguishes "periodic" from "one-shot" — a one-shot would
    // stop at field0 == 1 even after rearm, so reaching 2 is the
    // operational signal that the kernel is firing the timer
    // repeatedly.
    iter = 0;
    while (iter < SPIN_BOUND * 2) {
        if (field0_ptr.* >= 2) break;
        cpuRelax();
        iter += 1;
    }
    if (field0_ptr.* < 2) {
        testing.fail(7);
        return;
    }

    // While the periodic timer is still firing, field1.arm must
    // remain 1 (§[timer_arm] [test 08]: "[1].field1.arm remains 1"
    // for periodic timers; rearm with periodic=1 inherits the same
    // invariant per §[timer_rearm]).
    if ((field1_ptr.* & 1) != 1) {
        testing.fail(8);
        return;
    }

    // Clean up: cancel so the timer doesn't keep firing into the
    // shutdown path. Errors here are not part of the test 07
    // contract; ignore the return.
    _ = syscall.timerCancel(timer_handle);

    testing.pass();
}
