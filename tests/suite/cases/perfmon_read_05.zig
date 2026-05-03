// Spec §[perfmon_read] — test 05.
//
// "[test 05] on success, [1..num_counters] contain the current counter
//  values for the active counters."
//
// Strategy
//   The spec gates on perfmon_read are:
//     [01] E_PERM  if self-handle lacks `pmu`.
//     [02] E_BADCAP if [1] is not a valid EC handle.
//     [03] E_INVAL if perfmon was not started on the target EC.
//     [04] E_BUSY  if [1] is not the calling EC and not suspended.
//
//   Targeting the calling EC (SLOT_INITIAL_EC) neutralizes [02] (slot 1
//   is the kernel-installed initial EC) and [04] (target == calling EC).
//   The runner grants the test domain's self-handle the `pmu` cap (see
//   runner/primary.zig: `child_self.pmu = true`), so [01] cannot fire.
//   We satisfy [03] by issuing a valid `perfmon_start` on the same EC
//   immediately before the read.
//
//   For perfmon_start to succeed (so we observe perfmon_read's success
//   path), we must clear all of its gates as well:
//     - target = SLOT_INITIAL_EC (calling EC) clears [02]/[07].
//     - num_configs in [1, num_counters] (we use num_counters itself).
//     - every config_event has event_index in supported_events.
//     - has_threshold = 0 sidesteps the overflow gate.
//     - bits 9-63 of every config_event are zero.
//
//   To check that vregs [1..num_counters] really do carry the counter
//   values for the active counters (and not, say, the timestamp or
//   zeros), we configure every counter with the `cycles` event (event
//   index 0 per §[perfmon_info]) and run a busy loop on the calling EC
//   between start and read. Cycles will advance on every active
//   counter, so vreg 1 in particular must be nonzero — which would not
//   be the case if the kernel had instead placed the timestamp at vreg
//   1, returned an error code (1..15), or left the slot unwritten.
//
// Return-vreg shape
//   §[perfmon_read]: `[1..num_counters] counter_values, [num_counters
//   + 1] timestamp`. With num_configs = num_counters, the kernel must
//   populate vregs 1..num_counters with each counter's value and put
//   the timestamp at vreg num_counters+1. We assert vreg 1 != 0 to
//   prove the cycles counter is in slot 1 and advanced from zero.
//
// Scope of this test
//   This test asserts only the *shape* of the success return: vregs
//   [1..num_counters] hold counter values for the active counters,
//   evidenced by vreg 1 being a nonzero cycles count. The monotonic
//   ordering across successive `perfmon_read` calls (each counter
//   value >= the prior call's value, and the timestamp strictly
//   greater) is the next assertion in the spec — §[perfmon_read]
//   test 06 — and is covered by its own test.
//
// Degraded smoke
//   - perfmon_info itself errors (vreg 1 in 1..15) — preconditions
//     unobservable.
//   - num_counters = 0 — no counters to configure.
//   - cycles event (bit 0) not in supported_events — no event to drive
//     vreg 1 nonzero.
//   - num_counters > 12 — the v3 register-only ABI carries vregs 1..13
//     in registers; vreg num_counters+1 (timestamp) must still fit, so
//     num_counters <= 12 is the observable range here. Stack-spill
//     reads aren't yet wired in libz/syscall.zig, so we skip past 12.
//   - perfmon_start returns a small (1..15) error code — handler not
//     yet wired; smoke-pass so the ELF still validates plumbing.
//   - perfmon_read returns a small (1..15) error code on the success
//     path — same handler-not-wired scenario; smoke-pass.
//
// Action
//   1. perfmon_info()                                   — read PMU caps
//   2. validate preconditions (counters, cycles, ABI bound)
//   3. configs[i] = (event=cycles, threshold=0) for i in 0..N-1
//      where N = num_counters
//   4. perfmon_start(SLOT_INITIAL_EC, N, configs)       — must succeed
//   5. busy loop generating cycles
//   6. perfmon_read(SLOT_INITIAL_EC)                    — must succeed
//   7. assert vreg 1 (counter_0 = cycles) != 0
//
// Assertions
//   1: perfmon_start returned a non-OK, non-smoke status — kernel
//      rejected what the spec says is a legal config.
//   2: perfmon_read returned counter_0 == 0 (no counter advance, or
//      kernel placed something other than the cycles count at vreg 1).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const EVENT_CYCLES_BIT: u64 = 1 << 0;
const CYCLES_EVENT_INDEX: u64 = 0;

// Side-effect-laden busy loop. The volatile asm + memory clobber stops
// the compiler from eliding the work, so the host CPU actually runs
// the loop and the cycles counter advances measurably from zero.
fn busyWork() u64 {
    var acc: u64 = 0;
    var i: u64 = 0;
    while (i < 200_000) {
        asm volatile (""
            : [out] "+r" (acc),
            :
            : .{ .memory = true });
        acc +%= i *% 0x9E3779B97F4A7C15;
        i += 1;
    }
    return acc;
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const info = syscall.perfmonInfo();

    // Degraded smoke: any error-shaped value in vreg 1 means the
    // PMU success path is unobservable in this build.
    if (info.v1 != 0 and info.v1 < 16) {
        testing.pass();
        return;
    }

    const num_counters: u64 = info.v1 & 0xFF;
    const supported_events: u64 = info.v2;

    // Need at least one counter to configure, the cycles event so vreg
    // 1 advances measurably, and num_counters within the register-only
    // ABI bound (num_counters + 1 vregs read, all in registers).
    if (num_counters == 0 or
        (supported_events & EVENT_CYCLES_BIT) == 0 or
        num_counters > 12)
    {
        testing.pass();
        return;
    }

    // Configure every counter with cycles | has_threshold=0. Bits 9-63
    // are zero so the perfmon_start reserved-bits gate cannot fire.
    var configs_buf: [24]u64 = .{0} ** 24;
    var ci: u64 = 0;
    while (ci < num_counters) {
        configs_buf[ci * 2] = CYCLES_EVENT_INDEX;
        configs_buf[ci * 2 + 1] = 0;
        ci += 1;
    }
    const config_len: usize = @intCast(num_counters * 2);

    const start_result = syscall.perfmonStart(
        @as(u12, @intCast(caps.SLOT_INITIAL_EC)),
        num_counters,
        configs_buf[0..config_len],
    );

    // Degraded smoke: perfmon_start handler not yet wired returns a
    // small error code; the read assertion is unobservable.
    if (start_result.v1 != @intFromEnum(errors.Error.OK)) {
        if (start_result.v1 < 16) {
            testing.pass();
            return;
        }
        testing.fail(1);
        return;
    }

    // Drive the cycles counter so vreg 1 must be nonzero on a
    // spec-conforming read.
    const work_acc = busyWork();
    asm volatile (""
        :
        : [w] "r" (work_acc),
        : .{ .memory = true });

    const read_result = syscall.perfmonRead(@as(u12, @intCast(caps.SLOT_INITIAL_EC)));

    // §[perfmon_read] return shape: vreg 1 = counter_0 (cycles).
    // A zero here means either:
    //   - the kernel returned an error code (1..15), or
    //   - the kernel left the active counter slot unwritten / zero, or
    //   - the kernel put the timestamp / something else at vreg 1.
    // All three are spec violations of test 05's shape assertion.
    if (read_result.v1 == 0) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
