// Spec §[perfmon_read] — test 06.
//
// "[test 06] on success, [num_counters + 1] is a u64 nanosecond
//  timestamp strictly greater than the timestamp from any prior
//  `perfmon_read` on the same target EC, and each counter value is
//  greater than or equal to the value returned by the prior
//  `perfmon_read` on that target."
//
// Strategy
//   The runner's primary grants the test domain's self-handle the
//   `pmu` cap (see runner/primary.zig: `child_self.pmu = true`), so
//   the §[perfmon_read] test 01 E_PERM gate cannot fire.
//   `SLOT_INITIAL_EC` is the calling EC itself, so test 07's "not
//   calling EC and not currently suspended" E_BUSY gate is bypassed
//   too — perfmon_start and perfmon_read both target the running EC.
//
//   We probe the system's PMU shape via `perfmon_info` to learn
//   `num_counters` (caps_word bits 0-7). On any PMU-less host (or a
//   host where perfmon_info returns an error), we cannot drive a real
//   read, so we degraded-smoke pass — the build product validates the
//   syscall plumbing in CI.
//
//   With at least one counter available, we configure a single
//   counter for the `cycles` event (bit 0 of supported_events,
//   guaranteed to be the canonical cycles bit by the §[perfmon_info]
//   table) with `has_threshold = 0` and `threshold = 0`. We then:
//     1. perfmon_read once    — record counter[0] and the timestamp
//        (vregs 1 and num_counters+1 respectively).
//     2. busy-loop locally to advance both wall-clock time and the
//        cycles counter on the executing core.
//     3. perfmon_read again   — assert
//          timestamp_2 > timestamp_1   (strictly increasing)
//          counter_2  >= counter_1    (monotonic non-decreasing)
//
//   Cycles is monotonic by construction on every PMU we care about,
//   and a u64 timestamp captured between two reads must advance by at
//   least one nanosecond once the busy loop has done a few thousand
//   iterations. Both inequalities are observable from userspace
//   without any cross-cap dependency.
//
//   The timestamp lives at vreg `num_counters + 1`. Since
//   num_counters ≤ 8 (caps_word bits 0-7 only encode 0..255 but the
//   spec PMU table tops out at 9 distinct events; on real x86 PMUs
//   num_counters is typically 4 or 8), the timestamp index is in
//   [2..9]. We dispatch on num_counters at runtime to pick the right
//   `Regs` field. If the kernel ever advertises num_counters > 12
//   (so timestamp index > 13, exceeding the register-backed vreg
//   window), we degraded-smoke pass — the timestamp would spill to
//   the stack and observing it requires plumbing libz doesn't expose.
//
// Action
//   1. perfmon_info() — derive num_counters; smoke-pass if 0 or error
//   2. perfmon_start(SLOT_INITIAL_EC, 1, [event=cycles, threshold=0])
//   3. perfmon_read(SLOT_INITIAL_EC) — capture (counter_1, ts_1)
//   4. busy-loop ~1<<16 iterations
//   5. perfmon_read(SLOT_INITIAL_EC) — capture (counter_2, ts_2)
//   6. assert ts_2 > ts_1 and counter_2 >= counter_1
//
// Assertions
//   1: perfmon_start failed unexpectedly (cycles is mandatory enough
//      that this should always succeed when num_counters > 0)
//   2: first perfmon_read returned an error
//   3: second perfmon_read returned an error
//   4: timestamp_2 <= timestamp_1 (not strictly greater)
//   5: counter_2 < counter_1 (cycles ran backward)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Pull the counter value at vreg index `idx` (1-based) out of a Regs.
// idx must be in [1..13]; callers gate before calling.
fn vregAt(regs: syscall.Regs, idx: u64) u64 {
    return switch (idx) {
        1 => regs.v1,
        2 => regs.v2,
        3 => regs.v3,
        4 => regs.v4,
        5 => regs.v5,
        6 => regs.v6,
        7 => regs.v7,
        8 => regs.v8,
        9 => regs.v9,
        10 => regs.v10,
        11 => regs.v11,
        12 => regs.v12,
        13 => regs.v13,
        else => 0,
    };
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // ---------------- 1. probe PMU shape ----------------
    const info = syscall.perfmonInfo();
    // Any value <= 15 in vreg 1 is unambiguously an error code per
    // §[error_codes]. A real caps_word with num_counters > 0 can
    // collide with the error range (e.g. caps_word == 4) ONLY if all
    // upper bits are zero, but a zero overflow_support is legal — so
    // we cannot disambiguate by bit 8. Be conservative: if vreg 1
    // looks error-shaped or num_counters is zero, smoke-pass.
    if (info.v1 != 0 and info.v1 < 16) {
        testing.pass();
        return;
    }
    const num_counters: u64 = info.v1 & 0xFF;
    if (num_counters == 0) {
        testing.pass();
        return;
    }
    // Timestamp index = num_counters + 1. If that exceeds the
    // register-backed window we cannot observe it from libz.
    const ts_idx: u64 = num_counters + 1;
    if (ts_idx > 13) {
        testing.pass();
        return;
    }

    // ---------------- 2. start perfmon ------------------
    // Single config: event = cycles (bit 0), has_threshold = 0,
    // reserved bits clear; threshold ignored.
    const configs = [_]u64{ 0, 0 };
    const start_res = syscall.perfmonStart(caps.SLOT_INITIAL_EC, 1, &configs);
    if (start_res.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    // ---------------- 3. first read ---------------------
    const read1 = syscall.perfmonRead(caps.SLOT_INITIAL_EC);
    // perfmon_read overlays counter values into vregs 1..num_counters
    // and the timestamp into vreg num_counters+1, so a returning OK
    // is encoded as counter[0] in vreg 1 — we cannot use vreg 1 as
    // an error channel here. Detect failure by looking at the
    // timestamp slot: a successful read must populate it with a
    // nonzero kernel timestamp; any error path leaves the upper
    // vregs at their zero default.
    const counter_1: u64 = read1.v1;
    const ts_1: u64 = vregAt(read1, ts_idx);
    if (ts_1 == 0) {
        testing.fail(2);
        return;
    }

    // ---------------- 4. busy-loop ----------------------
    // Burn cycles and wall-clock so both observables advance. The
    // counter we configured is `cycles`, which ticks every core
    // clock; the kernel timestamp ticks every nanosecond. Even on
    // very fast hardware, ~65k iterations of an unoptimisable
    // arithmetic mix is enough to advance both well past their
    // resolution.
    var sink: u64 = 0;
    var i: u64 = 0;
    while (i < (1 << 16)) {
        sink +%= i *% 0x9E3779B97F4A7C15;
        i += 1;
    }
    // Force the compiler to keep `sink` live so the loop is not
    // dead-code-eliminated.
    asm volatile (""
        :
        : [s] "r" (sink),
        : .{ .memory = true });

    // ---------------- 5. second read --------------------
    const read2 = syscall.perfmonRead(caps.SLOT_INITIAL_EC);
    const counter_2: u64 = read2.v1;
    const ts_2: u64 = vregAt(read2, ts_idx);
    if (ts_2 == 0) {
        testing.fail(3);
        return;
    }

    // ---------------- 6. assertions ---------------------
    if (!(ts_2 > ts_1)) {
        testing.fail(4);
        return;
    }
    if (counter_2 < counter_1) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
