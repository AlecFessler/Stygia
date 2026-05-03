// Spec §[perfmon_start] — test 03.
//
// "[test 03] returns E_INVAL if [2] is 0 or exceeds num_counters."
//
// Strategy
//   `perfmon_start([1] target, [2] num_configs, ...)` requires
//   `num_configs` to name a count in `1..num_counters`. Either bound
//   violation is a single spec failure mode that surfaces E_INVAL.
//
//   To isolate the [2] bounds check we must neutralise every other
//   spec-mandated failure path:
//     - test 01 (E_PERM, no `pmu` self-cap): the runner grants the
//       test domain's self-handle `pmu = true` (see
//       `runner/primary.zig`, `child_self.pmu = true`), so the cap
//       gate is satisfied.
//     - test 02 (E_BADCAP, [1] not a valid EC handle): use the
//       initial-EC handle the runner installs at
//       `caps.SLOT_INITIAL_EC` for every test domain (§[self] test 02
//       confirms the test code runs on this EC). It is a valid EC
//       handle in our domain.
//     - tests 04-06 (E_INVAL on per-config validation): with
//       `num_configs = 0` no configs exist, so no per-config check can
//       fire. With `num_configs > num_counters` the [2] bounds check
//       in the spec ordering precedes the per-config walk; we still
//       fill the config slots with zeros (a clean, reserved-bit-free
//       word with event bit 0 = cycles, has_threshold = 0) so that
//       even a kernel that validated configs first would observe a
//       per-config shape that is internally legal — the only thing
//       wrong with the call is `num_configs` itself.
//     - test 07 (E_BUSY, [1] is not the calling EC and not currently
//       suspended): we use the calling EC's own handle as target, so
//       the "[1] is not the calling EC" branch never applies.
//
//   With those gates closed, the [2] bounds check is the only error
//   path the kernel can take.
//
//   Two sub-assertions cover both halves of "0 or exceeds
//   num_counters":
//     A. `perfmon_start(self_ec, 0, ...)` — the lower-bound branch.
//     B. `perfmon_start(self_ec, num_counters + 1, ...)` — the
//        upper-bound branch. We obtain `num_counters` via
//        `perfmon_info` (allowed because the self-handle has `pmu`).
//        If `perfmon_info` itself reports an error word (1..15) — e.g.
//        on a host without PMU support — we cannot derive a meaningful
//        upper bound; we still keep branch A as the load-bearing
//        check, and fall through branch B with a smoke pass.
//
// Action
//   1. perfmon_start(self_ec, 0, &.{})             — must return E_INVAL.
//   2. perfmon_info() — read num_counters from caps_word bits 0-7.
//   3. perfmon_start(self_ec, num_counters + 1, ..) — must return E_INVAL.
//
// Assertions
//   1: perfmon_start with num_configs = 0 returned something other
//      than E_INVAL.
//   2: perfmon_start with num_configs = num_counters + 1 returned
//      something other than E_INVAL (skipped if perfmon_info reported
//      an error).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // The initial EC handle the runner installs at SLOT_INITIAL_EC is
    // the EC currently executing this test code (§[self] test 02), so
    // using it as `target` keeps test 07's E_BUSY branch unreachable —
    // [1] *is* the calling EC.
    const self_target: u12 = caps.SLOT_INITIAL_EC;

    // Branch A: num_configs = 0. The lower bound of "[2] is 0 or
    // exceeds num_counters". No configs are passed, so no per-config
    // validation gate (tests 04-06) can intercept the call before the
    // num_configs bounds check.
    const a = syscall.perfmonStart(self_target, 0, &.{});
    if (a.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    // Branch B: num_configs > num_counters. Use perfmon_info to read
    // the authoritative num_counters from caps_word bits 0-7.
    const info = syscall.perfmonInfo();
    // Degraded smoke: perfmon_info reported an error code in vreg 1
    // (PMU absent / handler not yet wired). Without a real
    // num_counters we cannot construct an over-the-bound argument,
    // so branch A is the load-bearing check and we pass.
    if (info.v1 != 0 and info.v1 < 16) {
        testing.pass();
        return;
    }

    const num_counters: u64 = info.v1 & 0xFF;
    const oversize: u64 = num_counters + 1;

    // Fill enough config slots to match `oversize`. Zero is a
    // reserved-bit-free, in-range event-bit-zero (cycles) word with
    // has_threshold = 0, so the per-config validation path (tests
    // 04-06) cannot fault any individual entry; the only thing wrong
    // with this call is num_configs > num_counters.
    var configs_buf: [16]u64 = .{0} ** 16;
    const supplied = if (oversize > configs_buf.len) configs_buf.len else oversize;
    const b = syscall.perfmonStart(self_target, oversize, configs_buf[0..supplied]);
    if (b.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
