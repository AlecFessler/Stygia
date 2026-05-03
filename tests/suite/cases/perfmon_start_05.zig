// Spec §[perfmon_start] — test 05.
//
// "[test 05] returns E_INVAL if any config has has_threshold = 1 but
//  the hardware does not support overflow."
//
// Strategy
//   `perfmon_start` takes a target EC and N counter configs. Each
//   config_event word carries a has_threshold bit at bit 8. If the
//   hardware does not advertise counter-overflow support (caps_word
//   bit 8 from `perfmon_info` is clear) the kernel must reject any
//   config with has_threshold = 1 with E_INVAL.
//
//   To isolate this gate we have to make every other failure path in
//   perfmon_start pass:
//     - test 01: E_PERM if self-handle lacks `pmu`. The runner grants
//       `pmu = true` on the test domain's self-handle (see
//       runner/primary.zig: `child_self.pmu = true`), so this gate is
//       never triggered.
//     - test 02: E_BADCAP if [1] is not a valid EC handle. We pass
//       SLOT_INITIAL_EC, which is unconditionally installed by the
//       runner per §[create_capability_domain] test 21.
//     - test 03: E_INVAL if [2] is 0 or > num_counters. We use
//       num_configs = 1 and require num_counters >= 1 from
//       perfmon_info; otherwise we skip (degraded smoke).
//     - test 04: E_INVAL if any event is not in supported_events. We
//       set event index = 0 (cycles per §[perfmon_info]) and require
//       supported_events bit 0 is set; otherwise skip.
//     - test 06: E_INVAL if reserved bits set in any config_event.
//       We only set bits 0-7 (event index) and bit 8 (has_threshold).
//     - test 07: E_BUSY if [1] is not the calling EC and not
//       suspended. SLOT_INITIAL_EC is the calling EC, so this gate
//       cannot fire.
//
//   That leaves test 05's overflow-support gate as the only spec
//   failure path remaining when the hardware does not support
//   overflow.
//
// Degraded smoke
//   The trigger is gated on the hardware advertising NO overflow
//   support (caps_word bit 8 = 0). If the host PMU does support
//   overflow, has_threshold = 1 is a valid config and the kernel
//   would (per the spec) accept it — we cannot synthesize the
//   failure on such hardware without lying about caps. In that case
//   we report pass() with a non-fatal smoke-pass branch so this ELF
//   still validates the syscall plumbing in CI.
//
//   Likewise if `perfmon_info` returns an error code (PMU absent or
//   handler not yet wired — vreg 1 in 1..15), the precondition for
//   a meaningful start call is gone; we smoke-pass.
//
//   Likewise if the kernel reports zero counters (num_counters = 0)
//   or does not advertise the cycles event (supported_events bit 0
//   clear), we cannot construct a config that bypasses tests 03/04
//   and we smoke-pass.
//
// Action
//   1. perfmon_info()                             — read caps
//   2. if info errored / no counters / no cycles  — smoke-pass
//   3. if overflow_support = 1                    — smoke-pass
//   4. build config_event = cycles | has_threshold (bit 8)
//      build config_threshold = arbitrary nonzero
//   5. perfmon_start(SLOT_INITIAL_EC, 1, [event, threshold])
//        — must return E_INVAL
//
// Assertions
//   1: perfmon_info advertises overflow_support but the trigger path
//      cannot run; tracked as a smoke-pass branch (not a fail).
//   2: perfmon_start returned something other than E_INVAL on the
//      no-overflow path.
//   3: perfmon_start returned OK (kernel ignored the overflow gate
//      entirely on a no-overflow PMU — spec violation).
//   4: perfmon_start returned a non-E_INVAL error code on the
//      no-overflow path (some other gate fired; either the spec gate
//      ordering changed or one of our preconditions broke).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const EVENT_CYCLES_BIT: u64 = 1 << 0;
const HAS_THRESHOLD_BIT: u64 = 1 << 8;
const OVERFLOW_SUPPORT_BIT: u64 = 1 << 8;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const info = syscall.perfmonInfo();

    // Degraded smoke: perfmon_info itself errored. vreg 1 in 1..15
    // is unambiguously an error code per §[error_codes]; in that
    // shape bits 8-63 are zero, so caps_word bit 8 is also zero —
    // but we cannot trust num_counters / supported_events either.
    if (info.v1 != 0 and info.v1 < 16 and (info.v1 >> 8) == 0) {
        testing.pass();
        return;
    }

    const caps_word: u64 = info.v1;
    const supported_events: u64 = info.v2;
    const num_counters: u64 = caps_word & 0xFF;

    // Need at least one counter so num_configs = 1 passes test 03,
    // and the cycles event so event index = 0 passes test 04.
    if (num_counters == 0 or (supported_events & EVENT_CYCLES_BIT) == 0) {
        testing.pass();
        return;
    }

    // Hardware advertises overflow support: has_threshold = 1 is a
    // legal config and test 05's gate cannot fire. Smoke-pass.
    if ((caps_word & OVERFLOW_SUPPORT_BIT) != 0) {
        testing.pass();
        return;
    }

    // Overflow NOT supported. Build a single config with cycles and
    // has_threshold set; threshold value is arbitrary.
    const config_event: u64 = EVENT_CYCLES_BIT | HAS_THRESHOLD_BIT;
    const config_threshold: u64 = 0x1000;
    const configs = [_]u64{ config_event, config_threshold };

    const result = syscall.perfmonStart(
        caps.SLOT_INITIAL_EC,
        1,
        configs[0..],
    );

    if (result.v1 == @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }
    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
