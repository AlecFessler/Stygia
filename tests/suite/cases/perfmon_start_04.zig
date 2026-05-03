// Spec §[perfmon_start] — test 04.
//
// "[test 04] returns E_INVAL if any config's event is not in
//  supported_events."
//
// Strategy
//   The supported_events bitmask returned by perfmon_info indexes nine
//   defined event bits per the §[perfmon_info] table:
//     bit 0  cycles            bit 5  branch_misses
//     bit 1  instructions      bit 6  bus_cycles
//     bit 2  cache_references  bit 7  stalled_cycles_frontend
//     bit 3  cache_misses      bit 8  stalled_cycles_backend
//     bit 4  branch_instructions
//   Bits 9..63 of supported_events are reserved-by-omission — perfmon
//   info test 04 already enforces that a conformant kernel leaves
//   them clear. So any config_event with an event index in 9..63 is
//   guaranteed not to be in supported_events, and the perfmon_start
//   spec mandates E_INVAL.
//
//   To isolate the "event not in supported_events" check we make every
//   other spec-mandated failure path pass:
//     - self-handle carries `pmu` (so test 01 PERM does not fire). The
//       runner's primary grants `pmu` on the test domain's self-handle
//       (see runner/primary.zig: `child_self.pmu = true`).
//     - [1] is a valid EC handle (so test 02 BADCAP does not fire). The
//       runner installs the test's own EC at SLOT_INITIAL_EC.
//     - [2] = 1 is in range. The lower bound is num_configs >= 1 by
//       spec test 03; the upper bound is num_counters, which spec
//       §[perfmon_info] test 02 places in supported_events bits 0-7,
//       and at least one counter must exist on conformant hardware.
//       Passing 1 keeps us inside [1, num_counters] under any positive
//       counter count.
//     - [1] is the calling EC (so test 07 BUSY does not fire — that
//       check is gated on "[1] is not the calling EC").
//     - reserved bits 9..63 of config_event stay zero and bit 8
//       (has_threshold) stays zero (so tests 05/06 INVAL paths do not
//       fire).
//   The only failure path the call can take is the test 04 check.
//
//   Pick event index 63 — the highest value the bits-0-7 field can
//   express. Spec §[perfmon_info] test 04 requires bits 9..63 of
//   supported_events to be zero, so bit 63 is provably never set, and
//   the kernel must reject the call with E_INVAL.
//
// Action
//   1. perfmon_start(target=SLOT_INITIAL_EC, num_configs=1,
//      config_event = 63, config_threshold = 0)
//
// Assertion
//   1: perfmon_start returned something other than E_INVAL

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // config_event packed per §[perfmon_start]:
    //   bits 0-7: event index (we want one outside supported_events)
    //   bit 8:    has_threshold = 0
    //   bits 9-63: reserved = 0
    // Event index 63 is the largest the 8-bit field can hold, and is
    // guaranteed reserved-by-omission per §[perfmon_info] test 04.
    const unsupported_event_index: u64 = 63;
    const config_event: u64 = unsupported_event_index;
    const config_threshold: u64 = 0;

    const configs = [_]u64{ config_event, config_threshold };

    const result = syscall.perfmonStart(
        caps.SLOT_INITIAL_EC,
        1,
        configs[0..],
    );

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
