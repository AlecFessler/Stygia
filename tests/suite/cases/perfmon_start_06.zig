// Spec §[perfmon_start] perfmon_start — test 06.
//
// "[test 06] returns E_INVAL if any reserved bits are set in any
//  config_event."
//
// Strategy
//   §[perfmon_start] specifies each config_event word as
//     bits 0-7:  event index (per perfmon_info supported_events)
//     bit  8:    has_threshold
//     bits 9-63: _reserved
//   Setting any bit outside the defined fields is a spec violation
//   that must surface E_INVAL at the syscall ABI layer.
//
//   To isolate the reserved-bit check we make every other check pass:
//     [test 01] E_PERM   — caller's self-handle lacks `pmu`.
//                          Runner grants `pmu` (runner/primary.zig).
//     [test 02] E_BADCAP — [1] is not a valid EC handle.
//                          Use SLOT_INITIAL_EC, which is the calling
//                          EC and always present in the table.
//     [test 03] E_INVAL  — [2] is 0 or exceeds num_counters.
//                          perfmon_info_02 asserts that on success
//                          num_counters >= 1, so num_configs = 1 is
//                          safe regardless of the host PMU.
//     [test 04] E_INVAL  — config event not in supported_events.
//                          Read supported_events via perfmon_info and
//                          pick the lowest-set bit as the event index.
//     [test 05] E_INVAL  — has_threshold=1 but no overflow support.
//                          Set has_threshold=0; this check cannot fire
//                          regardless of the hardware's overflow_support.
//     [test 07] E_BUSY   — target is not the calling EC and not
//                          suspended. Target = the calling EC.
//
//   That leaves the reserved-bit check as the only spec-mandated
//   failure path. We then dispatch perfmon_start with reserved bit 63
//   of config_event[0] set on top of a valid (event_index, has_threshold=0)
//   pair.
//
//   The libz `syscall.perfmonStart` wrapper takes the configs as a
//   `[]const u64`, which already preserves arbitrary bit patterns —
//   it would not mask reserved bits. We still go through `issueReg`
//   directly here to keep the bypass shape identical to affinity_04
//   and restrict_05, and to make it explicit that vreg 3 carries the
//   config_event word verbatim.
//
// Action
//   1. perfmon_info()
//        — must succeed; pull num_counters (>= 1) and supported_events
//          (must be nonzero per perfmon_info_04)
//   2. perfmon_start(target=SLOT_INITIAL_EC,
//                    num_configs=1,
//                    config_event = event_index | (1 << 63),
//                    config_threshold = 0)
//        — must return E_INVAL (reserved bit 63 of config_event set;
//          low 8 bits hold a valid event index; has_threshold=0;
//          target is the calling EC so test 07 cannot fire)
//
// Assertions
//   1: perfmon_info returned an error word in vreg 1 (the runner
//      contract this test relies on is gone)
//   2: perfmon_info reported zero supported events (no valid event
//      index can be constructed)
//   3: perfmon_start with reserved bit 63 of config_event set
//      returned something other than E_INVAL

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const info = syscall.perfmonInfo();
    // A real caps_word always has num_counters in bits 0-7 (>= 1 per
    // perfmon_info_02) and the upper 56 bits zero or with bit 8 set.
    // Any value <= 15 with no other bits set is an error code.
    if (info.v1 != 0 and info.v1 < 16 and (info.v1 >> 8) == 0) {
        testing.fail(1);
        return;
    }

    const supported_events: u64 = info.v2;
    if (supported_events == 0) {
        testing.fail(2);
        return;
    }

    // Lowest-set bit in supported_events is a valid event index.
    const event_index: u64 = @ctz(supported_events);

    // Reserved bit 63 of config_event set; low 8 bits hold the valid
    // event index; bit 8 (has_threshold) clear so test 05 cannot fire.
    // Bypass the typed wrapper and dispatch issueReg directly so vreg
    // 3 carries the malformed config_event word verbatim.
    const config_event: u64 = event_index | (@as(u64, 1) << 63);
    const r = syscall.issueReg(.perfmon_start, 0, .{
        .v1 = caps.SLOT_INITIAL_EC,
        .v2 = 1,
        .v3 = config_event,
        .v4 = 0,
    });
    if (r.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
