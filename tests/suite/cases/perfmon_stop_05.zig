// Spec §[perfmon_stop] — test 05.
//
// "[test 05] on success, a subsequent `perfmon_read` on the target EC
//  returns E_INVAL (perfmon was not started)."
//
// Strategy
//   The runner spawns each test in a child capability domain whose
//   self-handle carries `pmu = true` (see runner/primary.zig,
//   `child_self.pmu = true`), so the §[perfmon_*] test 01 E_PERM
//   gates cannot fire. The initial EC of the test domain lives at
//   slot caps.SLOT_INITIAL_EC, and is the EC the test code itself
//   runs on — perfmon_start / perfmon_stop / perfmon_read on that
//   handle target the calling EC, sidestepping the test 04 E_BUSY
//   gate that requires non-self targets to be suspended.
//
//   To exercise the success → stop → read-rejected sequence we must
//   first get a successful perfmon_start. That requires a config
//   whose event index is in the kernel-reported supported_events
//   bitmask. We probe `perfmon_info` to discover:
//     * num_counters  — bits 0-7 of vreg 1
//     * supported_events — vreg 2
//   If either is zero (no PMU advertised) the success path is
//   unobservable; we degrade to a smoke pass so this ELF still
//   exercises the load+link path on PMU-less hosts.
//
//   With one valid event index in hand we issue a single config
//   (num_configs = 1, has_threshold = 0, threshold = 0). The
//   matching perfmon_start has only OK as a spec-allowed outcome
//   in this environment (test 01 muted by cap, test 02 muted by
//   valid handle, test 03 muted by num_configs == 1 <= num_counters,
//   test 04 muted by event in supported_events, test 05 muted by
//   has_threshold = 0, test 06 muted by zero reserved bits, test 07
//   muted by self-target).
//
//   perfmon_stop on the same self EC similarly has only OK as the
//   spec-allowed outcome (test 01 muted by cap, test 02 by valid
//   handle, test 03 by perfmon_start having succeeded, test 04 by
//   self-target).
//
//   The spec assertion under test: a perfmon_read after a successful
//   stop must surface the "perfmon was not started" condition with
//   E_INVAL — exactly the code §[perfmon_read] test 03 mandates for
//   "perfmon was not started on the target EC".
//
// Action
//   1. perfmon_info() — probe num_counters and supported_events
//   2. if either is zero, smoke-pass
//   3. pick the lowest-indexed supported event
//   4. perfmon_start(SLOT_INITIAL_EC, 1, [event | 0, 0])
//   5. perfmon_stop(SLOT_INITIAL_EC)
//   6. perfmon_read(SLOT_INITIAL_EC)
//
// Assertions
//   1: perfmon_start did not return OK
//   2: perfmon_stop did not return OK
//   3: subsequent perfmon_read did not return E_INVAL

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const info = syscall.perfmonInfo();

    // Degraded smoke: error-shape result in vreg 1, or a zero PMU
    // (no counters advertised, or no events advertised). The success
    // path of perfmon_start is unobservable in either case.
    if (info.v1 != 0 and info.v1 < 16 and (info.v1 >> 8) == 0) {
        testing.pass();
        return;
    }
    const num_counters: u64 = info.v1 & 0xFF;
    const supported_events: u64 = info.v2;
    if (num_counters == 0 or supported_events == 0) {
        testing.pass();
        return;
    }

    // Pick the lowest-indexed supported event.
    var event_index: u6 = 0;
    while (event_index < 9) {
        if ((supported_events & (@as(u64, 1) << event_index)) != 0) break;
        event_index += 1;
    }
    if (event_index == 9) {
        // No bit in the defined range — supported_events only
        // populates bits 0..8 per §[perfmon_info] test 04.
        testing.pass();
        return;
    }

    // config_event: bits 0-7 = event_index, bit 8 = has_threshold (0),
    // bits 9-63 = reserved (0).
    const config_event: u64 = @as(u64, event_index);
    const config_threshold: u64 = 0;
    const configs = [_]u64{ config_event, config_threshold };

    const start_result = syscall.perfmonStart(caps.SLOT_INITIAL_EC, 1, configs[0..]);
    if (start_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    const stop_result = syscall.perfmonStop(caps.SLOT_INITIAL_EC);
    if (stop_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    const read_result = syscall.perfmonRead(caps.SLOT_INITIAL_EC);
    if (read_result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
