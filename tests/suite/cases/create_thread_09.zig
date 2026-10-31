// Spec §[create_thread] create_thread — test 09.
//
// "[test 09] returns E_INVAL if [5] affinity has bits set outside the
//  system's core count."
//
// Strategy
//   The runner gives every test thread a self-handle with `crec` set and
//   `pri = 3` (see runner/primary.zig). The child process's
//   `thread_inner_ceiling` is also wide open (0xFF in primary.zig), so a
//   minimal ThreadCap with `restart_policy = 0` is a subset and won't trip
//   test 03. Likewise `priority = 0` stays under the pri ceiling and
//   `target = 0` (self) sidesteps the test 02/04/05/07 IPC paths.
//   `stack_pages = 1` keeps test 08 from firing.
//
//   That leaves the affinity mask as the only spec-mandated failure
//   path. The harness declares its provisioned core count via
//   -Dexpected_cores; set bit `cores` (bits 0..cores-1 are valid, so bit
//   `cores` is the first invalid bit). The kernel must reject with
//   E_INVAL.
//
//   The suite build rejects expected_cores outside 1..63, so bit `cores`
//   fits in the u64 affinity mask.
//
// Action
//   1. create_thread(
//          caps   = {restart_policy=0, priority=0},
//          entry  = &dummyEntry,
//          stack  = 1,
//          target = 0 (self),
//          affinity = (1 << cores))     — must return E_INVAL
//
// Assertions
//   1: create_thread returned something other than E_INVAL

const lib = @import("lib");
const test_environment = @import("test_environment");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const cores: u64 = test_environment.expected_cores;

    const thread_caps = caps.ThreadCap{
        .restart_policy = 0,
    };
    // §[create_thread] caps word: caps in bits 0-15,
    // target_caps in 16-31 (ignored when target=self), priority in
    // 32-33. priority=0 keeps the call within the runner's pri ceiling.
    const caps_word: u64 = @as(u64, thread_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);

    // First bit beyond the system's core count: bit `cores` is invalid
    // (valid bits are 0..cores-1). All lower bits cleared so the mask
    // is unambiguously "cores+ only".
    const bad_affinity: u64 = @as(u64, 1) << @intCast(cores);

    const result = syscall.createThread(
        caps_word,
        entry,
        1,
        0,
        bad_affinity,
    );

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
