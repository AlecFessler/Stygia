// Spec §[create_execution_context] create_execution_context — test 09.
//
// "[test 09] returns E_INVAL if [5] affinity has bits set outside the
//  system's core count."
//
// Strategy
//   The runner gives every test EC a self-handle with `crec` set and
//   `pri = 3` (see runner/primary.zig). The child domain's
//   `ec_inner_ceiling` is also wide open (0xFF in primary.zig), so a
//   minimal EcCap with `restart_policy = 0` is a subset and won't trip
//   test 03. Likewise `priority = 0` stays under the pri ceiling and
//   `target = 0` (self) sidesteps the test 02/04/05/07 IDC paths.
//   `stack_pages = 1` keeps test 08 from firing.
//
//   That leaves the affinity mask as the only spec-mandated failure
//   path. To produce a mask with bits set outside the system's core
//   count, query `info_system` for the online core count and then set
//   bit `cores` (zero-indexed: bits 0..cores-1 are valid cores, so bit
//   `cores` is the first invalid bit). The kernel must reject with
//   E_INVAL.
//
//   As a defensive paranoia check, `cores` is asserted to be <= 63 so
//   that bit `cores` actually fits in a u64. On any platform Zag
//   targets this holds trivially; if it ever fails the harness reports
//   an assertion id rather than silently miscompiling the shift.
//
// Action
//   1. info_system()  — read [1] cores
//   2. create_execution_context(
//          caps   = {restart_policy=0, priority=0},
//          entry  = &dummyEntry,
//          stack  = 1,
//          target = 0 (self),
//          affinity = (1 << cores))     — must return E_INVAL
//
// Assertions
//   1: info_system reported a core count outside the supported range
//      [1, 63] (would make the test ill-formed)
//   2: create_execution_context returned something other than E_INVAL

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const sys = syscall.infoSystem();
    const cores: u64 = sys.v1;
    if (cores == 0 or cores > 63) {
        testing.fail(1);
        return;
    }

    const ec_caps = caps.EcCap{
        .restart_policy = 0,
    };
    // §[create_execution_context] caps word: caps in bits 0-15,
    // target_caps in 16-31 (ignored when target=self), priority in
    // 32-33. priority=0 keeps the call within the runner's pri ceiling.
    const caps_word: u64 = @as(u64, ec_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);

    // First bit beyond the system's core count: bit `cores` is invalid
    // (valid bits are 0..cores-1). All lower bits cleared so the mask
    // is unambiguously "cores+ only".
    const bad_affinity: u64 = @as(u64, 1) << @intCast(cores);

    const result = syscall.createExecutionContext(
        caps_word,
        entry,
        1,
        0,
        bad_affinity,
    );

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
