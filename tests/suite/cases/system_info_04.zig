// Spec §[system_info] info_cores — test 04.
//
// "[test 04] returns E_INVAL if [1] core_id is greater than or equal
//  to `info_system`'s `cores`."
//
// Strategy
//   `info_cores` takes a single core_id in [1] and must reject any id
//   that names a core outside the platform's online set. The boundary
//   the spec pins is `cores`, the count returned by `info_system` —
//   valid ids are 0..cores-1, so id == cores is the smallest invalid
//   value and the cleanest probe of this rule.
//
//   To isolate the boundary check we make every other check pass:
//     - Reserved-bit check (test 05): we pass core_id == cores. So
//       long as cores fits in the defined low bits of [1], no
//       reserved bit is set. The spec doesn't pin the width of the
//       core_id field, but on any platform Zag targets cores is small
//       (< 64), so the value is well below any plausible reserved
//       region and below 2^32.
//
//   That leaves the out-of-range check as the only spec-mandated
//   failure path.
//
//   First we call `info_system()` to read the canonical cores count
//   the spec ties this rule to. `info_system` takes no inputs and has
//   no documented error path, so its v1 output is the cores value.
//
//   Defensive paranoia: cores is asserted to be in (0, 63]. Cores == 0
//   would make the boundary value (0) collide with the valid range
//   and leave nothing to probe; cores > 63 would either cross
//   syscall-ABI assumptions in this test harness or signal a corrupt
//   info_system reply. Either case makes the test ill-formed and we
//   surface that as a distinct assertion id rather than miscount.
//
// Action
//   1. info_system()           — read [1] cores
//   2. info_cores(core_id = cores) — must return E_INVAL
//
// Assertions
//   1: info_system reported a core count outside the supported range
//      [1, 63] (would make the test ill-formed)
//   2: info_cores with core_id == cores returned something other than
//      E_INVAL

const lib = @import("lib");

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

    const result = syscall.infoCores(cores);

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
