// Spec §[system_info] info_system — test 01.
//
// "[test 01] on success, [1] equals the number of online CPU cores
//  reported by the platform."
//
// Strategy
//   `info_system` takes no inputs and requires no caps, so the only
//   possible kernel report on a working build is success: vreg 1 ==
//   cores, vreg 2 == features, vreg 3 == total_phys_pages, vreg 4 ==
//   page_size_mask. There is no documented error path for this
//   syscall and the spec assigns no reserved-bit gate to its inputs.
//
//   The faithful black-box check on "[1] equals the number of online
//   CPU cores" is to cross-verify the count vreg 1 carries against
//   the sibling syscall `info_cores`, the spec's authoritative
//   per-core enumeration handle. `info_cores` test 04 promises
//   E_INVAL when `core_id >= info_system.cores`, so probing
//   `info_cores(cores)` lets us observe whether the boundary the
//   kernel enforces lines up with the value vreg 1 carries.
//
//   We deliberately do NOT cross-check `info_cores(i)` for i in
//   [0..cores) here. The flag word that call returns on success
//   overlaps the §[error_codes] range 1..15 (e.g., flags = 1 on a
//   plain online core collides with E_ABANDONED), so a userspace
//   black box has no robust way to distinguish a successful
//   per-core read from an error code via vreg 1 alone. The
//   per-core online-bit invariant is the subject of info_cores
//   test 06 — keeping it out of this test avoids piling
//   non-spec-faithful disambiguation on top of test 01.
//
//   Black-box invariants this test asserts:
//     a. `cores` is at least 1 — every booted system has at least
//        the BSP online, so a zero count contradicts the spec line.
//     b. `info_cores(cores)` returns E_INVAL — the boundary
//        promised by `info_cores` test 04 lines up with the count
//        in vreg 1, the only way the count and the platform's
//        online-core count can agree without falling out of sync.
//
// Action
//   1. info_system()                            — must succeed
//   2. info_cores(cores)                        — must return E_INVAL
//
// Assertions
//   1: info_system reported zero cores (cannot be a working platform)
//   2: info_cores(cores) did not return E_INVAL — the boundary
//      promised by info_cores test 04 disagrees with vreg 1, which
//      means the count cannot equal the platform's online core count

const lib = @import("lib");

const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const sys = syscall.infoSystem();
    const cores: u64 = sys.v1;

    if (cores == 0) {
        testing.fail(1);
        return;
    }

    const past_end = syscall.infoCores(cores);
    if (past_end.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
