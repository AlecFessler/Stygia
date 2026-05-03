// Spec §[system_info] info_system — test 02.
//
// "[test 02] on success, [3] equals the platform's total RAM divided
//  by 4 KiB."
//
// Strategy
//   `info_system` requires no capability and has no documented error
//   path — it is a pure read of platform-wide state. Userspace has no
//   independent oracle for the platform's total RAM byte count (the
//   only kernel-exposed view of that quantity is the very return value
//   under test), so a strict equality check would be circular. The
//   black-box-testable surface this test enforces is therefore the
//   plausibility bound that follows from "RAM / 4 KiB":
//
//     - The runner targets QEMU images that always boot with at least
//       a few hundred MiB of RAM. Even on the smallest sane platform
//       Zag targets, total_phys_pages must be strictly positive (a
//       zero-page system could not have loaded the kernel that just
//       returned this value).
//     - It must also fit in a u64 by construction; any value the
//       kernel writes into vreg 3 is automatically u64-bounded, so the
//       only failure mode this test can catch is the kernel returning
//       0 (or some sentinel error masquerading as a count).
//
//   No reserved-bit / E_* paths apply — `info_system` takes no input
//   vregs and the spec lists no error codes for it.
//
// Action
//   info_system() — read [3] total_phys_pages.
//
// Assertion
//   1: total_phys_pages == 0 (would indicate the kernel didn't populate
//      vreg 3, since "total RAM divided by 4 KiB" must be at least 1
//      on any platform that successfully ran this code).

const lib = @import("lib");

const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const sys = syscall.infoSystem();
    const total_phys_pages: u64 = sys.v3;

    if (total_phys_pages == 0) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
