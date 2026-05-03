// Spec §[system_info] info_system — test 03.
//
// "[test 03] on success, [4] bit 0 is set on every supported architecture."
//
// Strategy
//   §[system_info] info_system is a pure read with no documented error
//   path: it requires no cap and accepts no input. Every supported
//   architecture (x86-64 today, aarch64 planned) must therefore return
//   success and report at minimum 4 KiB physical page allocation
//   support — bit 0 of [4] page_size_mask. The hardware architectures
//   Zag targets all have 4 KiB as their base page size, and the kernel
//   PMM allocates in 4 KiB units, so bit 0 must be set unconditionally.
//
//   Other bits of page_size_mask (bit 1 = 2 MiB, bit 2 = 1 GiB) are
//   architecture- and CPU-feature-dependent and therefore not asserted
//   here; reserved bits 3-63 must be zero per the spec, but that is a
//   separate prose contract not tagged as a test.
//
//   info_system has no failure path defined in the spec, so we treat
//   the call as authoritative and only inspect the post-condition on
//   [4]. As a defensive sanity guard we also require [1] cores >= 1
//   (a kernel that booted at all has at least one online core); a zero
//   core count would mean the syscall didn't actually run, which would
//   be an ill-formed environment rather than a kernel bug this test
//   targets.
//
// Action
//   1. info_system()                     — read [1] cores, [4] page_size_mask
//   2. inspect [4] bit 0                 — must be set
//
// Assertions
//   1: info_system reported zero cores (environment ill-formed)
//   2: page_size_mask bit 0 (4 KiB) is not set

const lib = @import("lib");

const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const sys = syscall.infoSystem();
    if (sys.v1 == 0) {
        testing.fail(1);
        return;
    }

    const page_size_mask = sys.v4;
    if ((page_size_mask & 1) == 0) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
