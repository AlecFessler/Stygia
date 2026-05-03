// Spec §[device_irq] device_irq — test 04.
//
// "[test 04] when the device has no IRQ delivery configured,
//  [1].field1.irq_count remains 0."
//
// DEGRADED SMOKE VARIANT
//   Faithful test 04 needs the calling capability domain to hold a
//   handle to a device_region that was *not* configured for IRQ
//   delivery — e.g. a port_io device_region with no IRQ binding, or
//   an MMIO device_region whose underlying device the kernel did not
//   wire to an IRQ line. With such a handle in slot S, the assertion
//   reads back as a one-liner: `caps.readCap(cap_table_base, S).field1
//   == 0`, optionally with a fresh `sync(S)` first to force a
//   kernel-authoritative snapshot.
//
//   Per §[device_region] (line 115 of specv3.md), device_region
//   handles are kernel-issued at boot to the root service and
//   propagate elsewhere only via xfer / suspend-reply transfer. The
//   v0 test runner (runner/primary.zig) spawns each spec test as a
//   child capability domain whose `passed_handles` carry only the
//   result port at slot 3 — no device_region of any flavor is
//   forwarded into the test child.
//
//   Without a device_region in scope inside the test child, neither
//   side of the assertion is reachable: there is no handle to read
//   field1 from, and no way to confirm that the device backing it has
//   no IRQ delivery configured. The structural shape of the test —
//   "read field1 of a non-IRQ device_region; expect 0" — collapses
//   to a no-op once the device_region argument is removed.
//
//   This smoke variant therefore checks no spec assertion. It is left
//   in place as a coverage placeholder so the slot stays accounted
//   for in the manifest and so a future runner extension that mints
//   or forwards device_regions to test children can graft the
//   faithful body onto an already-wired test ELF.
//
// Strategy (smoke prelude)
//   The test does just enough syscall work to confirm the test ELF
//   loads, runs, and reports through the standard pass channel:
//     1. `self()` — round-trip a syscall through the kernel; the
//        return is not consulted.
//     2. `pass()` — report the spec slot as smoke-only via assertion
//        id 0.
//
//   We deliberately do *not* mint a VAR or any other unrelated
//   handle. The faithful path's only fixture requirement is a
//   non-IRQ device_region; no auxiliary VAR/PF/EC construction is
//   needed in the eventual replacement, so the smoke prelude leaves
//   that surface untouched.
//
// Action
//   1. self() — exercises the syscall path and returns a self-handle
//                snapshot; the value is discarded.
//
// Assertion
//   No spec assertion is checked — the device_region surface needed
//   to observe `field1.irq_count == 0` is not reachable from the v0
//   test child. Passes with assertion id 0 to mark this slot as
//   smoke-only in coverage.
//
// Faithful-test note
//   Faithful test deferred pending a runner extension that mints (or
//   carves out from a kernel-issued boot-time region) a device_region
//   with no IRQ delivery configured and forwards it to the test
//   child via `passed_handles`. With that handle at slot
//   `SLOT_FIRST_PASSED + N`, the action becomes:
//
//     <runner: forward non-irq device_region D to the test child>
//     <child: sync(D)>                                // refresh field0/1
//     <child: cap = caps.readCap(cap_table_base, D)>  // read snapshot
//     <child: assert cap.field1 == 0>                 // irq_count = 0
//
//   That equality assertion (id 1) would replace this smoke's pass-
//   with-id-0. If the runner has both an IRQ-configured and a non-
//   IRQ device_region forwarded, this test must read the *non-IRQ*
//   one — reading the IRQ-configured one would race against any
//   actual IRQ that has fired since boot.

const lib = @import("lib");

const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Smoke prelude: round-trip a syscall to confirm the test ELF
    // loads and dispatches through the kernel. Result is discarded —
    // no spec assertion of test 04 is reachable from here.
    _ = syscall.self();

    // No spec assertion is being checked — the non-IRQ device_region
    // handle the assertion would read from is not in the test child's
    // capability table. Pass with assertion id 0 to mark this slot as
    // smoke-only in coverage.
    testing.pass();
}
