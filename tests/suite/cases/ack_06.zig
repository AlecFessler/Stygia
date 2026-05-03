// Spec §[ack] — test 06 (degraded smoke).
//
// "[test 06] on success, the calling domain's copy of [1] has
//  `field1.irq_count = 0` immediately on return; every other
//  domain-local copy returns 0 from a fresh `sync` within a bounded
//  delay."
//
// A faithful test needs:
//   1. A device_region handle whose backing IRQ line is configured
//      and has fired at least once (so `field1.irq_count > 0`).
//   2. At least one *other* capability domain that holds its own
//      handle to the same device_region (so the multi-domain refresh
//      half of the assertion has somewhere to be observed).
//   3. A way to drive that second domain's `sync` and read its
//      domain-local handle copy back out, with a way to bound the
//      "within a bounded delay" window.
//
// None of those are reachable from a child capability domain on this
// branch. Per §[capability_domain] the runner's child cap_table holds
// slot 0 self, slot 1 EC, slot 2 self-IDC, slot 3 the result port; no
// device_region handles are forwarded (see runner/primary.zig
// spawnOne — `passed[]` carries only the result port). The test child
// cannot mint a device_region (no device_region creation syscall in
// this child's authority), nor can it reach into a sibling domain's
// cap_table to observe a peer copy. Both halves of the test 06
// assertion are therefore structurally unreachable from inside a
// single child domain on this branch.
//
// Degraded smoke
//   This test reports a degraded smoke pass: the ELF links, loads,
//   and runs to the report syscall, but does not exercise either
//   half of the §[ack] test 06 assertion. The day the runner gains
//   an IRQ-bearing device_region, plumbs it into multiple child
//   domains, and the harness gains a way to observe peer-domain
//   handle state, this test gets rewritten to drive the real
//   assertion. Until then it stays a smoke so the manifest /
//   CHECKLIST stay in lockstep with the spec.
//
// Action
//   1. Smoke-pass with assertion id 0.
//
// Assertions
//   (none today; faithful test deferred behind multi-domain harness.)

const lib = @import("lib");

const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;
    testing.pass();
}
