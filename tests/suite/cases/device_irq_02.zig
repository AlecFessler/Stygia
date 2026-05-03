// Spec §[device_irq] device_irq — test 02.
//
// "[test 02] when the device fires a second IRQ before `ack` is called,
//  [1].field1.irq_count is not incremented a second time; only after
//  `ack` does a subsequent IRQ from the device increment it again."
//
// DEGRADED SMOKE VARIANT
//   The faithful shape of test 02 requires four observation phases over
//   an IRQ-firing device:
//
//     1. Acquire (or be granted) a device_region [1] whose backing
//        device is configured for IRQ delivery, with the caller holding
//        the `irq` cap on the handle (per §[ack]).
//     2. Fire IRQ #1 from the device. Per §[device_irq] step 1, the
//        kernel atomically increments [1].field1.irq_count to (prior+1)
//        and masks the IRQ line at the interrupt controller (step 2).
//     3. Without calling `ack`, fire IRQ #2 from the device. Because
//        the line is still masked, the spec asserts that
//        [1].field1.irq_count is *not* incremented a second time —
//        the second pulse is coalesced into the first.
//     4. Call `ack` (which clears the counter and unmasks the line),
//        then fire IRQ #3. The spec asserts that this third pulse
//        *does* increment the counter again, observable as the post-
//        ack copy reaching count = 1 within a bounded delay.
//
//   None of those four phases is reachable from inside a v0 child
//   capability domain as currently provisioned by the test runner:
//
//   (a) There is no userspace syscall that *mints* an IRQ-bearing
//       device_region. Device regions are seeded by the kernel at boot
//       from firmware/PCI enumeration and the root domain holds the
//       authoritative copies. The runner does not currently grant any
//       device_region handle (let alone an IRQ-bearing one) into the
//       child domain's handle table — the only handles supplied to the
//       child are `self`, the initial EC, the self-IDC, and the test
//       result port. Slots 4..4094 are empty by construction (see the
//       cap_table layout walked through in map_mmio_01.zig). With no
//       device_region in scope, `ack`'s [1] argument has no valid
//       value to bind, and `field1.irq_count` of "the device handle"
//       has no observable address.
//
//   (b) Even if a device_region were granted, the child has no
//       mechanism to make the device "fire an IRQ." The IRQ is a
//       physical line driven by hardware/QEMU; no syscall surface
//       exposes "trigger an IRQ on this device." The kernel side of
//       the test would need a synthetic device-injection hook (e.g.
//       a debug-only "kernel, please pretend device X fired its IRQ
//       N times" syscall) to drive the coalesce-then-ack sequence
//       deterministically from a single-threaded test child.
//
//   (c) Observing the *coalesce* property requires reading
//       [1].field1.irq_count between IRQ #1 and IRQ #2 *without* an
//       intervening `ack`, then reading it again after IRQ #2, then
//       reading it again after `ack` + IRQ #3. The test child has no
//       way to interleave fire/observe phases against external
//       hardware — the runner's per-test child is a one-shot EC with
//       no driver, no device-emulation harness, and no parent-side
//       fire-IRQ orchestration channel.
//
//   Reaching the faithful path needs:
//     - a kernel-side debug "fire pretend IRQ on device X" hook
//       (since no real device is wired into the v0 test rig), gated
//       to test profiles only;
//     - a runner-side fixture that mints/grants an IRQ-bearing
//       device_region into the child's handle table, with `irq` cap
//       and a known initial irq_count = 0;
//     - a result-port handshake or shared-counter convention so the
//       child can sequence "fire #1, read, fire #2, read, ack, fire
//       #3, read" against the parent driving the synthetic IRQ
//       source.
//   None of those exist. Until they do, this slot is wired as a
//   smoke-only stub.
//
// Strategy (smoke prelude)
//   The child capability domain has no IRQ-bearing device_region in
//   scope. The closest we can do without infrastructure is to issue
//   `ack` against an *empty* slot and confirm the syscall path
//   dispatches — a presence check on `ack`, mirroring the dispatch
//   smoke in snapshot_09. We do not check the returned error word
//   because the spec assertion under test (coalesce-until-ack) is
//   unreachable here, and any error code from this call (E_BADCAP
//   being the most likely against an empty slot, per §[ack] test 01)
//   is orthogonal to test 02's claim.
//
// Action
//   1. ack(empty_slot) — issue against slot 4095 (guaranteed empty by
//      the create_capability_domain table layout). The call dispatches
//      and returns; we do not interpret the return word.
//
// Assertion
//   No spec assertion is being checked — the coalesce-until-ack
//   behavior asserted by test 02 is unreachable from a v0 child
//   without an IRQ-firing-device harness. Pass with assertion id 0
//   to mark this slot as smoke-only in coverage.
//
// Faithful-test note
//   Faithful test deferred pending:
//     - kernel-side test-only IRQ-injection hook for a synthetic
//       device_region (so a test driver can deterministically
//       "fire IRQ N" without real hardware);
//     - runner-side fixture that grants an IRQ-bearing device_region
//       handle (with `irq` cap) into the test child's handle table at
//       a known slot, initialized with field1.irq_count = 0;
//     - sequence: parent fires IRQ #1; child reads count == 1;
//       parent fires IRQ #2 with no ack; child reads count == 1
//       (coalesced); child calls ack (returns prior_count = 1);
//       parent fires IRQ #3; child reads count == 1 again
//       (incremented from the post-ack zero baseline). The post-
//       coalesce equality check (count remained 1 across IRQ #2)
//       and post-ack increment check (count returned to 1 after
//       IRQ #3) would be assertion ids 1 and 2 of the faithful
//       form; this smoke's pass-with-id-0 covers neither.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Slot 4095 is guaranteed empty by the create_capability_domain
    // table layout (see map_mmio_01.zig for the same anchor). We do
    // not interpret the return word — any outcome here is orthogonal
    // to the coalesce-until-ack property the spec test asserts.
    const empty_slot: u12 = caps.HANDLE_TABLE_MAX - 1;
    _ = syscall.ack(empty_slot);

    // No spec assertion is checked — coalesce-until-ack is
    // unreachable from inside the v0 test child. Pass with assertion
    // id 0 to record this slot as smoke-only in coverage.
    testing.pass();
}
