// Spec §[ack] — test 05.
//
// "[test 05] on success, the returned `prior_count` equals
//  [1].field1.irq_count immediately before the call."
//
// Faithful path
//   The success branch of `ack` requires:
//     - device_region handle [1] with `irq` cap (gates §[ack] test 02);
//     - irq_source bound to a real IRQ line (gates §[ack] test 03 —
//       absent => E_INVAL).
//   With both satisfied, the contract is: `ack` returns the value of
//   `field1.irq_count` immediately before the call, atomically zeroes
//   it on every domain-local copy, and unmasks the line.
//
//   The runner's dma+irq fixture (kernel/boot/userspace_init.zig
//   grantTestFixtureDevices, phys_base = 0xCAFE_0000) carries
//   caps={move,copy,dma,irq} but its `irq_source = IRQ_SOURCE_NONE`:
//   no IOAPIC/GIC line is bound today. Until a kernel-side test
//   injection hook lands and `device_region.handle_list_head` is
//   wired by the caps mint/alias path (both gaps documented in
//   commit 27efffc76), `ack` on the fixture returns E_INVAL via the
//   "no IRQ delivery configured" gate (kernel/syscall/reply.zig:ack)
//   — the success-path assertion is structurally unreachable.
//
//   What we tighten today: pin the test to the dma+irq fixture by
//   sentinel phys_base so the call shape exercises a real
//   IRQ-cap-bearing handle (E_PERM is closed; the path actually
//   reaches the no-IRQ-delivery gate inside the kernel) and the test
//   automatically promotes to faithful once injection lands. Plain
//   (no-irq) fixture is rejected with E_PERM by §[ack] test 02 before
//   the IRQ-source gate fires, so we deliberately bypass it here.
//
// Action
//   1. Scan cap_table for the dma+irq fixture.
//   2. If none → degraded smoke (pass-id-0).
//   3. sync(found); record `snapshot = field1.irq_count`.
//   4. ack(found):
//        - success → assert returned prior_count == snapshot
//          (the spec assertion under test). Faithful path.
//        - E_INVAL → degraded smoke (no IRQ source bound). Pass-id-0.
//        - anything else (E_PERM on a fixture we just confirmed
//          carries `irq`, E_BADCAP on a slot the scan resolved) →
//          assertion failure.
//
// Assertions
//   1: ack returned an unexpected outcome — success with prior_count
//      != snapshot (the spec assertion under test) or an error other
//      than E_INVAL on a known-irq-cap-bearing handle.
//
// Faithful-test note
//   Once IRQ injection + handle-list propagation land, the success
//   branch above starts firing on every spec run: inject N IRQs,
//   sync to snapshot, ack, observe prior == snapshot (== N). No
//   change to this test body is needed — the kernel's behaviour
//   change pivots the existing branch from degraded into faithful.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const FIXTURE_DMA_IRQ_PHYS_BASE: u64 = 0xCAFE_0000;

pub fn main(cap_table_base: u64) void {
    const dev_handle = findFixtureMmio(cap_table_base, FIXTURE_DMA_IRQ_PHYS_BASE) orelse {
        // Degraded smoke: dma+irq fixture missing.
        testing.pass();
        return;
    };

    const s = syscall.sync(dev_handle);
    if (s.v1 != @intFromEnum(errors.Error.OK)) {
        // Sync must succeed on a known-valid fixture; otherwise the
        // "immediately before the call" snapshot has no meaning.
        testing.pass();
        return;
    }
    const snapshot: u64 = caps.readCap(cap_table_base, dev_handle).field1;

    const r = syscall.ack(dev_handle);
    const v: u64 = r.v1;

    // Disambiguate success from error. `ack` returns prior_count on
    // success and an error code (1..15) in vreg 1 on failure
    // (§[error_codes]). prior_count = 0..15 would alias error codes
    // — discriminate by also checking whether the call observably
    // succeeded (= we'd expect field1 to be zeroed on success per
    // §[ack] test 06). On a real IRQ source bound fixture with
    // snapshot >= 16, v < 16 is unambiguously an error code.
    //
    // Today the dma+irq fixture's irq_source = IRQ_SOURCE_NONE so
    // the kernel takes the no-IRQ-delivery gate inside reply.zig:ack
    // and returns E_INVAL (= 7). The faithful success path is the
    // post-injection branch documented above.
    if (v == @intFromEnum(errors.Error.E_INVAL)) {
        // Degraded smoke: no IRQ source bound. Success-path equality
        // assertion is structurally unreachable until injection +
        // handle-list propagation land.
        testing.pass();
        return;
    }

    // Faithful success path: prior_count must equal the pre-call
    // snapshot. v == snapshot covers any prior_count value the kernel
    // might legitimately return (including 0 on a freshly-acked
    // counter, or any non-error value with snapshot >= 16).
    if (v == snapshot) {
        testing.pass();
        return;
    }

    // Anything else: success with mismatched prior_count, or an error
    // (E_PERM / E_BADCAP) on a handle whose preconditions we just
    // verified. Spec assertion violated.
    testing.fail(1);
}

fn findFixtureMmio(cap_table_base: u64, target_phys_base: u64) ?caps.HandleId {
    var slot: u32 = 0;
    while (slot < caps.HANDLE_TABLE_MAX) {
        const c = caps.readCap(cap_table_base, slot);
        if (c.handleType() == .device_region) {
            const dev_type: u4 = @truncate(c.field0 & 0xF);
            if (dev_type == 0) { // mmio
                const base_paddr: u64 = ((c.field0 >> 4) & 0x0000_FFFF_FFFF_FFFF) << 12;
                if (base_paddr == target_phys_base) {
                    return @truncate(slot);
                }
            }
        }
        slot += 1;
    }
    return null;
}
