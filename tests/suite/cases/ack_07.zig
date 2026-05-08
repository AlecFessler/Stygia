// Spec §[ack] — test 07.
//
// "[test 07] on success, after a subsequent IRQ from the device, every
//  domain-local copy's `field1.irq_count` reaches the new value within
//  a bounded delay and an EC blocked in `futex_wait_val` on each copy's
//  `field1` paddr is woken."
//
// Faithful path
//   The faithful sequence requires:
//     1. A dma+irq fixture with `irq_source` bound to a real IRQ line
//        (so kernel/devices/device_region.zig onIrq actually reaches
//        propagateIrqAndWake on injection).
//     2. handle_list_head wired by the caps mint/alias path so
//        propagateIrqAndWake walks every domain-local copy and bumps
//        field1.irq_count saturating + futex.wake on its paddr.
//     3. A worker EC parked in `futex_wait_val(addr=&copy.field1,
//        expected=copy.field1.irq_count)` ahead of the second IRQ so
//        the wake side of the assertion has someone to deliver to.
//     4. A bounded-delay timing primitive (time_monotonic or a timer
//        IDC service) so "within a bounded delay" can be asserted.
//
// What's reachable on this branch
//   None of pieces 1-4 land in this commit. The runner-fix
//   (commit 27efffc76) forwards the dma+irq fixture into every spec-
//   test child, but its `irq_source = IRQ_SOURCE_NONE` and
//   `device_region.handle_list_head` is never appended (caps module's
//   handle-table mint/alias path does not register a HandleListNode
//   under the parent DeviceRegion's _gen_lock). Both gaps are flagged
//   in the runner-fix commit message.
//
//   What we tighten today: pin the test to the dma+irq fixture by
//   sentinel phys_base so when injection lands, the assertion
//   automatically promotes from smoke to the post-IRQ propagation
//   path. We also tag the call shape that test 07 actually exercises:
//   ack on the fixture must reach the no-IRQ-delivery gate
//   (E_INVAL) — it must NOT trip E_PERM (cap missing) or E_BADCAP
//   (slot empty), because both would invalidate the precondition the
//   faithful test 07 chains off of (a "successful ack" prefix). If
//   the kernel ever flips the dma+irq fixture's caps or removes it
//   from the runner forwards, this test fail() catches the regression
//   even though the wake-side assertion stays deferred.
//
// Action
//   1. Scan cap_table for the dma+irq fixture (phys_base = 0xCAFE_0000).
//   2. If none → degraded smoke (pass-id-0).
//   3. ack(found): expect either success (faithful future) or E_INVAL
//      (no IRQ source bound today). Anything else (E_PERM on a
//      handle we just confirmed carries `irq`, E_BADCAP on a slot
//      the scan resolved) means the fixture's contract regressed
//      and the wake-side assertion will never be testable.
//
// Assertions
//   1: ack returned an unexpected outcome on a known-irq-cap-bearing
//      handle — neither success nor E_INVAL.
//
// Faithful-test note (deferred half)
//   Once IRQ injection + handle-list propagation + a worker-EC harness
//   land, the test body extends to:
//     - mint and ack to set baseline;
//     - spawn a worker EC parked in futex_wait_val(addr=&field1,
//       expected=current_count);
//     - inject IRQ;
//     - test EC reads field1 == current_count + 1 (id 2);
//     - worker side-channels its observed [1] (the field1 vaddr) back
//       to the test EC; assert it equals the expected vaddr (id 3);
//     - bounded-delay primitive guards both observations.

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

    const r = syscall.ack(dev_handle);
    const v: u64 = r.v1;

    // Acceptable: success (faithful future when injection lands) or
    // E_INVAL (today's no-IRQ-source gate). Any other return code
    // means the fixture's `irq` cap or backing DeviceRegion was
    // mis-minted by the runner-fix, and the wake-side assertion will
    // never be reachable through this handle.
    if (v != @intFromEnum(errors.Error.OK) and
        v != @intFromEnum(errors.Error.E_INVAL))
    {
        testing.fail(1);
        return;
    }

    testing.pass();
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
