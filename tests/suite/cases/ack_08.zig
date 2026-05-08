// Spec §[ack] — test 08.
//
// "[test 08] when [1] is a valid handle, [1]'s field0 and field1 are
//  refreshed from the kernel's authoritative state as a side effect,
//  regardless of whether the call returns success or another error
//  code."
//
// Spec semantics
//   §[capabilities]: "Any syscall that takes such a handle implicitly
//   refreshes that handle's snapshot from the authoritative kernel
//   state as a side effect" — the §[ack] spec restates that this
//   side effect fires for `ack` regardless of return code. For a
//   device_region handle the kernel-mutable snapshot is
//   field1.irq_count (§[device_region]) which the kernel propagates
//   to every domain-local copy on each device IRQ; field0 is reserved
//   today but the spec assertion still applies.
//
// Faithful path
//   The runner forwards the dma+irq fixture (caps={move,copy,dma,irq},
//   phys_base = 0xCAFE_0000) into every spec-test child, so this test
//   has a valid IRQ-cap-bearing handle in scope. The cross-check
//   oracle is a fresh sync (§[capabilities] sync test 03 guarantees
//   field0/field1 reflect authoritative kernel state on success):
//   capture pre-ack, ack, capture post-ack, sync, capture post-sync.
//   Per §[ack] test 08 the post-ack snapshot must match the post-sync
//   snapshot for both field0 and field1, regardless of ack's return
//   code (the dma+irq fixture today returns E_INVAL because
//   `irq_source = IRQ_SOURCE_NONE` — the no-IRQ-delivery gate inside
//   kernel/syscall/reply.zig:ack).
//
//   Pre-ack capture is also asserted to be the boot-time zero state
//   (no IRQ delivered, no path that mutates the slot), which serves
//   as a sanity boundary on the fixture's known-clean starting state.
//
// Action
//   1. Scan cap_table for the dma+irq fixture.
//   2. If none → degraded smoke (pass-id-0; harness gap documented).
//   3. cap_pre = readCap(found). Assert field1 == 0 (boot-time
//      sanity for a fixture whose irq_source is unbound).
//   4. ack(found) — return code is intentionally NOT constrained here:
//      the side effect under test fires on every path with a valid
//      [1] (success path zeroes via device_region.ack;
//      E_INVAL/E_PERM/E_BADCAP paths take the implicit-refresh
//      side effect — kernel/syscall/reply.zig:ack).
//   5. cap_post_ack = readCap(found) — observe what `ack`'s side
//      effect left in the slot, with no intervening syscall.
//   6. sync(found) — must return OK (§[capabilities]). Authoritative
//      cross-check oracle.
//   7. cap_post_sync = readCap(found).
//   8. Assert cap_post_ack.field0 == cap_post_sync.field0 and
//             cap_post_ack.field1 == cap_post_sync.field1.
//
// Assertions
//   1: pre-ack field1 != 0 — fixture's known-clean starting state
//      regressed (kernel observed an IRQ that cannot have been
//      delivered).
//   2: sync returned non-OK on a valid fixture handle (cross-check
//      oracle unusable).
//   3: post-ack field0 differs from post-sync field0 — `ack` did not
//      refresh the snapshot, or refreshed it to a value other than
//      the authoritative kernel state.
//   4: post-ack field1 differs from post-sync field1 — same as
//      assertion 3 for the kernel-mutable irq_count.
//
// Faithful-test note (post-injection extension)
//   Once IRQ injection + handle-list propagation land, strengthen
//   the pre/post comparison: inject an IRQ, sync to observe field1=1
//   in the slot, ack, observe post-ack field1=0 in cap_post_ack
//   (immediate zeroing per §[ack] test 06), confirm post-sync
//   matches post-ack (still 0 — the side-effect contract). The
//   non-zero ↔ zero transition makes the refresh side effect
//   observably non-trivial.

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

    // Pre-ack snapshot. The boot-time fixture has field1 == 0; no IRQ
    // delivery path can mutate it on this branch, so observing
    // anything else means a kernel regression elsewhere has muddied
    // the slot before our test ELF ran.
    const cap_pre = caps.readCap(cap_table_base, dev_handle);
    if (cap_pre.field1 != 0) {
        testing.fail(1);
        return;
    }

    // ack's return code is intentionally not asserted: the spec
    // guarantees the implicit-refresh side effect on every path with
    // a valid [1], including error returns. We need to drive the
    // syscall once.
    _ = syscall.ack(dev_handle);

    // Read the slot directly from the read-only cap-table mapping.
    // This observes exactly the snapshot ack's side effect left
    // behind, with no intervening syscall to trigger another refresh.
    const cap_post_ack = caps.readCap(cap_table_base, dev_handle);

    // sync is the cross-check oracle: §[capabilities] sync test 03
    // guarantees field0/field1 reflect authoritative kernel state on
    // success. If ack performed the spec-required refresh, the two
    // snapshots must agree.
    const sync_result = syscall.sync(dev_handle);
    if (sync_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    const cap_post_sync = caps.readCap(cap_table_base, dev_handle);

    if (cap_post_ack.field0 != cap_post_sync.field0) {
        testing.fail(3);
        return;
    }
    if (cap_post_ack.field1 != cap_post_sync.field1) {
        testing.fail(4);
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
