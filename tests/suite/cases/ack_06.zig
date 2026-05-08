// Spec §[ack] — test 06.
//
// "[test 06] on success, the calling domain's copy of [1] has
//  `field1.irq_count = 0` immediately on return; every other
//  domain-local copy returns 0 from a fresh `sync` within a bounded
//  delay."
//
// Faithful path (two-half assertion)
//   Half A — caller's own copy reads 0 immediately on return: this
//   needs a successful ack (irq_source bound), preferably with prior >
//   0 so the "zeroing happened" claim is observably nontrivial.
//
//   Half B — every other domain-local copy converges to 0 within a
//   bounded delay: this needs at least one sibling capability domain
//   holding a copied alias of the same handle, and a way to read its
//   slot. The runner today spawns each spec test as a single child
//   capability domain; multi-domain copy observation is unreachable
//   without spawning a peer (and a side-channel back to the test EC).
//
// What's reachable on this branch
//   The runner forwards the dma+irq fixture (caps={move,copy,dma,irq},
//   phys_base = 0xCAFE_0000) into every test child. Its `irq_source =
//   IRQ_SOURCE_NONE` so the kernel takes `ack`'s no-IRQ-delivery gate
//   and returns E_INVAL (kernel/syscall/reply.zig:ack). The success
//   branch of half A is unreachable until IRQ injection + handle-list
//   propagation land (commit 27efffc76 documents both gaps).
//
//   What we tighten: half A's degenerate (prior=0) variant on the
//   real IRQ-cap-bearing fixture handle. The fixture's field1.irq_count
//   stays at 0 throughout the v0 child's lifetime (no IRQ delivered,
//   no path that increments it), and §[ack] test 08 promises the
//   implicit-refresh side effect on every return path including
//   E_INVAL. So immediately after ack returns, the caller's slot must
//   read field1 = 0 — same value the success branch would observe
//   after zeroing, just trivially because nothing was ever non-zero.
//   Half B is the deferred multi-domain piece.
//
// Action
//   1. Scan cap_table for the dma+irq fixture.
//   2. If none → degraded smoke (pass-id-0).
//   3. ack(found): record return.
//   4. Read the cap-table slot directly (no intervening sync — §[ack]
//      test 08's implicit-refresh side effect must have left the slot
//      authoritative). Assert field1 == 0.
//   5. If ack returned anything other than success or E_INVAL on a
//      fixture we just confirmed carries `irq`, fail(2) — the
//      preconditions for the half-A boundary are violated.
//
// Assertions
//   1: caller's copy of field1 is non-zero immediately on return —
//      either the success branch failed to zero (faithful violation)
//      or the implicit-refresh side effect on E_INVAL stranded an
//      out-of-band irq_count value in the cap table.
//   2: ack returned an unexpected outcome on a known-irq-cap-bearing
//      handle (neither success nor E_INVAL).
//
// Faithful-test note (deferred half)
//   Half B (cross-domain propagation within a bounded delay) needs:
//     - sibling capability domain spawned with a copied alias of the
//       fixture (xfer / passed_handles);
//     - reporting channel from sibling back to test EC (e.g. a
//       result port or shared word);
//     - bounded-delay primitive (timer / time_monotonic).
//   Once injection lands, augment this test with: pre-IRQ snapshot,
//   inject IRQ (caller observes irq_count=1), ack, observe caller's
//   slot reads 0 IMMEDIATELY (same body), sibling-side observe 0
//   within bounded delay (id 3).

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

    // Read the slot directly — no intervening sync. §[ack] test 08
    // promises the implicit-refresh side effect on every return path
    // (success or error), so the post-call cap table snapshot is
    // authoritative without an explicit sync round-trip.
    const cap_post = caps.readCap(cap_table_base, dev_handle);

    // Half A boundary: caller's domain copy reads field1 = 0
    // immediately on return. Holds in two cases here:
    //   - ack succeeded: the kernel zeroed field1 across the per-region
    //     handle list (kernel/devices/device_region.zig:ack).
    //   - ack returned E_INVAL: nothing ever incremented field1 (no
    //     IRQ delivery on this fixture), so it stays at the boot-time
    //     0 the kernel mints handles with.
    if (cap_post.field1 != 0) {
        testing.fail(1);
        return;
    }

    // Outcome must be either success or the documented E_INVAL gate;
    // E_PERM / E_BADCAP would mean the fixture's preconditions
    // regressed.
    if (v != @intFromEnum(errors.Error.OK) and
        v != @intFromEnum(errors.Error.E_INVAL))
    {
        testing.fail(2);
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
