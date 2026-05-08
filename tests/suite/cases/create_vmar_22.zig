// Spec §[create_vmar] — test 22 (first clause).
//
// "[test 22] on success, when caps.dma = 1, field1's `device` field
//  equals [5]'s handle id, and a subsequent `map_pf` into this VMAR
//  routes the bound device's accesses at field0 + offset to the
//  installed page_frame."
//
// The second clause (DMA traffic routing through the IOMMU) requires
// emitting bus transactions from a real device and observing the IOVA
// translation. That is out of scope for a userspace spec test in v0
// — no DMA initiator is reachable from a child capability domain. This
// test exercises the first clause: on a successful dma create_vmar,
// the resulting VMAR's field1 `device` subfield equals the bound
// device_region's handle id (per §[var] field1 layout, bits 41-52).
//
// Strategy
//   Drive create_vmar down its dma success path. Per §[create_vmar]
//   the prelude checks must all pass:
//     - self-handle has `crvr` (runner grants it).
//     - caps.r/w ⊆ vmar_inner_ceiling (runner template = 0x01FF, which
//       includes r, w, and dma — bits 0, 1, and 6 of vmar_inner_ceiling).
//     - caps.dma = 1, caps.x = 0 (test 12 closed).
//     - caps.mmio = 0, dma = 1 → test 13 closed.
//     - caps.max_sz = 0 (test 03/07/10 closed).
//     - props.sz = 0 (4 KiB), cur_rwx = 0b011 (r|w) ⊆ caps.{r,w} →
//       test 16 closed.
//     - pages = 1 (test 05 closed), preferred_base = 0 (test 06 closed).
//     - reserved bits zero (test 17 closed).
//     - [5] is a valid device_region handle with the `dma` cap. The
//       runner's spawnOne forwards a fixture device_region with
//       caps={move,copy,dma,irq} at phys_base 0xCAFE_0000 (gated on
//       -Dtests_fixture_devices=true). We scan the cap table for the
//       first device_region whose DeviceCap.dma bit is set and use it
//       as [5].
//
// Action
//   1. Scan cap_table for the first device_region with caps.dma = 1.
//      If none → smoke-pass (runner built without fixture devices).
//   2. createVmar(caps={r,w,dma}, props={cur_rwx=0b011, sz=0, cch=0},
//                 pages=1, preferred_base=0, device_region=found)
//      — must return a valid VMAR handle.
//   3. readCap(handle) → assert handleType == virtual_memory_address_region.
//   4. Decode field1 bits 41-52 (the `device` subfield) and assert it
//      equals the bound device_region's handle id.
//
// Assertions
//   1: createVmar did not return a valid handle (any error breaks the
//      prelude; the dma success path was set up correctly).
//   2: returned slot's handleType is not virtual_memory_address_region.
//   3: field1's `device` subfield (bits 41-52) does not equal the
//      bound device handle id — the spec assertion under test.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

const CUR_RWX: u64 = 0b011; // r|w
const SZ: u64 = 0; // 4 KiB
const CCH: u64 = 0; // wb

pub fn main(cap_table_base: u64) void {
    const dev_handle = findDmaDeviceRegion(cap_table_base) orelse {
        // Runner not built with -Dtests_fixture_devices=true. The
        // first-clause assertion is structurally unreachable without a
        // dma-capable device; smoke-pass.
        testing.pass();
        return;
    };

    const vmar_caps = caps.VmarCap{ .r = true, .w = true, .dma = true };
    const props: u64 = (CCH << 5) | (SZ << 3) | CUR_RWX;

    const cv = syscall.createVmar(
        @as(u64, vmar_caps.toU16()),
        props,
        1, // pages = 1
        0, // preferred_base — kernel chooses
        @as(u64, dev_handle),
    );
    if (testing.isHandleError(cv.v1)) {
        testing.fail(1);
        return;
    }

    const vmar_handle: u12 = @truncate(cv.v1 & 0xFFF);
    const cap = caps.readCap(cap_table_base, vmar_handle);

    if (cap.handleType() != caps.HandleType.virtual_memory_address_region) {
        testing.fail(2);
        return;
    }

    // §[var] field1 layout: device subfield occupies bits 41-52
    // (12 bits, matching the 12-bit handle id width).
    const device_field: u12 = @truncate((cap.field1 >> 41) & 0xFFF);
    if (device_field != dev_handle) {
        testing.fail(3);
        return;
    }

    testing.pass();
}

// Scan the handle table for the first device_region whose DeviceCap.dma
// is set. The runner's fixture forwarder places the dma+irq fixture
// (caps={move,copy,dma,irq}, phys_base 0xCAFE_0000) at a higher slot id
// than the bare fixture (caps={move,copy}); we filter on the cap bit
// rather than slot order to remain robust to forwarder reordering.
fn findDmaDeviceRegion(cap_table_base: u64) ?caps.HandleId {
    var slot: u32 = 0;
    while (slot < caps.HANDLE_TABLE_MAX) {
        const c = caps.readCap(cap_table_base, slot);
        if (c.handleType() == .device_region) {
            const dev_caps: caps.DeviceCap = @bitCast(c.caps());
            if (dev_caps.dma) {
                return @truncate(slot);
            }
        }
        slot += 1;
    }
    return null;
}
