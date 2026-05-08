// Spec §[map_pf] — test 13.
//
// "[test 13] on success, when [1].caps.dma = 1, a DMA read by the
//  bound device from `VMAR.base + offset` returns the installed
//  page_frame's contents, and a DMA access whose access type is not
//  in `VMAR.cur_rwx` ∩ `page_frame.r/w/x` is rejected by the IOMMU
//  rather than reaching the page_frame."
//
// Hardware-traffic clauses
//   The "DMA read returns page_frame contents" and "out-of-rwx DMA
//   rejected by IOMMU" assertions both require a real bus initiator
//   (the bound device) emitting transactions against the VMAR's IOVA.
//   The v3 userspace surface has no primitive for synthesizing DMA
//   cycles from a child capability domain — only an integration harness
//   driving the kernel's IOMMU under hardware (or a QEMU-backed
//   fixture) can observe those clauses faithfully. Both clauses stay
//   out of reach of any test running entirely inside a userspace EC.
//
// What this test exercises
//   The kernel-observable structural invariant the hardware-traffic
//   clauses sit on top of: a successful map_pf into a dma VMAR (a)
//   takes the dma dispatch path (§[map_pf] description: "DMA VMAR
//   (caps.dma = 1): pages are mapped into the bound device's IOMMU
//   page tables") rather than the regular CPU dispatch, and (b) leaves
//   the VMAR's field1 `device` subfield equal to the bound
//   device_region's handle id (§[var] field1 bits 41-52). Any test
//   that observes DMA traffic through this VMAR depends on those two
//   structural properties being intact; if the kernel silently
//   dropped to the regular CPU path or cleared `device`, no DMA traffic
//   could be routed even with a hardware initiator. Asserting them
//   here pins the structural prerequisites the hardware test needs.
//
// Strategy
//   §[create_vmar] dma success path requires:
//     - self-handle has `crvr` (runner grants it).
//     - caps.r/w ⊆ vmar_inner_ceiling (runner template = 0x01FF
//       includes r, w, dma — bits 0, 1, and 6).
//     - caps.dma = 1, caps.x = 0 (test 12 closed).
//     - caps.mmio = 0 (tests 04/08/11/13 closed).
//     - caps.max_sz = 0, props.sz = 0 (tests 03/07/09/10 closed).
//     - props.cur_rwx = 0b011 (r|w) ⊆ caps.{r,w} (test 16 closed).
//     - pages = 1 (test 05), preferred_base = 0 (test 06 closed).
//     - reserved bits zero (test 17 closed).
//     - [5] valid dma device_region (tests 14/15 closed).
//
//   §[map_pf] dma path requires:
//     - [1] valid VMAR handle with caps.mmio = 0 (test 03 closed).
//     - N >= 1 (test 04 closed).
//     - offset aligned to VMAR.sz (test 05 closed): we use 0.
//     - pf.sz >= VMAR.sz (test 06 closed): both 4 KiB.
//     - range within VMAR size and non-overlapping (tests 07/08/09):
//       single pair at offset 0 in a 1-page VMAR.
//     - field1.map ∈ {0, 1} (test 10 closed): freshly created VMAR
//       has map = 0.
//
// Action
//   1. Scan cap_table for the first device_region with caps.dma = 1.
//      If none → smoke-pass (runner built without fixture devices).
//   2. createVmar(caps={r,w,dma}, props={cur_rwx=0b011, sz=0, cch=0},
//                 pages=1, preferred_base=0, device_region=found)
//      — must succeed.
//   3. createPageFrame(caps={r,w}, props=0, pages=1) — must succeed.
//   4. mapPf(vmar, &.{0, pf_handle}) — must return OK on the dma
//      dispatch path.
//   5. readCap(vmar) and assert:
//        - field1.device (bits 41-52) == found device handle id.
//        - field1.map (bits 39-40) == 1 (pf installed).
//
// Assertions
//   1: createVmar returned an error (dma success path setup broke).
//   2: createPageFrame returned an error.
//   3: mapPf did not return OK on the dma dispatch path.
//   4: post-map readCap field1's `device` subfield does not equal the
//      bound device handle id (§[var] field1 bits 41-52). This is the
//      structural prerequisite the hardware DMA-traffic clause sits on:
//      if `device` is wrong, no IOMMU translation would route the bound
//      device's transactions to this page_frame.
//   5: post-map readCap field1's `map` subfield is not 1 (§[map_pf]
//      test 11). If `map` stayed 0, the kernel didn't install the pf;
//      if it became 2 (mmio) or 3 (demand), the dma dispatch went
//      through the wrong path.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const CUR_RWX: u64 = 0b011; // r|w
const SZ: u64 = 0; // 4 KiB
const CCH: u64 = 0; // wb

pub fn main(cap_table_base: u64) void {
    const dev_handle = findDmaDeviceRegion(cap_table_base) orelse {
        // Runner built without -Dtests_fixture_devices=true. The dma
        // create_vmar prelude is unreachable; smoke-pass.
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

    // r|w mirrors the VMAR's cur_rwx so the intersection equals the
    // VMAR's cur_rwx — the IOMMU PTEs the kernel would install (per
    // §[map_pf] test 13's "VMAR.cur_rwx ∩ page_frame.r/w/x" rule)
    // permit the spec-allowed access set to the maximum extent.
    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // pages = 1
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(2);
        return;
    }
    const pf_handle: u64 = @as(u64, cpf.v1 & 0xFFF);

    const m = syscall.mapPf(vmar_handle, &.{ 0, pf_handle });
    if (m.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // §[var] field1 layout (per spec table):
    //   bits 39-40 = map (0=unmapped, 1=pf, 2=mmio, 3=demand)
    //   bits 41-52 = device (12-bit handle id of the bound
    //                device_region; immutable on dma VMARs from
    //                create_vmar)
    const cap = caps.readCap(cap_table_base, vmar_handle);
    const device_field: u12 = @truncate((cap.field1 >> 41) & 0xFFF);
    if (device_field != dev_handle) {
        testing.fail(4);
        return;
    }

    const map_field: u2 = @truncate((cap.field1 >> 39) & 0x3);
    if (map_field != 1) {
        testing.fail(5);
        return;
    }

    testing.pass();
}

// Scan the handle table for the first device_region whose DeviceCap.dma
// is set. The runner's fixture forwarder (runner/primary.zig spawnOne)
// places the dma+irq fixture (caps={move,copy,dma,irq}, phys_base
// 0xCAFE_0000) at a higher slot id than the bare fixture
// (caps={move,copy}); we filter on the cap bit rather than slot order
// to remain robust to forwarder reordering.
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
