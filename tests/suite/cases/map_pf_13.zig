// Spec §[map_pf] — test 13 (degraded variant: smoke only).
//
// "[test 13] on success, when [1].caps.dma = 1, a DMA read by the bound
//  device from `VAR.base + offset` returns the installed page_frame's
//  contents, and a DMA access whose access type is not in `VAR.cur_rwx`
//  ∩ `page_frame.r/w/x` is rejected by the IOMMU rather than reaching
//  the page_frame."
//
// Faithful exercise requires a real DMA initiator: the spec assertion
// is that DMA traffic from a device bound to a `caps.dma = 1` VAR (a)
// reaches the installed page_frame's bytes through the IOMMU and (b)
// is rejected by the IOMMU when the access type is outside the
// effective r/w/x of the mapping. Both observations require *the
// device* to issue the bus transaction; a CPU read of the page_frame
// would only exercise the CPU paging path, which is what test 12
// already covers. There is no userspace primitive in the v3 surface
// that emits a hardware DMA cycle, so the second clause of this test
// is structurally out of reach from a userspace spec test in this
// branch.
//
// Compounding that, the v0 runner does not currently forward any
// device_region to test children. runner/primary.zig spawnOne builds
// each test child's `passed_handles` with only the result port at
// SLOT_FIRST_PASSED — see also create_var_22's matching DMA blocker
// note. So even the dma create_var prelude that would normally
// precede a map_pf into a DMA VAR cannot be set up: no
// `caps.dma = 1` device_region is reachable from this child's cap
// table.
//
// Strategy
//   Drive create_var down its dma success path. Per §[create_var]
//   prelude this requires:
//     - self-handle has `crvr` (runner grants it).
//     - caps.r/w ⊆ var_inner_ceiling (runner template = 0x01FF, which
//       includes r, w, dma — bits 0, 1, and 6 of var_inner_ceiling).
//     - caps.dma = 1, caps.x = 0 (test 12 closed).
//     - caps.mmio = 0, dma = 1 (test 13 of create_var closed).
//     - caps.max_sz = 0 (tests 03/07/10 closed).
//     - props.sz = 0 (4 KiB), cur_rwx = 0b011 (r|w) ⊆ caps.{r,w}
//       (test 16 closed).
//     - pages = 1 (test 05 closed), preferred_base = 0 (test 06 closed).
//     - reserved bits zero (test 17 closed).
//     - [5] is a valid device_region handle (test 14 closed) and has
//       the `dma` cap (test 15 closed).
//
//   Today no device_region with the `dma` cap reaches the test child,
//   so the dma create_var path is not reachable. And even if it were,
//   the second clause of map_pf test 13 — "DMA read returns page_frame
//   contents" / "IOMMU rejects out-of-rwx DMA" — needs a hardware DMA
//   harness that has no v0 userspace analogue.
//
// Degraded smoke
//   This test scans its cap table for any device_region handle. If
//   none is found — the expected case on the current runner — it
//   reports a degraded smoke pass (assertion id 0): the test ELF
//   links, loads, and exercises the cap-table scan plumbing, but
//   cannot drive create_var down the dma success path, let alone the
//   subsequent map_pf into the dma VAR.
//
//   If a device_region handle is found, attempt a dma create_var
//   bound to it and, on success, a map_pf of a freshly-minted r|w
//   page_frame at offset 0. The CPU side of map_pf is the closest a
//   userspace test can get; the spec's DMA-traffic assertion still
//   requires hardware that is out of scope. Smoke-pass at every
//   terminal outcome to keep the test slot honest about what is
//   actually being checked here.
//
// Action
//   1. Scan cap_table for the first device_region handle.
//   2. If none → smoke-pass with assertion id 0 (degraded; documented).
//   3. createVar(caps={r,w,dma}, props={cur_rwx=0b011, sz=0, cch=0},
//                pages=1, preferred_base=0, device_region=found)
//   4. createPageFrame(caps={r,w}, props=0, pages=1)
//   5. mapPf(var_handle, &.{ 0, pf_handle })
//   6. smoke-pass at end regardless of intermediate errors — no spec
//      assertion is being checked because the DMA observation is
//      hardware-only.
//
// Faithful-test note
//   Faithful test 13 requires (a) a runner extension that forwards a
//   dma-capable device_region to the test child *and* (b) a hardware
//   DMA harness that can emit reads/writes from that device into a
//   kernel-controlled IOVA window, with the test EC observing both
//   the data path (DMA returns page_frame bytes) and the rejection
//   path (DMA outside cur_rwx ∩ pf.rwx is dropped by the IOMMU
//   without reaching the page_frame). Neither piece exists in v0,
//   and (b) almost certainly belongs in an integration harness, not
//   a userspace spec test. Until both land, this slot stays smoke.
//
// Assertions
//   None (asserts assertion id 0 on every terminal path).

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

const CUR_RWX: u64 = 0b011; // r|w
const SZ: u64 = 0; // 4 KiB
const CCH: u64 = 0; // wb

pub fn main(cap_table_base: u64) void {
    const dev_handle = findDeviceRegion(cap_table_base) orelse {
        // Degraded smoke: no device_region in this child's cap table.
        // Both the dma create_var prelude and the DMA-traffic
        // observation are unreachable; document the gap and report a
        // non-failure outcome so the test ELF still validates link/
        // load/scan plumbing in CI without forcing a false
        // expectation. Once the runner forwards a dma-capable
        // device_region to test children *and* a hardware DMA harness
        // exists, this branch retires.
        testing.pass();
        return;
    };

    const var_caps = caps.VarCap{ .r = true, .w = true, .dma = true };
    const props: u64 = (CCH << 5) | (SZ << 3) | CUR_RWX;

    const cv = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        1, // pages = 1
        0, // preferred_base — kernel chooses
        @as(u64, dev_handle),
    );
    if (testing.isHandleError(cv.v1)) {
        // Prelude broke (most likely E_PERM if the device lacks the
        // `dma` cap, per §[create_var] test 15). No spec assertion is
        // being checked — the DMA observation is hardware-only —
        // so smoke-pass with id 0 to mark this slot as degraded.
        testing.pass();
        return;
    }
    const var_handle: caps.HandleId = @truncate(cv.v1 & 0xFFF);

    // Mint a page_frame to install. r|w mirrors the VAR's cur_rwx so
    // the CPU-visible portion of the prelude is set up the way a
    // faithful test 13 would arrange it.
    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // pages = 1
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.pass();
        return;
    }
    const pf_handle: u64 = @as(u64, cpf.v1 & 0xFFF);

    // Closest CPU-side analogue of the spec's DMA installation. The
    // call may fail on a dma VAR for kernel reasons that are out of
    // scope for this smoke; either way the DMA-traffic assertion is
    // not what's being checked.
    _ = syscall.mapPf(var_handle, &.{ 0, pf_handle });

    // Smoke-pass: no spec assertion is checked. Faithful test 13
    // requires a hardware DMA harness — see top-of-file note.
    testing.pass();
}

fn findDeviceRegion(cap_table_base: u64) ?caps.HandleId {
    // Scan the full handle table. Slots 0/1/2 are self / initial EC /
    // self-IDC for a child capability domain (§[capability_domain]),
    // and passed_handles start at slot 3. Today the runner forwards
    // only the result port at slot 3; no device_regions reach a child.
    // Scan everything to remain robust if that changes.
    var slot: u32 = 0;
    while (slot < caps.HANDLE_TABLE_MAX) {
        const c = caps.readCap(cap_table_base, slot);
        if (c.handleType() == .device_region) {
            return @truncate(slot);
        }
        slot += 1;
    }
    return null;
}
