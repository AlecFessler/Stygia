// Spec §[unmap] — test 03.
//
// "[test 03] returns E_INVAL if [1].field1 `map` is 2 (mmio) and
//  N > 0."
//
// Strategy
//   To isolate the `map = 2 + N > 0` check every earlier §[unmap] gate
//   must be inert:
//     - test 01 (invalid VMAR)         — pass a freshly-minted MMIO VMAR.
//     - test 02 (`map` = 0)            — drive `map` to 2 via a
//                                         successful map_mmio call
//                                         before issuing unmap.
//
//   Reaching `map = 2` requires a successful map_mmio call (§[map_mmio]
//   test 06), which itself requires a *valid* device_region handle in
//   [2] (test 02) whose size matches the MMIO VMAR's size (test 05).
//   The runner forwards a boot-minted bare device_region (caps =
//   {move, copy}, dev_type = mmio, sentinel phys_base 0xBABE_0000) to
//   every test child via `passed_handles` (see runner/primary.zig).
//   The fixture region is 4 KiB (size_pages = 1 in field0), matching
//   a freshly-created MMIO VMAR with `pages = 1` and `sz = 0`. The
//   bare fixture has neither `dma` nor `irq` caps — neither is needed
//   for an mmio mapping, since map_mmio's success path consults only
//   the size match plus the valid-handle / type check.
//
//   With `map = 2` reached we issue `unmap(vmar, &.{ 0 })`. Selector
//   value 0 satisfies N > 0 (it's a single-element slice), so test 03
//   fires: the kernel must return E_INVAL because mmio unmap must be
//   atomic (N = 0). The selector contents are irrelevant — for
//   `map = 2` the spec requires N = 0, so any N > 0 trips test 03
//   regardless of what the selector encodes.
//
// Action
//   1. Scan cap_table for the plain fixture device_region (mmio,
//      phys_base = 0xBABE_0000). If absent (kernel built without
//      -Dtests_fixture_devices) → degraded smoke pass.
//   2. createVmar(caps={r, w, mmio}, props={cch=1, sz=0,
//                cur_rwx=0b011}, pages=1, preferred_base=0,
//                device_region=0). Required §[create_vmar] shape for
//                an MMIO VMAR (caps.mmio=1 → sz=0, caps.x=0,
//                caps.dma=0; cch=1 = uc).
//   3. mapMmio(mmio_var, plain_fixture). On success `map` becomes 2
//      per §[map_mmio] test 06.
//   4. unmap(mmio_var, &.{ 0 }). N = 1 with `map = 2` — kernel must
//      return E_INVAL via test 03.
//
// Assertions
//   1: vreg 1 was not E_INVAL after unmap on a `map = 2` VMAR with
//      N > 0 — the spec assertion under test.
//   2: a setup syscall returned an error code (createVmar or
//      map_mmio), breaking the success-path precondition.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Sentinel phys_base of the bare (caps={move,copy}) test-fixture mmio
// device_region minted by the kernel at boot under
// -Dtests_fixture_devices and forwarded to every test child by the
// runner. Must match runner/primary.zig:FIXTURE_PLAIN_PHYS_BASE and
// kernel/boot/userspace_init.zig:grantTestFixtureDevices.
const FIXTURE_PLAIN_PHYS_BASE: u64 = 0xBABE_0000;

pub fn main(cap_table_base: u64) void {
    const dev_handle = findFixtureMmio(cap_table_base, FIXTURE_PLAIN_PHYS_BASE) orelse {
        // Degraded smoke: fixture devices absent (kernel built without
        // -Dtests_fixture_devices). The test 03 path requires a real
        // device_region to drive `map` to 2; pass with assertion id 0
        // so the slot validates link/load/scan plumbing without forcing
        // a false expectation in this configuration.
        testing.pass();
        return;
    };

    // Build an MMIO VMAR matching the fixture device's 4 KiB size.
    // §[create_vmar] for caps.mmio=1: props.sz=0, caps.x=0,
    // caps.dma=0, cch=1 (uc). The runner's vmar_inner_ceiling
    // (0x01FF) permits {r, w, mmio}.
    const mmio_caps = caps.VmarCap{ .r = true, .w = true, .mmio = true };
    const props: u64 = (1 << 5) | // cch = 1 (uc) — required for mmio
        (0 << 3) | // sz = 0 (4 KiB) — required when caps.mmio = 1
        0b011; // cur_rwx = r|w
    const cvar = syscall.createVmar(
        @as(u64, mmio_caps.toU16()),
        props,
        1, // pages = 1 (4 KiB) — matches fixture size_pages = 1
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(2);
        return;
    }
    const vmar_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);

    // Drive `map` 0 -> 2 via a successful map_mmio. Per §[map_mmio]
    // test 02 [2] must be a valid device_region handle; per test 05
    // [2]'s size must equal [1]'s size — the fixture's 4 KiB and the
    // VMAR's 4 KiB match. Per test 06 `map` becomes 2 on success.
    const r_map = syscall.mapMmio(vmar_handle, dev_handle);
    if (errors.isError(r_map.v1)) {
        testing.fail(2);
        return;
    }

    // unmap with N = 1 against a `map = 2` VMAR. Selector value 0 is
    // arbitrary — for `map = 2` the spec requires N = 0, so any
    // N > 0 trips test 03 regardless of selector contents. The kernel
    // must return E_INVAL.
    const result = syscall.unmap(vmar_handle, &.{0});

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}

// Scan the caller's cap_table for an mmio device_region whose
// `phys_base` matches `target_phys_base`. Returns the slot id or null
// if no matching handle is present. §[device_region] field0 layout
// (mmio): bits 4-51 carry paddr>>12.
fn findFixtureMmio(cap_table_base: u64, target_phys_base: u64) ?caps.HandleId {
    var slot: u32 = 0;
    while (slot < caps.HANDLE_TABLE_MAX) {
        const c = caps.readCap(cap_table_base, slot);
        if (c.handleType() == .device_region) {
            const dev_type: u4 = @truncate(c.field0 & 0xF);
            // mmio = 0
            if (dev_type == 0) {
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
