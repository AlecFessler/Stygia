// Spec §[unmap] — test 09.
//
// "[test 09] on success, when N is 0 and `map` was 2, the
//  device_region installation is removed and `device` is cleared
//  to 0."
//
// Strategy
//   To exercise the test 09 success leg every earlier §[unmap] gate
//   must be inert and `map` must already be 2:
//     - test 01 (invalid VMAR)         — pass a freshly-minted MMIO
//                                        VMAR.
//     - test 02 (`map` = 0)            — drive `map` to 2 via a
//                                        successful map_mmio call
//                                        before unmap.
//     - test 03 (`map` = 2 + N > 0)    — call unmap with N = 0, the
//                                        only N value the spec admits
//                                        for `map = 2`.
//
//   Reaching `map = 2` requires a successful map_mmio call (§[map_mmio]
//   test 06), which itself requires a *valid* device_region handle in
//   [2] (test 02) whose size matches the MMIO VMAR's size (test 05).
//   The runner forwards a boot-minted bare device_region (caps =
//   {move, copy}, dev_type = mmio, sentinel phys_base 0xBABE_0000) to
//   every test child via `passed_handles` (see runner/primary.zig).
//   The fixture region is 4 KiB (size_pages = 1), matching a
//   freshly-created MMIO VMAR with `pages = 1` and `sz = 0`. The bare
//   fixture has neither `dma` nor `irq` caps — neither is needed for
//   an mmio mapping.
//
//   Per §[map_mmio] test 07, on success `field1.device` is set to
//   [2]'s handle id. After the unmap call (with N = 0 on a
//   `map = 2` VMAR), §[unmap] test 09 requires `device` to be
//   cleared to 0. Per §[capabilities], any syscall taking a handle
//   refreshes that handle's snapshot from authoritative state — a
//   subsequent `sync` against the VMAR forces a fresh field1 read.
//
//   §[var] field1 layout:
//     page_count[0..31] | sz[32..33] | cch[34..35] |
//     cur_rwx[36..38]   | map[39..40] | device[41..52]
//   `device` is a 12-bit field at bits 41-52; mask via
//     (field1 >> 41) & 0xFFF.
//
// Action
//   1. Scan cap_table for the plain fixture device_region (mmio,
//      phys_base = 0xBABE_0000). If absent (kernel built without
//      -Dtests_fixture_devices) → degraded smoke pass.
//   2. createVmar(caps={r, w, mmio}, props={cch=1, sz=0,
//                cur_rwx=0b011}, pages=1, preferred_base=0,
//                device_region=0).
//   3. mapMmio(mmio_var, plain_fixture). On success `map` = 2 and
//      `device` = plain_fixture's id (§[map_mmio] tests 06/07).
//   4. unmap(mmio_var, &.{}). N = 0; per §[unmap] test 08 the mmio
//      installation is removed and `map` becomes 0; per test 09
//      `device` is cleared to 0.
//   5. sync(vmar_handle). Forces a fresh field1 snapshot per
//      §[sync] test 03.
//   6. readCap(cap_table_base, vmar_handle) → field1.device.
//
// Assertions
//   1: field1.device was non-zero after a successful N=0 unmap on a
//      VMAR that had been in `map = 2` — the spec assertion under
//      test (test 09).
//   2: a setup syscall returned an error code (createVmar, map_mmio,
//      unmap, or sync), breaking the success-path precondition.

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

const DEVICE_SHIFT: u6 = 41;
const DEVICE_MASK: u64 = 0xFFF;

fn deviceField(field1: u64) u64 {
    return (field1 >> DEVICE_SHIFT) & DEVICE_MASK;
}

pub fn main(cap_table_base: u64) void {
    const dev_handle = findFixtureMmio(cap_table_base, FIXTURE_PLAIN_PHYS_BASE) orelse {
        // Degraded smoke: fixture devices absent (kernel built without
        // -Dtests_fixture_devices). The test 09 success leg requires a
        // real device_region to drive `map` to 2; pass with assertion
        // id 0 so the slot validates link/load/scan plumbing without
        // forcing a false expectation in this configuration.
        testing.pass();
        return;
    };

    // Build an MMIO VMAR matching the fixture device's 4 KiB size.
    // §[create_vmar] for caps.mmio=1: props.sz=0, caps.x=0,
    // caps.dma=0, cch=1 (uc).
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

    // Drive `map` 0 -> 2 via a successful map_mmio. After this:
    //   field1.map    = 2 (§[map_mmio] test 06)
    //   field1.device = dev_handle (§[map_mmio] test 07)
    const r_map = syscall.mapMmio(vmar_handle, dev_handle);
    if (errors.isError(r_map.v1)) {
        testing.fail(2);
        return;
    }

    // unmap with N = 0 against a `map = 2` VMAR. Per §[unmap] test 08
    // the mmio installation is removed and `map` becomes 0; per test 09
    // `device` is cleared to 0. The call must succeed.
    const r_unmap = syscall.unmap(vmar_handle, &.{});
    if (errors.isError(r_unmap.v1)) {
        testing.fail(2);
        return;
    }

    // §[sync] test 03: field0/field1 reflect the authoritative kernel
    // state at the moment of the call. Forces a fresh snapshot before
    // the readCap below observes field1.device.
    const r_sync = syscall.sync(vmar_handle);
    if (errors.isError(r_sync.v1)) {
        testing.fail(2);
        return;
    }

    const cap_after = caps.readCap(cap_table_base, vmar_handle);
    if (deviceField(cap_after.field1) != 0) {
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
