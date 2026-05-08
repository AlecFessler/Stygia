// Spec §[map_mmio] — test 06.
//
// "[test 06] on success, [1].field1 `map` becomes 2."
//
// Strategy
//   To exercise the success leg every earlier §[map_mmio] gate must
//   pass:
//     - test 01 (VMAR is invalid)         — a valid MMIO VMAR is minted
//                                           below.
//     - test 02 (device_region BADCAP)   — supply the runner-forwarded
//                                           bare fixture device_region
//                                           (caps={move,copy}, mmio,
//                                           phys_base=0xBABE_0000).
//     - test 03 (caps.mmio not set)      — caps.mmio = 1 here.
//     - test 04 (`map` already non-zero) — a freshly created MMIO
//                                           VMAR sits in `map = 0` per
//                                           §[var].
//     - test 05 (size mismatch with [2]) — the plain fixture is 4 KiB
//                                           and the VMAR is 4 KiB.
//
//   With the success leg taken, §[map_mmio] test 06 requires
//   `[1].field1.map == 2` — a subsequent cap-table refresh (any
//   handle-taking syscall, or an explicit `sync`) must surface the
//   updated `map` field.
//
//   §[var] field1 layout:
//     page_count[0..31] | sz[32..33] | cch[34..35] |
//     cur_rwx[36..38]   | map[39..40] | device[41..52]
//
// Action
//   1. Scan the cap_table for the plain mmio fixture device_region. If
//      absent (kernel built without -Dtests_fixture_devices) →
//      degraded smoke pass.
//   2. createVmar(caps={r,w,mmio}, props={cch=1 (uc), sz=0,
//                cur_rwx=0b011}, pages=1, preferred_base=0,
//                device_region=0).
//   3. mapMmio(mmio_var, plain_fixture). Must succeed.
//   4. sync(mmio_var) to force a fresh field1 snapshot.
//   5. readCap → field1; extract `map` and assert it equals 2.
//
// Assertions
//   1: field1.map was not 2 after a successful map_mmio — the spec
//      assertion under test (test 06).
//   2: a setup syscall returned an error (createVmar, map_mmio, or
//      sync) — precondition broken.

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

const MAP_SHIFT: u6 = 39;
const MAP_MASK: u64 = 0b11;

fn mapField(field1: u64) u64 {
    return (field1 >> MAP_SHIFT) & MAP_MASK;
}

pub fn main(cap_table_base: u64) void {
    const dev_handle = findFixtureMmio(cap_table_base, FIXTURE_PLAIN_PHYS_BASE) orelse {
        // Degraded smoke: no fixture device, the success leg is
        // unreachable. Pass with id 0 to mark this slot as smoke-only.
        testing.pass();
        return;
    };

    const mmio_caps = caps.VmarCap{ .r = true, .w = true, .mmio = true };
    const props: u64 = (1 << 5) | // cch = 1 (uc) — required for mmio
        (0 << 3) | // sz = 0 (4 KiB) — required when caps.mmio = 1
        0b011; // cur_rwx = r|w
    const cvar = syscall.createVmar(
        @as(u64, mmio_caps.toU16()),
        props,
        1, // pages = 1 (4 KiB) — matches fixture
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(2);
        return;
    }
    const vmar_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);

    const r_map = syscall.mapMmio(vmar_handle, dev_handle);
    if (errors.isError(r_map.v1)) {
        testing.fail(2);
        return;
    }

    const r_sync = syscall.sync(vmar_handle);
    if (errors.isError(r_sync.v1)) {
        testing.fail(2);
        return;
    }

    const cap_after = caps.readCap(cap_table_base, vmar_handle);
    if (mapField(cap_after.field1) != 2) {
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
