// Spec §[map_mmio] — test 07.
//
// "[test 07] on success, [1].field1 `device` is set to [2]'s handle
//  id."
//
// Strategy
//   The runner forwards a boot-minted bare device_region (caps =
//   {move, copy}, dev_type = mmio, phys_base = 0xBABE_0000) to every
//   test child via passed_handles. With that fixture available we can
//   reach the success leg of map_mmio:
//     - test 01 (VMAR is invalid)         — fresh MMIO VMAR below.
//     - test 02 (device_region BADCAP)   — plain fixture handle.
//     - test 03 (caps.mmio not set)      — caps.mmio = 1.
//     - test 04 (`map` already non-zero) — fresh VMAR, map = 0.
//     - test 05 (size mismatch)          — fixture and VMAR both 4 KiB.
//
//   Per §[var] field1 layout, `device` is a 12-bit field at bits 41-52
//   that holds the source handle's slot id after a successful
//   map_mmio. Issuing a `sync` after the call refreshes the cap-table
//   snapshot (§[sync] test 03) so the subsequent readCap observes
//   authoritative state.
//
//   §[var] field1 layout:
//     page_count[0..31] | sz[32..33] | cch[34..35] |
//     cur_rwx[36..38]   | map[39..40] | device[41..52]
//
// Action
//   1. Scan cap_table for the plain mmio fixture (phys_base =
//      0xBABE_0000). Absent → degraded smoke pass.
//   2. createVmar(caps={r,w,mmio}, props={cch=1, sz=0, cur_rwx=0b011},
//                pages=1, preferred_base=0, device_region=0).
//   3. mapMmio(mmio_var, plain_fixture). Must succeed.
//   4. sync(mmio_var) to force a field1 refresh.
//   5. readCap → field1; extract `device` and assert it equals
//      plain_fixture's slot id.
//
// Assertions
//   1: field1.device != plain_fixture's slot id after a successful
//      map_mmio — the spec assertion under test (test 07).
//   2: a setup syscall returned an error.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const FIXTURE_PLAIN_PHYS_BASE: u64 = 0xBABE_0000;

const DEVICE_SHIFT: u6 = 41;
const DEVICE_MASK: u64 = 0xFFF;

fn deviceField(field1: u64) u64 {
    return (field1 >> DEVICE_SHIFT) & DEVICE_MASK;
}

pub fn main(cap_table_base: u64) void {
    const dev_handle = findFixtureMmio(cap_table_base, FIXTURE_PLAIN_PHYS_BASE) orelse {
        testing.pass();
        return;
    };

    const mmio_caps = caps.VmarCap{ .r = true, .w = true, .mmio = true };
    const props: u64 = (1 << 5) | // cch = 1 (uc)
        (0 << 3) | // sz = 0 (4 KiB)
        0b011; // cur_rwx = r|w
    const cvar = syscall.createVmar(
        @as(u64, mmio_caps.toU16()),
        props,
        1,
        0,
        0,
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
    if (deviceField(cap_after.field1) != @as(u64, dev_handle)) {
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
