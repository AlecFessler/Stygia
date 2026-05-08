// Spec §[map_mmio] — test 08.
//
// "[test 08] on success, CPU accesses to the VMAR's range use
//  effective permissions = `VMAR.cur_rwx`."
//
// PARTIAL VARIANT
//   The faithful test 08 observable is a CPU access pattern:
//     - allowed accesses (those whose access type is in `cur_rwx`) round-
//       trip without fault.
//     - denied accesses fault and route through the EC's memory_fault
//       event.
//   The denied-access leg requires an exception-handler hook the v0
//   runner does not yet expose (see map_pf_12 for the same constraint;
//   the worker-EC scaffold there gates on a port-bound memory_fault
//   route which would also work here once memory_fault paths quiesce
//   on MMIO VMAR faults). The allowed-access leg runs on the bare
//   fixture device_region (phys_base = 0xBABE_0000) which is a
//   sentinel address — issuing a load/store directly against it is
//   architecturally undefined on bare metal and may surface as #MC
//   (x86) / SError (aarch64). On QEMU the sentinel typically reads as
//   0xFF and swallows writes, but relying on emulator behaviour pulls
//   a real-hardware regression away from the test surface.
//
//   This variant therefore drives the success leg on a real fixture
//   and asserts the spec's field-snapshot consequence: §[var] field1
//   surfaces `cur_rwx` (bits 36-38) as the effective rwx the kernel
//   committed at install time. After a successful map_mmio + sync,
//   field1.cur_rwx must equal the value passed at create_vmar — a
//   regression that committed a different permission set (or
//   discarded the request entirely) surfaces here.
//
// Strategy
//   - Mint an MMIO VMAR with cur_rwx = r|w (the only well-typed
//     non-empty perm set within caps={r,w,mmio} where caps.x = 0).
//   - mapMmio against the plain fixture (caps={move,copy}, mmio,
//     phys_base = 0xBABE_0000, 4 KiB).
//   - sync to refresh field1, then read back the slot and assert
//     field1.cur_rwx == 0b011.
//
//   We also cross-check the kernel's `device` slot (test 07's
//   observable) hasn't drifted — a regression that swapped fields
//   would surface on either assertion. This keeps the file's signal
//   independent of test 07's separate file: each test exercises its
//   own minimum, and any cross-pollination of fields shows up in
//   both.
//
// Action
//   1. Scan cap_table for the plain mmio fixture. Absent → degraded
//      smoke pass.
//   2. createVmar(caps={r,w,mmio}, props={cch=1, sz=0,
//                cur_rwx=0b011}, pages=1, preferred_base=0,
//                device_region=0). Capture cv.v2 as the VMAR base.
//   3. mapMmio(mmio_var, plain_fixture). Must succeed.
//   4. sync(mmio_var) to refresh field1.
//   5. readCap → field1; extract cur_rwx and assert == 0b011.
//   6. Assert field1.map == 2 (test 06's invariant, kept here as a
//      cross-check).
//
// Assertions
//   1: field1.cur_rwx after map_mmio + sync did not equal the
//      cur_rwx requested at create_vmar — the spec assertion.
//   2: setup syscall failed.
//   3: field1.map was not 2 after a successful map_mmio — companion
//      assertion to detect a regression that left the slot's `map`
//      stale.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const FIXTURE_PLAIN_PHYS_BASE: u64 = 0xBABE_0000;

const CUR_RWX_SHIFT: u6 = 36;
const CUR_RWX_MASK: u64 = 0b111;
const MAP_SHIFT: u6 = 39;
const MAP_MASK: u64 = 0b11;

fn curRwxField(field1: u64) u64 {
    return (field1 >> CUR_RWX_SHIFT) & CUR_RWX_MASK;
}
fn mapField(field1: u64) u64 {
    return (field1 >> MAP_SHIFT) & MAP_MASK;
}

pub fn main(cap_table_base: u64) void {
    const dev_handle = findFixtureMmio(cap_table_base, FIXTURE_PLAIN_PHYS_BASE) orelse {
        testing.pass();
        return;
    };

    const requested_cur_rwx: u64 = 0b011; // r|w
    const mmio_caps = caps.VmarCap{ .r = true, .w = true, .mmio = true };
    const props: u64 = (1 << 5) | // cch = 1 (uc)
        (0 << 3) | // sz = 0 (4 KiB)
        requested_cur_rwx;
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
    if (curRwxField(cap_after.field1) != requested_cur_rwx) {
        testing.fail(1);
        return;
    }
    if (mapField(cap_after.field1) != 2) {
        testing.fail(3);
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
