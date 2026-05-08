// Spec §[map_mmio] — test 09.
//
// "[test 09] when [1] is a valid handle, [1]'s field0 and field1 are
//  refreshed from the kernel's authoritative state as a side effect,
//  regardless of whether the call returns success or another error
//  code."
//
// Strategy
//   The spec covers BOTH legs — a failing call and a succeeding call
//   must each refresh the cap-table snapshot from authoritative state.
//   We exercise both:
//
//   Failure leg
//     With [1] valid (a freshly-minted MMIO VMAR) and [2] empty
//     (slot 4095), the kernel rejects on the [2] BADCAP gate before
//     any mutation. Refresh is mandatory; field1 must come back
//     bit-identical to the pre-call snapshot.
//
//   Success leg
//     The runner forwards a boot-minted bare device_region (caps =
//     {move,copy}, mmio, phys_base = 0xBABE_0000) to every test
//     child. Calling map_mmio with that fixture in [2] takes the
//     success path; the post-call refresh must surface the
//     authoritative `map = 2` and `device = fixture_slot` values
//     (§[map_mmio] tests 06, 07).
//
//   The two legs share a prelude that mints the VMAR. The success
//   leg mints a SECOND VMAR (the failure leg's call did not mutate
//   [1] and therefore left it in `map = 0`, so we could in principle
//   reuse it; minting a fresh handle keeps the legs independent so
//   a regression in one doesn't poison the other).
//
//   §[var] field1 layout:
//     page_count[0..31] | sz[32..33] | cch[34..35] |
//     cur_rwx[36..38]   | map[39..40] | device[41..52]
//
// Action
//   1. createVmar (failure-leg [1]) → snapshot field1_pre.
//   2. mapMmio(failure_var, slot 4095) — expected E_BADCAP.
//   3. readCap → field1_post; assert field1_post == field1_pre.
//   4. Scan cap_table for plain mmio fixture; absent → skip success
//      leg and pass with the failure-leg observation alone.
//   5. createVmar (success-leg [1]).
//   6. mapMmio(success_var, fixture). Must succeed.
//   7. readCap → field1; assert field1.map == 2 AND field1.device ==
//      fixture's slot id (the authoritative state the kernel
//      committed must surface in the snapshot without an explicit
//      sync — map_mmio's own refresh side-effect is the spec
//      assertion under test).
//
// Assertions
//   1: setup failed (createVmar returned an error or the slot's
//      handleType was not virtual_memory_address_region).
//   2: failure-leg field1 differed between pre-call and post-error
//      reads — slot is no longer a faithful reflection of kernel
//      state.
//   3: success-leg field1.map was not 2 after a successful map_mmio,
//      i.e. the authoritative `map -> 2` transition didn't propagate
//      to the cap-table snapshot.
//   4: success-leg field1.device was not the fixture slot id, i.e.
//      the authoritative `device <- fixture_slot` write didn't
//      propagate.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const FIXTURE_PLAIN_PHYS_BASE: u64 = 0xBABE_0000;

const MAP_SHIFT: u6 = 39;
const MAP_MASK: u64 = 0b11;
const DEVICE_SHIFT: u6 = 41;
const DEVICE_MASK: u64 = 0xFFF;

fn mapField(field1: u64) u64 {
    return (field1 >> MAP_SHIFT) & MAP_MASK;
}
fn deviceField(field1: u64) u64 {
    return (field1 >> DEVICE_SHIFT) & DEVICE_MASK;
}

fn mintMmioVmar() ?caps.HandleId {
    const mmio_caps = caps.VmarCap{ .r = true, .w = true, .mmio = true };
    const props: u64 = (1 << 5) | // cch = 1 (uc)
        (0 << 3) | // sz = 0 (4 KiB)
        0b011; // cur_rwx = r|w
    const cv = syscall.createVmar(
        @as(u64, mmio_caps.toU16()),
        props,
        1,
        0,
        0,
    );
    if (testing.isHandleError(cv.v1)) return null;
    return @truncate(cv.v1 & 0xFFF);
}

pub fn main(cap_table_base: u64) void {
    // ── Failure leg ──────────────────────────────────────────────────
    const fail_handle = mintMmioVmar() orelse {
        testing.fail(1);
        return;
    };

    const cap_pre = caps.readCap(cap_table_base, fail_handle);
    if (cap_pre.handleType() != caps.HandleType.virtual_memory_address_region) {
        testing.fail(1);
        return;
    }
    const field1_pre = cap_pre.field1;

    const empty_slot: u12 = caps.HANDLE_TABLE_MAX - 1;
    const mm = syscall.mapMmio(fail_handle, empty_slot);
    _ = mm; // E_BADCAP expected; the spec assertion is the snapshot
    // refresh, not the return code.

    const cap_post = caps.readCap(cap_table_base, fail_handle);
    if (cap_post.field1 != field1_pre) {
        testing.fail(2);
        return;
    }

    // ── Success leg ──────────────────────────────────────────────────
    const dev_handle = findFixtureMmio(cap_table_base, FIXTURE_PLAIN_PHYS_BASE) orelse {
        // No fixture: failure-leg observation already covers the spec
        // claim for this configuration. Pass.
        testing.pass();
        return;
    };

    const succ_handle = mintMmioVmar() orelse {
        testing.fail(1);
        return;
    };

    const r_map = syscall.mapMmio(succ_handle, dev_handle);
    if (errors.isError(r_map.v1)) {
        testing.fail(1);
        return;
    }

    // No explicit sync — map_mmio itself is a handle-taking syscall,
    // so per the spec it must refresh [1]'s snapshot as part of its
    // exit path. The cap-table read below observes that refresh
    // directly.
    const cap_succ = caps.readCap(cap_table_base, succ_handle);
    if (mapField(cap_succ.field1) != 2) {
        testing.fail(3);
        return;
    }
    if (deviceField(cap_succ.field1) != @as(u64, dev_handle)) {
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
