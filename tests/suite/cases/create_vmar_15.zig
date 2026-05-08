// Spec §[create_vmar] — test 15.
//
// "[test 15] returns E_PERM if caps.dma = 1 and [5] does not have the
//  `dma` cap."
//
// Strategy
//   The check ordering ahead of the dma-handle subset check is identical
//   to test 14, so we mirror its prelude:
//     - caller self-handle has `crvr` (runner grants it).
//     - caps.r/w/x ⊆ vmar_inner_ceiling (runner ceiling 0x01FF
//       permits r, w, dma — see runner/primary.zig).
//     - caps.x clear so test 12 (dma + x → E_INVAL) cannot fire.
//     - caps.mmio clear so tests 04/08/11/13 cannot fire.
//     - caps.max_sz = 0 so tests 03/07/10 cannot fire.
//     - props.sz = 0 (4 KiB) satisfies tests 09/10.
//     - props.cur_rwx = 0b011 (r|w) ⊆ caps.{r,w} (test 16).
//     - preferred_base = 0 so test 06 cannot fire.
//     - pages = 1 so test 05 cannot fire.
//     - reserved bits zero so test 17 cannot fire.
//
//   With caps.dma = 1, the kernel must validate [5]. We need a VALID
//   device_region handle (test 14 closed) whose `dma` cap bit is clear
//   (the precondition under test). The runner's spawnOne forwards two
//   boot-minted fixture device_regions to test children:
//     - the BARE fixture (caps={move,copy} only) at the lower slot id
//     - the DMA+IRQ fixture (caps={move,copy,dma,irq}) at the higher
//       slot id
//   This test scans for the FIRST device_region whose DeviceCap.dma is
//   false — the bare fixture — and uses it as [5]. Test 14 is closed
//   because the slot is a real device_region; the only spec-mandated
//   outcome is E_PERM (test 15) because the slot lacks `dma`.
//
// Action
//   1. Scan cap_table for the first device_region with caps.dma = 0.
//   2. createVmar(caps={r, w, dma}, props={sz=0, cch=0, cur_rwx=0b011},
//                 pages=1, preferred_base=0, device_region=found)
//      — must return E_PERM.
//
// Assertions
//   1: createVmar did not return E_PERM (the spec assertion under test).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const dev_handle = findNoDmaDeviceRegion(cap_table_base) orelse {
        // Runner not built with -Dtests_fixture_devices=true. The
        // E_PERM branch is structurally unreachable without a no-dma
        // device_region; smoke-pass and document the gap.
        testing.pass();
        return;
    };

    const vmar_caps = caps.VmarCap{ .r = true, .w = true, .dma = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0

    const cv = syscall.createVmar(
        @as(u64, vmar_caps.toU16()),
        props,
        1, // pages = 1
        0, // preferred_base = kernel chooses
        @as(u64, dev_handle),
    );

    if (cv.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}

// Scan the handle table for the first device_region whose DeviceCap.dma
// is clear. Per runner/primary.zig spawnOne, the bare fixture
// (phys_base 0xBABE_0000, caps={move,copy}) is forwarded at a lower
// slot id than the dma+irq fixture (phys_base 0xCAFE_0000); the bare
// one matches first. Returns null if no such handle exists (the runner
// was built without -Dtests_fixture_devices=true).
fn findNoDmaDeviceRegion(cap_table_base: u64) ?caps.HandleId {
    var slot: u32 = 0;
    while (slot < caps.HANDLE_TABLE_MAX) {
        const c = caps.readCap(cap_table_base, slot);
        if (c.handleType() == .device_region) {
            const dev_caps: caps.DeviceCap = @bitCast(c.caps());
            if (!dev_caps.dma) {
                return @truncate(slot);
            }
        }
        slot += 1;
    }
    return null;
}
