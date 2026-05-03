// Spec §[capability_domain] acquire_vmars — test 07.
//
// "[test 07] MMIO and DMA VARs in the target domain are not included
//  in the returned handles."
//
// Variant chosen: regular-VMAR-only smoke (no MMIO/DMA exclusion proof).
//
//   The full positive variant requires the target domain to hold at
//   least one MMIO and at least one DMA VMAR alongside one or more
//   regular (map=0/3) VARs, then asserts that `acquire_vmars` returns
//   only handles to the regular ones. Both MMIO and DMA VMAR creation
//   need a valid device_region handle (`create_vmar` tests 14 and the
//   surrounding caps.mmio/caps.dma rules), but the runner does not
//   pass any device_region handles to test capability domains — the
//   primary spawns each child with `passed_handles = [result_port]`
//   (see `tests/suite/runner/primary.zig`). Without a device_region,
//   `create_vmar` with caps.mmio = 1 or caps.dma = 1 is rejected
//   before a VMAR is minted, so the negative side of the partition
//   ("MMIO and DMA VARs ... are not included") cannot be populated
//   from inside a single test ELF.
//
//   This test exercises the success-path shape of `acquire_vmars` and
//   the structural contract that any handle it does return must not
//   carry caps.mmio or caps.dma. Concretely: the test domain creates
//   one regular VMAR (caps={r, w}, no mmio, no dma), calls
//   `acquire_vmars` on its own self-IDC at SLOT_SELF_IDC, and walks
//   each returned handle's caps field through the read-only-mapped
//   cap table to confirm caps.mmio = 0 and caps.dma = 0 on every
//   entry. A handle with either bit set would directly contradict
//   test 07's invariant. The full partition (proving MMIO/DMA VARs
//   were filtered *out*) needs a device_region passed in by the
//   runner — a follow-up once the runner gains a synthetic
//   device_region for VMAR exercise tests.
//
// Strategy
//   1. The child's self-IDC at SLOT_SELF_IDC is minted by the kernel
//      with caps = passed cridc_ceiling. The runner sets
//      cridc_ceiling = 0x3F (move|copy|crec|aqec|aqvr|restart_policy),
//      so this handle has the `aqvr` cap required by test 02.
//   2. Create one regular VMAR with caps={r, w} and props
//      cur_rwx=r|w, sz=0 (4 KiB). caps.mmio=0 and caps.dma=0 by
//      construction, satisfying create_vmar tests 11/12/13. props.sz
//      defaults to 0 so the device_region argument is ignored.
//   3. Call `acquire_vmars(SLOT_SELF_IDC)`. The kernel writes the
//      handle count into the returned syscall word's bits 12-19 and
//      writes handles into vregs [1..count].
//   4. For each returned handle id, read its cap from the cap table
//      and assert caps.mmio=0 and caps.dma=0. The libz `caps.VmarCap`
//      packed struct lays out mmio at bit 5 and dma at bit 8 per
//      §[var] handle ABI.
//
//   The Regs result struct only exposes vregs 1..13, so the walk is
//   capped at 13 returned handles. A real domain inventory could
//   exceed 13; the walk skips slots beyond what the register-only
//   ABI surfaces. With a single regular VMAR in scope the actual
//   count is 1 in normal kernel operation, well within the bound.
//
// Action
//   1. create_vmar(caps={r,w}, props=cur_rwx=r|w, pages=1)  — must succeed
//   2. acquire_vmars(SLOT_SELF_IDC)                          — must succeed
//   3. for h in handles[1..min(count, 13)]: read cap, assert
//      caps.mmio = 0 and caps.dma = 0
//
// Assertions
//   1: setup syscall failed (create_vmar returned an error word in vreg 1)
//   2: acquire_vmars returned an error code in vreg 1 with count = 0
//   3: a returned handle's cap had caps.mmio = 1 (forbidden by test 07)
//   4: a returned handle's cap had caps.dma  = 1 (forbidden by test 07)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    // §[create_vmar]: caps in bits 0-15 of [1]; reserved upper bits zero.
    const vmar_caps = caps.VmarCap{ .r = true, .w = true };
    const caps_word: u64 = @as(u64, vmar_caps.toU16());

    // §[create_vmar] [2] props: cur_rwx in bits 0-2, sz in bits 3-4,
    // cch in bits 5-6. cur_rwx = r|w = 0b011, sz = 0 (4 KiB), cch = 0 (wb).
    const props_word: u64 = 0b011;

    const cv = syscall.createVmar(caps_word, props_word, 1, 0, 0);
    if (testing.isHandleError(cv.v1)) {
        testing.fail(1);
        return;
    }

    // SLOT_SELF_IDC carries `aqvr` (set in cridc_ceiling by the runner).
    const av = syscall.acquireVmars(caps.SLOT_SELF_IDC);

    // Decode count from the returned syscall word's bits 12-19.
    const count: u8 = @truncate((av.word >> 12) & 0xFF);
    if (count == 0 and testing.isHandleError(av.regs.v1)) {
        testing.fail(2);
        return;
    }

    // Walk register-backed returned handles. Handle slots arrive in
    // vregs [1..count]; bounded at 13 by the register-only ABI.
    const slots = [_]u64{
        av.regs.v1, av.regs.v2, av.regs.v3,  av.regs.v4,
        av.regs.v5, av.regs.v6, av.regs.v7,  av.regs.v8,
        av.regs.v9, av.regs.v10, av.regs.v11, av.regs.v12,
        av.regs.v13,
    };

    const walk: usize = if (count > slots.len) slots.len else count;
    var i: usize = 0;
    while (i < walk) {
        const handle_id: u12 = @truncate(slots[i] & 0xFFF);
        const cap = caps.readCap(cap_table_base, handle_id);
        const var_cap: caps.VmarCap = @bitCast(cap.caps());
        if (var_cap.mmio) {
            testing.fail(3);
            return;
        }
        if (var_cap.dma) {
            testing.fail(4);
            return;
        }
        i += 1;
    }

    testing.pass();
}
