// Spec §[snapshot] — test 05.
//
// "[test 05] returns E_INVAL if [1] and [2] have different sizes
// (`page_count` × `sz`)."
//
// Strategy
//   The size-mismatch gate compares the byte size of the two VARs
//   (`page_count` × `sz`). To isolate that gate we must let every
//   prior §[snapshot] check pass:
//     - test 01 / 02 (E_BADCAP): both args are valid VAR handles minted
//       by `create_var`.
//     - test 03 (E_INVAL): [1].caps.restart_policy must be 3 (snapshot).
//     - test 04 (E_INVAL): [2].caps.restart_policy must be 2 (preserve).
//     - test 06 (E_INVAL): no reserved bits set in [1] or [2] — handles
//       carry only the requested cap bits.
//   With those satisfied, the only remaining spec-mandated failure path
//   is the size mismatch. VAR #1 reserves 1 × 4 KiB page; VAR #2
//   reserves 2 × 4 KiB pages. Same page size, different page_count =
//   different byte size → E_INVAL.
//
//   The root domain's `var_inner_ceiling` permits {r, w, max_sz=0} and
//   its `restart_policy_ceiling.var_restart_max` is 3 (see
//   runner/primary.zig: ceilings_outer = 0x...03FE...), so both
//   restart_policy values requested here are within bounds. mmio = 0
//   and dma = 0 close off device-binding paths; preferred_base = 0 lets
//   the kernel choose; cur_rwx = 0b011 matches caps.{r,w}; reserved
//   bits stay clean (this also satisfies create_var test 17).
//
// Action
//   1. createVar(caps={r,w,restart_policy=3}, props={cur_rwx=0b011,
//                sz=0, cch=0}, pages=1, preferred_base=0,
//                device_region=0) — must succeed (target VAR, 4 KiB).
//   2. createVar(caps={r,w,restart_policy=2}, props={cur_rwx=0b011,
//                sz=0, cch=0}, pages=2, preferred_base=0,
//                device_region=0) — must succeed (source VAR, 8 KiB).
//   3. snapshot(target_var, source_var) — must return E_INVAL because
//      the two VARs have different byte sizes.
//
// Assertion
//   1: snapshot did not return E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Target VAR: restart_policy = 3 (snapshot), 1 × 4 KiB = 4 KiB.
    const target_caps = caps.VarCap{ .r = true, .w = true, .restart_policy = 3 };
    const props_4k: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0

    const cv_target = syscall.createVar(
        @as(u64, target_caps.toU16()),
        props_4k,
        1, // pages = 1 → 4 KiB
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cv_target.v1)) {
        testing.fail(1);
        return;
    }
    const target_handle: u12 = @truncate(cv_target.v1 & 0xFFF);

    // Source VAR: restart_policy = 2 (preserve), 2 × 4 KiB = 8 KiB.
    const source_caps = caps.VarCap{ .r = true, .w = true, .restart_policy = 2 };

    const cv_source = syscall.createVar(
        @as(u64, source_caps.toU16()),
        props_4k,
        2, // pages = 2 → 8 KiB (different size from target)
        0,
        0,
    );
    if (testing.isHandleError(cv_source.v1)) {
        testing.fail(1);
        return;
    }
    const source_handle: u12 = @truncate(cv_source.v1 & 0xFFF);

    const result = syscall.snapshot(target_handle, source_handle);
    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
