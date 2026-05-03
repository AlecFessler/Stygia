// Spec §[acquire_vars] — test 02.
//
// "[test 02] returns E_PERM if [1] does not have the `aqvr` cap."
//
// Strategy
//   The child capability domain receives a self-IDC handle at
//   `SLOT_SELF_IDC` (slot 2) when the kernel constructs the new
//   domain via `create_capability_domain`. Its caps come from the
//   `cridc_ceiling` field that the parent (primary.zig) supplies in
//   `ceilings_inner`; the runner sets that ceiling to 0x3F, which
//   covers IDC bits 0-5 — including `aqvr` (bit 4).
//
//   We need an IDC handle that is otherwise valid but lacks `aqvr`,
//   so the only spec-mandated failure path on `acquire_vars` is the
//   E_PERM cap check (test 02). `restrict` is the canonical way to
//   strip a cap from an existing handle: it accepts any new caps
//   that are a strict subset of the current caps. Dropping the single
//   `aqvr` bit while leaving the rest untouched satisfies the
//   bitwise-subset rule and the IDC `restart_policy` numeric rule
//   (we don't change that field).
//
//   With the cap stripped, `acquire_vars(self_idc)` must report
//   E_PERM. The handle is still valid (no E_BADCAP, test 01); the
//   syscall word's reserved bits are clean (no E_INVAL, test 03);
//   and the caller's handle table has plenty of free slots even if
//   the domain happened to expose any VARs (no E_FULL, test 04).
//
// Action
//   1. restrict(SLOT_SELF_IDC, full_idc_caps & ~aqvr) — must succeed.
//   2. acquire_vars(SLOT_SELF_IDC)                    — must return E_PERM.
//
// Assertions
//   1: restrict returned a non-OK error word.
//   2: acquire_vars returned something other than E_PERM.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // The self-IDC at slot 2 was minted with caps drawn from the
    // parent's `cridc_ceiling = 0x3F`, i.e. IDC bits 0-5 all set:
    // {move, copy, crec, aqec, aqvr, restart_policy}. Drop aqvr
    // and keep the rest so the only check that can fire on
    // acquire_vars is the cap-presence one.
    const reduced = caps.IdcCap{
        .move = true,
        .copy = true,
        .crec = true,
        .aqec = true,
        .aqvr = false,
        .restart_policy = true,
    };
    const new_caps_word: u64 = @as(u64, reduced.toU16());
    const restrict_result = syscall.restrict(caps.SLOT_SELF_IDC, new_caps_word);
    if (restrict_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    const result = syscall.acquireVars(caps.SLOT_SELF_IDC);
    if (result.regs.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
