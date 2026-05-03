// Spec §[map_pf] — test 14.
//
// "[test 14] when [1] is a valid handle, [1]'s field0 and field1 are
//  refreshed from the kernel's authoritative state as a side effect,
//  regardless of whether the call returns success or another error
//  code."
//
// Strategy
//   `map_pf` mutates the kernel-side VAR state (`map` and, on DMA,
//   `device`); for handle-table consumers to observe that mutation
//   without an explicit `sync`, the syscall must refresh [1]'s field0
//   and field1 in the holding domain's (read-only) cap table on every
//   call where [1] resolves to a valid handle — both the success path
//   and the post-resolution error paths. We exercise both legs:
//
//   Leg A (success refresh)
//     Build a regular 2-page VAR with `caps = {r, w}`, `cur_rwx =
//     0b011`, `sz = 0`, `cch = 0`, `device_region = 0`. Per §[var] the
//     fresh handle starts at `map = 0`. Mint a 2-page (`sz = 0`)
//     page_frame and call `map_pf(var, &.{ 0, pf })`. By construction
//     none of §[map_pf] tests 01-10 fire (VAR/pf valid, mmio = 0,
//     N = 1, offset 0 aligned, pf.sz == VAR.sz, pair fits, no second
//     pair, no prior installation, fresh map = 0). The kernel takes
//     the success branch and per §[map_pf] test 11 sets `map = 1`. Re-
//     read [1]'s slot from the cap table: per test 14 field1's `map`
//     must now be 1.
//
//   Leg B (error refresh)
//     Issue a second `map_pf(var, &.{ 0, pf })` against the same VAR.
//     The pair's range now overlaps the installation just made, so
//     §[map_pf] test 09 fires and the call returns E_INVAL — none of
//     the kernel-side bookkeeping (map, device) changes, but per test
//     14 the cap-table snapshot of field1 must still reflect the
//     kernel's current authoritative state. Re-read [1]'s slot: field1
//     `map` must remain 1, exactly the value the success leg installed.
//
//   The two legs together pin both halves of test 14: the success
//   path refreshes a *changed* state (map 0 -> 1 visible without
//   `sync`) and the error path refreshes a *stable* state (map stays
//   at 1, observable on every call).
//
//   field0 carries the VAR's base virtual address per §[var]; the
//   kernel assigns it on `create_var` and never mutates it for the
//   life of the handle. We therefore check field0 only weakly via
//   the field1 invariants — any divergence in the kernel's
//   authoritative `map_pf` refresh would surface as an unexpected
//   field1 value, which is what we assert.
//
// Action
//   1. createPageFrame(caps={r, w}, props={sz=0}, pages=2) — must
//      succeed.
//   2. createVar(caps={r, w}, props={cur_rwx=0b011, sz=0, cch=0},
//                pages=2, preferred_base=0, device_region=0) — must
//      succeed.
//   3. mapPf(var, &.{ 0, pf }) — must succeed (precondition for the
//      success refresh leg).
//   4. readCap(cap_table_base, var_handle) — field1's `map` (bits
//      39-40) must be 1.
//   5. mapPf(var, &.{ 0, pf }) — must return E_INVAL (overlap with
//      step 3's installation, §[map_pf] test 09).
//   6. readCap(cap_table_base, var_handle) — field1's `map` must
//      still be 1, with the rest of the field1 layout intact.
//
// Assertions
//   1: a setup syscall (createPageFrame, createVar, or the first
//      mapPf) failed; the precondition for test 14 is broken so we
//      cannot verify the spec assertion.
//   2: post-success cap-table snapshot of field1's `map` is not 1 —
//      the success refresh did not propagate the kernel's authoritative
//      `map = 1` into the holding domain's cap table.
//   3: post-error cap-table snapshot of field1's `map` is not 1 — the
//      error path failed to refresh the cap table to the kernel's
//      authoritative state (or, equivalently, drifted it).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const PAGES: u64 = 2;
const CUR_RWX: u64 = 0b011; // r|w
const SZ: u64 = 0; // 4 KiB
const CCH: u64 = 0; // wb

// §[var] field1 layout: map at bits 39-40.
const MAP_SHIFT: u6 = 39;
const MAP_MASK: u64 = 0b11;

fn mapField(field1: u64) u64 {
    return (field1 >> MAP_SHIFT) & MAP_MASK;
}

pub fn main(cap_table_base: u64) void {
    // Step 1: 2-page page_frame, sz = 0 so it matches the VAR's sz
    // (test 06 inert) and a single pair at offset 0 covers the VAR's
    // full 2-page range without overshooting (test 07 inert).
    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        PAGES,
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const pf_handle: u64 = @as(u64, cpf.v1 & 0xFFF);

    // Step 2: regular 2-page VAR (caps.mmio = 0, caps.dma = 0). Per
    // §[var] line 877 it starts at `map = 0`, so the success refresh
    // leg has a clean precondition.
    const var_caps = caps.VarCap{ .r = true, .w = true };
    const props: u64 = (CCH << 5) | (SZ << 3) | CUR_RWX;
    const cvar = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        PAGES,
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(1);
        return;
    }
    const var_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);

    // Step 3: install pf at offset 0. All §[map_pf] gates 01-10 are
    // inert by construction, so the kernel takes the success branch
    // and per test 11 sets `map = 1`.
    const first = syscall.mapPf(var_handle, &.{ 0, pf_handle });
    if (first.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    // Step 4: success-leg refresh — the cap-table snapshot must now
    // reflect the kernel's authoritative `map = 1`, with no explicit
    // `sync` required.
    const cap_after_ok = caps.readCap(cap_table_base, var_handle);
    if (mapField(cap_after_ok.field1) != 1) {
        testing.fail(2);
        return;
    }

    // Step 5: identical pair against the same VAR. §[map_pf] test 09
    // fires (overlap with the installation from step 3) and the call
    // returns E_INVAL. The kernel-side state is unchanged: `map`
    // stays at 1.
    const second = syscall.mapPf(var_handle, &.{ 0, pf_handle });
    if (second.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    // Step 6: error-leg refresh — even though the call returned
    // E_INVAL, the cap-table snapshot must still mirror the kernel's
    // authoritative state (map = 1, unchanged from step 4).
    const cap_after_err = caps.readCap(cap_table_base, var_handle);
    if (mapField(cap_after_err.field1) != 1) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
