// Spec §[idc_read] — test 08.
//
// "[test 08] when [1] is a valid handle, [1]'s field0 and field1 are
//  refreshed from the kernel's authoritative state as a side effect,
//  regardless of whether the call returns success or another error
//  code."
//
// Strategy
//   `idc_read` is a pure read of VAR contents — it never mutates the
//   VAR's `map`, `device`, `cur_rwx`, or any other field1 state. The
//   test 08 invariant therefore says: every call where [1] resolves
//   to a valid handle (success or post-resolution error) refreshes
//   the cap-table snapshot of [1] to mirror the kernel's authoritative
//   state. We exercise both legs:
//
//   Leg A (call against a fresh VAR — refresh of unchanged state)
//     Build a regular 1-page VAR with `caps = {r, w}`, `cur_rwx =
//     0b011`, `sz = 0`, `cch = 0`, `device_region = 0`. Per §[var] the
//     fresh handle starts at `map = 0`. Snapshot field1. Issue
//     `idc_read(var, 0, 1)` — count = 1 qword (8 bytes) at offset 0
//     fits within the VAR's 4 KiB size, offset is 8-byte aligned, the
//     handle has the `r` cap, count is in 1..125, no reserved bits
//     are set, and [1] is a valid VAR — so none of §[idc_read] tests
//     01-06 fire. The call may succeed (reading zero-initialized
//     demand-allocated memory) or, if the kernel rejects reads of an
//     unmapped (`map = 0`) range, return E_INVAL. Either way the
//     kernel-side VAR state is unchanged, so a refresh per test 08
//     leaves field1 bit-identical to the pre-call snapshot.
//
//   Leg B (call against a pf-mapped VAR — refresh of changed state)
//     Mint a 1-page (`sz = 0`) page_frame and call `map_pf(var, &.{
//     0, pf })`. Per §[map_pf] tests 11/14 the kernel sets `map = 1`
//     and refreshes [1]'s field1, so the cap table now mirrors the
//     kernel's authoritative `map = 1`. Issue `idc_read(var, 0, 1)`
//     against the same VAR — none of §[idc_read] tests 01-06 fire
//     (same arguments as leg A, but now there is a backing page so
//     the kernel takes the success branch per test 07). Re-read [1]:
//     per test 08 field1 must still reflect `map = 1`. If the
//     success-path refresh dropped or zeroed the slot, field1's
//     `map` would read back as 0 and we'd catch the bug.
//
//   The two legs together pin both halves of test 08: the leg-A path
//   refreshes a *stable* state (snapshot match across a call that may
//   have errored or succeeded with no kernel-side mutation) and the
//   leg-B path refreshes a *non-trivial* authoritative state (`map =
//   1`, set by an earlier `map_pf`, must remain visible after the
//   `idc_read` refresh).
//
//   field0 carries the VAR's base virtual address per §[var]; the
//   kernel assigns it on `create_var` and never mutates it for the
//   life of the handle. We therefore check field0 only weakly via
//   the field1 invariants — any divergence in the kernel's
//   authoritative `idc_read` refresh would surface as an unexpected
//   field1 value, which is what we assert.
//
// Action
//   1. createVar(caps={r, w}, props={cur_rwx=0b011, sz=0, cch=0},
//                pages=1, preferred_base=0, device_region=0) — must
//      succeed. Per §[var] starts at `map = 0`.
//   2. readCap(cap_table_base, var_handle) — snapshot field1 (the
//      precondition for the leg-A comparison).
//   3. idcRead(var, 0, 1) — may succeed or return any error code. By
//      construction §[idc_read] tests 01-06 do not fire, and the call
//      cannot mutate kernel-side VAR state (idc_read is a pure read).
//   4. readCap(cap_table_base, var_handle) — field1 must equal the
//      pre-call snapshot (kernel authoritative state never changed,
//      so a refresh leaves the slot bit-identical).
//   5. createPageFrame(caps={r, w}, props={sz=0}, pages=1) — must
//      succeed.
//   6. mapPf(var, &.{ 0, pf }) — must succeed (sets `map = 1`,
//      precondition for the leg-B refresh).
//   7. idcRead(var, 0, 1) — must succeed (§[idc_read] gates 01-06
//      inert, backing exists, so test 07's success branch fires).
//   8. readCap(cap_table_base, var_handle) — field1's `map` must be 1,
//      reflecting the kernel's authoritative post-map_pf state still
//      mirrored after idc_read's refresh.
//
// Assertions
//   1: a setup syscall (createVar, createPageFrame, mapPf, or the
//      leg-B idcRead) returned an unexpected status — the precondition
//      for test 08 is broken so we cannot verify the spec assertion.
//   2: post-leg-A cap-table snapshot of field1 differed from the
//      pre-call snapshot — the refresh on a call that did not mutate
//      the VAR left the slot out of sync with the kernel's
//      authoritative (unchanged) state.
//   3: post-leg-B cap-table snapshot of field1's `map` is not 1 —
//      the success-path refresh did not propagate (or zeroed out) the
//      kernel's authoritative `map = 1` state in the holding domain's
//      cap table.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const PAGES: u64 = 1;
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
    // Step 1: regular 1-page VAR (caps.mmio = 0, caps.dma = 0). Per
    // §[var] line 877 it starts at `map = 0`. The VAR has the `r` cap
    // (idc_read precondition test 02 inert) and the page covers the
    // 8-byte read range below (test 05 inert).
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

    // Step 2: snapshot field1 before the leg-A call. The kernel's
    // authoritative state at this point: `map = 0`, no installations,
    // no bound device.
    const cap_pre_a = caps.readCap(cap_table_base, var_handle);
    if (cap_pre_a.handleType() != caps.HandleType.virtual_address_range) {
        testing.fail(1);
        return;
    }
    const field1_pre_a = cap_pre_a.field1;

    // Step 3: idc_read against the fresh VAR. count = 1, offset = 0
    // (8-byte aligned, fits within the VAR's 4 KiB size); the [1]
    // handle is a valid VAR with the `r` cap and no reserved bits set
    // — so §[idc_read] tests 01-06 are all inert. The call's outcome
    // (success or error) is irrelevant to test 08: the spec only
    // requires that the cap-table refresh holds. Either way the call
    // is a pure read of VAR contents and cannot mutate kernel-side
    // VAR state, so the authoritative state remains exactly what step
    // 2 snapshotted.
    _ = syscall.idcRead(var_handle, 0, 1);

    // Step 4: leg-A refresh — the kernel's authoritative VAR state is
    // unchanged from step 2, so a refresh of field0/field1 must leave
    // the slot bit-identical to the pre-call snapshot.
    const cap_post_a = caps.readCap(cap_table_base, var_handle);
    if (cap_post_a.field1 != field1_pre_a) {
        testing.fail(2);
        return;
    }

    // Step 5: 1-page page_frame, sz = 0 so it matches the VAR's sz
    // (§[map_pf] test 06 inert) and a single pair at offset 0 covers
    // the VAR's full 1-page range without overshooting (test 07
    // inert).
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

    // Step 6: install pf at offset 0. All §[map_pf] gates 01-10 are
    // inert by construction, so the kernel takes the success branch
    // and per test 11 sets `map = 1`. §[map_pf] test 14 also refreshes
    // the cap table, so the leg-B precondition (cap-table reflects
    // `map = 1`) holds.
    const map_call = syscall.mapPf(var_handle, &.{ 0, pf_handle });
    if (map_call.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    // Step 7: idc_read with backing now installed. None of §[idc_read]
    // tests 01-06 fire (same arguments as step 3), and there is a
    // backing page at offset 0, so the kernel takes the success
    // branch.
    const ok_call = syscall.idcRead(var_handle, 0, 1);
    if (ok_call.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    // Step 8: leg-B refresh — idc_read does not mutate VAR state, so
    // the kernel's authoritative `map = 1` (set by step 6) must still
    // be reflected in the cap-table snapshot. A broken refresh that
    // dropped or zeroed the slot would surface as `map != 1` here.
    const cap_post_b = caps.readCap(cap_table_base, var_handle);
    if (mapField(cap_post_b.field1) != 1) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
