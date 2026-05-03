// Spec §[remap] — test 09.
//
// "[test 09] when [1] is a valid handle, [1]'s field0 and field1 are
//  refreshed from the kernel's authoritative state as a side effect,
//  regardless of whether the call returns success or another error
//  code."
//
// Strategy
//   `remap` mutates the kernel-side VAR state (`cur_rwx` on the
//   success path); for handle-table consumers to observe that mutation
//   without an explicit `sync`, the syscall must refresh [1]'s field0
//   and field1 in the holding domain's (read-only) cap table on every
//   call where [1] resolves to a valid handle — both the success path
//   and the post-resolution error paths. We exercise both legs:
//
//   Leg A (error refresh)
//     Build a regular 1-page VAR with `caps = {r, w}`, `cur_rwx =
//     0b011`, `sz = 0`, `cch = 0`, `device_region = 0`. Per §[var] the
//     fresh handle starts at `map = 0`. Snapshot field1 from the
//     read-only cap table. Then call `remap(var, 0b001)` — §[remap]
//     test 02 fires because `map = 0` and the call returns E_INVAL
//     before any kernel-side bookkeeping mutates. Per test 09 the cap
//     table snapshot of field1 must still mirror the kernel's
//     authoritative state — bit-for-bit identical to the pre-call
//     snapshot, since the kernel never touched the VAR.
//
//   Leg B (success refresh)
//     Mint a 1-page (`sz = 0`) page_frame with caps `{r, w}` and call
//     `map_pf(var, &.{ 0, pf })`. By construction none of §[map_pf]
//     tests 01-10 fire, so the kernel takes the success branch and per
//     §[map_pf] test 11 sets `map = 1` without otherwise touching
//     `cur_rwx`. Then call `remap(var, 0b001)` — 0b001 is a strict
//     subset of caps.r|w (= 0b011) and of the installed page_frame's
//     r|w caps (= 0b011), bits 3-63 are zero, and caps.dma = 0, so
//     none of §[remap] tests 01-06's rejection paths fire and the
//     kernel takes the success branch and per test 07 sets `cur_rwx =
//     0b001`. Re-read [1]'s slot from the cap table: per test 09
//     field1's `cur_rwx` must now be 0b001, observable without any
//     explicit `sync`.
//
//   The two legs together pin both halves of test 09: the error path
//   refreshes a *stable* state (snapshot match across an erroring
//   call) and the success path refreshes a *changed* state (cur_rwx
//   0b011 -> 0b001 visible without `sync`).
//
//   field0 carries the VAR's base virtual address per §[var]; the
//   kernel assigns it on `create_var` and never mutates it for the
//   life of the handle. We therefore check field0 only weakly via the
//   field1 invariants — any divergence in the kernel's authoritative
//   `remap` refresh would surface as an unexpected field1 value, which
//   is what we assert.
//
//   §[var] field1 layout:
//     page_count[0..31] | sz[32..33] | cch[34..35] |
//     cur_rwx[36..38]   | map[39..40] | device[41..52]
//   `cur_rwx` at bits 36-38 is a 3-bit field; mask it via
//     (field1 >> 36) & 0b111.
//
// Action
//   1. createVar(caps={r, w}, props={cur_rwx=0b011, sz=0, cch=0},
//                pages=1, preferred_base=0, device_region=0) — must
//      succeed. Per §[var] starts at `map = 0`.
//   2. readCap(cap_table_base, var_handle) — snapshot field1 (the
//      precondition for the error-leg comparison).
//   3. remap(var_handle, 0b001) — must return E_INVAL (§[remap] test
//      02 fires because `map = 0`); the [1] gate has already passed
//      so the spec's "[1] valid" precondition for test 09 holds.
//   4. readCap(cap_table_base, var_handle) — field1 must equal the
//      pre-call snapshot (kernel authoritative state never changed,
//      so a refresh leaves the slot bit-identical).
//   5. createPageFrame(caps={r, w}, props={sz=0}, pages=1) — must
//      succeed.
//   6. mapPf(var_handle, &.{ 0, pf }) — must succeed (sets `map = 1`,
//      precondition for the success-leg refresh).
//   7. remap(var_handle, 0b001) — must succeed; per §[remap] test 07
//      `cur_rwx` becomes 0b001.
//   8. readCap(cap_table_base, var_handle) — field1's `cur_rwx` must
//      be 0b001, reflecting the kernel's authoritative post-remap
//      state.
//
// Assertions
//   1: a setup syscall (createVar, createPageFrame, the success-leg
//      mapPf, or the success-leg remap) returned an unexpected status,
//      or step 3's remap returned something other than E_INVAL — the
//      precondition for test 09 is broken so we cannot verify the
//      spec assertion.
//   2: post-error cap-table snapshot of field1 differed from the
//      pre-error snapshot — the failing-call refresh left the slot
//      out of sync with the kernel's authoritative (unchanged) state.
//   3: post-success cap-table snapshot of field1's `cur_rwx` is not
//      0b001 — the success-path refresh did not propagate the
//      kernel's authoritative `cur_rwx = 0b001` (set by §[remap] test
//      07) into the holding domain's cap table.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const PAGES: u64 = 1;
const INITIAL_CUR_RWX: u64 = 0b011; // r|w
const NEW_CUR_RWX: u64 = 0b001; // r only
const SZ: u64 = 0; // 4 KiB
const CCH: u64 = 0; // wb

// §[var] field1 layout: cur_rwx at bits 36-38.
const CUR_RWX_SHIFT: u6 = 36;
const CUR_RWX_MASK: u64 = 0b111;

fn curRwxField(field1: u64) u64 {
    return (field1 >> CUR_RWX_SHIFT) & CUR_RWX_MASK;
}

pub fn main(cap_table_base: u64) void {
    // Step 1: regular 1-page VAR (caps.mmio = 0, caps.dma = 0). Per
    // §[var] it starts at `map = 0`, so the error-refresh leg has a
    // clean precondition (test 02 of §[remap] fires because `map = 0`).
    const var_caps = caps.VarCap{ .r = true, .w = true };
    const props: u64 = (CCH << 5) | (SZ << 3) | INITIAL_CUR_RWX;
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

    // Step 2: snapshot field1 before the failing call. The kernel's
    // authoritative state at this point: `map = 0`, no installations,
    // cur_rwx = 0b011.
    const cap_pre_err = caps.readCap(cap_table_base, var_handle);
    if (cap_pre_err.handleType() != caps.HandleType.virtual_address_range) {
        testing.fail(1);
        return;
    }
    const field1_pre_err = cap_pre_err.field1;

    // Step 3: remap on a fresh VAR. §[remap] test 02 fires (`map = 0`)
    // and the call returns E_INVAL before any kernel-side mutation.
    // The [1] gate has already passed because `var_handle` is a valid
    // VAR — that's the precondition for the spec's "[1] valid →
    // field0/field1 refreshed" requirement.
    const err_call = syscall.remap(var_handle, NEW_CUR_RWX);
    if (err_call.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    // Step 4: error-leg refresh — the kernel never reached remap's
    // mutation path (test 02 fired first), so the authoritative VAR
    // state is unchanged. A refresh of field0/field1 must therefore
    // leave the slot bit-identical to the pre-call snapshot.
    const cap_post_err = caps.readCap(cap_table_base, var_handle);
    if (cap_post_err.field1 != field1_pre_err) {
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
    // and per test 11 sets `map = 1` without otherwise touching
    // `cur_rwx`.
    const map_call = syscall.mapPf(var_handle, &.{ 0, pf_handle });
    if (map_call.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    // Step 7: remap to a strict subset of caps.r/w/x and of the
    // installed page_frame's r/w/x caps: 0b001 = r only. None of
    // §[remap] tests 01-06's rejection paths fire, so the kernel
    // takes the success branch and per test 07 sets `cur_rwx = 0b001`.
    const ok_call = syscall.remap(var_handle, NEW_CUR_RWX);
    if (ok_call.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    // Step 8: success-leg refresh — the cap-table snapshot must now
    // reflect the kernel's authoritative `cur_rwx = 0b001`, with no
    // explicit `sync` required.
    const cap_post_ok = caps.readCap(cap_table_base, var_handle);
    if (curRwxField(cap_post_ok.field1) != NEW_CUR_RWX) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
