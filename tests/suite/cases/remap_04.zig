// Spec §[remap] — test 04.
//
// "[test 04] returns E_INVAL if [1].field1 `map` is 1 and [2]
//  new_cur_rwx is not a subset of the intersection of all installed
//  page_frames' r/w/x caps."
//
// Strategy
//   The rule under test fires only on the page-frame-backed branch
//   (`map = 1`) and only when the caller asks for a `cur_rwx` whose
//   r/w/x bits exceed at least one installed page_frame's r/w/x.
//   Earlier remap gates have to be inert by construction so the test
//   exercises test 04 in isolation:
//
//     - test 01 (BADCAP on [1]):           pass a real VAR handle.
//     - test 02 (E_INVAL when map ∈ {0,2}): drive `map` to 1 by calling
//       `map_pf` after `create_var` (a fresh VAR starts at `map = 0`,
//       per §[var]; §[map_pf] test 11 transitions it to 1).
//     - test 03 (cur_rwx ⊄ caps.rwx):      pick caps and new_cur_rwx
//       so that new_cur_rwx is a subset of caps. Here caps = {r, w}
//       and new_cur_rwx = r|w → subset, so test 03 stays inert.
//     - test 05 (caps.dma = 1, x in cur_rwx): caps.dma = 0, so inert.
//     - test 06 (reserved bits in [2]):    new_cur_rwx = 0b011 has no
//       reserved bits set.
//
//   With the earlier gates inert, the remap call must hit test 04's
//   intersection check. Construct a single installed page_frame whose
//   r/w/x caps are r-only (no w). The intersection across all installed
//   page_frames is therefore {r}. Asking remap for new_cur_rwx = r|w
//   makes the w bit fall outside that intersection, so test 04 must
//   return E_INVAL.
//
//   The VAR's `cur_rwx` at create time is r|w (props = 0b011) so that
//   the §[map_pf] success precondition for `map = 1` is reached
//   without triggering any §[map_pf] gate. A page_frame with caps = {r}
//   has fewer effective rights than the VAR's cur_rwx; §[map_pf] does
//   not reject such an install (the intersection is taken on access,
//   per §[map_pf] test 12). So `map_pf` succeeds and `map` becomes 1.
//
// Action
//   1. createPageFrame(caps={r}, props=0, pages=1) — must succeed;
//      the page_frame whose r-only caps will define the intersection.
//   2. createVar(caps={r, w}, props={cur_rwx=0b011, sz=0, cch=0},
//                pages=1, preferred_base=0, device_region=0) — must
//      succeed. Per §[var] line 877 starts at `map = 0`.
//   3. mapPf(var, &.{ 0, pf }) — must succeed (all §[map_pf] gates
//      01-10 inert by construction). Per §[map_pf] test 11 transitions
//      `map` from 0 → 1, satisfying the precondition for §[remap]
//      test 04.
//   4. remap(var, new_cur_rwx=0b011) — must return E_INVAL because
//      the requested r|w is not a subset of the installed page_frame's
//      r-only caps.
//
// Assertions
//   1: vreg 1 was not E_INVAL on the remap call (the spec assertion
//      under test).
//   2: a setup syscall (createPageFrame, createVar, or the success-leg
//      mapPf) returned an unexpected status — the precondition for
//      test 04 is broken so we cannot proceed to verify the rule.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: page_frame with caps = {r} only. Its r/w/x is r, so
    // the intersection across all installed page_frames is r. The w
    // bit of any new_cur_rwx the test asks for therefore falls
    // outside that intersection and must trip §[remap] test 04.
    const pf_caps = caps.PfCap{ .r = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // pages
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(2);
        return;
    }
    const pf_handle: u64 = @as(u64, cpf.v1 & 0xFFF);

    // Step 2: regular VAR with caps = {r, w} and cur_rwx = r|w. The
    // generous caps keep §[remap] test 03 inert (new_cur_rwx r|w ⊆
    // caps r|w). caps.dma = 0 keeps test 05 inert. caps.mmio = 0 and
    // no device_region binding by construction.
    const var_caps = caps.VarCap{ .r = true, .w = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0.
    const cvar = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        1, // pages
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(2);
        return;
    }
    const var_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);

    // Step 3: install the r-only page_frame at offset 0. By
    // construction every §[map_pf] gate 01-10 is inert (valid VAR,
    // valid page_frame, N = 1, sz match, offset 0 within range, no
    // mmio/dma corner cases). §[map_pf] test 11 transitions `map`
    // from 0 to 1, which is the precondition for §[remap] test 04.
    const map_call = syscall.mapPf(var_handle, &.{ 0, pf_handle });
    if (map_call.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    // Step 4: remap to cur_rwx = r|w. The intersection across all
    // installed page_frames is r (only the one r-only pf is
    // installed); the w bit falls outside that intersection, so per
    // §[remap] test 04 the call must return E_INVAL.
    const result = syscall.remap(var_handle, 0b011);

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
