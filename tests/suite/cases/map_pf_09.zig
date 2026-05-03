// Spec §[map_pf] — test 09.
//
// "[test 09] returns E_INVAL if any pair's range overlaps an existing
//  mapping in the VAR."
//
// Strategy
//   To isolate the "overlap with an existing mapping" rejection we
//   need a VAR that already has at least one page_frame installed,
//   then issue a second map_pf whose pair touches the same offset.
//   With a VAR sized to a single 4 KiB page (sz = 0, pages = 1) and
//   a page_frame matching that geometry:
//     - The first map_pf(var, &{ 0, pf }) succeeds and transitions
//       the VAR's `map` from 0 to 1 (§[map_pf] test 11).
//     - The second map_pf(var, &{ 0, pf }) provides one well-formed
//       pair (N = 1, offset = 0 aligned to sz = 0, pf size matches
//       VAR size, pair range fits in the VAR, no intra-call
//       overlap). The only remaining failure mode in the §[map_pf]
//       gating order before the install-side bookkeeping is the
//       check against existing installations. The kernel must
//       therefore reject with E_INVAL per test 09.
//
//   Reusing the same page_frame handle in both calls is intentional:
//   the spec text scopes the overlap on the *VAR's* installed range,
//   not on which page_frame backs it. The same pf_handle is a valid
//   handle for the BADCAP gate (§[map_pf] test 02) so the second call
//   only fails if the kernel honours the existing-mapping check.
//
//   Rejection paths inert on the second call:
//     - test 01 (VAR invalid)  — same fresh VAR handle from setup.
//     - test 02 (pf invalid)   — same fresh page_frame handle.
//     - test 03 (caps.mmio)    — VAR built with mmio = 0.
//     - test 04 (N == 0)       — N = 1.
//     - test 05 (alignment)    — offset 0 is aligned to any sz.
//     - test 06 (pf sz < VAR)  — both sz = 0.
//     - test 07 (range > VAR)  — single 4 KiB pair fits a 1-page VAR.
//     - test 08 (intra-call)   — only one pair.
//     - test 10 (map ∈ {2,3})  — first map_pf set map = 1, not 2/3.
//   The only remaining gate is test 09 itself.
//
// Action
//   1. createPageFrame(caps={r,w}, props={sz=0}, pages=1) — must
//      succeed. Provides the page_frame for both map_pf calls.
//   2. createVar(caps={r,w}, props={sz=0, cur_rwx=0b011}, pages=1,
//      preferred_base=0, device_region=0) — must succeed. Provides
//      a regular VAR with map = 0.
//   3. mapPf(var_handle, &.{ 0, pf_handle }) — must succeed
//      (precondition: an installation now exists at offset 0).
//   4. mapPf(var_handle, &.{ 0, pf_handle }) — must return E_INVAL
//      because offset 0 already has a mapping.
//
// Assertions
//   1: a setup syscall (createPageFrame, createVar, or the first
//      mapPf) returned an error code; the precondition for test 09
//      is broken so we cannot verify the spec assertion.
//   2: the second mapPf did not return E_INVAL — the overlap with
//      the existing mapping was not rejected as the spec requires.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: stage a 4 KiB page_frame. sz = 0 matches the VAR's
    // sz so §[map_pf] test 06 (pf sz smaller than VAR sz) cannot
    // pre-empt the overlap check.
    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // pages = 1
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const pf_handle: caps.HandleId = @truncate(cpf.v1 & 0xFFF);

    // Step 2: build a regular (non-mmio, non-dma) 1-page VAR with
    // map = 0. cur_rwx = r|w matches the page_frame's caps so the
    // first map_pf is unambiguously well-formed.
    const var_caps = caps.VarCap{ .r = true, .w = true };
    const cvar = syscall.createVar(
        @as(u64, var_caps.toU16()),
        0b011, // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0
        1, // pages = 1
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(1);
        return;
    }
    const var_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);

    // Step 3: install pf_handle at offset 0. After this call the
    // VAR's map is 1 with one installed page_frame covering offset
    // 0..4096. Any non-success result here means the precondition
    // for test 09 is broken — fail under assertion id 1.
    const first = syscall.mapPf(var_handle, &.{ 0, pf_handle });
    if (first.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    // Step 4: second map_pf at the same offset. All other §[map_pf]
    // gates (tests 01-08, 10) are inert by construction, so the
    // kernel must reject with E_INVAL on the existing-mapping check
    // (test 09 itself).
    const second = syscall.mapPf(var_handle, &.{ 0, pf_handle });
    if (second.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
