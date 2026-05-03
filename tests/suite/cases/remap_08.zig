// Spec §[remap] — test 08.
//
// "[test 08] on success, subsequent accesses to mapped pages use
//  effective permissions = `cur_rwx` ∩ `page_frame.r/w/x` (for map=1)
//  or `cur_rwx` (for map=3)."
//
// DEGRADED SMOKE VARIANT
//   Faithful coverage of test 08 requires demonstrating that BOTH the
//   allowed and denied arms of every (cur_rwx, pf.rwx) intersection
//   take effect after a remap call. The denied arms are the load-
//   bearing half of the assertion: if remap silently kept the old
//   PTEs, an "after-remap" write to a page whose effective `w` bit was
//   cleared would still succeed and the regression would slip past a
//   pure happy-path probe. Catching that requires the test EC to
//   attempt a now-disallowed access and observe a CPU page fault that
//   is delivered back to the test domain through some exception-
//   handler hook. The v0 runner has no such hook (see map_pf_12 for
//   the same constraint): a #PF on the test EC is handled by the
//   kernel default, which terminates or restarts the child rather
//   than surfacing a "permission denied" signal.
//
//   Exhaustive coverage therefore requires:
//     - one VAR per cur_rwx-before-remap variant + one new_cur_rwx
//       per remap target cell (and the symmetric pf.rwx variants);
//     - per-cell allowed-access + denied-access pairs;
//     - an exception-handler hook so the test can catch faults on
//       newly-disallowed accesses post-remap and distinguish them
//       from "remap did nothing" regressions.
//
//   None of those are in scope for v0. This file lands a single happy-
//   path probe on the map=1 arm: a VAR with caps={r,w} and initial
//   cur_rwx=r|w, mapped with a page_frame whose caps={r,w}, then
//   remap'd to new_cur_rwx=r (drop write). The pre-remap intersection
//   (r|w) ∩ (r|w) = r|w, so a CPU write+read at VAR.base[0] before
//   the remap call must round-trip. The post-remap negative arm — a
//   write that should now fault because the effective `w` bit is 0 —
//   is documented but not exercised, exactly as in map_pf_12.
//
// Strategy
//   1. create_page_frame(caps={r,w}, props=0, pages=1) — must succeed.
//      Same shape as map_pf_12: r|w, no x, single 4 KiB page.
//   2. create_var(caps={r,w}, props={cur_rwx=r|w, sz=0, cch=0},
//                 pages=1, preferred_base=0, device_region=0) — must
//      succeed; a regular VAR (caps.dma=0, caps.mmio=0) starting in
//      `map = 0` per §[var].
//   3. map_pf(var, &.{ 0, pf }) — installs the page_frame at offset
//      0, transitioning `map` to 1 (§[map_pf] test 11). Effective
//      permissions on VAR.base[0..4096] are now (r|w) ∩ (r|w) = r|w.
//   4. Pre-remap probe: write 0xA5 to VAR.base[0]; read back. Both
//      accesses use effective r|w; round-trip must succeed.
//   5. remap(var, new_cur_rwx = 0b001 = r-only). Must succeed; per
//      test 07, field1.cur_rwx is now r. Per test 08 (the assertion
//      under test), effective permissions on VAR.base[0..4096] become
//      (r) ∩ (r|w) = r — write should now fault. Not exercised here;
//      see the hook caveat above.
//
// Action
//   See Strategy. The sentinel byte 0xA5 is arbitrary; same role as
//   in map_pf_12.
//
// Assertions
//   1: setup failed — create_page_frame, create_var, map_pf, or the
//      remap call itself returned an error. Folded into one id to
//      keep the smoke surface narrow; the negative-arm probe that
//      would split these out is gated on the exception-handler hook.
//   2: pre-remap byte didn't round-trip — VAR.base[0] read back a
//      value other than 0xA5 before the remap was issued. Indicates
//      the page_frame is not actually reachable through VAR.base + 0
//      under the initial cur_rwx, so the post-remap arm of the
//      assertion would be vacuous even if the hook existed.
//
// Faithful-test note
//   A faithful test 08 would, for the map=1 arm, mint VARs across the
//   non-trivial cur_rwx variants ({r}, {w}, {r,w}, plus the executable
//   variants once §[create_var] gating is set up), pair each with a
//   page_frame whose caps span the corresponding intersection cells,
//   call remap to flip cur_rwx, and then for each cell:
//     - attempt the access types implied by the new effective bits;
//     - for "allowed" access types, verify success + content fidelity
//       and verify the byte written before the remap survived (the
//       remap must not invalidate page contents);
//     - for "denied" access types, install a CPU exception handler
//       on the test EC that catches #PF, advances RIP past the
//       offending instruction, and records the fault; verify the
//       handler fired exactly the expected number of times.
//   The map=3 arm would mint demand-paged VARs (no page_frame
//   intersection; effective = cur_rwx directly) and run the same
//   pattern. The handler hook is the gating runner extension shared
//   with map_pf test 12.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: page_frame with caps={r, w}. Same shape as map_pf_12;
    // no x bit so the (cur_rwx, pf) intersection along x is trivially
    // 0 and the remap probe stays within the r/w plane.
    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // pages
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const pf_handle: u64 = @as(u64, cpf.v1 & 0xFFF);

    // Step 2: regular VAR with caps={r, w} and cur_rwx = r|w. Per
    // §[var] starts in map = 0 (no explicit mapping). caps.mmio = 0
    // and caps.dma = 0 — this is the CPU-mapped path, the same path
    // remap test 08 governs for map=1.
    const var_caps = caps.VarCap{ .r = true, .w = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0
    const cvar = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        1, // pages = 1
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(1);
        return;
    }
    const var_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);
    const var_base: u64 = cvar.v2; // §[create_var] test 19: field0 = base.

    // Step 3: install the page_frame at offset 0. Per §[map_pf] test
    // 11, `map` transitions 0 -> 1, so the VAR is now eligible for
    // remap (§[remap] test 02 rejects map=0). Effective permissions
    // on VAR.base[0..4096] become (r|w) ∩ (r|w) = r|w.
    const mr = syscall.mapPf(var_handle, &.{ 0, pf_handle });
    if (mr.v1 != 0) {
        testing.fail(1);
        return;
    }

    // Step 4: pre-remap probe. With effective r|w both the write and
    // the read at VAR.base[0] succeed and the byte round-trips. The
    // sentinel 0xA5 is non-zero so a stale-or-unmapped page (the
    // page_frame is zero-filled) is detectable. Volatile cast keeps
    // the optimizer from constant-folding the round-trip away.
    const dst: *volatile u8 = @ptrFromInt(var_base);
    dst.* = 0xA5;
    const got = dst.*;
    if (got != 0xA5) {
        testing.fail(2);
        return;
    }

    // Step 5: remap to new_cur_rwx = r (drop write). Per §[remap]
    // test 07, field1.cur_rwx is now r. Per test 08 — the rule under
    // test — effective permissions on VAR.base[0..4096] become
    // (r) ∩ (r|w) = r, so a subsequent write to VAR.base[0] would
    // fault. Asserting that fault requires the exception-handler hook
    // documented in the prelude; without it, the smoke covers only
    // the success-of-call + retained-readability arm. A regression
    // that fails to update PTEs at all would still let remap return
    // 0; a regression that returns an error code on a valid remap
    // call would trip assertion 1.
    const rr = syscall.remap(var_handle, 0b001);
    if (rr.v1 != 0) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
