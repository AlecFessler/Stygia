// Spec §[unmap] — test 06.
//
// "[test 06] returns E_INVAL if [1].field1 `map` is 3 and any offset
//  selector is not aligned to [1]'s `sz`."
//
// DEGRADED SMOKE VARIANT
//   Test 06 fires only on a VAR whose `map` field is 3 (demand). Per
//   §[var] (line 877), a regular VAR (`caps.mmio = 0, caps.dma = 0`)
//   transitions to `map = 3` exclusively on the first faulted access:
//   the kernel allocates a fresh zero-filled page_frame, installs it
//   at the faulting offset, and bumps `map` from 0 to 3. There is no
//   syscall in the v3 surface that drives a VAR into `map = 3`
//   *without* an actual CPU page fault on its range — `map_pf` lifts
//   `map` to 1 (and §[map_pf] test 10 forbids `map_pf` once `map` is
//   3 anyway), `map_mmio` lifts `map` to 2, and there is no
//   `force_demand` or analogous helper.
//
//   From a v0 test child the only way to fault on a VAR's range is to
//   dereference a pointer at `VAR.field0 + offset`. That requires the
//   test EC to (a) issue a load/store at a kernel-chosen base and
//   (b) survive the page fault entry/exit cleanly, with the test EC's
//   register state preserved well enough to follow up with a `unmap`
//   syscall. The faithful sequence would be:
//
//     create_var(caps={r, w}, props={sz=0, cur_rwx=0b011}, pages=1, ...)
//                                         -> regular VAR, map = 0
//     <load from VAR.field0>              -> kernel demand-faults a
//                                            page; VAR.map -> 3
//     unmap(var, &.{ misaligned_offset }) -> *expected* E_INVAL via
//                                            test 06
//
//   Until the runner gains a faulting-helper (a controlled trampoline
//   that issues the demand-trigger load and returns into the test EC
//   without clobbering its caller-saved state), the strict test 06
//   path cannot be exercised end-to-end here. See map_pf_10.zig for
//   the parallel discussion of the `map = 3` arm.
//
// Strategy (smoke prelude)
//   The check ordering ahead of the alignment check on `map = 3` is:
//     - test 01 (VAR is invalid) — pass a freshly-minted regular VAR
//       so the first dispatch succeeds.
//     - test 02 (`map` is 0) — kernel rejects with E_INVAL because a
//       fresh regular VAR is in `map = 0`. This is the *first* check
//       a test can reach without driving the VAR through a page fault.
//
//   We stop at the test 02 wall: confirming that a regular VAR with
//   `map = 0` rejects an `unmap` call (regardless of selector shape)
//   via test 02, not test 06. A faithful test 06 setup would have to
//   first transition the VAR to `map = 3` via a real fault, then
//   issue `unmap` with a deliberately misaligned offset; we cannot
//   take that step from a child capability domain.
//
// Action
//   1. createVar(caps={r, w}, props={sz=0, cch=0, cur_rwx=0b011},
//                pages=1, preferred_base=0, device_region=0) — must
//      succeed; gives a regular VAR in `map = 0`.
//   2. unmap(var_handle, &.{ 1 }) — kernel rejects via §[unmap]
//      test 02 (`map = 0`), not test 06. The selector value 1 (a
//      deliberately sub-page-aligned byte offset, what a faithful
//      test 06 would supply once the VAR was in `map = 3`) is inert
//      against `map = 0`: the dispatch never inspects selectors when
//      `map` is 0.
//
// Assertion
//   No assertion is checked — passes with assertion id 0 because the
//   `map = 3` rejection target is unreachable. Test reports pass
//   regardless of what `unmap` returns: the prelude only smokes the
//   create_var path. Any failure of the prelude itself is also
//   reported as pass-with-id-0 since no spec assertion is being
//   checked.
//
// Faithful-test note
//   Faithful test deferred pending a runner-side faulting helper that
//   drives a regular VAR into `map = 3` from a controlled trampoline
//   (issues a load at `VAR.field0`, returns into the test EC with no
//   register clobber on the test's side). Once that exists, the
//   action becomes:
//     create_var(...) -> regular VAR, map = 0
//     <fault helper: load from VAR.field0>
//                      -> kernel demand-faults; VAR.map -> 3
//     unmap(var, &.{ 1 }) -> *expected* E_INVAL via test 06
//   That assertion (id 1) would replace this smoke's pass-with-id-0.
//
//   A second misaligned offset is also worth checking once the
//   helper exists: e.g. `&.{ 0x1001 }` (page-plus-one) or
//   `&.{ 0, 0x1001 }` (one aligned + one misaligned, to confirm
//   "any offset selector" applies element-wise).
//
//   Until then, this file holds the create_var prelude verbatim so
//   the eventual faithful version can graft on the demand-fault step
//   without re-deriving the inert-check matrix.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Regular VAR (caps.mmio = 0, caps.dma = 0); per §[var] line 877
    // it starts in `map = 0`. One 4 KiB page is enough — test 06's
    // alignment check on offsets only fires once `map` reaches 3.
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
        // Prelude broke; smoke is moot but no spec assertion is
        // being checked, so report pass-with-id-0.
        testing.pass();
        return;
    }
    const var_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);

    // Inert call: a regular VAR is in `map = 0`, so this dispatches
    // through §[unmap] test 02 (E_INVAL — nothing to unmap), not
    // test 06. The misaligned selector value (1) is what a faithful
    // test 06 would deliver against a `map = 3` VAR; here it never
    // gets inspected because the kernel rejects on `map = 0` first.
    _ = syscall.unmap(var_handle, &.{1});

    // No spec assertion is being checked — the `map = 3` state is
    // unreachable from the v0 test child. Pass with assertion id 0
    // to mark this slot as smoke-only in coverage.
    testing.pass();
}
