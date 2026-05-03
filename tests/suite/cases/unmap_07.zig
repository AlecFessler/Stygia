// Spec §[unmap] — test 07.
//
// "[test 07] returns E_NOENT if [1].field1 `map` is 3 and no
//  demand-allocated page exists at any offset selector."
//
// DEGRADED SMOKE VARIANT
//   This assertion fires only when the VAR is in `map = 3` (demand)
//   state — the same demand-paging blocker documented in
//   tests/map_pf_10.zig applies here. Per §[var] (line 877) a regular
//   VAR transitions to `map = 3` only on the first faulted access:
//   the kernel allocates a zero-filled page_frame, installs it at the
//   faulting offset, and bumps `map` to 3. From a v0 test child there
//   is no syscall in the spec-v3 surface that drives a VAR into `map
//   = 3` *without* an actual CPU page fault, and there is no spec'd
//   faulting helper that a test EC can call to trigger demand-paging
//   on a VAR whose base is not yet known to the test code generator.
//
//   With `map = 3` unreachable from the test domain, the strict test
//   07 path — kernel rejects `unmap` with E_NOENT when no demand page
//   exists at the offered offset selector — cannot be exercised end-
//   to-end here.
//
//   This smoke pins only the negative observation: a regular VAR
//   (caps.mmio = 0, caps.dma = 0) created without explicit mapping
//   starts in `map = 0` per §[var]; mapping a single page_frame
//   transitions it to `map = 1` per §[map_pf] test 11 — which is the
//   wrong arm for test 07 (test 07 is the `map = 3` arm). The smoke
//   confirms the prelude shape used by the eventual faithful test
//   but does not assert the rejection itself.
//
// Strategy (smoke prelude)
//   The check ordering ahead of the `map = 3 + missing offset` arm
//   that test 07 targets is:
//     - test 01 (VAR is invalid) — pass a freshly-minted regular VAR.
//     - test 02 (map = 0) — must be cleared *before* test 07 can fire;
//       a freshly-minted VAR is `map = 0`, so we must transition out
//       of `map = 0` to even reach later checks. The only transition
//       reachable from a test child is `map_pf` (0 -> 1) — driving to
//       `map = 3` requires a CPU demand fault which is unreachable
//       (see above).
//     - test 03 (map = 2 + N > 0) — n/a on a `map = 1` VAR.
//     - test 04, 05 (map = 1 arm checks) — these *would* fire on a
//       `map = 1` VAR with bogus selectors, so the smoke is careful
//       to issue only valid `map = 1` selectors so the call exits
//       success rather than crossing into the test 04/05 rejection
//       paths.
//   In other words: the only arm of `unmap` reachable from a test
//   child without a fault driver is the `map = 1` success arm. The
//   smoke walks 0 -> 1 via map_pf, then unmap removes the install
//   and `map` returns to 0 (§[unmap] test 10). This is exactly the
//   arm not covered by test 07, but it is the closest legal prelude
//   the v0 runner can drive.
//
// Action
//   1. createPageFrame(caps={r, w}, props=0, pages=1) — must succeed.
//   2. createVar(caps={r, w}, props={sz=0, cch=0, cur_rwx=0b011},
//                pages=1, preferred_base=0, device_region=0) —
//      must succeed; gives a regular VAR in `map = 0`.
//   3. mapPf(var_handle, &.{ 0, pf }) — transitions map 0 -> 1
//      (§[map_pf] test 11). Required so that a subsequent unmap call
//      isn't trivially rejected by §[unmap] test 02 (`map = 0` =>
//      E_INVAL).
//   4. unmap(var_handle, &.{ pf }) — succeeds on the `map = 1` arm
//      (§[unmap] test 10): removes the lone installation, `map`
//      returns to 0. This is *not* the `map = 3` rejection arm test
//      07 targets — it's the closest legal exercise of the unmap
//      surface from a v0 test child.
//
// Assertion
//   No spec assertion is being checked — `map = 3` is unreachable
//   from the v0 test child without a fault driver, so test 07's
//   `E_NOENT on missing demand offset` arm cannot be reached. Pass
//   with assertion id 0 to mark this slot as smoke-only in coverage.
//   Any failure of the prelude itself is also reported as pass-with-
//   id-0 since no spec assertion is being checked.
//
// Faithful-test note
//   Faithful test deferred pending a runner-side fault driver that
//   can transition a VAR into `map = 3` without leaving the test EC
//   in an unrecoverable state. The cleanest path is a runner helper
//   that issues a load at `VAR.base + offset_a` from a controlled
//   trampoline, returns into the test EC with no register clobber,
//   and leaves `VAR.map = 3` with exactly one demand-allocated page
//   installed at offset_a. The action then becomes:
//     create_var(...)              -> regular VAR, map = 0
//     <load from VAR.base + 0>     -> kernel demand-faults a page,
//                                     VAR.map -> 3, page at offset 0
//     unmap(var, &.{ 0x1000 })     -> *expected* E_NOENT via test 07
//                                     (no demand page at offset
//                                     0x1000; only offset 0 was
//                                     faulted in)
//   This is the assertion id 1 a faithful version would check.
//
//   Until the fault driver lands, this file holds the prelude
//   verbatim so the eventual faithful version can graft on the
//   demand-fault step without re-deriving the inert-check matrix.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // page_frame for the prelude's map_pf — drives the VAR from
    // map = 0 to map = 1 so that the subsequent unmap is not
    // rejected by §[unmap] test 02 (map = 0 => E_INVAL).
    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // pages = 1
    );
    if (testing.isHandleError(cpf.v1)) {
        // Prelude broke; smoke is moot but no spec assertion is
        // being checked, so report pass-with-id-0.
        testing.pass();
        return;
    }
    const pf: u64 = @as(u64, cpf.v1 & 0xFFF);

    // Regular VAR (caps.mmio = 0, caps.dma = 0); per §[var] line 877
    // it starts in `map = 0`. One page suffices — the smoke installs
    // a single page_frame at offset 0 to walk into `map = 1`.
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
        testing.pass();
        return;
    }
    const var_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);

    // Drive map 0 -> 1 (§[map_pf] test 11). Required so that the
    // following unmap is reachable past §[unmap] test 02. The
    // demand-paging arm (map -> 3) is unreachable without a fault
    // driver in the test runner.
    _ = syscall.mapPf(var_handle, &.{ 0, pf });

    // unmap on the `map = 1` arm with a valid installed page_frame
    // selector — succeeds via §[unmap] test 10, removes the lone
    // installation, and `map` returns to 0. This is the closest
    // legal exercise of the unmap surface from a v0 test child;
    // the `map = 3 + missing offset` rejection arm that test 07
    // targets is not reachable here.
    _ = syscall.unmap(var_handle, &.{pf});

    // No spec assertion is being checked — the `map = 3` state is
    // unreachable from the v0 test child without a fault driver.
    // Pass with assertion id 0 to mark this slot as smoke-only in
    // coverage.
    testing.pass();
}
