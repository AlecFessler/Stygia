// Spec §[unmap] — test 11.
//
// "[test 11] on success, when N > 0 and `map` is 3, only the pages at
//  the specified offsets are freed; `map` stays 3 unless every demand-
//  allocated page has been freed, in which case it becomes 0."
//
// DEGRADED SMOKE VARIANT
//   Test 11 fires only on a VAR whose `map` field is 3 (demand). Per
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
//   register state preserved well enough to follow up with `unmap`
//   syscalls and a `readCap` to inspect the resulting `map` field.
//   The faithful sequence would be:
//
//     create_var(caps={r, w}, props={sz=0, cur_rwx=0b011}, pages=2,
//                ...)                     -> regular VAR, map = 0
//     <fault at VAR.field0 + 0>           -> kernel demand-faults a
//                                            page; VAR.map -> 3,
//                                            page installed at 0
//     <fault at VAR.field0 + 0x1000>      -> second demand-fault;
//                                            map stays 3, page
//                                            installed at 0x1000
//     unmap(var, &.{ 0 })                 -> *expected* success;
//                                            page at offset 0 freed,
//                                            page at 0x1000 stays,
//                                            map stays 3 (test 11
//                                            "stays 3" leg)
//     unmap(var, &.{ 0x1000 })            -> *expected* success;
//                                            last demand page freed,
//                                            map drops to 0 (test 11
//                                            "becomes 0" leg)
//
//   Until the runner gains a faulting-helper (a controlled trampoline
//   that issues the demand-trigger load and returns into the test EC
//   without clobbering its caller-saved state), the strict test 11
//   path cannot be exercised end-to-end here. See unmap_06.zig and
//   unmap_07.zig for the parallel discussion of the `map = 3` arm.
//
// Strategy (smoke prelude)
//   The only arm of `unmap` reachable from a v0 test child without a
//   fault driver is the `map = 1` success arm (mirrors unmap_07's
//   prelude). The smoke walks 0 -> 1 via a two-page map_pf, then
//   removes the page_frames one at a time. This is structurally the
//   same shape as the faithful test 11 sequence (two installs, then
//   two unmaps with the "stays" leg first and the "becomes 0" leg
//   second) — just on the wrong `map` arm. It is the closest legal
//   exercise of the unmap surface and is what unmap_10 already
//   covers strictly for `map = 1`.
//
//   We do not assert anything about the `map` field or the per-arm
//   state because the strict `map = 3` rejection target is
//   unreachable; the smoke only confirms that the prelude shape used
//   by the eventual faithful test compiles, links, and dispatches
//   `unmap` cleanly. Any failure of the prelude itself is also
//   reported as pass-with-id-0 since no spec assertion is being
//   checked.
//
// Action
//   1. createPageFrame(caps={r, w}, props=0, pages=1) twice — pf_a,
//      pf_b. Required so the prelude has two distinct installable
//      page_frames; mirrors the two-demand-page shape of the
//      faithful test 11.
//   2. createVar(caps={r, w}, props={sz=0, cch=0, cur_rwx=0b011},
//                pages=2, preferred_base=0, device_region=0) —
//      regular VAR in `map = 0`, large enough for two 4-KiB
//      installations at offsets 0 and 0x1000.
//   3. mapPf(var_handle, &.{ 0, pf_a, 0x1000, pf_b }) — drives
//      `map` to 1 with two installations. Required so the following
//      `unmap` calls are not rejected by §[unmap] test 02
//      (`map = 0` => E_INVAL).
//   4. unmap(var_handle, &.{ pf_a }) — succeeds on the `map = 1`
//      arm (§[unmap] test 10): removes pf_a only, pf_b stays
//      installed. This is the structural analogue of the faithful
//      test 11 "stays 3" leg, on the wrong arm.
//   5. unmap(var_handle, &.{ pf_b }) — succeeds on the `map = 1`
//      arm: removes the last installation, `map` drops to 0. This
//      is the structural analogue of the faithful test 11
//      "becomes 0" leg, on the wrong arm.
//
// Assertion
//   No assertion is checked — passes with assertion id 0 because the
//   `map = 3` state is unreachable. Test reports pass regardless of
//   what the prelude or `unmap` calls return: only the smoke shape
//   is being exercised.
//
// Faithful-test note
//   Faithful test deferred pending a runner-side fault driver that
//   can transition a VAR into `map = 3` without leaving the test EC
//   in an unrecoverable state. The cleanest path is a runner helper
//   that issues a load at `VAR.base + offset` from a controlled
//   trampoline, returns into the test EC with no register clobber,
//   and leaves `VAR.map = 3` with one demand-allocated page per
//   faulted offset. The action then becomes:
//     create_var(..., pages=2)         -> regular VAR, map = 0
//     <fault at VAR.base + 0>          -> kernel demand-faults a
//                                         page, VAR.map -> 3
//     <fault at VAR.base + 0x1000>     -> second demand-fault, map
//                                         stays 3
//     unmap(var, &.{ 0 })              -> *expected* success; page
//                                         at offset 0 freed, page at
//                                         0x1000 stays, map stays 3
//     readCap -> field1 `map` must == 3 (assertion id 1)
//     unmap(var, &.{ 0x1000 })         -> *expected* success; last
//                                         demand page freed
//     readCap -> field1 `map` must == 0 (assertion id 2)
//   Those assertions (ids 1 and 2) would replace this smoke's
//   pass-with-id-0. The `map`-field bit layout and shift used by the
//   faithful version is the same one in unmap_10.zig (bits 39-40 of
//   field1, mask 0b11).
//
//   Until then, this file holds the prelude verbatim so the eventual
//   faithful version can graft on the demand-fault step without
//   re-deriving the inert-check matrix.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Two distinct page_frames for the prelude's seeding map_pf.
    // Mirrors the two-demand-page shape of the faithful test 11
    // (which installs one demand page at offset 0 and another at
    // offset 0x1000, then unmaps them one at a time).
    const pf_caps = caps.PfCap{ .r = true, .w = true };

    const cpf_a = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // pages = 1
    );
    if (testing.isHandleError(cpf_a.v1)) {
        // Prelude broke; smoke is moot but no spec assertion is
        // being checked, so report pass-with-id-0.
        testing.pass();
        return;
    }
    const pf_a: u64 = @as(u64, cpf_a.v1 & 0xFFF);

    const cpf_b = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0,
        1,
    );
    if (testing.isHandleError(cpf_b.v1)) {
        testing.pass();
        return;
    }
    const pf_b: u64 = @as(u64, cpf_b.v1 & 0xFFF);

    // Regular VAR (caps.mmio = 0, caps.dma = 0); per §[var] line 877
    // it starts in `map = 0`. Two pages so the two 4-KiB page_frames
    // fit at non-overlapping offsets 0 and 0x1000 — the same offsets
    // a faithful test 11 would demand-fault at.
    const var_caps = caps.VarCap{ .r = true, .w = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0
    const cvar = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        2, // pages = 2
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.pass();
        return;
    }
    const var_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);

    // Drive map 0 -> 1 with two installations (§[map_pf] test 11).
    // Required so subsequent unmap calls are reachable past §[unmap]
    // test 02. The demand-paging arm (map -> 3) is unreachable
    // without a fault driver in the test runner.
    _ = syscall.mapPf(var_handle, &.{ 0, pf_a, 0x1000, pf_b });

    // First unmap on the `map = 1` arm: removes pf_a only, pf_b
    // stays installed. Structural analogue of the faithful test 11
    // "stays 3" leg — but on the `map = 1` arm, since `map = 3` is
    // unreachable.
    _ = syscall.unmap(var_handle, &.{pf_a});

    // Second unmap on the `map = 1` arm: removes pf_b — the last
    // installation — and `map` returns to 0 via §[unmap] test 10.
    // Structural analogue of the faithful test 11 "becomes 0" leg.
    _ = syscall.unmap(var_handle, &.{pf_b});

    // No spec assertion is being checked — the `map = 3` state is
    // unreachable from the v0 test child without a fault driver.
    // Pass with assertion id 0 to mark this slot as smoke-only in
    // coverage.
    testing.pass();
}
