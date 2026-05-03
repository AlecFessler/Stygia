// Spec §[map_pf] — test 12.
//
// "[test 12] on success, when [1].caps.dma = 0, CPU accesses to
//  `VAR.base + offset` use effective permissions = `VAR.cur_rwx` ∩
//  `page_frame.r/w/x` per page."
//
// DEGRADED SMOKE VARIANT
//   The full assertion enumerates every (VAR.cur_rwx, pf.rwx) pair —
//   nine non-trivial intersections (excluding pf.x, which §[create_var]
//   tests 11/12 already gate on the VAR side and which would also
//   require an executable VAR for the CPU to actually fetch from a
//   pf-installed page) — and asserts that each effective permission
//   matches `cur_rwx ∩ pf.rwx`. Demonstrating "permission denied" arms
//   requires the test EC to attempt a disallowed access (e.g. a write
//   to a page whose effective `w` bit is 0) and observe a CPU page
//   fault that is delivered back to the test domain through some
//   exception-handler hook. The v0 runner has no such hook: the test
//   ELF runs as the initial EC of a child capability domain whose only
//   communication channel is a result port. A page fault on the test
//   EC has no in-domain handler; the kernel's default behavior would
//   be to terminate the child or restart it (§[restart_semantics]),
//   neither of which surfaces as a clean "permission denied" signal.
//
//   Exhaustive coverage therefore requires:
//     - additional page_frame variants per intersection cell (e.g.
//       caps.r-only, caps.w-only, caps.r|w, caps.r|w|x, etc.);
//     - per-test cur_rwx settings on the VAR;
//     - an exception-handler hook so the test can catch faults on
//       disallowed accesses and distinguish them from disallowed-but-
//       silently-succeeded accesses (i.e. effective bits broader than
//       expected).
//
//   None of those are in scope for v0. This file lands a single happy-
//   path probe: a VAR with caps={r,w} and cur_rwx=r|w, mapped with a
//   page_frame whose caps={r,w}. The intersection (r|w) ∩ (r|w) = r|w,
//   so a CPU write followed by a CPU read at VAR.base + 0 must both
//   succeed without faulting, and the byte must round-trip. Any
//   regression that drops the effective `r` or `w` bit on this
//   configuration would terminate the test EC on the first access; a
//   regression that leaves the page entirely unmapped or maps it with
//   wrong contents would cause the round-trip read to mismatch.
//
// Strategy
//   1. create_page_frame(caps={r,w}, props=0, pages=1) — must succeed;
//      this is the page_frame whose r|w (no x) caps will intersect
//      with the VAR's cur_rwx = r|w to yield effective r|w.
//   2. create_var(caps={r,w}, props={cur_rwx=r|w, sz=0, cch=0},
//                 pages=1, preferred_base=0, device_region=0) — must
//      succeed; gives a regular VAR (caps.dma=0, caps.mmio=0) in
//      `map = 0` whose base is kernel-chosen and reported in field0.
//   3. map_pf(var, &.{ 0, pf }) — installs the page_frame at offset
//      0 of the VAR, transitioning `map` to 1 per §[map_pf] test 11.
//      Effective permissions on VAR.base[0..4096] become r|w per
//      §[map_pf] test 12 (the rule under test).
//   4. Write a known sentinel byte at VAR.base[0]; read it back.
//      Both accesses use effective r|w, so neither faults.
//
// Action
//   See Strategy above. The sentinel value 0xA5 is arbitrary; any
//   non-zero pattern that survives a fresh page_frame's zero-fill
//   suffices to detect a stale-or-unmapped page.
//
// Assertions
//   1: setup failed — create_page_frame, create_var, or map_pf
//      returned an error in v1. (All three are required for the probe
//      to be meaningful; folding them into one id keeps the smoke's
//      surface narrow.)
//   2: byte didn't round-trip — VAR.base[0] read back a value other
//      than the sentinel. Indicates the page_frame is not actually
//      reachable through VAR.base + 0, or is mapped with stale /
//      unrelated contents.
//
// Faithful-test note
//   A faithful test 12 would mint at least one page_frame per
//   intersection cell (e.g. {r}, {w}, {r,w}, no-perm) and one VAR
//   per cur_rwx variant, then for each cell:
//     - install the page_frame at offset 0;
//     - attempt the access types implied by the cell;
//     - for "allowed" access types, verify success + content fidelity;
//     - for "denied" access types, install a CPU exception handler
//       on the test EC that catches #PF, advances RIP past the
//       offending instruction, and records the fault; verify the
//       handler fired exactly the expected number of times.
//   The handler hook is the gating runner extension: it has to plumb
//   the kernel's IDT delivery into a test-visible callback before the
//   denied-arm assertions can run.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: page_frame with caps={r, w}. No x — the VAR is also
    // non-executable (caps.x=0), so the intersection along x is
    // trivially 0. The r and w bits are what test 12 asserts about.
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

    // Step 2: regular VAR with caps={r, w} and cur_rwx = r|w. By
    // §[var] line 877 the VAR starts in `map = 0` because no explicit
    // mapping was supplied. caps.mmio=0 and caps.dma=0, so this is the
    // CPU-mapped path that test 12 governs.
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
    // 11, `map` transitions 0 -> 1. Per the rule under test, effective
    // permissions on VAR.base[0..4096] become (cur_rwx) ∩ (pf.caps r/w/x)
    // = (r|w) ∩ (r|w) = r|w.
    const mr = syscall.mapPf(var_handle, &.{ 0, pf_handle });
    if (mr.v1 != 0) {
        testing.fail(1);
        return;
    }

    // Step 4: write + read at VAR.base[0]. Both accesses use the
    // effective r|w computed above; neither should fault. The sentinel
    // 0xA5 is non-zero so it can't collide with the page_frame's
    // initial zero-fill. The reads/writes go through a volatile cast
    // so the optimizer can't constant-fold the round-trip away.
    const dst: *volatile u8 = @ptrFromInt(var_base);
    dst.* = 0xA5;
    const got = dst.*;
    if (got != 0xA5) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
