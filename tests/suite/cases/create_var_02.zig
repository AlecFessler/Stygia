// Spec §[create_var] create_var — test 02.
//
// "[test 02] returns E_PERM if caps' r/w/x bits are not a subset of the
//  caller's `var_inner_ceiling`'s r/w/x bits."
//
// DEGRADED SMOKE VARIANT
//   The strict E_PERM path here requires the caller's
//   `var_inner_ceiling` (self-handle field0 bits 8-23) to have at least
//   one of r/w/x cleared so that we can pass a caps word with that bit
//   set and trip the subset check. The runner primary spawns each test
//   as a child capability domain with `var_inner_ceiling = 0x01FF`
//   (every defined bit set: move, copy, r, w, x, mmio, max_sz, dma —
//   see runner/primary.zig's `ceilings_inner = 0x001C_011F_3F01_FFFF`).
//   With every r/w/x bit already permitted by the ceiling, the
//   strict-superset case is unconstructible from inside this domain.
//
//   The faithful test would either (a) require a per-test override of
//   the runner-supplied `var_inner_ceiling` (so the test child is born
//   with one of r/w/x cleared), or (b) extend the test to spawn a
//   nested sub-domain with reduced ceilings and observe its
//   `create_var` attempt fail. Neither path exists in the v0 runner;
//   `restrict` cannot lower ceilings (it only tightens caps).
//
//   This smoke variant instead asserts the complementary positive
//   observation: a `create_var` whose caps r/w/x bits are *exactly* the
//   subset of the caller's `var_inner_ceiling` (read from slot 0)
//   does NOT return E_PERM via the test-02 subset rule. That confirms
//   the kernel's ceiling-enforcement code at this site is keyed on
//   *non-subset* and not on *equality*, which is the closest black-box
//   check available with the runner as it stands.
//
// Strategy
//   1. Read self-handle field0 from slot 0; extract var_inner_ceiling
//      bits 8-23 and mask out the r/w/x bits (VarCap bits 2..4).
//   2. Build a `VarCap` whose r/w/x bits exactly mirror the ceiling's
//      r/w/x bits — no other VAR-specific bits set so unrelated tests
//      (07/08/11/12/13/14/15/17) don't fire.
//   3. Pick props.cur_rwx = the same r/w/x bits so test 16 (cur_rwx
//      not a subset of caps r/w/x) doesn't fire.
//   4. pages = 1 (test 05 inert), preferred_base = 0 (test 06 inert),
//      device_region = 0 (ignored when caps.dma = 0), props.sz = 0,
//      props.cch = 0.
//   5. Call create_var. The exact-subset r/w/x must not surface E_PERM.
//
// GAP
//   The strict-superset side of the rule (a caps r/w/x bit set that the
//   ceiling does NOT have) is left for the multi-level test infra
//   extension. Until the runner mints test domains with reduced
//   `var_inner_ceiling`, this file lives in the manifest as a smoke
//   test pinning only the subset-equal path.
//
// Assertion
//   1: create_var returned E_PERM (the smoke variant's negative
//      observation: a same-as-ceiling r/w/x must not reject).
//
// Faithful-test note
//   Faithful test deferred pending sub-domain plumbing in the runner
//   (so the test child is born with at least one of r/w/x cleared in
//   var_inner_ceiling). The current pass uses assertion id 0 — see the
//   `testing.pass()` call at the end.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    // §[capability_domain] self-handle field0 layout: var_inner_ceiling
    // at bits 8-23. Snapshot directly from slot 0 — `sync` is
    // unnecessary since ceilings are install-at-create and not
    // kernel-mutated thereafter.
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    const var_inner_ceiling: u64 = (self_cap.field0 >> 8) & 0xFFFF;

    // VarCap bits 2..4 are r/w/x. Extract just those bits from the
    // ceiling so the request is by construction a subset.
    const rwx_mask: u64 = 0b1_1100; // bits 2..4
    const ceiling_rwx: u64 = var_inner_ceiling & rwx_mask;

    // Compose a caps word with only the ceiling's r/w/x bits set. Other
    // VarCap bits (move/copy, mmio, max_sz, dma, restart_policy) stay
    // clear so unrelated test paths (03/04/07..15/17) don't fire.
    const caps_word: u64 = ceiling_rwx;

    // §[create_var] props word: cur_rwx in bits 0-2, sz in bits 3-4,
    // cch in bits 5-6. Map the caps r/w/x at bits 2..4 down to props
    // cur_rwx at bits 0..2 so cur_rwx is exactly caps' r/w/x — test 16
    // (cur_rwx not a subset of caps r/w/x) cannot fire. sz = 0 (4 KiB);
    // cch = 0 (wb).
    const cur_rwx: u64 = ceiling_rwx >> 2;
    const props: u64 = cur_rwx;

    const result = syscall.createVar(
        caps_word,
        props,
        1, // pages — nonzero (test 05 inert)
        0, // preferred_base — kernel chooses (test 06 inert)
        0, // device_region — ignored when caps.dma = 0
    );

    if (result.v1 == @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
