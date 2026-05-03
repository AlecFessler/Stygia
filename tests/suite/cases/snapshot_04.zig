// Spec §[snapshot] — test 04.
//
// "[test 04] returns E_INVAL if [2].caps.restart_policy is not 2
//  (preserve)."
//
// Strategy
//   §[snapshot] requires the source VAR ([2]) to carry
//   `caps.restart_policy = 2` (preserve). Per §[var] VarCap layout
//   `restart_policy` lives at bits 9-10 with values
//     0=free / 1=decommit / 2=preserve / 3=snapshot.
//   Anything other than `2` on the source must surface E_INVAL at
//   this gate.
//
//   To isolate test 04 from the surrounding snapshot prelude we
//   defeat tests 01/02/03/05/06 by construction:
//     - test 01 (target [1] not a valid VAR) — pass a freshly-minted
//       VAR handle.
//     - test 02 (source [2] not a valid VAR) — same.
//     - test 03 (target.caps.restart_policy != 3) — mint the target
//       with `restart_policy = 3` (snapshot). Per §[create_capability_domain]
//       test 07's notes, the runner's `restart_policy_ceiling.var_restart_max`
//       = 3, so this is permitted.
//     - test 05 ([1] and [2] sizes differ) — both VARs are
//       `pages = 1, sz = 0` (one 4 KiB page each).
//     - test 06 (reserved bits in [1] or [2]) — `syscall.snapshot`
//       is invoked with bare 12-bit handle ids, so the upper bits of
//       the syscall words are zero by construction.
//
//   With every other gate inert, the only remaining cause of E_INVAL
//   is the source's `restart_policy` ≠ 2. We mint the source with
//   default VarCap values (`restart_policy = 0`, i.e. `free`), which
//   is unambiguously not 2.
//
// Action
//   1. createVar(caps={r, w, restart_policy=3}, props=0b011, pages=1)
//      → target VAR with `restart_policy = snapshot`.
//   2. createVar(caps={r, w}, props=0b011, pages=1)
//      → source VAR with default `restart_policy = 0` (free).
//   3. snapshot(target, source) — must return E_INVAL because the
//      source's `restart_policy` is 0, not 2.
//
// Assertion
//   1: snapshot did not return E_INVAL when [2].caps.restart_policy
//      != 2.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: target VAR with caps.restart_policy = 3 (snapshot). The
    // VarCap layout puts restart_policy at bits 9-10. r|w gives the
    // VAR the same effective surface as the source (sizes and shape
    // match) but the cap bits themselves do not enter the test 04
    // gate — only the source's restart_policy does.
    const target_caps = caps.VarCap{
        .r = true,
        .w = true,
        .restart_policy = 3, // snapshot — defeats §[snapshot] test 03.
    };
    const target_props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0
    const ctarget = syscall.createVar(
        @as(u64, target_caps.toU16()),
        target_props,
        1, // pages = 1
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(ctarget.v1)) {
        // Prelude broke; cannot exercise the test 04 gate without
        // a snapshot-policy target. Surface as the spec assertion.
        testing.fail(1);
        return;
    }
    const target_handle: caps.HandleId = @truncate(ctarget.v1 & 0xFFF);

    // Step 2: source VAR with default restart_policy = 0 (free) —
    // any value other than 2 fires §[snapshot] test 04. Same size
    // (pages=1, sz=0) as the target so test 05 stays inert.
    const source_caps = caps.VarCap{
        .r = true,
        .w = true,
        // restart_policy left at default 0 — explicitly NOT 2.
    };
    const source_props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0
    const csource = syscall.createVar(
        @as(u64, source_caps.toU16()),
        source_props,
        1, // pages = 1 (matches target → test 05 inert)
        0, // preferred_base = kernel chooses
        0, // device_region = unused
    );
    if (testing.isHandleError(csource.v1)) {
        testing.fail(1);
        return;
    }
    const source_handle: caps.HandleId = @truncate(csource.v1 & 0xFFF);

    // Step 3: snapshot(target, source). Source's restart_policy is 0,
    // not 2 (preserve), so §[snapshot] test 04 must surface E_INVAL.
    const result = syscall.snapshot(target_handle, source_handle);

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
