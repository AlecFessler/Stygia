// Spec §[snapshot] — test 07.
//
// "[test 07] calling `snapshot` a second time on the same target
//  replaces the prior source binding."
//
// DEGRADED SMOKE VARIANT
//   The spec assertion is that the *prior* source binding is replaced
//   by the new one. Verifying that replacement directly requires
//   inspecting the kernel-internal target -> source binding, which is
//   not reflected in any observable userspace handle field: §[var]
//   field0/field1 layout exposes the VAR's own state (base, page_count,
//   sz, cch, cur_rwx, map, device) but does not surface the snapshot
//   binding pointer. The only spec-observable signal that the binding
//   was actually rewired is downstream restart behavior — §[snapshot]
//   tests 09/10/11 exercise that path — and the v0 testing harness has
//   no facility to drive a domain restart from inside a single test
//   ELF and re-observe the post-restart state.
//
//   This smoke variant therefore asserts only the call-shape claim:
//   issuing snapshot([1]=target, [2]=source_b) after a successful
//   snapshot([1]=target, [2]=source_a) does not reject the second
//   call. A correct kernel must accept the second call (because the
//   spec says it replaces the prior binding rather than returning,
//   e.g., E_BUSY for "already bound"); a broken kernel that refused
//   second-bind would surface here as the second snapshot returning a
//   non-OK error code. The binding-replacement semantic itself is
//   deferred to the restart-driven tests that need a richer harness.
//
// Strategy
//   The runner spawns each test as a child capability domain with
//   var_inner_ceiling permitting r/w and var_restart_max = 3
//   (snapshot) — see restart_semantics_02.zig for the precedent. So
//   we can mint:
//     var1 — target, caps.restart_policy = 3 (snapshot), pages = 1
//     var2 — source A, caps.restart_policy = 2 (preserve), pages = 1
//     var3 — source B, caps.restart_policy = 2 (preserve), pages = 1
//   All three use props.sz = 0 (4 KiB) so size matching for §[snapshot]
//   test 05 holds (page_count × sz equal across all three).
//
//   Per §[snapshot] [1] must have caps.restart_policy = 3 and [2]
//   must have caps.restart_policy = 2; sizes must match; reserved
//   bits must be zero; both must be valid VAR handles. The minimum
//   caps in caps.r/w (we set r and w on each) keep §[create_var]
//   tests 02-13 from rejecting either VAR.
//
// Action
//   1. createVar(target,   caps={r,w,restart_policy=3}, props=0b011, 1 page) — var1.
//   2. createVar(source A, caps={r,w,restart_policy=2}, props=0b011, 1 page) — var2.
//   3. createVar(source B, caps={r,w,restart_policy=2}, props=0b011, 1 page) — var3.
//   4. snapshot(var1, var2) — must return OK (binds A as the source).
//   5. snapshot(var1, var3) — must return OK (replaces A with B).
//
// Assertions
//   1: any of the three createVar calls returned an error code
//      (setup precondition broken).
//   2: the first snapshot(var1, var2) returned a non-OK error
//      (precondition for the replacement test under test).
//   3: the second snapshot(var1, var3) returned a non-OK error —
//      the spec assertion under test failed (kernel rejected the
//      replacement bind that the spec requires to succeed).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// §[create_var] props: cur_rwx in bits 0-2, sz in bits 3-4, cch in
// bits 5-6. cur_rwx = r|w = 0b011; sz = 0 (4 KiB); cch = 0 (wb). All
// three VARs use the same props so their sizes (page_count × sz)
// match for §[snapshot] test 05.
const PROPS: u64 = 0b011;
const PAGES: u64 = 1;

fn createTargetVar() ?caps.HandleId {
    const c = caps.VarCap{
        .r = true,
        .w = true,
        .restart_policy = 3, // snapshot — required for §[snapshot] [1]
    };
    const r = syscall.createVar(@as(u64, c.toU16()), PROPS, PAGES, 0, 0);
    if (testing.isHandleError(r.v1)) return null;
    return @as(caps.HandleId, @truncate(r.v1 & 0xFFF));
}

fn createSourceVar() ?caps.HandleId {
    const c = caps.VarCap{
        .r = true,
        .w = true,
        .restart_policy = 2, // preserve — required for §[snapshot] [2]
    };
    const r = syscall.createVar(@as(u64, c.toU16()), PROPS, PAGES, 0, 0);
    if (testing.isHandleError(r.v1)) return null;
    return @as(caps.HandleId, @truncate(r.v1 & 0xFFF));
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const target = createTargetVar() orelse {
        testing.fail(1);
        return;
    };
    const source_a = createSourceVar() orelse {
        testing.fail(1);
        return;
    };
    const source_b = createSourceVar() orelse {
        testing.fail(1);
        return;
    };

    // First bind: target ← source_a. Must succeed; this establishes
    // the prior binding the second call is meant to replace.
    const r_first = syscall.snapshot(target, source_a);
    if (errors.isError(r_first.v1)) {
        testing.fail(2);
        return;
    }

    // Second bind on the same target with a different source. Per
    // §[snapshot] test 07, this must succeed and replace the prior
    // binding rather than returning E_BUSY or otherwise rejecting.
    const r_second = syscall.snapshot(target, source_b);
    if (errors.isError(r_second.v1)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
