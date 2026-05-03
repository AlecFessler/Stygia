// Spec §[restart_semantics] restart_semantics — test 02.
//
// "[test 02] returns E_PERM if `create_var` is called with
//  caps.restart_policy exceeding the calling domain's
//  restart_policy_ceiling.var_restart_max."
//
// DEGRADED SMOKE VARIANT
//   The strict E_PERM path here requires the calling domain's
//   `restart_policy_ceiling.var_restart_max` to be strictly less than
//   some value of `caps.restart_policy` we can pass to `create_var`.
//   `restart_policy` on a VAR cap is a 2-bit numeric enum (0..3); the
//   primary runner spawns each test as a child capability domain with
//   `restart_policy_ceiling.var_restart_max = 3` (snapshot, the
//   maximum-privilege value — see runner/primary.zig's
//   `ceilings_outer = 0x...03FE...`). With the ceiling at the field's
//   maximum representable value, no `caps.restart_policy` value can
//   exceed it, so the E_PERM branch is structurally unreachable from
//   inside the child without first spawning a *nested* sub-domain
//   with a reduced ceiling — which would require either embedding a
//   second ELF or extending the runner to host nested sub-tests.
//
//   The faithful version is therefore deferred until the runner gains
//   nested-domain support. This smoke variant instead asserts the
//   complementary positive observation: a `create_var` with
//   `caps.restart_policy = 3` (snapshot — the ceiling value, not
//   exceeding it) does NOT return E_PERM. That confirms the kernel's
//   ceiling-enforcement code at this site is keyed on *exceeding* and
//   not on *equaling*, which is the closest black-box check we can do
//   with the runner as it stands.
//
// Strategy
//   create_var with caps = { r, w, restart_policy = 3 (snapshot) }
//   and minimum-viable props to clear every other create_var failure
//   path. The relevant exclusions, drawn from §[create_var]:
//     - caps.r = caps.w = true, no x/mmio/dma — within the runner's
//       var_inner_ceiling = 0x01FF (test 01-04 don't fire).
//     - props.cur_rwx = 0b011 (r|w) — subset of caps.r/w/x (test 16).
//     - props.sz = 0 (4 KiB), caps.max_sz = 0 — no sz mismatch
//       (tests 07, 09, 10).
//     - props.cch = 0 (wb).
//     - pages = 1 — nonzero (test 05).
//     - preferred_base = 0 — kernel chooses (test 06 inert).
//     - device_region = 0 — ignored when caps.dma = 0.
//     - caps.restart_policy = 3 (snapshot) — equals, does not exceed,
//       the runner-granted var_restart_max ceiling of 3.
//
// Action
//   1. create_var(caps={r, w, restart_policy=3}, props={cur_rwx=r|w}, ...)
//
// Assertion
//   1: create_var returned E_PERM (the smoke variant's negative
//      observation: ceiling-equal must not reject).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const var_caps = caps.VarCap{
        .r = true,
        .w = true,
        .restart_policy = 3, // snapshot — equals var_restart_max ceiling
    };
    // §[create_var] props word: cur_rwx in bits 0-2, sz in bits 3-4,
    // cch in bits 5-6. cur_rwx = r|w = 0b011; sz = 0 (4 KiB); cch = 0 (wb).
    const props: u64 = 0b011;
    const result = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        1, // pages
        0, // preferred_base — kernel chooses
        0, // device_region — ignored when caps.dma = 0
    );

    if (result.v1 == @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
