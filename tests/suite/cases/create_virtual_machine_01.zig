// Spec §[create_virtual_machine] — test 01.
//
// "[test 01] returns E_PERM if the caller's self-handle lacks `crvm`."
//
// Spec semantics
//   §[create_virtual_machine]: "Self-handle cap required: `crvm`."
//   §[restrict]: "Reduces the caps on a handle in place. The new caps
//   must be a subset of the current caps. No self-handle cap is
//   required — reducing authority never requires authority." Restrict
//   on the self-handle is therefore a legal way for a domain to drop
//   bits from its own SelfCap without spawning a child domain.
//
// Strategy
//   The runner mints each test's child capability domain with a
//   SelfCap that includes `crvm` (see runner/primary.zig — the child
//   needs crvm to construct VM handles tested elsewhere in the
//   suite). To exercise the missing-`crvm` failure path, the test
//   itself must drop `crvm` from its self-handle before calling
//   create_virtual_machine.
//
//   `restrict` lets a domain reduce its own SelfCap caps in place.
//   The new caps must be a bitwise subset of the current caps, so we
//   compute the reduced SelfCap by copying the runner's grant and
//   clearing only the `crvm` bit. All other bits remain set, so the
//   subset check passes and the only behavioural change is `crvm`
//   becoming 0. After the restrict succeeds, create_virtual_machine
//   must return E_PERM per the cap-required rule.
//
// Action
//   1. restrict(SLOT_SELF, runner_caps_minus_crvm) — must succeed.
//   2. create_virtual_machine(caps=VmCap{}, policy_pf=0)
//      — must return E_PERM.
//
// Assertions
//   1: restrict returned a non-zero error word (failed to drop crvm).
//   2: create_virtual_machine returned something other than E_PERM.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Mirror runner/primary.zig's child_self grant exactly, with
    // `crvm` cleared. Every other bit must stay set so the bitwise
    // subset check in `restrict` (§[restrict] test 02) accepts the
    // reduction. `pri` is a 2-bit numeric field on SelfCap; restrict's
    // bitwise subset rule applies to it as well, so we keep pri = 3
    // (matching the runner).
    const reduced = caps.SelfCap{
        .crcd = true,
        .crec = true,
        .crvr = true,
        .crpf = true,
        .crvm = false, // <-- the bit under test
        .crpt = true,
        .pmu = true,
        .fut_wake = true,
        .timer = true,
        .pri = 3,
    };

    const restrict_result = syscall.restrict(
        caps.SLOT_SELF,
        @as(u64, reduced.toU16()),
    );
    if (restrict_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    // §[virtual_machine] VmCap layout: policy = bit 0, restart_policy
    // = bit 1; reserved bits clean. policy_pf = 0 — the cap check in
    // create_virtual_machine is gated on the self-handle's `crvm` bit
    // and runs before any page-frame-handle validation, so the
    // not-a-valid-page-frame outcome is only reachable when the cap
    // check passes. With `crvm` cleared the kernel must short-circuit
    // to E_PERM.
    const vm_caps = caps.VmCap{};
    const result = syscall.createVirtualMachine(
        @as(u64, vm_caps.toU16()),
        0,
    );

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
