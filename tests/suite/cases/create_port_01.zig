// Spec §[create_port] — test 01.
//
// "[test 01] returns E_PERM if the caller's self-handle lacks `crpt`."
//
// Spec semantics
//   §[create_port]: "Self-handle cap required: `crpt`."
//   §[restrict]: "Reduces the caps on a handle in place. The new caps
//   must be a subset of the current caps. No self-handle cap is
//   required — reducing authority never requires authority." Restrict
//   on the self-handle is therefore a legal way for a domain to drop
//   bits from its own SelfCap without spawning a child domain.
//
// Strategy
//   The runner mints each test's child capability domain with a
//   SelfCap that includes `crpt` (see runner/primary.zig — the child
//   needs crpt to mint ports for itself in the create_port tests
//   exercising the success path and other failure modes). To exercise
//   the missing-`crpt` failure path, the test itself must drop `crpt`
//   from its self-handle before calling create_port.
//
//   `restrict` lets a domain reduce its own SelfCap caps in place.
//   The new caps must be a bitwise subset of the current caps, so we
//   compute the reduced SelfCap by copying the runner's grant and
//   clearing only the `crpt` bit. All other bits remain set, so the
//   subset check passes and the only behavioural change is `crpt`
//   becoming 0. After the restrict succeeds, create_port must return
//   E_PERM per the cap-required rule.
//
// Action
//   1. restrict(SLOT_SELF, runner_caps_minus_crpt) — must succeed.
//   2. create_port(caps=PortCap{bind,recv}) — must return E_PERM.
//
// Assertions
//   1: restrict returned a non-zero error word (failed to drop crpt).
//   2: create_port returned something other than E_PERM.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Mirror runner/primary.zig's child_self grant exactly, with
    // `crpt` cleared. Every other bit must stay set so the bitwise
    // subset check in `restrict` (§[restrict] test 02) accepts the
    // reduction. `pri` is a 2-bit numeric field on SelfCap; restrict's
    // bitwise subset rule applies to it as well, so we keep pri = 3
    // (matching the runner).
    const reduced = caps.SelfCap{
        .crcd = true,
        .crec = true,
        .crvr = true,
        .crpf = true,
        .crvm = true,
        .crpt = false, // <-- the bit under test
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

    // §[port] PortCap layout: bind = bit 4, recv = bit 3. Reserved
    // bits clean; restart_policy = 0. None of the per-arg validation
    // paths apply (all reserved bits clear, caps subset of the
    // runner's port_ceiling), so the only error the kernel can return
    // is the missing-`crpt` E_PERM under test.
    const port_caps = caps.PortCap{ .bind = true, .recv = true };
    const result = syscall.createPort(@as(u64, port_caps.toU16()));

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
