// Spec §[create_vcpu] — test 01.
//
// "[test 01] returns E_PERM if the caller's self-handle lacks `crec`."
//
// Spec semantics
//   §[create_vcpu]: "Caps required: caller's self-handle must have
//   `crec`. Holding the VM handle implies the authority to spawn vCPUs
//   in it."
//   §[restrict]: "Reduces the caps on a handle in place. The new caps
//   must be a subset of the current caps. No self-handle cap is
//   required — reducing authority never requires authority." Restrict
//   on the self-handle is therefore a legal way for a domain to drop
//   bits from its own SelfCap without spawning a child domain.
//
// Strategy
//   The runner mints each test's child capability domain with a
//   SelfCap that includes `crec` (see runner/primary.zig — the child
//   needs crec to construct EC handles tested elsewhere in the
//   suite). To exercise the missing-`crec` failure path, the test
//   itself must drop `crec` from its self-handle before calling
//   create_vcpu.
//
//   `restrict` lets a domain reduce its own SelfCap caps in place.
//   The new caps must be a bitwise subset of the current caps, so we
//   compute the reduced SelfCap by copying the runner's grant and
//   clearing only the `crec` bit. All other bits remain set, so the
//   subset check passes and the only behavioural change is `crec`
//   becoming 0. After the restrict succeeds, create_vcpu must return
//   E_PERM per the cap-required rule.
//
// Action
//   1. restrict(SLOT_SELF, runner_caps_minus_crec) — must succeed.
//   2. create_vcpu(caps=EcCap{}, vm_handle=0, affinity=0, exit_port=0)
//      — must return E_PERM.
//
// Assertions
//   1: restrict returned a non-zero error word (failed to drop crec).
//   2: create_vcpu returned something other than E_PERM.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Mirror runner/primary.zig's child_self grant exactly, with
    // `crec` cleared. Every other bit must stay set so the bitwise
    // subset check in `restrict` (§[restrict] test 02) accepts the
    // reduction. `pri` is a 2-bit numeric field on SelfCap; restrict's
    // bitwise subset rule applies to it as well, so we keep pri = 3
    // (matching the runner).
    const reduced = caps.SelfCap{
        .crcd = true,
        .crec = false, // <-- the bit under test
        .crvr = true,
        .crpf = true,
        .crvm = true,
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

    // §[create_vcpu] caps layout: bits 0-15 = EcCap, bits 32-33 =
    // priority. EcCap{} = all bits clear, priority = 0; reserved bits
    // clean. vm_handle = 0, affinity = 0, exit_port = 0 — the cap
    // check on the self-handle's `crec` bit runs before any per-arg
    // validation (vm-handle lookup, port-handle lookup, affinity
    // mask), so the kernel must short-circuit to E_PERM regardless of
    // the values supplied for those arguments.
    const ec_caps = caps.EcCap{};
    const result = syscall.createVcpu(
        @as(u64, ec_caps.toU16()),
        0,
        0,
        0,
    );

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
