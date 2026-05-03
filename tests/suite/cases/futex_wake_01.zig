// Spec §[futex_wake] — test 01.
//
// "[test 01] returns E_PERM if the caller's self-handle lacks
// `fut_wake`."
//
// Spec semantics
//   §[futex_wake]: "Self-handle cap required: `fut_wake`."
//   §[restrict]: "Reduces the caps on a handle in place. The new caps
//   must be a subset of the current caps. No self-handle cap is
//   required — reducing authority never requires authority." Restrict
//   on the self-handle is a legal way for a domain to drop bits from
//   its own SelfCap.
//
// Strategy
//   The runner mints each test's child capability domain with a
//   SelfCap that includes `fut_wake` (see runner/primary.zig — the
//   child needs `fut_wake` to construct futex wake calls tested
//   elsewhere in the suite). To exercise the missing-`fut_wake`
//   failure path, the test itself must drop `fut_wake` from its
//   self-handle before calling futex_wake.
//
//   `restrict` lets a domain reduce its own SelfCap caps in place.
//   The new caps must be a bitwise subset of the current caps, so we
//   compute the reduced SelfCap by copying the runner's grant and
//   clearing only the `fut_wake` bit. All other bits remain set, so
//   the subset check passes and the only behavioural change is
//   `fut_wake` becoming 0. After the restrict succeeds, futex_wake
//   must return E_PERM per the cap-required rule.
//
// Action
//   1. restrict(SLOT_SELF, runner_caps_minus_fut_wake) — must succeed.
//   2. futex_wake(addr=&local, count=1) — must return E_PERM.
//
// Assertions
//   1: restrict returned a non-zero error word (failed to drop
//      fut_wake).
//   2: futex_wake returned something other than E_PERM.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Mirror runner/primary.zig's child_self grant exactly, with
    // `fut_wake` cleared. Every other bit must stay set so the
    // bitwise subset check in `restrict` (§[restrict] test 02)
    // accepts the reduction. `pri` is a 2-bit numeric field on
    // SelfCap; restrict's bitwise subset rule applies to it as well,
    // so we keep pri = 3 (matching the runner).
    const reduced = caps.SelfCap{
        .crcd = true,
        .crec = true,
        .crvr = true,
        .crpf = true,
        .crvm = true,
        .crpt = true,
        .pmu = true,
        .fut_wake = false, // <-- the bit under test
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

    // §[futex_wake]: addr must be 8-byte aligned and a valid user
    // address in the caller's domain. The cap check on `fut_wake` is
    // gated on the self-handle's `fut_wake` bit and runs before any
    // other validation (alignment, address validity), so neither
    // E_INVAL on alignment nor E_BADADDR on the address can preempt
    // it. We point at a local u64 (8-byte aligned, in our domain) and
    // pass count = 1 to keep all other inputs valid; with `fut_wake`
    // cleared the kernel must short-circuit to E_PERM.
    var local: u64 align(8) = 0;
    const result = syscall.futexWake(@intFromPtr(&local), 1);

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
