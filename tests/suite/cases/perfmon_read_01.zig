// Spec §[perfmon_read] — test 01.
//
// "[test 01] returns E_PERM if the caller's self-handle lacks `pmu`."
//
// Strategy
//   The runner's primary gives every test domain a self-handle with
//   `pmu = true` (see runner/primary.zig, child_self). To force the
//   perfmon_read E_PERM path we must drop the `pmu` bit on the
//   self-handle before invoking the syscall.
//
//   perfmon_read takes an EC handle in [1], so we also need a valid
//   EC handle to feed in — otherwise the call would short-circuit on
//   test 02's E_BADCAP gate. We mint a fresh EC into our own domain
//   via `create_execution_context(target = self)`. The runner grants
//   `crec` on the test domain's self-handle, so creation succeeds
//   without any pmu involvement.
//
//   Once we hold a valid EC handle, we read the current self-handle
//   caps verbatim out of the read-only-mapped cap table, clear bit 6
//   (`pmu`), and write that reduced word back via §[restrict]. Most
//   SelfCap fields use plain bitwise subset semantics; the spec only
//   pins numeric restart_policy ordering for EC and VAR handles
//   (§[capabilities] restrict tests 03/04). Every other bit stays
//   identical, so neither the bitwise subset check nor any
//   reserved-bit rejection can fire — restrict must succeed, and the
//   only spec-mandated outcome of the subsequent perfmon_read call
//   is E_PERM.
//
// Action
//   1. create_execution_context(...) — mint a valid EC handle.
//   2. read self-handle caps from slot 0 of the cap table.
//   3. restrict(self, caps & ~pmu) — must succeed.
//   4. perfmon_read(ec) — must return E_PERM.
//
// Assertions
//   1: setup precondition violated — either the EC mint failed (so
//      we have no valid handle to feed perfmon_read), or the
//      self-handle did not actually carry `pmu` to begin with
//      (runner contract broken)
//   2: restrict failed when dropping the pmu bit
//   3: perfmon_read returned something other than E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const PMU_BIT: u16 = 1 << 6;

pub fn main(cap_table_base: u64) void {
    // Mint a valid EC handle so [1] is not E_BADCAP. EC creation
    // requires only `crec` on the self-handle, which the runner
    // grants — no pmu involvement here.
    const ec_caps = caps.EcCap{ .restart_policy = 0 };
    const caps_word: u64 = @as(u64, ec_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages — nonzero
        0, // target = self — mint into the caller's domain
        0, // affinity = 0 — any core
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(1);
        return;
    }
    const ec_handle: u12 = @truncate(cec.v1 & 0xFFF);

    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    const cur_caps: u16 = self_cap.caps();

    if ((cur_caps & PMU_BIT) == 0) {
        testing.fail(1);
        return;
    }

    const reduced_caps: u16 = cur_caps & ~PMU_BIT;
    const restrict_result = syscall.restrict(caps.SLOT_SELF, @as(u64, reduced_caps));
    if (restrict_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    const result = syscall.perfmonRead(ec_handle);
    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
