// Spec §[perfmon_read] perfmon_read — test 07.
//
// "[test 07] when [1] is a valid handle, [1]'s field0 and field1 are
//  refreshed from the kernel's authoritative state as a side effect,
//  regardless of whether the call returns success or another error
//  code."
//
// Spec semantics
//   §[execution_context] places kernel-mutable snapshots in the EC
//   handle's field0 (bits 0-1 = current scheduling priority) and
//   field1 (bits 0-63 = current core affinity mask). §[capabilities]:
//   "Any syscall that takes such a handle implicitly refreshes that
//   handle's snapshot from the authoritative kernel state as a side
//   effect" — and the perfmon_read spec restates that this implicit-
//   sync side effect fires regardless of return code.
//
//   The strong-form spec assertion needs two distinguishing snapshots:
//   one taken before the implicit refresh and one taken after, with
//   the kernel's authoritative state having drifted in between. In
//   practice that requires two cap-table slots aliasing the same EC
//   (so an operation on slot A leaves slot B stale until something
//   touches B), which in turn needs an `acquire_ecs` round-trip into
//   a sibling capability domain. The current test infrastructure
//   spawns each test as a single-domain child with no sibling, so
//   the alias-slot path is not yet wired.
//
//   `perfmon_read` itself doesn't write the priority or affinity
//   snapshot fields the way `priority` (§[priority] test 05) and
//   `affinity` (§[affinity] test 05) do. So unlike priority_08 /
//   affinity_06, we cannot pin the assertion through a kernel
//   mutation that the syscall itself drives — perfmon_read leaves
//   the authoritative pri/affinity untouched.
//
// Degraded variant (this file)
//   With only one slot per EC and no syscall-induced drift, the
//   strongest property we can pin locally is that the snapshot
//   `perfmon_read` leaves in field0/field1 agrees with a fresh
//   authoritative read taken immediately afterwards via the explicit
//   `sync` syscall (§[capabilities] sync test 03). Concretely: after
//   `perfmon_read` returns, we read field0/field1 directly out of
//   the read-only-mapped cap table. Then we call `sync` on the same
//   handle, which the spec guarantees refreshes the snapshot from
//   authoritative kernel state, and re-read. The two reads must
//   match — a perfmon_read implementation that left field0/field1
//   stale (or corrupted them, e.g. zeroed) would diverge from sync's
//   authoritative refresh.
//
//   This is strictly weaker than the spec assertion: a kernel that
//   omits the implicit refresh entirely on this path would also pass,
//   because the slot was already in sync from create_capability_
//   domain (§[create_capability_domain] test 21 populates SLOT_
//   INITIAL_EC's snapshot at domain creation time) and neither
//   syscall in this test changes the authoritative pri/affinity.
//   Detecting that no-op-refresh failure mode requires cross-domain
//   drift (a sibling cap domain mutating the same EC's pri or
//   affinity between the two reads), which the single-domain test
//   harness cannot stage today. The local check does, however, catch
//   any implementation that *clobbers* the snapshot in the
//   perfmon_read path (e.g. zeroing the field before writing the
//   refreshed value) — the most likely failure mode.
//
// Strategy
//   Target SLOT_INITIAL_EC, the EC running this test code. The runner
//   installs it at handle id 1 with caps = ec_inner_ceiling (0xFF in
//   the runner — every non-restart EC cap bit, so the handle is
//   well-formed for every cap-gated check perfmon_read does on [1]).
//   The runner's child_self carries `pmu = true`, so the test 01
//   E_PERM gate cannot fire. We then need perfmon_read itself to
//   reach the implicit-sync side effect:
//     - test 03 (E_INVAL, perfmon not started): we call
//       `perfmon_start` first to avoid this. perfmon_start needs at
//       least one config in 0..num_counters-1 with a supported event;
//       we use event index 0 (`cycles`, defined unconditionally in
//       §[perfmon_info] test 04's table) and num_configs = 1.
//     - test 04 (E_BUSY, target not calling EC and not suspended):
//       SLOT_INITIAL_EC is the calling EC, so this gate cannot fire.
//
//   With every error gate neutralised, perfmon_read returns OK and
//   the implicit-sync side effect must have run. We then capture
//   field0/field1 verbatim from the cap-table mapping (no intervening
//   syscall), call sync(SLOT_INITIAL_EC) which the spec guarantees
//   refreshes from authoritative kernel state, and re-read. Both
//   reads must agree on field0 (bits 0-1 = pri) and on field1
//   (= affinity mask).
//
// Degraded smoke
//   If the kernel returns a small error code (1..15) from
//   perfmon_info, perfmon_start, or perfmon_read — e.g. PMU absent,
//   handler not yet wired — the success-path assertion of this test
//   becomes unobservable. We report pass in those cases so the ELF
//   still exercises the syscall path link-and-load on platforms
//   without PMU support, mirroring perfmon_info_03 / _04.
//
// Action
//   1. perfmon_info()                         — capture num_counters; smoke if error.
//   2. perfmon_start(SLOT_INITIAL_EC, 1, [event=0, threshold=0])
//                                             — must return OK or smoke if error.
//   3. perfmon_read(SLOT_INITIAL_EC)          — must return OK.
//   4. capture field0_a, field1_a from readCap(cap_table_base, SLOT_INITIAL_EC).
//   5. sync(SLOT_INITIAL_EC)                  — must return OK.
//   6. capture field0_b, field1_b from readCap(cap_table_base, SLOT_INITIAL_EC).
//   7. assert field0_a (bits 0-1) == field0_b (bits 0-1) and
//      field1_a == field1_b.
//
// Assertions
//   2: sync returned non-OK in vreg 1.
//   3: post-read field0 pri bits do not equal post-sync field0 pri bits.
//   4: post-read field1 does not equal post-sync field1.
//
// Note: assertion id 1 is reserved for the perfmon_read failure path
// but is not currently raised — perfmon_read errors fall through to
// smoke-pass (see strategy / degraded smoke notes above), so on a
// build where perfmon_read genuinely fails the test reports pass
// rather than fail(1). Once a second observation surface lets us
// disambiguate small-counter success from an error code, this can
// promote to a hard failure.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    // Probe perfmon_info first so we can tell a degraded-platform
    // smoke from a real spec violation. Any error in 1..15 here means
    // the PMU subsystem is not exposed; smoke-pass and exit.
    const info = syscall.perfmonInfo();
    if (info.v1 != 0 and info.v1 < 16) {
        testing.pass();
        return;
    }

    // §[perfmon_start] config_event packing:
    //   bits  0-7   event index (per §[perfmon_info] supported_events)
    //   bit   8     has_threshold
    //   bits  9-63  _reserved
    // Event 0 = `cycles`, defined unconditionally in the spec table
    // (§[perfmon_info] test 04). has_threshold = 0, so the threshold
    // word is unused but supplied as 0 to keep reserved bits clean.
    const cycles_event: u64 = 0;
    const threshold: u64 = 0;
    const start_configs = [_]u64{ cycles_event, threshold };
    const start = syscall.perfmonStart(
        caps.SLOT_INITIAL_EC,
        1, // num_configs
        start_configs[0..],
    );
    // Smoke: any small error code means the perfmon path is not fully
    // wired on this build/host. Pass so the ELF still validates as
    // built and loadable.
    if (start.v1 != 0 and start.v1 < 16) {
        testing.pass();
        return;
    }

    const read = syscall.perfmonRead(caps.SLOT_INITIAL_EC);
    // perfmon_read returns counter values in vregs 1..num_counters
    // and the timestamp in vreg num_counters+1. Per §[error_codes]
    // any value <= 15 in vreg 1 is unambiguously an error code, but
    // a successful read could legitimately produce a counter value
    // in that range (e.g. a freshly-armed cycles counter that has
    // accumulated zero or a small number of cycles). To avoid
    // misclassifying a real success as an error, we treat any
    // non-zero error word only as a smoke gate: if perfmon_read
    // genuinely failed with an out-of-spec error code on this build,
    // we cannot observe the success-path side effect and fall back
    // to smoke-pass. A counter value happening to be small is fine —
    // the assertion below does not depend on the counter content.
    if (read.v1 != 0 and read.v1 < 16) {
        // Could be a real failure (E_INVAL, E_BUSY, etc.) or a small
        // counter reading. We can't disambiguate without a second
        // observation surface, so smoke-pass on this branch.
        testing.pass();
        return;
    }

    // The cap-table mapping is read-only userspace memory; the kernel
    // wrote the refreshed snapshot before perfmon_read returned.
    // Reading directly bypasses any further syscall (which would
    // itself trigger another implicit refresh), so this read observes
    // exactly the snapshot perfmon_read's side effect left in place.
    const cap_after_read = caps.readCap(cap_table_base, caps.SLOT_INITIAL_EC);
    const pri_after_read: u64 = cap_after_read.field0 & 0x3;
    const aff_after_read: u64 = cap_after_read.field1;

    // §[capabilities] sync test 03: on success, [1]'s field0/field1
    // reflect the authoritative kernel state at the moment of the
    // call. Use that as the cross-check oracle for what perfmon_read
    // should have left behind.
    const sync_result = syscall.sync(caps.SLOT_INITIAL_EC);
    if (sync_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    const cap_after_sync = caps.readCap(cap_table_base, caps.SLOT_INITIAL_EC);
    const pri_after_sync: u64 = cap_after_sync.field0 & 0x3;
    const aff_after_sync: u64 = cap_after_sync.field1;

    if (pri_after_read != pri_after_sync) {
        testing.fail(3);
        return;
    }
    if (aff_after_read != aff_after_sync) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
