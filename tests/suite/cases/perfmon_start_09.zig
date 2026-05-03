// Spec §[perfmon_start] perfmon_start — test 09.
//
// "[test 09] when [1] is a valid handle, [1]'s field0 and field1 are
//  refreshed from the kernel's authoritative state as a side effect,
//  regardless of whether the call returns success or another error
//  code."
//
// Strategy
//   §[capabilities]: "Any syscall that takes such a handle implicitly
//   refreshes that handle's snapshot from the authoritative kernel
//   state as a side effect." For an EC handle (§[execution_context])
//   field0 bits 0-1 carry the priority and field1 bits 0-63 carry the
//   affinity mask. The `perfmon_start` syscall takes [1] as an EC
//   handle, so the implicit-sync rule applies whenever [1] is valid.
//
//   The strong-form spec assertion needs two distinguishing snapshots
//   — one taken before the implicit refresh and one taken after, with
//   the kernel's authoritative state having drifted in between. That
//   requires two cap-table slots aliasing the same EC (so an
//   operation on slot A leaves slot B stale until something touches
//   B), which in turn needs an `acquire_ecs` round-trip into a
//   sibling capability domain. The current test runner spawns each
//   test as a single-domain child with no sibling, so the alias-slot
//   path is not yet wired.
//
//   The single-domain limitation: with only one slot per EC, an
//   implementation that simply leaves the slot untouched on either
//   path would still pass any field-equality check, because the slot
//   is in sync from creation. The strongest assertion we can make
//   locally is: after `perfmon_start`, the holder's field0/field1
//   match the kernel-authoritative state observed via an immediately
//   following `sync`. That catches any implementation that
//   *clobbers* the snapshot during perfmon_start (e.g., zeroing the
//   field on the E_INVAL path before the bounds check rejects), and
//   pins the post-call snapshot to the same authoritative state
//   `sync` would expose.
//
//   We pick the E_INVAL arm — `num_configs = 999`, well beyond the
//   `num_counters` ceiling for any real PMU, so test 03 fires. The
//   spec test 09 explicitly extends the implicit-sync rule to "any
//   error code" so we can use it to exercise an error-path refresh
//   simultaneously with the success-path field-stability check.
//   Setup neutralizes the other failure paths so test 09 is the only
//   spec assertion exercised:
//     - self-handle has `pmu` (runner contract), so test 01 cannot
//       fire.
//     - [1] is a freshly-minted EC handle, so test 02 cannot fire.
//     - All configs slots are zero; with num_configs = 999 the
//       num_counters check (test 03) fires before any per-config
//       checks (tests 04/05/06) can.
//     - The target is the calling EC, so the suspended-target check
//       (test 07) cannot fire.
//
// Action
//   1. create_execution_context(caps={susp, term} | (priority=2 << 32),
//      entry=&dummy, stack_pages=1, target=0, affinity=1)
//                                                — must succeed
//   2. perfmon_start(ec, num_configs=999, configs=&{})
//                                                — must return E_INVAL
//   3. readCap(ec) → after_start_field0/field1
//   4. sync(ec)                                  — must return OK
//   5. readCap(ec) → after_sync_field0/field1
//   6. assert after_start_field0 == after_sync_field0
//      and after_start_field1 == after_sync_field1
//
// Assertions
//   1: create_execution_context returned an error word in vreg 1
//   2: perfmon_start with num_configs > num_counters did not return
//      E_INVAL
//   3: sync on the EC handle did not return OK
//   4: post-perfmon_start field0 does not match the post-sync
//      authoritative snapshot, meaning perfmon_start either failed
//      to refresh field0 or clobbered it on the failure path
//   5: post-perfmon_start field1 does not match the post-sync
//      authoritative snapshot, meaning perfmon_start either failed
//      to refresh field1 or clobbered it on the failure path

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    // §[create_execution_context] caps word: caps in bits 0-15,
    // target_caps in 16-31 (ignored when target=self), priority in
    // 32-33. Seed priority = 2 and affinity = 1 (core 0 only) so the
    // authoritative kernel state for this EC has non-zero, single-bit
    // distinguishing values in both field0 and field1 — any
    // implementation that zeroed the snapshot on the E_INVAL path
    // would observably diverge from the post-sync read.
    const ec_caps = caps.EcCap{
        .susp = true,
        .term = true,
    };
    const seeded_priority: u64 = 2;
    const caps_word: u64 =
        @as(u64, ec_caps.toU16()) |
        (seeded_priority << 32);
    const seeded_affinity: u64 = 1;

    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages
        0, // target = self
        seeded_affinity,
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(1);
        return;
    }
    const ec_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // §[perfmon_start] test 03: num_configs = 0 or > num_counters
    // returns E_INVAL. 999 is well beyond the 8-bit num_counters
    // ceiling (§[perfmon_info] caps word bits 0-7), so the bounds
    // check fires unconditionally regardless of the host PMU.
    // configs is empty — reading a config word with num_configs=999
    // would require a stack frame the kernel never reaches because
    // the bounds check is the first failure mode after [1] is
    // validated.
    const configs = [_]u64{};
    const result = syscall.perfmonStart(ec_handle, 999, &configs);
    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    // §[capabilities]: the implicit-sync side effect of perfmon_start
    // (test 09) must have run during the E_INVAL call above, so this
    // read sees the kernel's authoritative state regardless of the
    // failure return.
    const after_start = caps.readCap(cap_table_base, ec_handle);

    // sync on the same handle is the explicit equivalent of the
    // implicit-sync side effect (§[capabilities] sync test 03). With
    // no other syscall in between to mutate authoritative state, an
    // implementation that correctly refreshed the snapshot on the
    // perfmon_start path will observe field0/field1 unchanged here;
    // the comparison pins the post-perfmon_start snapshot to the
    // same authoritative-state value sync would expose.
    const sync_result = syscall.sync(ec_handle);
    if (sync_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }
    const after_sync = caps.readCap(cap_table_base, ec_handle);

    if (after_start.field0 != after_sync.field0) {
        testing.fail(4);
        return;
    }
    if (after_start.field1 != after_sync.field1) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
