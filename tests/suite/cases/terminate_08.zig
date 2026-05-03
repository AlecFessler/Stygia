// Spec §[execution_context] terminate — test 08.
//
// "[test 08] when [1] is a valid handle, [1]'s field0 and field1 are
//  refreshed from the kernel's authoritative state as a side effect,
//  regardless of whether the call returns success or another error
//  code."
//
// Strategy
//   §[execution_context] field layout:
//     field0 bits 0-1   = pri (current scheduling priority)
//     field1 bits 0-63  = affinity (current core mask)
//   Both are kernel-mutable snapshots. The implicit-sync side effect
//   on any syscall taking the handle is what this test validates.
//
//   The success path of `terminate` consumes the handle (test 05:
//   subsequent syscalls return E_TERM and the slot is released), so
//   the post-call cap-table read would not see a refreshed snapshot
//   on success. We therefore drive the assertion through a
//   well-defined error path instead — which the spec line covers
//   verbatim ("regardless of whether the call returns success or
//   another error code"). E_PERM is the cleanest such path: mint the
//   target EC without the `term` cap so terminate must reject under
//   test 02.
//
//   The runner spawns the test domain with `crec` and pri=3 in the
//   self-handle, plus ec_inner_ceiling = 0xFF (every EC cap bit
//   below restart_policy permitted). We mint the target EC with
//   priority = 2 (non-zero, within ceiling) and affinity = 1 (core 0
//   only). Caps include `susp` only — explicitly NOT `term` — so
//   terminate against this handle hits E_PERM per §[terminate]
//   test 02.
//
//   The new EC begins executing at `dummyEntry` which halts forever;
//   it never mutates its own pri or affinity, so the kernel's
//   authoritative state for those fields stays at the values we
//   passed at creation time. After the failed `terminate` call, the
//   handle's field0 must equal pri (= 2) and field1 must equal the
//   affinity mask we supplied (= 1). Reading directly from the
//   read-only cap-table mapping (no intervening syscall) is the way
//   to observe the refreshed snapshot the spec line names.
//
// Action
//   1. create_execution_context(target=self, caps={susp,rp=0},
//                               pri=2, affinity=0x1)         — must succeed
//   2. terminate(ec)                                          — must return E_PERM
//   3. readCap(cap_table_base, ec).field0 bits 0-1            — must equal 2
//   4. readCap(cap_table_base, ec).field1                     — must equal 0x1
//
// Assertions
//   1: setup syscall failed (create_execution_context returned an error)
//   2: terminate did not return E_PERM (test 02 path is the in-bounds trigger)
//   3: post-call field0's pri does not equal the priority we set
//   4: post-call field1 does not equal the affinity we set

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    // Mint an EC without the `term` cap so terminate hits E_PERM.
    // restart_policy = 0 keeps the create within the inner ceiling.
    const initial = caps.EcCap{
        .susp = true,
        .restart_policy = 0,
    };
    // §[create_execution_context] caps word:
    //   bits  0-15 caps          (caps on the returned handle)
    //   bits 16-31 target_caps   (ignored when target = self)
    //   bits 32-33 priority      (0-3, bounded by caller's priority ceiling)
    const target_priority: u64 = 2;
    const caps_word: u64 = @as(u64, initial.toU16()) | (target_priority << 32);
    const target_affinity: u64 = 0x1; // core 0 only

    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages — nonzero per test 08 of create_execution_context
        0, // target = self
        target_affinity,
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(1);
        return;
    }
    const ec_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // The handle lacks `term`, so terminate must reject with E_PERM
    // (§[terminate] test 02). The handle is still valid, so the
    // refresh side-effect this test asserts must apply.
    const result = syscall.terminate(ec_handle);
    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    // The cap-table mapping is read-only userspace memory; the kernel
    // wrote the refreshed snapshot before returning. Reading directly
    // bypasses any further syscall (which would itself trigger another
    // implicit refresh), so this read observes exactly the snapshot
    // terminate's side effect left in place.
    const cap = caps.readCap(cap_table_base, ec_handle);

    const observed_pri: u64 = cap.field0 & 0x3;
    if (observed_pri != target_priority) {
        testing.fail(3);
        return;
    }

    if (cap.field1 != target_affinity) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
