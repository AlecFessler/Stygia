// Spec §[affinity] affinity — test 05.
//
// "[test 05] on success, the target thread's affinity is set to [2]."
//
// Strategy
//   §[thread] field layout: field1 bits 0-63 carry the thread's
//   current 64-bit affinity mask. The `affinity` syscall mutates that
//   kernel-authoritative state, and per §[capabilities] the syscall
//   itself implicitly refreshes the [1] handle's field0/field1 snapshot
//   (also formalized as test 06 of this section). To be defensive
//   against any reordering of that side-effect, we additionally call
//   `sync` before reading the snapshot.
//
//   Mint a fresh thread with target=self so the handle lands directly in
//   our own table (slot returned by create_thread). Grant
//   the thread handle the `saff` cap so the affinity call's own cap check
//   (test 02) does not fire. Use an initial affinity mask of 0b0001
//   at create time, then call `affinity` with a different multi-bit
//   mask 0b0011 so the post-condition compare against the requested
//   mask is non-trivial (proves the kernel actually wrote the new
//   value rather than leaving the original in place).
//
//   Neutralize every other failure path so test 05 is the only spec
//   assertion exercised:
//     - target is a valid thread handle (just minted), so test 01 (BADCAP)
//       does not fire.
//     - target's caps include `saff`, so test 02 (PERM) does not fire.
//     - new_affinity bits 0-1 are inside the 4-core CI runner config,
//       so test 03 (out-of-range core) does not fire.
//     - reserved bits in [1] are clean (we pass a u12 through the
//       typed wrapper), so test 04 does not fire.
//
//   Pre-conditions on thread creation that must also pass:
//     - Caller already has `crec` on its self-handle (granted by the
//       runner via SelfCap.crec = true).
//     - caps = {saff, susp, term, restart_policy=0}, all within the
//       runner's child thread_inner_ceiling (0xFF, see runner/primary.zig
//       ceilings_inner).
//     - priority = 0, well under the runner's child priority ceiling
//       of 3.
//     - stack_pages = 1 (nonzero).
//     - create-time affinity 0b0001 is inside the 4-core system.
//     - reserved bits in the create caps word are clean.
//
// Action
//   1. create_thread(caps={saff,susp,term,rp=0},
//      entry=&dummyEntry, stack_pages=1, target=0,
//      affinity=0b0001)                                  — must succeed
//   2. affinity(thread_handle, 0b0011)                       — must succeed
//   3. sync(thread_handle)                                   — refresh field1
//   4. readCap(cap_table_base, thread_handle).field1 == 0b0011
//   5. affinity(SLOT_INITIAL_THREAD, 0b0010)                 — pin self to core 1
//   6. yieldThread(0)                                        — let scheduler re-pick
//   7. testing.currentCoreId() == 1                      — observe satisfaction
//
// Assertions
//   1: setup syscall failed (create_thread returned an error)
//   2: affinity itself returned non-OK
//   3: sync returned non-OK
//   4: post-sync field1 does not equal the requested affinity mask
//   5: self-affinity restriction returned non-OK
//   6: yield returned non-OK
//   7: post-yield core id is outside the new affinity mask, meaning the
//      scheduler did not honor the cap-driven restriction (this is the
//      end-to-end check that the affinity field actually steers
//      dispatch — without it the test only verifies the field0/field1
//      mirror, not the scheduler's run-queue selection)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const thread_caps = caps.ThreadCap{
        .saff = true,
        .susp = true,
        .term = true,
        .restart_policy = 0,
    };
    // §[create_thread] caps word: caps in bits 0-15,
    // target_caps in 16-31 (ignored when target=self), priority in
    // 32-33. priority=0 keeps the call within the child's pri ceiling.
    const caps_word: u64 = @as(u64, thread_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);

    // Cores 0-1 are inside the 4-core CI runner config so neither the
    // create-time test 09 nor the affinity-syscall test 03 can fire.
    const initial_affinity: u64 = 0b0001;
    const new_affinity: u64 = 0b0011;

    const cec = syscall.createThread(
        caps_word,
        entry,
        1,
        0,
        initial_affinity,
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(1);
        return;
    }
    const thread_handle: u12 = @truncate(cec.v1 & 0xFFF);

    const aff_result = syscall.affinity(thread_handle, new_affinity);
    if (aff_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    // Force a fresh kernel-authoritative refresh of the handle's
    // field0/field1 snapshot before reading. The affinity call itself
    // is spec'd to refresh per test 06, but `sync` is the explicit,
    // spec-blessed path that does not depend on the side-effect of
    // another op having taken effect first.
    const sync_result = syscall.sync(thread_handle);
    if (sync_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    const cap = caps.readCap(cap_table_base, thread_handle);
    if (cap.field1 != new_affinity) {
        testing.fail(4);
        return;
    }

    // End-to-end check: pin SELF to a single core and yield. After the
    // yield resumes us, RDPID (or aarch64 MPIDR_EL1) must report the
    // pinned core. Pick core 1 (single-bit mask 0b0010) so the RDPID
    // value is unambiguous — a kernel that ignored the affinity field
    // would re-pick the calling core (likely 0 if the runner spawned
    // us there) and the assertion fails. SLOT_INITIAL_THREAD carries the
    // child's `thread_inner_ceiling = 0xFF` which includes `saff`.
    const self_pin: u64 = 0b0010;
    const self_aff_result = syscall.affinity(caps.SLOT_INITIAL_THREAD, self_pin);
    if (self_aff_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(5);
        return;
    }

    const yield_result = syscall.yieldThread(0);
    if (yield_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(6);
        return;
    }

    const observed_core = testing.currentCoreId();
    if ((self_pin & (@as(u64, 1) << @truncate(observed_core))) == 0) {
        testing.fail(7);
        return;
    }

    // Restore unrestricted affinity before returning the result so the
    // self-handle's per-core pin doesn't leak into the thread's post-pass
    // cleanup path (the runner replies, our `_start` then calls
    // `delete(SLOT_SELF)` to drop the process; restricting that work to
    // a single core is unnecessary and tightens the dispatch deadline
    // unnecessarily).
    _ = syscall.affinity(caps.SLOT_INITIAL_THREAD, 0);
    testing.pass();
}
