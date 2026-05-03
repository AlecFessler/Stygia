// Spec §[affinity] affinity — test 06.
//
// "[test 06] when [1] is a valid handle, [1]'s field0 and field1 are
//  refreshed from the kernel's authoritative state as a side effect,
//  regardless of whether the call returns success or another error
//  code."
//
// Strategy
//   §[capabilities]: any syscall that takes a handle whose state can
//   drift implicitly refreshes the holder's field0/field1 snapshot
//   from the authoritative kernel state. For an EC handle (§[execution_
//   context]) field1 carries the affinity mask and field0 carries the
//   priority. The `affinity` syscall takes [1] as an EC handle, so the
//   implicit-sync rule applies.
//
//   To prove the snapshot was refreshed by the affinity call itself
//   (and not pre-populated by a prior syscall on the same handle),
//   we need a detectable change between the snapshot at handle
//   creation time and the snapshot after the affinity call. The
//   cap table is read-only mapped, so we can't fake a stale snapshot
//   directly — instead we let `create_execution_context` populate
//   field1 with one mask (M0) and have the affinity call drive the
//   kernel-authoritative state to a different mask (M1). If the
//   implicit-sync side effect fires, the post-call snapshot reads
//   M1; if it does not, the snapshot would still read M0.
//
//   We exercise the success branch ("regardless of ... success or
//   another error code"): a clean affinity call with [1] valid, [2]
//   in-bounds, all reserved bits clean, and the saff cap present.
//   The kernel sets the EC's affinity to M1 (test 05) and refreshes
//   the caller's snapshot (test 06). The error-path arm of test 06
//   would require a way to detect a refresh that does not change the
//   observed value, which requires drift the holder cannot induce
//   on its own from a single domain — covering the success arm is
//   the sharpest we can do with the cap-table-as-only-observation
//   surface.
//
//   Neutralize every other failure path so test 06 is the only spec
//   assertion exercised:
//     - target [1] is the freshly-minted EC handle, so no E_BADCAP
//       (test 01).
//     - the new EC's caps include `saff`, so no E_PERM (test 02).
//     - M1 = 0b0001 sits inside the 4-core CI runner, so no E_INVAL
//       on out-of-bounds bits (test 03).
//     - reserved bits in [1] are clean (handle id only), so no
//       E_INVAL on reserved bits (test 04).
//
//   The CI runner uses `-smp cores=4`, so any mask in [0..4) is
//   valid. M0 = 0b0010 (core 1), M1 = 0b0001 (core 0). Picking
//   single-bit, distinct masks makes the post-condition unambiguous.
//
// Action
//   1. create_execution_context(caps={susp,term,saff,rp=0}, entry=&dummy,
//      stack_pages=1, target=0, affinity=M0)        — must succeed
//   2. affinity(ec, M1)                              — must return OK
//   3. readCap(cap_table_base, ec).field1            — must equal M1
//
// Assertions
//   1: setup syscall failed (create_execution_context returned an error)
//   2: affinity returned non-OK in vreg 1
//   3: post-affinity field1 snapshot does not equal M1, meaning the
//      implicit-sync side effect of the affinity syscall did not refresh
//      the holder's snapshot to the new authoritative kernel state

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const ec_caps = caps.EcCap{
        .susp = true,
        .term = true,
        .saff = true,
        .restart_policy = 0,
    };
    // §[create_execution_context] caps word: caps in bits 0-15,
    // target_caps in 16-31 (ignored when target=self), priority in
    // 32-33. priority=0 keeps the call within the child's pri ceiling.
    const caps_word: u64 = @as(u64, ec_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);

    // M0: pre-affinity authoritative state, populated into the new
    // handle's field1 snapshot as a side effect of create_execution_
    // context (§[capabilities]).
    const m0: u64 = 0b0010;
    // M1: the value `affinity` will drive both the authoritative kernel
    // state (test 05) and, via implicit-sync, the caller's snapshot
    // (test 06) to.
    const m1: u64 = 0b0001;

    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1,
        0,
        m0,
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(1);
        return;
    }
    const ec_handle: u12 = @truncate(cec.v1 & 0xFFF);

    const result = syscall.affinity(ec_handle, m1);
    if (result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    const cap = caps.readCap(cap_table_base, ec_handle);
    if (cap.field1 != m1) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
