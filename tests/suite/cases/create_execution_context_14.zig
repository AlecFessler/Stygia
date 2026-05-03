// Spec §[create_execution_context] create_execution_context — test 14.
//
// "[test 14] on success, the EC's affinity is set to `[5]`."
//
// Strategy
//   §[execution_context] field layout: field1 bits 0-63 carry the EC's
//   current 64-bit affinity mask. The snapshot in the caller's handle
//   is populated by the kernel as part of any syscall that takes (or
//   produces) the handle, so the handle returned by
//   create_execution_context already carries the authoritative affinity
//   in field1. To be defensive against a future relaxation where the
//   creating call does not pre-populate the snapshot, we issue an
//   explicit `sync` before reading.
//
//   Build a target=self EC with a multi-bit affinity mask whose set
//   bits all fall inside the system's core count. The CI runner uses
//   `-smp cores=4`, so any mask whose bits land in [0..4) is valid;
//   pick 0b0011 (cores 0 and 1). Choosing more than one bit makes the
//   verification stronger than the trivial 0 ("kernel chooses any")
//   case allowed by the spec.
//
//   Neutralize every other failure path so test 14 is the only spec
//   assertion exercised:
//     - target = 0 (self) so [4]'s BADCAP/PERM checks are skipped
//       (tests 02, 04, 05, 07).
//     - caller already has `crec` on its self-handle (granted by the
//       runner via SelfCap.crec = true) so test 01 does not fire.
//     - caps = {susp, term, restart_policy=0}, all within the runner's
//       child ec_inner_ceiling (0xFF, see runner/primary.zig
//       ceilings_inner) so test 03 does not fire.
//     - priority = 0, well under the runner's child priority ceiling
//       of 3, so test 06 does not fire.
//     - stack_pages = 1 (nonzero) so test 08 does not fire.
//     - affinity bits 0-1 are inside the 4-core system, so test 09
//       does not fire.
//     - reserved bits in [1] are clean, so test 10 does not fire.
//
// Action
//   1. create_execution_context(caps={susp,term,rp=0}, entry=&dummy,
//      stack_pages=1, target=0, affinity=0b0011)             — must succeed
//   2. sync(ec_handle)                                       — refresh
//      field1 snapshot
//   3. readCap(cap_table_base, ec_handle).field1 == 0b0011
//
// Assertions
//   1: setup syscall failed (create_execution_context returned an error)
//   2: sync returned a non-OK status
//   3: post-sync field1 does not equal the requested affinity mask

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const ec_caps = caps.EcCap{
        .susp = true,
        .term = true,
        .restart_policy = 0,
    };
    // §[create_execution_context] caps word: caps in bits 0-15,
    // target_caps in 16-31 (ignored when target=self), priority in
    // 32-33. priority=0 keeps the call within the child's pri ceiling.
    const caps_word: u64 = @as(u64, ec_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);

    // Cores 0 and 1 — both inside the 4-core CI runner config so the
    // [5]-affinity bounds check (test 09) does not fire.
    const requested_affinity: u64 = 0b0011;

    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1,
        0,
        requested_affinity,
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(1);
        return;
    }
    const ec_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // Force a fresh kernel-authoritative refresh of the handle's
    // field0/field1 snapshot before reading. Per §[capabilities] the
    // create itself implicitly sets the snapshot, but `sync` is the
    // explicit, spec-blessed path to avoid relying on that
    // side-effect-of-create detail.
    const sync_result = syscall.sync(ec_handle);
    if (sync_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    const cap = caps.readCap(cap_table_base, ec_handle);
    if (cap.field1 != requested_affinity) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
