// Spec §[timer_arm] — test 10.
//
// "[test 10] calling `timer_arm` again yields a fresh, independent
//  timer handle; the prior handle's field0 and field1 are unaffected."
//
// Strategy
//   `timer_arm` mints a brand-new kernel timer object on every call.
//   To prove independence we mint two timers back-to-back and check
//   that:
//     (a) the second call returns a distinct handle id of type `timer`
//         (no aliasing onto the prior slot or onto a non-timer type);
//     (b) the prior timer's field0 is still 0 and its field1 still
//         encodes (arm=1, pd=0) — i.e. the second mint did not drain
//         its counter, did not cancel it, and did not flip its pd bit.
//
//   Both timers are armed one-shot with a deadline of 1e12 ns
//   (~1000 s). The runner finishes far before then, so neither timer
//   can fire mid-test; field0 cannot legitimately advance and field1
//   cannot transition arm -> 0 from the spec's one-shot fire path.
//
//   The runner's self-handle has `timer = true` and the default
//   `restart_policy_ceiling.tm_restart_max = 1`, so passing
//   `caps = {arm, cancel}` (restart_policy unset) lands every prior
//   timer_arm gate on the success path — tests 01-04 don't fire.
//
//   `sync` on the prior handle before readCap forces a fresh
//   kernel-authoritative snapshot of field0/field1 (§[capabilities] —
//   kernel-mutable fields drift, sync refreshes). Reading word0's
//   handle-type tag uses the static layout (Cap.handleType, bits
//   12-15 of word0), which is not subject to drift.
//
// Action
//   1. timer_arm({arm, cancel}, 1_000_000_000_000, periodic=0)  -> A
//   2. timer_arm({arm, cancel}, 1_000_000_000_000, periodic=0)  -> B
//   3. require A.id != B.id and B.type == timer
//   4. sync(A); readCap(A) -> field0 == 0 and field1 low 2 bits ==
//      0b01 (arm=1, pd=0)
//
// Assertions
//   1: first timer_arm returned an error word in vreg 1.
//   2: second timer_arm returned an error word in vreg 1.
//   3: second timer_arm aliased onto the first handle's id, or the
//      returned handle's type tag is not `timer` — a fresh independent
//      handle must differ in id and carry the timer type.
//   4: sync on the prior timer returned non-OK in vreg 1.
//   5: prior timer's field0 advanced from 0 (counter perturbed by the
//      second mint) — independence violated.
//   6: prior timer's field1.arm or field1.pd diverged from the
//      original (arm=1, pd=0) configuration — independence violated.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    // §[timer] caps word: bits 2 (arm), 3 (cancel). restart_policy
    // (bit 4) is left clear so test 02 doesn't apply. Reserved bits
    // (5-15) are zero so test 04 doesn't apply.
    const timer_caps = caps.TimerCap{
        .arm = true,
        .cancel = true,
    };
    const caps_word: u64 = @as(u64, timer_caps.toU16());

    // §[timer_arm]: deadline_ns must be nonzero (test 03). 1e12 ns is
    // far longer than the test runner's wall-clock so the one-shot
    // fire cannot land mid-test and confound the field0 readback.
    const deadline_ns: u64 = 1_000_000_000_000;
    const flags_oneshot: u64 = 0;

    const first = syscall.timerArm(caps_word, deadline_ns, flags_oneshot);
    if (testing.isHandleError(first.v1)) {
        testing.fail(1);
        return;
    }
    const first_handle: u12 = @truncate(first.v1 & 0xFFF);

    const second = syscall.timerArm(caps_word, deadline_ns, flags_oneshot);
    if (testing.isHandleError(second.v1)) {
        testing.fail(2);
        return;
    }
    const second_handle: u12 = @truncate(second.v1 & 0xFFF);

    // Independence on the handle layer: the second mint must not
    // overwrite the first slot, and the second handle must carry the
    // timer type tag (§[capabilities] word0 bits 12-15).
    const second_cap = caps.readCap(cap_table_base, second_handle);
    if (second_handle == first_handle or second_cap.handleType() != caps.HandleType.timer) {
        testing.fail(3);
        return;
    }

    // Refresh the prior handle's kernel-mutable snapshot before
    // inspecting field0/field1. §[capabilities]: sync forces a fresh
    // kernel-authoritative read.
    const sync_result = syscall.sync(first_handle);
    if (sync_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }

    const first_cap = caps.readCap(cap_table_base, first_handle);

    // §[timer_arm] test 06: on success, field0 = 0. The prior timer
    // cannot have fired yet (deadline 1e12 ns >> runner wall-clock),
    // so any non-zero counter here means the second mint perturbed
    // it.
    if (first_cap.field0 != 0) {
        testing.fail(5);
        return;
    }

    // §[timer] field1: bit 0 = arm, bit 1 = pd. Original config was
    // arm=1 / pd=0, so the low two bits must be 0b01. Reserved bits
    // (2-63) are not asserted here — the spec lists them as
    // _reserved, and the kernel's freedom over reserved bits is the
    // subject of separate spec tests.
    if ((first_cap.field1 & 0x3) != 0x1) {
        testing.fail(6);
        return;
    }

    testing.pass();
}
