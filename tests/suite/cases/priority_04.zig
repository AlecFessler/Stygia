// Spec §[priority] priority — test 04.
//
// "[test 04] returns E_INVAL if [2] is greater than 3."
//
// Strategy
//   The spec defines `[2] new_priority` as a 0..3 value. Any [2] > 3
//   is structurally out of range and must surface E_INVAL regardless
//   of permissions.
//
//   To isolate the out-of-range check we must make every neighboring
//   error path miss:
//     - test 01 (E_BADCAP):   [1] must reference a valid EC handle.
//     - test 02 (E_PERM):     [1] must carry the `spri` cap.
//     - test 03 (E_PERM):     [2] must not exceed the caller's
//                             self-handle `pri`.
//     - test 05 (E_INVAL):    no reserved bits set in [1].
//
//   The runner-spawned domain receives its initial EC at
//   SLOT_INITIAL_EC (slot 1) with caps = the runner's
//   `ec_inner_ceiling` (low byte 0xFF, see `runner/primary.zig`'s
//   `ceilings_inner`). 0xFF includes bit 3 = `spri`, so slot 1 is a
//   valid EC handle that carries the `spri` cap.
//
//   The caller's self-handle `pri` is set to 3 (`runner/primary.zig`
//   sets `child_self.pri = 3` when minting the test domain), which is
//   the maximum priority the spec admits. That means any [2] in
//   {0..3} satisfies the test 03 cap check, while any [2] > 3 must
//   trip the E_INVAL bound from test 04.
//
//   Tests 03 and 04 are mutually exclusive only if the kernel checks
//   the structural bound before the permission bound when [2] also
//   exceeds the caller's pri. Because the caller's pri is already the
//   spec maximum (3), the [2] > 3 case here cannot be observed via
//   any other error code without violating spec test 03's preamble
//   (E_PERM only when [2] exceeds the caller's pri — true here, but
//   any kernel that returned E_PERM for an out-of-range numeric value
//   would make test 04 untestable in any caller that holds pri = 3,
//   which is the only value reachable from the boot root). The
//   conventional ordering — structural validation before rights — is
//   the only reading consistent with both tests being independently
//   asserted.
//
// Action
//   priority(SLOT_INITIAL_EC, 4) — must return E_INVAL.
//
//   4 is the smallest value strictly greater than the spec maximum
//   of 3 and fits in any reasonable encoding the kernel might use
//   for the priority field, so the failure mode isn't masked by an
//   unrelated overflow.
//
// Assertion
//   1: priority(slot 1, new_priority = 4) returned something other
//      than E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const out_of_range_priority: u64 = 4;
    const result = syscall.priority(caps.SLOT_INITIAL_EC, out_of_range_priority);

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
