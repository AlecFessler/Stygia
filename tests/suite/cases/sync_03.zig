// Spec §[capabilities] sync — test 03.
//
// "[test 03] on success, [1]'s field0 and field1 reflect the
//  authoritative kernel state at the moment of the call."
//
// Strategy
//   sync's job is to refresh the holder-domain's snapshot of a
//   handle's field0/field1 from the authoritative kernel state.
//   §[capabilities]: "No-op for handles whose state does not drift."
//   A port (§[port]) is the simplest such handle: both field0 and
//   field1 are spec'd as `_reserved (64)`, so the authoritative
//   kernel state is 0/0 for the lifetime of the handle.
//
//   That gives us an unambiguous post-condition without depending on
//   any kernel-mutating syscall in the setup (e.g., the wrapper for
//   `priority` / `affinity` would need to round-trip through implicit
//   sync, which would conflate test 03 with the per-syscall implicit-
//   sync rules elsewhere in the spec).
//
//   Setup mints a port with `{bind, recv}` so the handle is well-
//   formed (caps have bits set, so any kernel scrub of word0 caps
//   would be detectable in restrict_06; here we only inspect
//   field0/field1). sync's spec lists only test 01 (BADCAP) and test
//   02 (reserved bits) as failure modes — neither applies here — so
//   the success post-condition is what we exercise.
//
// Action
//   1. create_port(caps={bind, recv})       — must succeed
//   2. sync(port)                           — must return OK
//   3. readCap(cap_table_base, port)        — verify field0 == 0 and
//                                              field1 == 0
//
// Assertions
//   1: setup syscall failed (create_port returned an error word)
//   2: sync returned non-OK in vreg 1
//   3: post-sync field0 or field1 do not match the authoritative
//      kernel state for a port (both 0)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const initial = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, initial.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    const result = syscall.sync(port_handle);
    if (result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    const cap = caps.readCap(cap_table_base, port_handle);
    if (cap.field0 != 0 or cap.field1 != 0) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
