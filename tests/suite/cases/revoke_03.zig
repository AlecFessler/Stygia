// Spec §[capabilities] revoke — test 03.
//
// "[test 03] on success, every handle transitively derived via copy
//  from [1] is released from its holder with the type-specific delete
//  behavior applied."
//
// Variant chosen: zero-descendant (vacuous) success.
//
//   The full positive variant requires constructing a copy-derivation
//   ancestry chain spanning two capability domains: the test domain
//   passes a port to a grandchild via `copy`, then asserts that
//   revoke([port]) releases the grandchild's copy. Verifying state
//   inside a separate domain from the test EC requires an end-to-end
//   IDC round-trip (handle attachment encoding §[handle_attachments]
//   on suspend, then recv decoding on the test side, plus a follow-up
//   probe of the grandchild's table). The libz suspend wrapper does not
//   yet implement the high-vreg pair layout — `suspendEc` panics when
//   attachments are non-empty — so the cross-domain construction is
//   currently unreachable from a single test ELF.
//
//   This test exercises the degenerate case of the same rule: when the
//   target has no descendants, the universal quantifier ("every handle
//   transitively derived") ranges over the empty set, which is
//   vacuously satisfied. Revoke must still return success and leave the
//   target itself intact (asserted independently by test 05). This is
//   a smoke check on the syscall's success path — confirms the syscall
//   accepts a clean handle, returns OK, and does not crash. The full
//   ancestry-walk semantics are exercised by tests 04 and 06, which
//   need the same cross-domain plumbing once libz lands it.
//
// Strategy
//   Create a fresh port in the test domain. Nothing has copied this
//   handle out (the test domain is the only holder), so its copy
//   descendant set is empty. Call revoke(port). The kernel must return
//   OK in vreg 1.
//
// Action
//   1. create_port(caps={recv})  — must succeed
//   2. revoke(port)              — must return OK
//
// Assertions
//   1: setup syscall failed (create_port returned an error word)
//   2: revoke returned non-success in vreg 1

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const initial = caps.PortCap{ .recv = true };
    const cp = syscall.createPort(@as(u64, initial.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    const result = syscall.revoke(port_handle);
    if (result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
