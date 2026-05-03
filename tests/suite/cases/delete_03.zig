// Spec §[capabilities] delete — test 03.
//
// "[test 03] on success, the handle is released and subsequent
//  operations on it return E_BADCAP."
//
// Strategy
//   Mint a fresh port handle so the slot is unambiguously occupied
//   by a real capability prior to delete. Port creation only
//   requires the self-handle's `crpt` cap (which the runner grants
//   to spawned tests) and the resulting slot is independent of the
//   four conventional kernel-installed slots (self, initial EC,
//   self-IDC, first-passed). Caps {bind, recv} pin the handle as a
//   port without any side-effecting interactions on delete that
//   would matter for this test — release just decrements both the
//   send and recv refcounts to zero.
//
//   Then call delete(port). On success vreg 1 is zero (delete
//   returns void). The slot is now released; per the spec line
//   under test, any subsequent operation on the same handle id
//   must return E_BADCAP.
//
//   `restrict(port, 0)` is the cleanest follow-up:
//     - it touches only the handle (no other state),
//     - new caps = 0 is a subset of any prior caps,
//     - reserved bits are clean,
//   so the only error path that can fire on the post-delete call
//   is BADCAP — exactly the post-condition the spec line names.
//
// Action
//   1. create_port(caps={bind, recv})    — must succeed
//   2. delete(port)                      — must succeed (vreg 1 == 0)
//   3. restrict(port, 0)                 — must return E_BADCAP
//
// Assertions
//   1: setup syscall failed (create_port returned an error word)
//   2: delete itself did not return success in vreg 1
//   3: post-delete restrict did not return E_BADCAP

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const initial = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, initial.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    const del = syscall.delete(port_handle);
    if (del.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    const after = syscall.restrict(port_handle, 0);
    if (after.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
