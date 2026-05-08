// Spec §[capabilities] restrict — test 08.
//
// "[test 08] on success, when the handle is a `port` handle and
//  `restrict` clears a cap that contributes to a port-side refcount
//  (`bind` or `recv`), the matching refcount is decremented as if
//  `delete` had been performed for that bit. Conversely, clearing a
//  non-lifetime cap (`suspend`, `xfer`, `restart_policy`, `move`,
//  `copy`) leaves both port-side refcounts intact: a recv on the
//  same handle with a finite `timeout_ns` returns `E_TIMEOUT` rather
//  than `E_CLOSED` when the `bind` cap is preserved and no senders
//  are queued."
//
// Strategy
//   The cap-split kernel (commits b666b6751 / 1944005f2) implements
//   restrict's lifetime semantics via cap-bit-edge dispatch in
//   kernel/caps/capability.zig:325-348. Only `bind` and `recv` clears
//   translate into refcount decs; `suspend`, `xfer`, `restart_policy`,
//   `move`, and `copy` clears are no-ops for port lifetime. The spec
//   line under test calls out that distinction.
//
//   Two observable witnesses:
//     (a) bind-clear edge fires the bind-side dec: covered by
//         recv test 17 (mint with `{recv, bind, suspend}`, restrict
//         to `{recv, suspend}`, recv → E_CLOSED — only achievable if
//         bind_refcount fell to 0).
//     (b) non-lifetime-cap clear is a no-op: this test's positive
//         half. We do TWO non-lifetime restricts back-to-back and
//         then assert recv (with a finite timeout) returns
//         E_TIMEOUT, not E_CLOSED. If either restrict had
//         spuriously decremented bind_refcount the second restrict
//         could have triggered observed_zero and the recv would
//         have returned E_CLOSED.
//
//   Doing two non-lifetime drops (`xfer` first, then `suspend`)
//   exercises the dispatcher's separation more aggressively than a
//   single clear: each call enters the cap-bit-edge code path, so a
//   bug that decrements the wrong refcount on either edge surfaces
//   as a false E_CLOSED on the recv. `bind` and `recv` are preserved
//   throughout, so any E_CLOSED from the recv is a kernel bug.
//
//   Failure-path neutralization is identical to recv test 18 (the
//   negative half of this assertion). The runner's port_ceiling
//   covers `{xfer, recv, bind, suspend}` and the test EC has plenty
//   of free slots for any reply mint that would never happen on the
//   timeout path.
//
//   Timeout: 10 ms matches recv test 14 / recv test 18.
//
// Action
//   1. create_port(caps = {xfer, recv, bind, suspend})       — must succeed
//   2. restrict(port, caps = {recv, bind, suspend})          — must return OK
//                                                              (drops xfer)
//   3. restrict(port, caps = {recv, bind})                   — must return OK
//                                                              (drops suspend)
//   4. recv(port, timeout_ns = 10_000_000)                   — must return
//                                                              E_TIMEOUT
//
// Assertions
//   1: create_port returned an error word (setup failure).
//   2: first restrict did not return OK.
//   3: second restrict did not return OK.
//   4: recv did not return E_TIMEOUT — an E_CLOSED here would mean
//      either xfer-clear or suspend-clear leaked into the bind/recv
//      refcount dispatch.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint with every lifetime + non-lifetime cap available
    // under the runner's port_ceiling = {xfer, recv, bind, suspend}.
    const initial = caps.PortCap{
        .xfer = true,
        .recv = true,
        .bind = true,
        .@"suspend" = true,
    };
    const cp = syscall.createPort(@as(u64, initial.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: drop `xfer` only. xfer is a non-lifetime cap; the
    // cap-bit-edge dispatch must not call any refcount dec.
    const after_xfer = caps.PortCap{
        .recv = true,
        .bind = true,
        .@"suspend" = true,
    };
    const r1 = syscall.restrict(port_handle, @as(u64, after_xfer.toU16()));
    if (r1.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    // Step 3: drop `suspend` next. suspend is also a non-lifetime
    // cap. After this restrict the handle carries only {recv, bind}
    // and both refcounts must still be 1.
    const after_suspend = caps.PortCap{
        .recv = true,
        .bind = true,
    };
    const r2 = syscall.restrict(port_handle, @as(u64, after_suspend.toU16()));
    if (r2.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Step 4: recv with a finite timeout. The bind cap survives, so
    // bind_refcount = 1, the E_CLOSED short-circuit at
    // kernel/sched/port.zig:527 does not fire, and the deadline
    // elapses to E_TIMEOUT.
    const timeout_ns: u64 = 10_000_000;
    const got = syscall.recv(port_handle, timeout_ns);
    if (got.regs.v1 != @intFromEnum(errors.Error.E_TIMEOUT)) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
