// Spec §[recv] recv — test 18.
//
// "[test 18] does NOT return E_CLOSED when `restrict` clears the
//  `suspend` cap on a port whose `bind`-cap holder remains: the
//  `suspend` cap does not contribute to bind-side lifetime, so a
//  recv with a finite `timeout_ns` returns `E_TIMEOUT` (no sender
//  queued) rather than E_CLOSED."
//
// Strategy
//   This is the negative complement of recv test 17: the cap-split
//   kernel separates `suspend` (which gates the suspend syscall) from
//   `bind` (which contributes to the port's bind-side refcount). The
//   restrict cap-bit-edge dispatch at kernel/caps/capability.zig:325
//   only translates `bind` and `recv` clears into refcount decs;
//   clearing `suspend` is a no-op for port lifetime. We exercise that
//   negative path directly:
//
//     - Mint a port with `{recv, bind, suspend}`. bind_refcount = 1,
//       recv_refcount = 1.
//     - Restrict to `{recv, bind}` — drops only `suspend`. Both
//       refcounts must remain at 1; nothing in restrict's
//       cap-bit-edge dispatch should fire for the suspend bit.
//     - recv on the same handle with a finite, nonzero timeout. With
//       no sender queued and no other EC in this domain to ever
//       queue one, the kernel must arm the deadline rather than
//       short-circuit through E_CLOSED. Result: E_TIMEOUT once the
//       deadline elapses.
//
//   Test 17 covers the positive bind-clear → E_CLOSED edge; this test
//   covers the suspend-clear → no-edge invariant. Together they pin
//   down that `bind` and `suspend` are independent in the lifetime
//   model.
//
//   Failure-path neutralization:
//     - createPort tests 01-03: runner-default ceilings cover
//       {recv, bind, suspend}; no reserved bits.
//     - restrict tests 02 & 05: requested caps {recv, bind} ⊂
//       current {recv, bind, suspend}; no reserved bits.
//     - recv test 01 (E_BADCAP): port handle from a successful
//       createPort, not deleted.
//     - recv test 02 (E_PERM no `recv`): we kept `recv`.
//     - recv test 03 (E_INVAL reserved bits): libz truncates to u12.
//     - recv test 04 (E_CLOSED on no-bind / no-route / no-event):
//       the bind cap is preserved across restrict, so bind_refcount
//       remains 1 and this gate does not fire.
//     - recv test 06 (E_FULL): plenty of free slots; the timeout
//       path returns before any reply mint anyway.
//
//   Timeout: 10 ms matches the analogous recv test 14, comfortably
//   above scheduling jitter on TCG/KVM hosts and small enough not to
//   noticeably extend the suite runtime.
//
// Action
//   1. create_port(caps = {recv, bind, suspend})              — must succeed
//   2. restrict(port, caps = {recv, bind})                    — must return OK
//                                                               (drops suspend)
//   3. recv(port, timeout_ns = 10_000_000)                    — must return
//                                                               E_TIMEOUT
//
// Assertions
//   1: create_port returned an error word (setup failure).
//   2: restrict did not return OK.
//   3: recv did not return E_TIMEOUT — most importantly, an E_CLOSED
//      here would mean the suspend-clear edge incorrectly drove
//      bind_refcount to 0.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1.
    const initial = caps.PortCap{
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

    // Step 2: drop only the `suspend` bit. The cap-bit-edge dispatch
    // at kernel/caps/capability.zig:336 short-circuits on the
    // (old.bind == new.bind) and (old.recv == new.recv) invariants —
    // neither `incBindRef`/`decBindRef` nor `incRecvRef`/`decRecvRef`
    // is called for a suspend-only clear. This is the spec-mandated
    // contract under test.
    const restricted = caps.PortCap{ .recv = true, .bind = true };
    const r = syscall.restrict(port_handle, @as(u64, restricted.toU16()));
    if (r.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    // Step 3: a finite-timeout recv. With bind_refcount still 1 the
    // E_CLOSED gate does not fire and the kernel arms the deadline.
    // No sender ever queues, so the deadline elapses and the kernel
    // returns E_TIMEOUT.
    const timeout_ns: u64 = 10_000_000; // 10 ms
    const got = syscall.recv(port_handle, timeout_ns);
    if (got.regs.v1 != @intFromEnum(errors.Error.E_TIMEOUT)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
