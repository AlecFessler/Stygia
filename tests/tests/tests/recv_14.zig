// Spec §[recv] recv — test 14.
//
// "[test 14] returns E_TIMEOUT if [2] timeout_ns is nonzero, no sender
//  is queued, and no sender becomes queued within [2] timeout_ns."
//
// Strategy
//   The timeout-after-blocking path is fully exercisable from a single
//   test EC. recv blocks while no sender is queued on the port; with
//   the test EC as the sole holder of the port handle and no other EC
//   in this domain, no sender can ever become queued, and the only
//   spec-defined return path is the timeout one.
//
//   We mint a fresh port with caps={bind, recv}:
//     - bind keeps a live bind-cap holder on the port, so the call
//       does not short-circuit through test 04 (E_CLOSED on no
//       bind-cap holder + no event_routes + no queued events) before
//       the kernel can even arm the deadline.
//     - recv lets this handle pass test 02 (E_PERM without `recv`).
//   The handle returned by createPort sits in the test domain's table
//   with reserved bits clean (the libz wrapper truncates to u12), so
//   tests 01 (E_BADCAP) and 03 (E_INVAL on reserved bits) cannot fire.
//
//   The runner does not bind any event_route to this freshly-minted
//   port and the test EC never queues an event on it, so the only EC
//   able to drive a sender event onto the port is none — recv must
//   block, the deadline must elapse, and the kernel must return
//   E_TIMEOUT in vreg 1.
//
//   We pick a 10-millisecond timeout (10_000_000 ns): comfortably above
//   any reasonable scheduling jitter on a TCG/KVM test host yet small
//   enough not to materially extend the suite runtime. This matches
//   the analogous futex_wait_val test 06.
//
//   Failure-path neutralization for the recv call itself:
//     - test 01 (E_BADCAP): the freshly-minted slot id is used.
//     - test 02 (E_PERM no `recv`): port_caps.recv = true.
//     - test 03 (E_INVAL on reserved bits): the libz wrapper takes
//       u12 and zero-extends.
//     - test 04 (E_CLOSED no bind/route/queue): the test EC holds the
//       port handle with the bind cap, keeping the bind refcount at
//       1, so this gate does not fire.
//     - test 06 (E_FULL): even though the timeout path returns before
//       any reply handle is minted, the test domain has plenty of
//       free slots — this gate is not reachable.
//
// Action
//   1. create_port(caps = {bind, recv})       — must succeed.
//   2. recv(port_handle, timeout_ns = 10_000_000) — must return
//      E_TIMEOUT in vreg 1.
//
// Assertions
//   1: create_port returned an error word (setup failure).
//   2: recv did not return E_TIMEOUT.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint the port. bind keeps the bind refcount at 1 so the
    // recv call cannot short-circuit through E_CLOSED before the
    // kernel arms the deadline; recv passes test 02's `recv`-cap gate.
    const port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: recv with a finite, nonzero timeout. No other EC exists
    // in this domain, no event_route targets the port, and no event
    // is ever queued, so the kernel's only spec-defined return is the
    // timeout path: vreg 1 = E_TIMEOUT once the 10ms deadline elapses.
    const timeout_ns: u64 = 10_000_000; // 10 ms
    const result = syscall.recv(port_handle, timeout_ns);

    if (result.regs.v1 != @intFromEnum(errors.Error.E_TIMEOUT)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
