// Spec §[recv] recv — test 17.
//
// "[test 17] returns E_CLOSED if `restrict` clears the `bind` cap on
//  the only `bind`-cap-holding handle while no event_routes target the
//  port and no vCPU `exit_port` pins it; the recv call observes this
//  on its very next invocation against the (still-recv-capable)
//  handle."
//
// Strategy
//   The cap split (kernel commits b666b6751 / 1944005f2) decouples
//   port lifetime into bind-side and recv-side refcounts. The bind-
//   side refcount aggregates `bind`-cap-holding handles, kernel-held
//   event_routes targeting the port, and vCPU `exit_port` pins. When
//   it hits zero, blocked receivers wake with E_CLOSED and any
//   subsequent recv on a still-recv-capable handle short-circuits the
//   same way (kernel/sched/port.zig:527 — `if (p.bind_refcount.snapshot()
//   == 0) return errors.E_CLOSED`).
//
//   `restrict` (kernel/caps/capability.zig:325) is the cleanest way to
//   exercise the bind-cap-clear edge without dropping the recv-cap
//   side: a handle minted with `{recv, bind, suspend}` and then
//   restricted to `{recv, suspend}` keeps the slab alive through its
//   recv-cap pin while the bind-cap-clear edge dispatches into
//   port.decBindRef under the port's `_gen_lock`. With no event_route
//   and no vCPU bound to the port, the bind refcount falls from 1 to
//   0 and propagateClosedToReceivers fires.
//
//   recv on the same (still-recv-capable) handle then exercises the
//   recv path's bind_refcount snapshot gate. The handle resolves, the
//   recv-cap check passes (we kept the recv cap), no sender is
//   queued, and the snapshot reads 0 → E_CLOSED.
//
//   Failure-path neutralization:
//     - createPort test 01 (lacks `crpt`): the runner grants `crpt`.
//     - createPort test 02 (caps ⊄ port_ceiling): runner ceiling is
//       0x5C = {xfer, recv, bind, suspend}; we request a subset.
//     - createPort test 03 (reserved bits): no high bits set.
//     - restrict test 02 (caps ⊄ current): we drop `bind` so the
//       requested set {recv, suspend} is a strict subset.
//     - restrict test 05 (reserved bits in [1] or [2]): clean.
//     - recv test 01 (E_BADCAP): handle came from a successful
//       createPort and was not deleted.
//     - recv test 02 (E_PERM no `recv`): we kept `recv`.
//     - recv test 03 (E_INVAL reserved bits): libz wrapper truncates
//       to u12 and zero-extends.
//     - recv test 04 (E_CLOSED on initial mint without bind): the
//       initial mint included `bind`; this test exercises the
//       transition from bind=1 to bind=0 via restrict, not the no-
//       bind-from-mint path covered by test 04.
//     - recv test 06 (E_FULL): plenty of free slots.
//   The bind_refcount-snapshot-zero E_CLOSED path is therefore the
//   only spec-defined return.
//
// Action
//   1. create_port(caps = {recv, bind, suspend})            — must succeed
//   2. restrict(port, caps = {recv, suspend})               — must return OK
//                                                             (drops bind)
//   3. recv(port, timeout_ns = 0)                           — must return
//                                                             E_CLOSED
//
// Assertions
//   1: create_port returned an error word (setup failure).
//   2: restrict did not return OK (setup failure or unexpected dec
//      behavior on the bind-cap-clear edge).
//   3: recv did not return E_CLOSED.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint a port carrying every lifetime-relevant cap so the
    // restrict in step 2 has a non-trivial bind-clear edge to exercise.
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

    // Step 2: restrict the handle to {recv, suspend}. The clear edge
    // on `bind` runs through kernel/caps/capability.zig:336 ->
    // port.decBindRef(p) under the port's _gen_lock. With no
    // event_route and no vCPU exit_port bound to this port, the bind
    // refcount falls to 0 and propagateClosedToReceivers wakes any
    // blocked receivers (none here). The slab stays alive because the
    // recv-cap holder (this handle) keeps recv_refcount = 1.
    const restricted = caps.PortCap{ .recv = true, .@"suspend" = true };
    const r = syscall.restrict(port_handle, @as(u64, restricted.toU16()));
    if (r.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    // Step 3: recv must short-circuit with E_CLOSED. The kernel's
    // bind_refcount.snapshot() == 0 check at kernel/sched/port.zig:527
    // fires before any wait-list manipulation, so this returns
    // immediately rather than blocking.
    const got = syscall.recv(port_handle, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.E_CLOSED)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
