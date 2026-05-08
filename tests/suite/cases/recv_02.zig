// Spec §[recv] recv — test 02.
//
// "[test 02] returns E_PERM if [1] does not have the `recv` cap."
//
// Strategy
//   create_port's structural rule (must include `recv` and one of
//   `{suspend, bind}`) prevents minting a port handle without `recv`
//   directly. To obtain a port-typed slot whose caps lack `recv`, we
//   mint with `{recv, bind}` and then `restrict` the handle to drop
//   `recv` while keeping `bind`. The kernel's recv-cap gate
//   (kernel/syscall/port.zig) reads the recv bit from the caller's
//   user_table snapshot — which `restrict` updates synchronously —
//   before locking the underlying port object, so the gate fires with
//   E_PERM purely from the user_table caps word.
//
//   Failure-path neutralization:
//     - test 01 (E_BADCAP if [1] not a valid port handle): handle id
//       comes from a successful create_port; the slot remains a port-
//       typed entry after restrict (restrict only updates caps).
//     - test 03 (E_INVAL on reserved bits in [1]): the libz `recv`
//       wrapper takes u12 and zero-extends, so reserved bits in [1]
//       are clean.
//   The recv cap check happens before the port-object lock acquisition
//   (kernel/syscall/port.zig: read user_table caps, branch on recv,
//   then call port_obj.recv), so even though restrict's recv-side
//   refcount drop terminates the underlying port, the syscall returns
//   E_PERM from the cap gate without ever touching the destroyed slab.
//
// Action
//   1. createPort(caps={recv, bind}) — must succeed.
//   2. restrict(port, caps={bind})   — drops `recv` from the handle's
//                                      caps; must return OK.
//   3. recv(port_handle) — must return E_PERM because the handle's
//      caps now lack `recv`.
//
// Assertions
//   1: createPort returned an error word in vreg 1 (setup failed).
//   2: restrict did not return OK (setup failed).
//   3: recv returned something other than E_PERM.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint a port that satisfies create_port's structural rule
    // ({recv, bind}). The runner's port_ceiling covers both bits.
    const port_caps = caps.PortCap{
        .recv = true,
        .bind = true,
    };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: drop the `recv` bit while leaving the slot itself
    // intact. The kernel's restrict path updates the caller's
    // user_table caps in place (kernel/caps/capability.zig), which is
    // the same word the recv-cap gate inspects.
    const restricted = caps.PortCap{ .bind = true };
    const r = syscall.restrict(port_handle, @as(u64, restricted.toU16()));
    if (r.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    // Step 3: recv must reject with E_PERM purely on the cap gate.
    const result = syscall.recv(port_handle, 0);

    if (result.regs.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
