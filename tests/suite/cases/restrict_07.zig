// Spec §[capabilities] restrict — test 07.
//
// "[test 07] on success, syscalls gated by caps cleared by restrict
//  return E_PERM when invoked via this handle."
//
// Strategy
//   Pick a non-EC, non-VAR handle so the cap-update path is the plain
//   bitwise subset rule and the gated syscall is side-effect free.
//   Port handles fit: §[port] caps include `recv` (bit 3) which gates
//   the `recv` syscall (§[recv] test 02 is the matching E_PERM
//   assertion when the cap is absent at call time).
//
//   Mint a port with caps {bind, recv}. The port has at least one
//   bind-cap holder (the test itself) for its full lifetime, so a
//   recv on it would not return E_CLOSED on the recv-cap path. The
//   bind cap is preserved across the restrict so the only change
//   gating recv is the dropped recv cap.
//
//   IMPORTANT: do NOT call recv before the restrict. recv blocks
//   waiting for an event; calling it on a still-recv-capable port
//   without a queued sender hangs the test EC. After restrict drops
//   the recv cap, the kernel must return E_PERM immediately
//   without entering the wait path (per §[recv] [test 02]).
//
// Action
//   1. create_port(caps={bind,recv})       — must succeed
//   2. restrict(port, caps={bind})         — must succeed (drops recv)
//   3. recv(port)                          — must return E_PERM
//
// Assertions
//   1: setup syscall failed (create_port returned an error word)
//   2: restrict returned a non-zero error word (drop recv)
//   3: recv returned something other than E_PERM

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

    const reduced = caps.PortCap{ .bind = true };
    const new_caps_word: u64 = @as(u64, reduced.toU16());
    const restrict_result = syscall.restrict(port_handle, new_caps_word);
    if (restrict_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    const recv_result = syscall.recv(port_handle, 0);
    if (recv_result.regs.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
