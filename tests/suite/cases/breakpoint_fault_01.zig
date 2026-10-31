// Regression: an unbound user breakpoint tears down its process on both
// architectures. A nested child first suspends on a private port to prove
// it reached app.main. After the parent replies, the child executes INT3
// or BRK and deliberately stays alive if the trap returns. The parent
// drops its own bind cap and expects recv to return E_CLOSED only when
// fault teardown releases the child's sole remaining bind cap.
const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const CHILD_CRIPC: u8 = 0x07;
const CHILD_PORT: caps.HandleId = caps.SLOT_FIRST_PASSED;
const SELF_ELF: caps.HandleId = caps.SLOT_FIRST_PASSED + 1;
const LIBZ_PF: caps.HandleId = caps.SLOT_FIRST_PASSED + 2;
const TIMEOUT_NS: u64 = 2_000_000_000;

pub fn main(cap_table_base: u64) void {
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    const my_cripc: u8 = @truncate((self_cap.field0 >> 24) & 0xFF);
    if (my_cripc == CHILD_CRIPC) {
        const ready = syscall.suspendThread(caps.SLOT_INITIAL_THREAD, CHILD_PORT, &.{});
        if (ready.v1 != @intFromEnum(errors.Error.OK)) spinForever();
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("int3"),
            .aarch64 => asm volatile ("brk #0"),
            else => @compileError("unsupported breakpoint test architecture"),
        }
        // An incorrectly resumed breakpoint must not close the port.
        spinForever();
    }

    const port_caps = caps.PortCap{
        .copy = true,
        .bind = true,
        .recv = true,
        .@"suspend" = true,
    };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) return testing.fail(1);
    const port_handle: caps.HandleId = @truncate(cp.v1 & 0xFFF);

    const child_self = caps.SelfCap{ .crvr = true, .pri = 3 };
    const ceilings_inner: u64 =
        @as(u64, 0xFF) |
        (@as(u64, 0x01FF) << 8) |
        (@as(u64, CHILD_CRIPC) << 24) |
        (@as(u64, 0x1F) << 32) |
        (@as(u64, 0x01) << 40) |
        (@as(u64, 0x5C) << 48);
    const ceilings_outer: u64 = 0x0000_003F_01FE_FFFF;
    const passed = [_]u64{
        (caps.PassedHandle{
            .id = port_handle,
            .caps = (caps.PortCap{ .bind = true, .@"suspend" = true }).toU16(),
            .move = false,
        }).toU64(),
        (caps.PassedHandle{
            .id = SELF_ELF,
            .caps = (caps.PfCap{ .r = true }).toU16(),
            .move = false,
        }).toU64(),
        (caps.PassedHandle{
            .id = LIBZ_PF,
            .caps = (caps.PfCap{ .r = true, .x = true }).toU16(),
            .move = false,
        }).toU64(),
    };
    const child = syscall.createProcess(
        @as(u64, child_self.toU16()),
        ceilings_inner,
        ceilings_outer,
        SELF_ELF,
        0,
        &passed,
    );
    if (testing.isHandleError(child.v1)) return testing.fail(2);

    // The child's bind cap is now the only one: loss of that cap is
    // observable as E_CLOSED rather than a timeout.
    const drop_bind = syscall.restrict(port_handle, (caps.PortCap{ .recv = true }).toU16());
    if (drop_bind.v1 != @intFromEnum(errors.Error.OK)) return testing.fail(3);

    const ready = syscall.recv(port_handle, TIMEOUT_NS);
    if (ready.regs.v1 != @intFromEnum(errors.Error.OK)) return testing.fail(4);
    const reply_slot: caps.HandleId = @truncate((ready.word >> 32) & 0xFFF);
    if (reply_slot == 0) return testing.fail(5);
    const reply_result = syscall.reply(reply_slot);
    if (reply_result.v1 != @intFromEnum(errors.Error.OK)) return testing.fail(6);

    const closed = syscall.recv(port_handle, TIMEOUT_NS);
    if (closed.regs.v1 != @intFromEnum(errors.Error.E_CLOSED)) return testing.fail(7);
    testing.pass();
}

fn spinForever() noreturn {
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("pause"),
            .aarch64 => asm volatile ("yield"),
            else => unreachable,
        }
    }
}
