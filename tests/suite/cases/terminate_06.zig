// Spec §[terminate] test 06: evicting a stale copied thread handle must
// unlink it from the copy-derivation tree before its slot is reused.
// The child terminates a copied target, evicts that stale handle through
// priority, then reuses its slot for a port. The parent revokes the original
// thread handle while the child is suspended. The new port must survive.
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const CHILD_CRIPC: u8 = 0x07;
const RESULT_PORT: caps.HandleId = caps.SLOT_FIRST_PASSED;
const SELF_ELF: caps.HandleId = caps.SLOT_FIRST_PASSED + 1;
const LIBZ_PF: caps.HandleId = caps.SLOT_FIRST_PASSED + 2;
const CONTROL_PORT: caps.HandleId = caps.SLOT_FIRST_PASSED + 3;
const TARGET_THREAD: caps.HandleId = caps.SLOT_FIRST_PASSED + 4;
const TIMEOUT_NS: u64 = 2_000_000_000;

pub fn main(cap_table_base: u64) void {
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    const cripc: u8 = @truncate((self_cap.field0 >> 24) & 0xFF);
    if (cripc == CHILD_CRIPC) {
        if (syscall.terminate(TARGET_THREAD).v1 != @intFromEnum(errors.Error.OK)) return testing.fail(4);
        if (syscall.priority(TARGET_THREAD, 0).v1 != @intFromEnum(errors.Error.E_TERM)) return testing.fail(5);

        const new_port_caps = caps.PortCap{ .recv = true, .bind = true };
        const new_port = syscall.createPort(@as(u64, new_port_caps.toU16()));
        if (testing.isHandleError(new_port.v1)) return testing.fail(6);
        const new_slot: caps.HandleId = @truncate(new_port.v1 & 0xFFF);
        if (new_slot != TARGET_THREAD) return testing.fail(7);

        // Signal the parent that the formerly linked slot now holds a port.
        const ready = syscall.suspendThread(caps.SLOT_INITIAL_THREAD, CONTROL_PORT, &.{});
        if (ready.v1 != @intFromEnum(errors.Error.OK)) return testing.fail(8);
        if (syscall.delete(new_slot).v1 != @intFromEnum(errors.Error.OK)) return testing.fail(9);
        testing.pass();
        return;
    }

    const control_caps = caps.PortCap{ .copy = true, .bind = true, .recv = true, .@"suspend" = true };
    const control = syscall.createPort(@as(u64, control_caps.toU16()));
    if (testing.isHandleError(control.v1)) return testing.fail(1);
    const control_slot: caps.HandleId = @truncate(control.v1 & 0xFFF);

    const thread_caps = caps.ThreadCap{ .copy = true, .term = true, .spri = true };
    const target = syscall.createThread(@as(u64, thread_caps.toU16()), @intFromPtr(&testing.dummyEntry), 1, 0, 0);
    if (testing.isHandleError(target.v1)) return testing.fail(2);
    const target_slot: caps.HandleId = @truncate(target.v1 & 0xFFF);

    const child_self = caps.SelfCap{ .crvr = true, .crpt = true, .pri = 3 };
    const ceilings_inner: u64 =
        @as(u64, 0xFF) |
        (@as(u64, 0x01FF) << 8) |
        (@as(u64, CHILD_CRIPC) << 24) |
        (@as(u64, 0x1F) << 32) |
        (@as(u64, 0x01) << 40) |
        (@as(u64, 0x5C) << 48);
    const ceilings_outer: u64 = 0x0000_003F_01FE_FFFF;
    const passed = [_]u64{
        (caps.PassedHandle{ .id = RESULT_PORT, .caps = (caps.PortCap{ .bind = true, .@"suspend" = true }).toU16(), .move = false }).toU64(),
        (caps.PassedHandle{ .id = SELF_ELF, .caps = (caps.PfCap{ .r = true }).toU16(), .move = false }).toU64(),
        (caps.PassedHandle{ .id = LIBZ_PF, .caps = (caps.PfCap{ .r = true, .x = true }).toU16(), .move = false }).toU64(),
        (caps.PassedHandle{ .id = control_slot, .caps = (caps.PortCap{ .bind = true, .@"suspend" = true }).toU16(), .move = false }).toU64(),
        (caps.PassedHandle{ .id = target_slot, .caps = thread_caps.toU16(), .move = false }).toU64(),
    };
    const child = syscall.createProcess(@as(u64, child_self.toU16()), ceilings_inner, ceilings_outer, SELF_ELF, 0, &passed);
    if (testing.isHandleError(child.v1)) return testing.fail(3);

    const event = syscall.recv(control_slot, TIMEOUT_NS);
    if (event.regs.v1 != @intFromEnum(errors.Error.OK)) return testing.fail(10);
    const reply_slot: caps.HandleId = @truncate((event.word >> 32) & 0xFFF);
    if (reply_slot == 0) return testing.fail(11);
    if (syscall.revoke(target_slot).v1 != @intFromEnum(errors.Error.OK)) return testing.fail(12);
    if (syscall.reply(reply_slot).v1 != @intFromEnum(errors.Error.OK)) return testing.fail(13);
    // The child reports the verdict after it resumes and probes its new port.
}
