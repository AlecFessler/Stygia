// §[restart_semantics] test 07: transfer of a device_region with keep
// is forbidden when the caller's dr_restart_max is zero. The runner passes
// this test's valid ELF page frame in slot 4.
const lib = @import("lib");
const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;
pub fn main(base: u64) void {
    const self = caps.readCap(base, caps.SLOT_SELF);
    if (((self.field1 >> 21) & 1) != 0) return testing.fail(1);
    var source: ?caps.HandleId = null;
    var slot: u32 = 3;
    while (slot < caps.HANDLE_TABLE_MAX) : (slot += 1) {
        const cap = caps.readCap(base, slot);
        if (cap.word0 != 0 and cap.handleType() == .device_region and
            (cap.caps() & (caps.DeviceCap{ .copy = true, .restart_policy = true }).toU16()) ==
                (caps.DeviceCap{ .copy = true, .restart_policy = true }).toU16())
        {
            source = @intCast(slot);
            break;
        }
    }
    const id = source orelse return testing.fail(2);
    const passed = [_]u64{(caps.PassedHandle{
        .id = id,
        .caps = (caps.DeviceCap{ .restart_policy = true }).toU16(),
        .move = false,
    }).toU64()};
    const elf: caps.HandleId = caps.SLOT_FIRST_PASSED + 1;
    const elf_cap = caps.readCap(base, elf);
    if (elf_cap.handleType() != .page_frame or
        (elf_cap.caps() & (caps.PfCap{ .r = true }).toU16()) == 0) return testing.fail(4);
    const result = syscall.createProcess(0, 0, 0, elf, 0, &passed);
    if (result.v1 != @intFromEnum(errors.Error.E_PERM))
        return testing.fail(if (testing.isHandleError(result.v1)) 100 + result.v1 else 3);
    testing.pass();
}
