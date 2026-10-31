// §[restart_semantics] test 07: transfer of a device_region with keep
// is forbidden when the caller's dr_restart_max is zero.
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
    // A fresh zero-filled frame is deliberately not an ELF. If the ceiling
    // check is missing, the call returns E_INVAL without spawning a child.
    const pf = syscall.createPageFrame((caps.PfCap{ .r = true }).toU16(), 0, 1);
    if (testing.isHandleError(pf.v1)) return testing.fail(4);
    const elf: caps.HandleId = @truncate(pf.v1 & 0xFFF);
    const result = syscall.createProcess(0, 0, 0, elf, 0, &passed);
    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) return testing.fail(100 + result.v1);
    testing.pass();
}
