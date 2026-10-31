// §[restart_semantics] test 06: the caller's ipc_restart_max is zero.
// create_process necessarily mints a caller IPC handle carrying the caller's
// cripc_ceiling (0x27, including restart_policy=1), so it must deny the call.
const lib = @import("lib");
const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;
pub fn main(base: u64) void {
    const self = caps.readCap(base, caps.SLOT_SELF);
    if (((self.field1 >> 24) & 1) != 0 or ((self.field0 >> 24) & 0x20) == 0) return testing.fail(1);
    // A fresh zero-filled frame is deliberately not an ELF. If the ceiling
    // check is missing, the call returns E_INVAL without spawning a child.
    const pf = syscall.createPageFrame((caps.PfCap{ .r = true }).toU16(), 0, 1);
    if (testing.isHandleError(pf.v1)) return testing.fail(4);
    const elf: caps.HandleId = @truncate(pf.v1 & 0xFFF);
    const result = syscall.createProcess(0, 0, 0, elf, 0, &.{});
    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) return testing.fail(100 + result.v1);
    testing.pass();
}
