// §[restart_semantics] test 06: the caller's ipc_restart_max is zero.
// create_process mints a caller IPC handle carrying the caller's cripc_ceiling
// (0x27, including restart_policy=1), so it must deny the call. The runner
// passes this test's valid ELF page frame in slot 4.
const lib = @import("lib");
const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;
pub fn main(base: u64) void {
    const self = caps.readCap(base, caps.SLOT_SELF);
    if (((self.field1 >> 24) & 1) != 0 or ((self.field0 >> 24) & 0x20) == 0) return testing.fail(1);
    const elf: caps.HandleId = caps.SLOT_FIRST_PASSED + 1;
    const elf_cap = caps.readCap(base, elf);
    if (elf_cap.handleType() != .page_frame or
        (elf_cap.caps() & (caps.PfCap{ .r = true }).toU16()) == 0) return testing.fail(4);
    const result = syscall.createProcess(0, 0, 0, elf, 0, &.{});
    if (result.v1 != @intFromEnum(errors.Error.E_PERM))
        return testing.fail(if (testing.isHandleError(result.v1)) 100 + result.v1 else 3);
    testing.pass();
}
