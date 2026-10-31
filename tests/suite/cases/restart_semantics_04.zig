// §[restart_semantics] test 04: VM restart ceiling is 0; requesting keep policy 1 must return E_PERM.
// The runner narrows only this test process's relevant ceiling.
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const self = caps.readCap(cap_table_base, caps.SLOT_SELF);
    if (((self.field1 >> 23) & 1) != 0) return testing.fail(99);

    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // one 4 KiB page is larger than VmPolicy
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const pf_handle: u12 = @truncate(cpf.v1 & 0xFFF);

    // §[virtual_machine] VmCap layout: bit 0 = policy, bit 1 =
    // restart_policy. Setting restart_policy = 1 is the cap shape the
    // spec calls out for this test.
    const vm_caps = caps.VmCap{ .restart_policy = true };
    const result = syscall.createVirtualMachine(
        @as(u64, vm_caps.toU16()),
        pf_handle,
    );

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
