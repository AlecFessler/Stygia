// §[restart_semantics] test 05: port restart ceiling is 0; requesting keep policy 1 must return E_PERM.
// The runner narrows only this test process's relevant ceiling.
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const self = caps.readCap(cap_table_base, caps.SLOT_SELF);
    if (((self.field1 >> 22) & 1) != 0) return testing.fail(99);
    // A well-formed port requests keep above the zero ceiling.
    const requested = caps.PortCap{
        .recv = true,
        .bind = true,
        .restart_policy = true,
    };
    const cp = syscall.createPort(@as(u64, requested.toU16()));
    if (cp.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }
    testing.pass();
}
