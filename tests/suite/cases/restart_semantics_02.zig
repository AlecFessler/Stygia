// §[restart_semantics] test 02: VMAR restart ceiling is 2; requesting snapshot policy 3 must return E_PERM.
// The runner narrows only this test process's relevant ceiling.
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const self = caps.readCap(cap_table_base, caps.SLOT_SELF);
    if (((self.field1 >> 18) & 3) != 2) return testing.fail(99);

    const vmar_caps = caps.VmarCap{
        .r = true,
        .w = true,
        .restart_policy = 3, // snapshot exceeds the narrowed ceiling
    };
    // §[create_vmar] props word: cur_rwx in bits 0-2, sz in bits 3-4,
    // cch in bits 5-6. cur_rwx = r|w = 0b011; sz = 0 (4 KiB); cch = 0 (wb).
    const props: u64 = 0b011;
    const result = syscall.createVmar(
        @as(u64, vmar_caps.toU16()),
        props,
        1, // pages
        0, // preferred_base — kernel chooses
        0, // device_region — ignored when caps.dma = 0
    );

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
