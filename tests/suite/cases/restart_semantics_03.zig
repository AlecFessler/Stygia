// §[restart_semantics] test 03: page-frame restart ceiling is 0; requesting keep policy 1 must return E_PERM.
// The runner narrows only this test process's relevant ceiling.
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const self = caps.readCap(cap_table_base, caps.SLOT_SELF);
    if (((self.field1 >> 20) & 1) != 0) return testing.fail(99);

    // §[page_frame] PfCap layout: r = bit 2, restart_policy = bit 7.
    // Setting r so the resulting handle is usable by a follow-up
    // map_pf if a future iteration of this test wants to extend the
    // assertion; restart_policy = 1 ("keep") is the value the spec
    // line under test gates on.
    const pf_caps = caps.PfCap{
        .r = true,
        .restart_policy = true,
    };

    const result = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB), reserved bits clean
        1, // pages: 1 (smallest non-zero allocation)
    );

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
