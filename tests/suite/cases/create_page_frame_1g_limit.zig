// Regression: a 1 GiB frame is a valid page-size request, but the buddy
// allocator currently has no block above 128 MiB. It must return E_NOMEM
// without trapping, and a subsequent ordinary allocation must still work.
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const large_caps = caps.PfCap{ .r = true, .w = true, .max_sz = 2 };
    const large = syscall.createPageFrame(large_caps.toU16(), 2, 1);
    if (large.v1 != @intFromEnum(errors.Error.E_NOMEM)) {
        testing.fail(1);
        return;
    }

    const small_caps = caps.PfCap{ .r = true, .w = true };
    const small = syscall.createPageFrame(small_caps.toU16(), 0, 1);
    if (testing.isHandleError(small.v1)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
