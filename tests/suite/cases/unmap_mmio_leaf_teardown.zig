// Regression: unmap(N=0) must clear a mapped MMIO leaf before process
// teardown. The fixture PA is outside RAM, so a leaked leaf makes the
// page-table walker attempt to free non-RAM at child exit.
const lib = @import("lib");
const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

fn fixture(cap_table_base: u64) ?u12 {
    for (0..caps.HANDLE_TABLE_MAX) |i| {
        const c = caps.readCap(cap_table_base, @intCast(i));
        if (c.handleType() != .device_region or (c.field0 & 0xf) != 0) continue;
        const phys = ((c.field0 >> 4) & 0x0000_ffff_ffff_ffff) << 12;
        if (phys == 0xbabe_0000) return @intCast(i);
    }
    return null;
}

pub fn main(cap_table_base: u64) void {
    const dev = fixture(cap_table_base) orelse return testing.pass();
    const vmar_caps = caps.VmarCap{ .r = true, .w = true, .mmio = true };
    const cv = syscall.createVmar(vmar_caps.toU16(), (1 << 5) | 0b011, 1, 0, 0);
    if (testing.isHandleError(cv.v1)) return testing.fail(1);
    const vmar: u12 = @truncate(cv.v1 & 0xfff);
    // Reuse the same VMAR to prove the first teardown left it reusable.
    for (0..2) |_| {
        if (syscall.mapMmio(vmar, dev).v1 != 0) return testing.fail(2);
        if (syscall.unmap(vmar, &.{}).v1 != 0) return testing.fail(3);
    }
    testing.pass();
}
