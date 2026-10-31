// Regression: a 2 MiB page_frame must cover all 512 leaves of a 4 KiB VMAR.
// Also exercise permission remap and selective unmap/reinstall of that span.
const lib = @import("lib");
const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

fn ok(value: u64) bool {
    return value == 0;
}

pub fn main(cap_table_base: u64) void {
    const pf_caps = caps.PfCap{ .r = true, .w = true, .max_sz = 1 };
    const cpf = syscall.createPageFrame(pf_caps.toU16(), 1, 1);
    if (testing.isHandleError(cpf.v1)) return testing.fail(1);
    const pf: u12 = @truncate(cpf.v1 & 0xfff);

    // Negative control: the same PF exceeds a VMAR by one 4 KiB leaf.
    const short_caps = caps.VmarCap{ .r = true, .w = true };
    const short = syscall.createVmar(short_caps.toU16(), 0b011, 511, 0, 0);
    if (testing.isHandleError(short.v1)) return testing.fail(2);
    const short_vmar: u12 = @truncate(short.v1 & 0xfff);
    if (syscall.mapPf(short_vmar, &.{ 0, pf }).v1 != @intFromEnum(errors.Error.E_INVAL))
        return testing.fail(3);

    const vmar_caps = caps.VmarCap{ .r = true, .w = true };
    const cv = syscall.createVmar(vmar_caps.toU16(), 0b011, 512, 0, 0);
    if (testing.isHandleError(cv.v1)) return testing.fail(4);
    const vmar: u12 = @truncate(cv.v1 & 0xfff);
    const base = caps.readCap(cap_table_base, vmar).field0;
    if (!ok(syscall.mapPf(vmar, &.{ 0, pf }).v1)) return testing.fail(5);

    // Touch every leaf, including the first, second and last. The old
    // implementation loops on a user page fault at the second leaf.
    for (0..512) |i| {
        const ptr: *volatile u64 = @ptrFromInt(base + i * 4096);
        ptr.* = 0xface0000 + i;
    }
    if (!ok(syscall.remap(vmar, 0b001).v1)) return testing.fail(6);
    for (0..512) |i| {
        const ptr: *volatile u64 = @ptrFromInt(base + i * 4096);
        if (ptr.* != 0xface0000 + i) return testing.fail(7);
    }
    if (!ok(syscall.unmap(vmar, &.{pf}).v1)) return testing.fail(8);
    if (!ok(syscall.mapPf(vmar, &.{ 0, pf }).v1)) return testing.fail(9);
    if (!ok(syscall.remap(vmar, 0b011).v1)) return testing.fail(10);
    for (0..512) |i| {
        const ptr: *volatile u64 = @ptrFromInt(base + i * 4096);
        if (ptr.* != 0xface0000 + i) return testing.fail(11);
        ptr.* = 0xbeef0000 + i;
    }
    if (!ok(syscall.unmap(vmar, &.{}).v1)) return testing.fail(12);
    testing.pass();
}
