// DMA remap regression. The test-profile kernel independently walks the CPU
// and IOMMU page tables on each successful remap. If it finds a CPU mapping
// at the IOVA, a wrong physical leaf, or stale R/W bits, remap returns an
// error and this case fails. This does not issue a device DMA transaction.
const lib = @import("lib");
const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

fn dmaDevice(base: u64) ?caps.HandleId {
    for (0..caps.HANDLE_TABLE_MAX) |slot| {
        const c = caps.readCap(base, @intCast(slot));
        if (c.handleType() != .device_region) continue;
        const dc: caps.DeviceCap = @bitCast(c.caps());
        if (dc.dma) return @intCast(slot);
    }
    return null;
}

fn curRwx(base: u64, handle: u12) u3 {
    return @truncate((caps.readCap(base, handle).field1 >> 36) & 7);
}

fn runSpan(base: u64, device: caps.HandleId, large_pf: bool) u64 {
    const vc = caps.VmarCap{ .r = true, .w = true, .dma = true };
    const pages: u64 = if (large_pf) 512 else 1;
    const made_vmar = syscall.createVmar(vc.toU16(), 0b011, pages, 0, device);
    if (testing.isHandleError(made_vmar.v1)) return 1;
    const vmar: u12 = @truncate(made_vmar.v1 & 0xFFF);
    const pc = caps.PfCap{ .r = true, .w = true, .max_sz = if (large_pf) 1 else 0 };
    const made_pf = syscall.createPageFrame(pc.toU16(), if (large_pf) 1 else 0, 1);
    if (testing.isHandleError(made_pf.v1)) return 2;
    const pf: u12 = @truncate(made_pf.v1 & 0xFFF);
    if (syscall.mapPf(vmar, &.{ 0, pf }).v1 != 0) return 3;
    if (syscall.remap(vmar, 0b001).v1 != 0) return 4;
    if (curRwx(base, vmar) != 0b001) return 5;
    // Re-upgrade to exercise both directions and every leaf of a split PF.
    if (syscall.remap(vmar, 0b011).v1 != 0) return 6;
    if (curRwx(base, vmar) != 0b011) return 7;
    if (syscall.unmap(vmar, &.{}).v1 != 0) return 8;
    return 0;
}

pub fn main(cap_table_base: u64) void {
    const device = dmaDevice(cap_table_base) orelse return testing.pass();
    const equal_failure = runSpan(cap_table_base, device, false);
    if (equal_failure != 0) return testing.fail(equal_failure);
    const split_failure = runSpan(cap_table_base, device, true);
    if (split_failure != 0) return testing.fail(10 + split_failure);

    // A failed permission request must leave the VMAR's live state intact.
    const vc = caps.VmarCap{ .r = true, .w = true, .dma = true };
    const made_vmar = syscall.createVmar(vc.toU16(), 0b011, 1, 0, device);
    if (testing.isHandleError(made_vmar.v1)) return testing.fail(21);
    const vmar: u12 = @truncate(made_vmar.v1 & 0xFFF);
    const pc = caps.PfCap{ .r = true };
    const made_pf = syscall.createPageFrame(pc.toU16(), 0, 1);
    if (testing.isHandleError(made_pf.v1)) return testing.fail(22);
    const pf: u12 = @truncate(made_pf.v1 & 0xFFF);
    if (syscall.mapPf(vmar, &.{ 0, pf }).v1 != 0) return testing.fail(23);
    // The installed PF rights remain bound after its user handle is gone.
    if (syscall.delete(pf).v1 != 0) return testing.fail(27);
    if (syscall.remap(vmar, 0b011).v1 != @intFromEnum(errors.Error.E_INVAL)) return testing.fail(24);
    if (curRwx(cap_table_base, vmar) != 0b011) return testing.fail(25);
    if (syscall.remap(vmar, 0b001).v1 != 0) return testing.fail(26);
    return testing.pass();
}
