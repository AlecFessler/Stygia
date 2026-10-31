const cpu = @import("../cpu.zig");
const interrupts = @import("../interrupts.zig");

const VENDOR_VECTOR: u8 = 0xFB;

pub fn init() void {
    interrupts.registerVector(VENDOR_VECTOR, vendorIrqHandler, .external);
}

/// One of two same-named handlers; only file scope tells them apart.
fn vendorIrqHandler(_: *cpu.Context) void {}
