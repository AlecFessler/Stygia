const cpu = @import("../cpu.zig");
const interrupts = @import("../interrupts.zig");

const PMI_VECTOR: u8 = 0xFB;

pub fn init() void {
    interrupts.registerVector(PMI_VECTOR, pmiHandler, .external);
}

/// One of two same-named handlers; only file scope tells them apart.
fn pmiHandler(_: *cpu.Context) void {}
