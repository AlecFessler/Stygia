const cpu = @import("cpu.zig");
const interrupts = @import("interrupts.zig");

pub fn init() void {
    interrupts.registerVector(14, pageFaultHandler, .exception);
    interrupts.registerVector(13, exceptionHandler, .exception);
}

fn pageFaultHandler(_: *cpu.Context) void {}
fn exceptionHandler(_: *cpu.Context) void {}
