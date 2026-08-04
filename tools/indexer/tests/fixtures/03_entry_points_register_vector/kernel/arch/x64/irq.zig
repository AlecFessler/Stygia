const cpu = @import("cpu.zig");
const interrupts = @import("interrupts.zig");
// Stygia style: every cross-module reference is bound to a file-local
// alias, so the handler argument is `paging_mod.tlbShootdownHandler`
// and discovery has to expand the alias before it can resolve.
const stygia = @import("stygia");
const paging_mod = stygia.arch.x64.paging;

pub fn init() void {
    interrupts.registerVector(
        0xFF,
        spuriousHandler,
        .external,
    );
    interrupts.registerVector(
        0xFD,
        paging_mod.tlbShootdownHandler,
        .external,
    );
    interrupts.registerVector(
        0xFE,
        schedTimerHandler,
        .external,
    );
    for (32..48) |i| {
        interrupts.registerVector(
            @intCast(i),
            deviceIrqHandler,
            .external,
        );
    }
    // A handler that is defined but never registered must NOT become an
    // entry point.
    _ = neverRegistered;
}

fn spuriousHandler(_: *cpu.Context) void {}
fn schedTimerHandler(_: *cpu.Context) void {}
fn deviceIrqHandler(_: *cpu.Context) void {}
fn neverRegistered(_: *cpu.Context) void {}
