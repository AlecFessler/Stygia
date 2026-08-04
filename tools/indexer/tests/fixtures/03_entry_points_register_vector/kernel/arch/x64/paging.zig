const cpu = @import("cpu.zig");

/// Registered from irq.zig through a file-local alias — the case a
/// name-list-based discovery pass misses entirely.
pub fn tlbShootdownHandler(_: *cpu.Context) void {}
