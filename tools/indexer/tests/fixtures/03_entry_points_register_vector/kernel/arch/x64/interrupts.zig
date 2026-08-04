const cpu = @import("cpu.zig");

pub const VectorKind = enum { exception, external };

const Handler = *const fn (*cpu.Context) void;

pub fn registerVector(vector: u8, handler: Handler, kind: VectorKind) void {
    _ = vector;
    _ = handler;
    _ = kind;
}
