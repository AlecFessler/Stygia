// A Zig generic: LLVM monomorphizes it to
// `slab.SecureSlab(source.Ctx,256).forEachAlive__anon_1234`, a *quoted* IR
// name (the instantiation argument list contains `(`, `,` and `)`), which
// the pre-fix ir_pass could not lex at all.
pub fn SecureSlab(comptime T: type, comptime N: usize) type {
    return struct {
        const Self = @This();

        slots: [N]T = undefined,

        pub fn forEachAlive(self: *Self, ctx: *anyopaque, visit: *const fn (*anyopaque, *T) bool) void {
            for (&self.slots) |*s| {
                if (!visit(ctx, s)) return;
            }
        }

        pub fn create(self: *Self) ?*T {
            return &self.slots[0];
        }
    };
}
