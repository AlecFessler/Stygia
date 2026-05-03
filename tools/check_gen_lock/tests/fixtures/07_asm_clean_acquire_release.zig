// EXPECT: clean
// Fully-naked-asm fn that acquires Foo's gen lock via cmpxchg, reads a
// field through the typed pointer, and releases. All offsets resolved
// via @offsetOf through comptimePrint args.

const std = @import("std");

const Foo = extern struct {
    _gen_lock: u64 = 0,
    value: u64 = 0,
};

pub fn asmClean() callconv(.naked) void {
    asm volatile (std.fmt.comptimePrint(
            \\.Lacq:
            \\lock cmpxchgq %%r11, {[lock_off]d}(%%rcx)
            \\je .Lhave
            \\jmp .Lbail
            \\.Lhave:
            \\movq {[val_off]d}(%%rcx), %%rax
            \\andq $-2, {[lock_off]d}(%%rcx)
            \\.Lbail:
            \\ret
            \\
        ,
            .{
                .lock_off = @offsetOf(Foo, "_gen_lock"),
                .val_off = @offsetOf(Foo, "value"),
            },
        ));
}
