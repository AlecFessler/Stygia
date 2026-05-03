// EXPECT: errors=1
// Fully-naked-asm fn that reads Foo.value BEFORE acquiring the gen lock.
// The analyzer should flag the unguarded access.

const std = @import("std");

const Foo = extern struct {
    _gen_lock: u64 = 0,
    value: u64 = 0,
};

pub fn asmEarlyAccess() callconv(.naked) void {
    asm volatile (std.fmt.comptimePrint(
            \\movq {[val_off]d}(%%rcx), %%rax
            \\.Lacq:
            \\lock cmpxchgq %%r11, {[lock_off]d}(%%rcx)
            \\je .Lhave
            \\jmp .Lbail
            \\.Lhave:
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
