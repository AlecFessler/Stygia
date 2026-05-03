// EXPECT: errors=1
// Fully-naked-asm fn that acquires Foo's gen lock then accesses a field
// via a hardcoded numeric offset (8 bytes) instead of @offsetOf. Once
// the analyzer types %rcx as *Foo (from the cmpxchg acquire), every
// subsequent raw-numeric offset through %rcx is rejected.

const std = @import("std");

const Foo = extern struct {
    _gen_lock: u64 = 0,
    value: u64 = 0,
};

pub fn asmRawOffset() callconv(.naked) void {
    asm volatile (std.fmt.comptimePrint(
            \\.Lacq:
            \\lock cmpxchgq %%r11, {[lock_off]d}(%%rcx)
            \\je .Lhave
            \\jmp .Lbail
            \\.Lhave:
            \\movq 8(%%rcx), %%rax
            \\andq $-2, {[lock_off]d}(%%rcx)
            \\.Lbail:
            \\ret
            \\
        ,
            .{ .lock_off = @offsetOf(Foo, "_gen_lock") },
        ));
}
