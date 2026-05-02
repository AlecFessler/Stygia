const builtin = @import("builtin");

const app = @import("app");
const lib = @import("lib");

// `pub` is required for `@hasDecl(root, "_start")` to see this decl
// from std/start.zig's startup-export logic. Without pub, std would
// happily emit its own `_start` (and a colliding `main` lookup) on
// the .linux/.none target test ELFs use to unlock dynamic linkage.
//
// Per §[create_capability_domain]: "The pointer to the new domain's
// read-only view of its capability table is passed as the first
// argument to the initial EC's entry point." On x86-64 SysV that's
// rdi at entry; on AAPCS64 that's x0 at entry. The linker script (or
// default ld.lld layout for the dynamic test ELFs) puts _start in
// .text and the kernel ELF loader jumps to it as an ordinary
// function call after applying R_*_RELATIVE relocs.
pub export fn _start(cap_table_base: u64) noreturn {
    app.main(cap_table_base);
    // Fall-through: drop the self-handle, which per spec §[delete]
    // cleans up the calling capability domain.
    //
    // Must use `issueRegDiscard` directly. ReleaseSmall LLVM otherwise
    // strips the entire `issueReg → issueRawNoStack` chain when the
    // returned `Regs` is unused — the chain has 13 output operands
    // none of which feed any side-effecting consumer downstream, so
    // the optimizer proves the chain dead and removes the inner
    // `asm volatile` along with it. The visible failure was the test
    // EC reaching `hlt` with its CD (and any periodic timer it had
    // armed) still live; the leaked timer would then fire forever
    // through `propagateAndWake` and starve the runner past iter
    // ~416, producing the cascade-MISS tail.
    lib.syscall.issueRegDiscard(.delete, 0, .{ .v1 = lib.caps.SLOT_SELF });
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfi"),
            else => @compileError("unsupported target architecture for _start halt"),
        }
    }
}

// Stub to satisfy std/start.zig's `@TypeOf(root.main)` lookup on the
// .linux target. std's posix-startup chain references `root.main` even
// when its `_start` isn't exported (because we provide ours), and Zig
// type-checks the chain regardless. The stub is never called because
// our `_start` is the one the kernel jumps into.
pub fn main() void {}
