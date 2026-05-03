const app = @import("app");
const lib = @import("lib");

// Per spec §[create_capability_domain]: "The pointer to the new domain's
// read-only view of its capability table is passed as the first argument
// to the initial EC's entry point." On x86-64 SysV that's rdi at entry;
// the linker puts _start in .text._start so the kernel jumps to it as an
// ordinary function call.
export fn _start(cap_table_base: u64) noreturn {
    app.main(cap_table_base);
    // Fall-through: drop the self-handle. Per spec §[delete] the
    // calling capability domain is cleaned up — every handle in its
    // table is released with its type-specific delete behavior, the
    // domain's address space is freed, and any vCPUs / VARs / page
    // frames are torn down.
    //
    // Use `issueRegDiscard` directly. ReleaseSmall LLVM otherwise
    // strips the entire `issueReg → issueRawNoStack` chain when the
    // returned `Regs` is unused — every output operand traces to a
    // discarded slot, which proves the chain dead and lets the
    // optimizer remove the `asm volatile` along with it.
    lib.syscall.issueRegDiscard(.delete, 0, .{ .v1 = lib.caps.SLOT_SELF });
    while (true) {
        switch (@import("builtin").cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfi"),
            else => {},
        }
    }
}
