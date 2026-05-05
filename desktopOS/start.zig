const app = @import("app");
const lib = @import("lib");

// Spec §[create_capability_domain]: rdi at entry = pointer to the
// read-only cap-table view. Linker places `_start` in `.text._start`
// so the kernel jumps to it as an ordinary call frame.
export fn _start(cap_table_base: u64) noreturn {
    app.main(cap_table_base);
    // Drop the self-handle (spec §[delete] semantics: domain teardown).
    // Use the discard variant directly so ReleaseSmall DCE doesn't strip
    // the asm volatile chain along with the discarded Regs return.
    lib.syscall.issueRegDiscard(.delete, 0, .{ .v1 = lib.caps.SLOT_SELF });
    while (true) {
        switch (@import("builtin").cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfi"),
            else => {},
        }
    }
}
