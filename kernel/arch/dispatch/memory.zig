const builtin = @import("builtin");
const stygia = @import("stygia");

const aarch64 = stygia.arch.aarch64;
const x64 = stygia.arch.x64;

/// Zero a 4 KiB page at `ptr` without first reading its contents into cache.
/// This is the PMM-free fast path: pages being returned to the free pool
/// typically are not in cache, so a plain `@memset` pays a read-for-ownership
/// on every cache line. Zeroing-write instructions (CLZERO on x86-64, DC ZVA
/// on aarch64) allocate the line write-only.
///
/// The caller guarantees `ptr` is 4 KiB-aligned and points to 4 KiB of
/// writable kernel VA. Falls back to `@memset` if the underlying CPU
/// lacks the zeroing instruction.
pub inline fn zeroPage(ptr: *anyopaque) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.cpu.zeroPage4K(ptr),
        .aarch64 => aarch64.cpu.zeroPage4K(ptr),
        else => unreachable,
    }
}
