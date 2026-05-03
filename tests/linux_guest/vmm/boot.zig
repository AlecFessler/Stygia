/// Linux boot protocol constants and command-line setup.
/// boot_params (zero page) is built inline in main.zig from the bzImage
/// header read out of guest memory after the kernel is loaded from disk.
const mem = @import("mem.zig");

// Guest physical memory layout
pub const BOOT_PARAMS_ADDR: u64 = 0x10000;
pub const CMDLINE_ADDR: u64 = 0x20000;
pub const KERNEL_ADDR: u64 = 0x100000;
pub const INITRAMFS_ADDR: u64 = 0x6000000; // 96 MB — must be above kernel decompression zone

/// Write command line to guest memory.
pub fn setupCmdline(cmdline: []const u8) void {
    mem.writeGuest(CMDLINE_ADDR, cmdline);
    // Null terminator
    const zero: [1]u8 = .{0};
    mem.writeGuest(CMDLINE_ADDR + cmdline.len, &zero);
}
