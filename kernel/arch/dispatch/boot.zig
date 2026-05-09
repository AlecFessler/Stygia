const builtin = @import("builtin");
const stygia = @import("stygia");

const aarch64 = stygia.arch.aarch64;
const x64 = stygia.arch.x64;

const PAddr = stygia.memory.address.PAddr;

pub fn init() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.init.init(),
        .aarch64 => aarch64.init.init(),
        else => unreachable,
    }
}

pub fn parseFirmwareTables(xsdp_paddr: PAddr) !void {
    switch (builtin.cpu.arch) {
        .x86_64 => try x64.acpi.parseAcpi(xsdp_paddr),
        .aarch64 => try aarch64.acpi.parseAcpi(xsdp_paddr),
        else => unreachable,
    }
}

pub fn print(
    comptime format: []const u8,
    args: anytype,
) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.serial.print(format, args),
        .aarch64 => aarch64.serial.print(format, args),
        else => unreachable,
    }
}

/// Lockless raw-bytes write to the active UART. Bypasses the per-arch
/// `print_lock` so that detector-instrumented panic paths don't recurse
/// through the very lock they're trying to report on.
pub fn printRaw(s: []const u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.serial.printRaw(s),
        .aarch64 => aarch64.serial.printRaw(s),
        else => unreachable,
    }
}
