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

/// Discover the platform's interrupt controller, console UART, core
/// topology and power conduit from whatever firmware description the
/// loader handed over, and finish by initializing the interrupt
/// controller.
///
/// `xsdp_paddr` is the ACPI XSDP; `dtb_paddr` a flattened devicetree.
/// Either may be zero. ACPI wins when both are present — every existing
/// boot on both arches goes through it, and the DT path must not perturb
/// that.
///
/// `console_paddr` is a UART base the loader resolved itself, or zero for
/// "discover one". It outranks both firmware descriptions, because a loader
/// that names a console has more information than the firmware tables do:
/// on the Raspberry Pi 5 the only observable UART is behind a PCIe bus the
/// DT parser refuses to translate across, and the loader is the thing that
/// brought that bus up and probed the registers. See
/// `boot.protocol.BootInfo.console_base`.
///
/// x86_64 ignores `dtb_paddr` and `console_paddr` entirely: there is no
/// devicetree-described x86 platform this kernel targets, and its console
/// is a fixed-port 16550 rather than discovered MMIO.
pub fn parseFirmwareTables(
    xsdp_paddr: PAddr,
    dtb_paddr: PAddr,
    console_paddr: PAddr,
) !void {
    switch (builtin.cpu.arch) {
        .x86_64 => try x64.acpi.parseAcpi(xsdp_paddr),
        .aarch64 => {
            // Install the loader's console first, so that every diagnostic
            // the discovery below emits lands on a line someone can watch.
            // Zero — every boot that exists today — skips this entirely and
            // the arms below are reached in exactly their previous state.
            const loader_console = console_paddr.addr != 0;
            if (loader_console) aarch64.dt_discovery.setLoaderConsole(console_paddr);

            if (xsdp_paddr.addr != 0) {
                // UEFI/ACPI boot — the only path any existing target
                // takes. Unchanged, and no new code runs.
                //
                // Note that `parseAcpi` has no `discover_uart` switch, so
                // on an ACPI boot an SPCR-described UART still displaces
                // `console_paddr`. That is deliberate: `acpi.zig` is the
                // file every existing boot on both arches runs through and
                // its zero-line diff is the no-regression guarantee here.
                // No loader produces the ACPI-plus-console_base pair — the
                // UEFI loader always sets `console_base` to 0 — so the
                // conflict is unreachable rather than merely unlikely. A
                // future ACPI board that needs an override is where the
                // switch gets added.
                try aarch64.acpi.parseAcpi(xsdp_paddr);
            } else if (dtb_paddr.addr != 0) {
                // No ACPI but a devicetree: bare-metal boards such as the
                // Raspberry Pi 5, where the DTB is the only description of
                // the GIC and the UART that exists.
                try aarch64.dt_discovery.parseDeviceTree(dtb_paddr, !loader_console);
            } else {
                // Neither. Preserves the pre-existing zero-XSDP fallback
                // in `acpi.parseAcpi` (QEMU virt's hardcoded PL011 +
                // PL031, and a zeroed `gic.init`) for direct-kernel boot.
                try aarch64.acpi.parseAcpi(xsdp_paddr);
            }
        },
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
