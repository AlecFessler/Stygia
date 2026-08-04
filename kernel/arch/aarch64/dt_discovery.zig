//! AArch64 devicetree device discovery.
//!
//! The devicetree counterpart to `acpi.zig`: same job (find the interrupt
//! controller, the console UART, the core topology and the PSCI conduit,
//! then hand the GIC driver its bases), same tail contract
//! (`gic.init(discovery)`), different firmware description.
//!
//! This exists because the Raspberry Pi 5 has no ACPI at all. Before it,
//! `init.zig` deferred GIC init to `acpi.parseAcpi`, so on a bare-metal
//! BCM2712 boot the chain was: no ACPI, no GIC, no timer interrupt, no
//! scheduler — plus a console pointed at QEMU virt's hardcoded PL011 at
//! PA 0x09000000, which on this SoC is not a UART.
//!
//! `arch/dispatch/boot.zig` chooses between this and `acpi.parseAcpi`;
//! ACPI wins whenever an XSDP is present, so no UEFI boot ever reaches
//! this file.
//!
//! Split of responsibility: all devicetree *parsing* lives in the
//! `std`-only `stygia.boot.fdt`, which is host-tested against a real Pi 5
//! blob. This file does only the things that need the kernel — mapping
//! MMIO into the physmap, and pushing the results into the drivers.
//!
//! What is deliberately NOT discovered here:
//!   - The generic timer needs nothing: CNTP is sysreg-based and its PPI
//!     is architecturally 30. `acpi.zig` does not parse GTDT either.
//!   - No RTC. `rtc.readRtc()` returns 0 when `setBase` was never called,
//!     which is the honest answer on a board whose RTC this kernel has no
//!     driver for; the QEMU PL031 fallback in `acpi.zig` is specific to
//!     QEMU virt and has no business firing on real hardware.

const std = @import("std");
const stygia = @import("stygia");

const aarch64_paging = stygia.arch.aarch64.paging;
const fdt = stygia.boot.fdt;
const gic = stygia.arch.aarch64.gic;
const memory_init = stygia.memory.init;
const paging = stygia.memory.paging;
const power = stygia.arch.aarch64.power;
const serial = stygia.arch.aarch64.serial;
const watchdog = stygia.arch.aarch64.watchdog;

const MappingKind = stygia.memory.address.MappingKind;
const MemoryPerms = stygia.memory.address.MemoryPerms;
const PAddr = stygia.memory.address.PAddr;
const VAddr = stygia.memory.address.VAddr;

/// GIC-400 / Cortex-A15 GIC: `reg[0]` = GICD, `reg[1]` = GICC.
/// Linux `arm,gic.yaml`; ARM IHI 0048B §5.3.
const gicv2_compatibles = [_][]const u8{ "arm,gic-400", "arm,cortex-a15-gic" };

/// GICv3: `reg[0]` = GICD, `reg[1]` = the redistributor range.
/// Linux `arm,gic-v3.yaml`; ARM IHI 0069H §8.1, §9.1.1.
const gicv3_compatibles = [_][]const u8{"arm,gic-v3"};

/// PL011 in its memory-mapped-on-the-main-bus form. Matched exactly: the
/// Pi 5's RP1 southbridge UARTs are `"arm,pl011-axi"` behind a PCIe bus
/// and are neither reachable through this path nor the debug console.
const pl011_compatibles = [_][]const u8{"arm,pl011"};

/// BCM2712 power-management block, which contains the SoC watchdog the
/// bare-metal Pi 5 loader arms before handing off. `reg[0]` is the whole
/// 0x308-byte PM register window; the kernel only writes PM_WDOG at +0x24.
///
/// `/soc/watchdog@7d200000` on the Pi 5, with `reg = <0x7d200000 0x308>`
/// translated through `/soc`'s `ranges = <0x7c000000 0x10 0x7c000000
/// 0x4000000>` to CPU-physical 0x10_7D20_0000 — the same address the
/// loader hardcodes and has verified counting down. `findCompatible`
/// performs that `ranges` walk itself (`fdt.translateUp`), so nothing here
/// re-derives it.
const bcm2712_pm_compatibles = [_][]const u8{"brcm,bcm2712-pm"};

/// Map a physical range as `kind` memory into the kernel's physmap
/// (TTBR1) and return the physmap VA of `phys_start`.
///
/// A near-copy of `acpi.mapDeviceRange`, generalized with a `MappingKind`
/// because the DTB blob itself is RAM (`.kernel_data`) while everything
/// else discovered through it is MMIO (`.kernel_mmio`). Duplicated on
/// purpose rather than making the ACPI helper `pub`: `acpi.zig` is the
/// path every existing boot takes, and keeping its diff at zero lines is
/// the strongest no-regression guarantee available here.
///
/// The physmap built by `memory.init()` covers only RAM the loader
/// reported as free/ACPI, so neither peripheral MMIO nor the loader's
/// reserved DTB page has a TTBR1 translation until this runs.
/// `aarch64.paging.mapPage` overwrites an existing leaf rather than
/// erroring, so overlapping calls are idempotent.
fn mapRange(phys_start: u64, length: u64, kind: MappingKind) !u64 {
    const perms: MemoryPerms = .{ .read = true, .write = true };
    const page = paging.PAGE4K;
    const start_aligned = std.mem.alignBackward(u64, phys_start, page);
    const end_aligned = std.mem.alignForward(u64, phys_start + length, page);
    var pa: u64 = start_aligned;
    while (pa < end_aligned) {
        try aarch64_paging.mapPage(
            memory_init.kernel_addr_space_root,
            PAddr.fromInt(pa),
            VAddr.fromPAddr(PAddr.fromInt(pa), null),
            perms,
            kind,
        );
        pa += page;
    }
    return VAddr.fromPAddr(PAddr.fromInt(phys_start), null).addr;
}

/// Map a console UART the loader already resolved and point the serial
/// driver at it.
///
/// Separate from `discoverUart` because the input is not a devicetree: the
/// loader hands the address over in `BootInfo.console_base`, having both
/// derived and probed it. `arch.boot.parseFirmwareTables` calls this before
/// any discovery so that the diagnostics discovery emits are visible, and
/// then passes `discover_uart = false` to `parseDeviceTree` so the DT
/// search cannot displace it.
///
/// One page is enough: `serial.zig` touches DR/FR/IBRD/FBRD/LCRH/CR, all
/// within the first 0x40 bytes, and the RP1 UART's own `reg` window is
/// only 0x100 bytes wide.
///
/// A mapping failure leaves the driver unset, which makes every `print` a
/// silent no-op. There is nowhere to report it to — the thing that failed
/// IS the console — and it can only happen if the page-table allocator is
/// exhausted this early, which would fail the boot moments later anyway.
pub fn setLoaderConsole(console_phys: PAddr) void {
    const va = mapRange(console_phys.addr, paging.PAGE4K, .kernel_mmio) catch return;
    serial.setBase(va);
}

/// Discover devices from the flattened devicetree at `dtb_phys` and
/// initialize the GIC.
///
/// Order matters: the UART is wired up first so that every diagnostic
/// after it has somewhere to go, and the watchdog second so the pet is
/// live for as much of the remaining boot as possible (the loader armed
/// it with a hard 15.99 s ceiling before jumping here). Anything that
/// fails to parse is logged and skipped rather than fatal — a missing
/// UART costs visibility, a missing PM block costs the watchdog pet on a
/// board that has one (and is the normal case everywhere else), and a
/// missing GIC leaves `gic.init` with zeroed state and its own guards
/// bail out safely, exactly as the zero-XSDP ACPI path already does.
///
/// `discover_uart` is false when the loader already installed a console
/// through `setLoaderConsole`. Searching the DT anyway would find the
/// board's on-SoC PL011 and overwrite a deliberately chosen, verified base
/// with one that may be reachable but unobservable — on the Pi 5 the SoC
/// PL011's pins go to an unwired JST-SH connector, so doing so silently
/// costs every subsequent line of output.
pub fn parseDeviceTree(dtb_phys: PAddr, discover_uart: bool) !void {
    const blob = try mapBlob(dtb_phys);
    const tree = try fdt.Fdt.init(blob);

    if (discover_uart) discoverUart(&tree);
    discoverWatchdog(&tree);
    var discovery = discoverGic(&tree);
    discoverCpus(&tree, &discovery);
    discoverPsci(&tree);

    // Same tail contract as `acpi.parseAcpi`: the GIC driver receives its
    // topology as an explicit argument, and a zeroed `GicDiscovery` is a
    // safe no-op rather than a crash.
    gic.init(discovery);
}

/// Map the blob and return it as a slice at its physmap VA.
///
/// Two-step because the blob's length lives inside the blob: map one page,
/// read `totalsize` out of the header, then map the rest. The re-map of
/// page 0 is harmless (`mapPage` overwrites).
///
/// `.kernel_data` and not `.kernel_mmio`: the DTB is ordinary RAM the
/// loader reserved, and mapping it Device-nGnRnE would make every
/// unaligned `std.mem.readInt` in the parser an alignment fault.
fn mapBlob(dtb_phys: PAddr) ![]const u8 {
    const page = paging.PAGE4K;
    const header_va = try mapRange(dtb_phys.addr, page, .kernel_data);
    const header: [*]const u8 = @ptrFromInt(header_va);
    // Only the header is readable so far, and it must not read past the
    // page even if the blob claims to be shorter than 40 bytes.
    const total = try fdt.totalSize(header[0..page]);

    const base_va = try mapRange(dtb_phys.addr, total, .kernel_data);
    const bytes: [*]const u8 = @ptrFromInt(base_va);
    return bytes[0..total];
}

/// Find the console PL011 and point the serial driver at it.
///
/// On failure the driver is left unset, which makes every `print` a
/// silent no-op (`serial.zig` guards on a null base). Notably this does
/// NOT fall back to QEMU virt's PL011 at PA 0x09000000 the way
/// `acpi.parseAcpi` does for a missing SPCR: a board that shipped a DTB
/// described its UART in it, and writing to an unrelated physical address
/// on real hardware is worse than staying quiet.
fn discoverUart(tree: *const fdt.Fdt) void {
    var regs: [1]fdt.Region = undefined;
    const m = fdt.findCompatible(tree, &pl011_compatibles, true, &regs) catch return;
    if (m.regs == 0) return;
    const uart_va = mapRange(regs[0].base, regs[0].size, .kernel_mmio) catch return;
    serial.setBase(uart_va);
}

/// Find the BCM2712 PM block and let `watchdog.pet()` start writing to it.
///
/// The bare-metal loader arms this watchdog for a full reset immediately
/// before the ERET into the kernel, and its counter is 20 bits at 65536 Hz
/// — a HARD 15.99 s ceiling that no larger arm value can extend. Any kernel
/// workload that runs longer than one timeout (the 485-test suite does, by
/// minutes) must re-arm it, which is what the IRQ-path pet does. Until this
/// runs, `watchdog.pet()` is a no-op, so the loader's single 15 s window is
/// the entire budget for early boot up to this point.
///
/// The pet is bounded, not open-ended — see `watchdog.CEILING_SECONDS`. This
/// call is what starts that budget, which is why the diagnostic below reports
/// it: a board that is expected to reset itself after N seconds and does not
/// is a different bug from one that resets too early.
///
/// Every branch that does not find a usable node leaves the pet disabled,
/// which is the correct behaviour on every other target: QEMU virt and a
/// Pi 5 under KVM both hand the kernel a DTB with no `brcm,bcm2712-pm`
/// node, so nothing is mapped and no PM register is ever written. The
/// diagnostic is printed either way — a silent watchdog is exactly the
/// failure mode that costs a board reset in the middle of a test run, so it
/// should be visible in the boot log rather than inferred from a reset.
///
/// One page covers it: the PM window is 0x308 bytes and the only register
/// the kernel touches is PM_WDOG at +0x24.
fn discoverWatchdog(tree: *const fdt.Fdt) void {
    var regs: [1]fdt.Region = undefined;
    const m = fdt.findCompatible(tree, &bcm2712_pm_compatibles, true, &regs) catch {
        serial.print("[dt] no brcm,bcm2712-pm node — watchdog pet disabled\n", .{});
        return;
    };
    if (m.regs == 0) {
        serial.print("[dt] brcm,bcm2712-pm node has no reg — watchdog pet disabled\n", .{});
        return;
    }
    const pm_va = mapRange(regs[0].base, regs[0].size, .kernel_mmio) catch {
        serial.print("[dt] could not map brcm,bcm2712-pm — watchdog pet disabled\n", .{});
        return;
    };
    if (!watchdog.setBase(pm_va)) {
        serial.print("[dt] CNTFRQ_EL0 is 0 — watchdog pet disabled (no time base)\n", .{});
        return;
    }

    // Pet once here rather than waiting for the first interrupt. This is the
    // first moment the kernel is able to, and it restarts the window from
    // "devicetree discovery finished" instead of from the loader's arm —
    // strictly more headroom for the rest of boot, at the cost of one store.
    watchdog.pet();

    // `remainingTicks` immediately after the pet is the cheapest available
    // proof that the mapping and the password are both right: a wrong base or
    // a dropped password reads back 0 (or the pre-pet value) instead of the
    // reload value.
    serial.print(
        "[dt] watchdog: PM at PA {x}, petting {d}s per IRQ for {d}s (counter {x})\n",
        .{
            regs[0].base,
            watchdog.windowSeconds(),
            watchdog.ceilingSeconds(),
            watchdog.remainingTicks() orelse 0,
        },
    );
    if (m.identity_levels != 0) {
        serial.print(
            "[dt] WARNING: PM address crossed {d} bus level(s) with no ranges\n",
            .{m.identity_levels},
        );
    }
}

/// Find the interrupt controller and populate a `GicDiscovery` with
/// physmap VAs.
///
/// GICv2 is tried first because it is what the only DT-booted target has.
/// A zeroed return is survivable — `gic.init` and `initDistributor` both
/// guard on a zero base.
fn discoverGic(tree: *const fdt.Fdt) gic.GicDiscovery {
    var discovery: gic.GicDiscovery = .{};

    var regs: [2]fdt.Region = undefined;
    if (fdt.findCompatible(tree, &gicv2_compatibles, true, &regs)) |m| {
        if (m.regs < 2) {
            serial.print(
                "[dt] GICv2 node has {d} reg entries, need GICD+GICC\n",
                .{m.regs},
            );
            return discovery;
        }
        // Map exactly what the DT declares (4 KiB GICD, 8 KiB GICC on
        // GIC-400) rather than rounding the distributor up to 64 KiB.
        //
        // That is safe against `initDistributor`'s version probe, which is
        // the only thing that would read past 4 KiB: it reads GICD_PIDR2
        // at 0x0FE8 first and only touches the GICv3 slot at 0xFFE8 when
        // ArchRev != 2. A GIC-400 reports ArchRev 2, so on this hardware
        // the out-of-window offset is never accessed. The GICv3 arm below
        // gets a 64 KiB distributor from its own `reg`.
        discovery.gicd_base = mapRange(
            regs[0].base,
            @max(regs[0].size, paging.PAGE4K),
            .kernel_mmio,
        ) catch return .{};
        discovery.gicc_base = mapRange(
            regs[1].base,
            @max(regs[1].size, paging.PAGE4K),
            .kernel_mmio,
        ) catch return .{};
        if (m.identity_levels != 0) {
            serial.print(
                "[dt] WARNING: GIC address crossed {d} bus level(s) with no ranges\n",
                .{m.identity_levels},
            );
        }
        return discovery;
    } else |_| {}

    // GICv3. UNTESTED ON HARDWARE: no board this kernel boots from a DTB
    // has a GICv3, and QEMU virt (which does) always boots through
    // UEFI/ACPI here. Kept because it is ~20 lines mirroring
    // `acpi.parseMadt`'s redistributor slicing and it is what any future
    // DT-described GICv3 board will need. Treat a first failure on such a
    // board as expected rather than surprising.
    if (fdt.findCompatible(tree, &gicv3_compatibles, true, &regs)) |m| {
        if (m.regs < 1) return discovery;
        // GICv3 distributor occupies 64 KiB. IHI 0069H §8.1.
        discovery.gicd_base = mapRange(
            regs[0].base,
            @max(regs[0].size, 64 * 1024),
            .kernel_mmio,
        ) catch return .{};
        if (m.regs < 2) return discovery;

        // `reg[1]` is a redistributor *range* holding one or more
        // redistributors back to back. Each GICv3 redistributor occupies
        // two 64 KiB frames (RD_base + SGI_base) for a 128 KiB stride.
        // IHI 0069H §9.1.1, §10.1 — same slicing as `acpi.parseMadt`.
        const stride: u64 = 128 * 1024;
        const range_len = std.mem.alignForward(u64, @max(regs[1].size, stride), stride);
        const gicr_va_base = mapRange(regs[1].base, range_len, .kernel_mmio) catch
            return discovery;
        var offset: u64 = 0;
        while (offset + stride <= range_len) {
            const idx: usize = @intCast(discovery.redist_count);
            if (idx >= discovery.gicr_bases.len) break;
            discovery.gicr_bases[idx] = gicr_va_base + offset;
            discovery.redist_count += 1;
            offset += stride;
        }
        return discovery;
    } else |_| {}

    serial.print("[dt] WARNING: no supported interrupt controller in devicetree\n", .{});
    return discovery;
}

/// Record the MPIDRs from `/cpus` and report how many cores to bring up.
///
/// The order of the `cpu@N` nodes defines the kernel's logical core
/// numbering, and on GICv2 — the only interrupt controller any DT-booted
/// target here has — that numbering is also the GIC CPU interface number
/// addressed by `GICD_SGIR.CPUTargetList` and `GICD_ITARGETSR`. The table
/// must therefore be recorded in devicetree order and never reordered;
/// `gic.setMpidr` documents the same contract from the other side.
///
/// Logical core 0 must be the core executing this code, since the whole
/// kernel treats `coreID() == 0` as "the BSP" (`hyp.init` bails on
/// non-zero, `exceptions` routes several PPIs on it) and `smpInitFull`
/// starts its CPU_ON loop at index 1. Every DT so far lists the boot core
/// first, so this is a diagnostic rather than a fixup: reordering the
/// table to force it would break the GIC interface numbering above, which
/// is wired in hardware and not ours to permute.
fn discoverCpus(tree: *const fdt.Fdt, discovery: *gic.GicDiscovery) void {
    var mpidrs: [max_cpus]u64 = undefined;
    const n = fdt.cpuMpidrs(tree, &mpidrs);
    for (mpidrs[0..n], 0..) |mpidr, i| gic.setMpidr(i, mpidr);
    discovery.core_count = n;

    // Printed unconditionally: this is the mapping every per-core array in
    // the kernel is indexed by, and on hardware that numbers cores outside
    // Aff0 it is the first thing to check when a core misbehaves.
    serial.print("[dt] {d} core(s) described, MPIDR", .{n});
    for (mpidrs[0..n]) |mpidr| serial.print(" {x}", .{mpidr});
    serial.print("\n", .{});

    if (n != 0 and gic.coreID() != 0) {
        serial.print(
            "[dt] WARNING: boot core is logical {d}, not 0 — /cpus does not list it first\n",
            .{gic.coreID()},
        );
    }
}

/// Upper bound on `/cpus` entries read from the devicetree. Sized for the
/// boot stack, not for the GIC's table (256 entries): no aarch64 target
/// this kernel runs on has more than a handful, and `gic.setMpidr`
/// bounds-checks the index anyway.
const max_cpus: usize = 16;

/// Set the PSCI conduit from `/psci`'s `method`.
///
/// Absent or unrecognized leaves `power.conduit` at its default of SMC,
/// matching how `acpi.parseFadt` treats an FADT without the
/// PSCI_COMPLIANT flag.
fn discoverPsci(tree: *const fdt.Fdt) void {
    const method = fdt.psciMethod(tree) orelse return;
    switch (method) {
        .smc => power.setConduit(.smc),
        .hvc => power.setConduit(.hvc),
    }
}
