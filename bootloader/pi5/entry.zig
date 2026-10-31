//! Raspberry Pi 5 native boot entry.
//!
//! This is a SECOND bootloader, parallel to the UEFI one in bootloader/main.zig,
//! for a platform that has no UEFI. It exists because bare metal is the only
//! configuration that can exercise aarch64 virtualization on real silicon: Pi
//! firmware hands the kernel EL2 (Linux runs VHE here), whereas under Pi KVM the
//! guest is pinned at EL1 and 38 hv tests pass trivially through an `E_NODEV`
//! early-out. Nothing in this directory is generic kernel code — it is specific
//! to one board, and it talks to the kernel only through `BootInfo`.
//!
//! Firmware contract, all of it measured on a Pi 5 Model B Rev 1.0 rather than
//! taken from documentation:
//!
//!   * The file named by `kernel=` is loaded as a RAW binary at `kernel_address`
//!     (pinned to 0x80000) and branched to at offset 0. So `_start` must be the
//!     first byte of the image — see the linksection note below.
//!   * Entry is at **EL2** with `SCTLR_EL2 = 0x30c50830`, i.e. **MMU off**.
//!   * `x0` holds the DTB physical address (observed 0x2efebe00; it moves
//!     between boots, so it must never be hardcoded).
//!   * ATF is resident at 0x0-0x7FFFF and provides **PSCI v1.1**, which gives us
//!     `SYSTEM_RESET` to return the board to Pi OS and `CPU_ON` for SMP.
//!
//! `bootloader/aarch64_el2_drop.zig` IS reused, all of it except the allocator.
//! That file mirrors an existing EL2 MMU configuration into EL1 (`TTBR0_EL2` ->
//! `TTBR0_EL1`, `MAIR_EL2` -> `MAIR_EL1`, `TCR_EL1` rebuilt from `TCR_EL2`,
//! `SCTLR_EL1` from `SCTLR_EL2`), which an earlier revision of this comment
//! called meaningless here on the grounds that those registers hold reset values
//! without UEFI. That was true when the drop happened at entry; it is not true
//! now. `mmu.zig` programs MAIR_EL2 *and* MAIR_EL1, TCR_EL2 and TTBR0_EL2 itself,
//! and the drop happens at the very end with all of that live — so mirroring is
//! exactly the right operation and reimplementing it would only be a chance to
//! reintroduce its bugs. The one part that genuinely cannot be reused is
//! `allocateHypVectorStub`, which allocates through UEFI `BootServices`;
//! `handoff.zig :: allocHypStub` is the arena-backed equivalent and copies the
//! same comptime-assembled, position-independent `hyp_vectors_bytes`.
//!
//! The drop is deliberately LAST rather than first (the UEFI path drops on line
//! 190, before it does anything else). It has to be: `mmu.syncTables` and
//! `mmu.enable` use `tlbi alle2` and write SCTLR_EL2/TTBR0_EL2, and every MMIO
//! window this loader maps — UART, PCIe, the watchdog's PM block — goes into the
//! live TTBR0_EL2 through those paths. All of it is illegal or meaningless at EL1.
//! See `handoff.zig` for the consequences that ordering has for `BootInfo`.
//!
//! Safety model: booting this is a ONE-SHOT `tryboot`. Any reset falls back to
//! `config.txt` and stock Pi OS, so a wedged loader self-recovers on the next
//! reset. The corollary is that a HANG does not self-recover — only a reset does
//! — which is why the failure path here resets rather than spinning wherever it
//! can, and why the early log commits at every checkpoint.

const std = @import("std");

const stygia = @import("stygia");

const boot_info = @import("boot_info.zig");
const dtb = @import("dtb.zig");
const el2_drop = @import("el2_drop");
const handoff = @import("handoff.zig");
const kernel_load = @import("kernel_load.zig");
const log = @import("early_log.zig");
const mmu = @import("mmu.zig");
const page_allocator = @import("page_allocator.zig");
const pcie = @import("pcie.zig");
const pi5_paging = @import("paging.zig");
const uart = @import("uart.zig");
const vectors = @import("vectors.zig");
const watchdog = @import("watchdog.zig");
const blobs = @import("pi5_blobs");

const arch = stygia.arch.dispatch;
const paging = stygia.memory.paging;
const MemoryPerms = stygia.memory.address.MemoryPerms;
const PAddr = stygia.memory.address.PAddr;
const VAddr = stygia.memory.address.VAddr;
const kernel_code = stygia.memory.address.AddrSpacePartition.kernel_code;
const physmap = stygia.memory.address.AddrSpacePartition.physmap;

/// One-shot validation of the watchdog: hang on purpose so the reset can be
/// observed. Set false once proven — leaving it true means the loader never
/// reaches the kernel.
const TEST_WATCHDOG: bool = false;

/// PSCI SMC64 function IDs (Arm DEN 0022). ATF on this board advertises v1.1.
const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;

/// Provided by the linker script; bounds the loader image for reservation.
extern const __image_start: anyopaque;
extern const __image_end: anyopaque;

/// Stack top, chosen in the linker script. Grows down.
const STACK_SIZE: u64 = 0x4000;
extern const __stack_top: anyopaque;

fn psciSystemReset() noreturn {
    log.commit();
    asm volatile ("smc #0"
        :
        : [fid] "{x0}" (PSCI_SYSTEM_RESET),
        : .{ .memory = true });
    // SYSTEM_RESET is specified not to return. If it does, the call is
    // unsupported and the board now needs a physical power cycle — worth saying
    // so explicitly, because the symptom (a dark board) is identical to a dozen
    // other failures.
    log.str("*** PSCI SYSTEM_RESET returned: unsupported. Board will hang.\n");
    log.commit();
    while (true) asm volatile ("wfe");
}

fn currentEl() u64 {
    var v: u64 = undefined;
    asm volatile ("mrs %[v], CurrentEL"
        : [v] "=r" (v),
    );
    return (v >> 2) & 0x3;
}

fn sctlrEl2() u64 {
    var v: u64 = undefined;
    asm volatile ("mrs %[v], sctlr_el2"
        : [v] "=r" (v),
    );
    return v;
}

/// Consume — and report — any asynchronous external abort the loader left pending,
/// so the kernel starts from a clean slate.
///
/// This is not hygiene, it is a measured bug fix. The loader deliberately reads
/// windows that nothing answers: PCIe config space before the link is trained,
/// controller offsets that return `0xDEADDEAD`, BARs that are not yet assigned.
/// On this SoC at least one of those produces an external abort that is reported
/// ASYNCHRONOUSLY, and PSTATE.A is set for the whole life of the loader, so it just
/// sits there pending. The kernel then inherits it and the first `eret` into
/// userspace — the first instruction anywhere in the boot that unmasks SError —
/// detonates it. Measured on hardware exactly once the console came up:
///
///     UNEXPECTED EXCEPTION: ESR=0xbe000011 ELR=0xbef933afb1c FAR=0xffff0000d7000000
///     KERNEL PANIC: Unexpected exception vector taken
///
/// `ESR` EC=0x2F is SError, AET=0b000 (uncontainable), and `ELR` is the root thread's
/// entry point — i.e. the abort had nothing to do with the code it landed on, which
/// is precisely what makes it so misleading to debug from the kernel side.
///
/// `esb` (Error Synchronization Barrier, ARMv8.2-RAS, implemented by Cortex-A76)
/// is the architected way to deal with this: with SError masked it converts a
/// pending abort into a *deferred* error recorded in DISR_EL1 instead of leaving it
/// to fire later. Writing DISR_EL1 back to zero discards it. `esb` sits in the HINT
/// space, so on a part without RAS it is simply a NOP and this degrades to reading a
/// register that always reads zero.
///
/// Reported rather than silently swallowed: an abort here means the loader touched
/// something it should not have, and that is worth seeing even though discarding it
/// is the right thing to do.
fn drainDeferredErrors() void {
    // Retire outstanding accesses first, or `esb` has nothing to synchronize.
    asm volatile ("dsb sy" ::: .{ .memory = true });
    asm volatile ("esb");

    var disr: u64 = undefined;
    asm volatile ("mrs %[v], disr_el1"
        : [v] "=r" (disr),
    );

    // Bit 31 (A) means a deferred error is recorded; the rest mirrors an SError ESR.
    if ((disr & (1 << 31)) == 0) {
        log.str("    no deferred external abort pending (DISR_EL1 = 0)\n");
        return;
    }

    log.str("    *** DEFERRED EXTERNAL ABORT consumed here: DISR_EL1 = ");
    log.hex(disr);
    log.str("\n    *** (loader device probing left it pending; discarding so it does\n");
    log.str("    *** not surface inside the kernel at the first eret to EL0)\n");

    asm volatile ("msr disr_el1, %[v]"
        :
        : [v] "r" (@as(u64, 0)),
    );
    asm volatile ("isb");
}

fn logRanges(name: []const u8, ranges: []const dtb.Range) void {
    log.str("  ");
    log.str(name);
    log.str(" (");
    log.dec(ranges.len);
    log.str("):\n");
    for (ranges) |r| {
        log.str("    ");
        log.hex(r.base);
        log.str(" .. ");
        log.hex(r.end());
        log.str("  ");
        log.size(r.size);
        log.byte('\n');
    }
}

/// Report and sanity-check the blobs carried inside the loader image.
///
/// Three things are verified, each of which has a failure mode that is very hard
/// to diagnose later:
///
///   * page alignment, because `bytesAsValue(Elf64_Ehdr, ..)` assumes natural
///     alignment and an unaligned Device-memory access faults with the MMU off;
///   * the ELF magic, which proves firmware loaded this far into a ~10 MB file
///     rather than truncating it;
///   * a non-zero length, which catches the build wiring silently embedding an
///     empty placeholder (the aarch64 `embedded_bins` stubs are empty slices, and
///     picking one of those up by mistake would look like a working build).
fn checkBlobs() bool {
    // Both checks run before either can fail the boot, so one log shows the state
    // of the whole payload rather than just the first broken half.
    const kernel_ok = checkBlob("kernel  ", &blobs.kernel_elf);
    const rs_ok = checkBlob("root_svc", &blobs.root_service_elf);
    log.commit();
    return kernel_ok and rs_ok;
}

fn checkBlob(name: []const u8, bytes: []const u8) bool {
    const addr = @intFromPtr(bytes.ptr);

    log.str("  ");
    log.str(name);
    log.str(" @ ");
    log.hex(addr);
    log.str("  ");
    log.size(bytes.len);

    if (bytes.len == 0) {
        log.str("  *** EMPTY\n");
        return false;
    }
    if ((addr & (boot_info.PAGE - 1)) != 0) {
        log.str("  *** NOT PAGE ALIGNED\n");
        return false;
    }
    // ELF magic, read bytewise: a naturally aligned single-byte Device access is
    // always safe, whatever the surrounding alignment turns out to be.
    if (!(bytes[0] == 0x7F and bytes[1] == 'E' and bytes[2] == 'L' and bytes[3] == 'F')) {
        log.str("  *** BAD ELF MAGIC (");
        log.hex(bytes[0]);
        log.byte(' ');
        log.hex(bytes[1]);
        log.byte(' ');
        log.hex(bytes[2]);
        log.byte(' ');
        log.hex(bytes[3]);
        log.str(")\n");
        return false;
    }
    log.str("  ELF ok\n");
    return true;
}

export fn piMain(dtb_phys: u64) noreturn {
    log.init();
    log.str("stygia pi5 loader\n");
    log.commit();

    // Vectors go in before anything that can fault. Everything executing above
    // this line has invisible failures: a fault there wedges the core, and a
    // wedge means a physical power cycle, which cold-boots the board and erases
    // this very log. Only log.init() precedes it, and only because the handler
    // needs somewhere to write — those 16 byte stores are the same ones the C0
    // stub already proved work.
    vectors.install();
    log.str("  EL2 vectors installed at ");
    log.hex(@intFromPtr(&vectors.pi5Vectors));
    log.byte('\n');
    log.commit();

    // Only now, with vectors live, touch the embedded payload. This is the first
    // code that reads far into the image — ~10 MB past the entry point — and it is
    // the check that firmware actually loaded the whole file rather than a prefix.
    // A short load would otherwise show up much later as a corrupt ELF header or
    // a truncated section, at which point it looks like a parser bug.
    if (!checkBlobs()) psciSystemReset();

    const el = currentEl();
    log.str("  CurrentEL = EL");
    log.dec(el);
    log.byte('\n');
    if (el != 2) {
        // Everything downstream — the hyp stub, arrived_at_el2, the whole reason
        // this path exists — depends on being at EL2. Continuing at EL1 would
        // produce a kernel that boots and silently lacks HV support.
        log.str("  *** expected EL2; refusing to continue\n");
        psciSystemReset();
    }

    const sctlr = sctlrEl2();
    log.str("  SCTLR_EL2 = ");
    log.hex(sctlr);
    if ((sctlr & 1) != 0) {
        // The map we build and the addresses we log would all be virtual, and
        // every physical address in this loader would be wrong.
        log.str("  *** MMU is ON at entry; this path assumes it is off\n");
        log.commit();
        psciSystemReset();
    }
    log.str("  (MMU off)\n");
    log.commit();

    log.str("  dtb = ");
    log.hex(dtb_phys);
    log.byte('\n');

    const map = dtb.parseMemory(dtb_phys) catch |err| {
        log.str("  *** DTB parse failed: ");
        log.str(@errorName(err));
        log.byte('\n');
        psciSystemReset();
    };
    const dtb_size: u64 = blk: {
        const p: *volatile [4]u8 = @ptrFromInt(@as(usize, @intCast(dtb_phys)) + 4);
        const b = p.*;
        break :blk (@as(u64, b[0]) << 24) | (@as(u64, b[1]) << 16) |
            (@as(u64, b[2]) << 8) | @as(u64, b[3]);
    };
    log.str("  dtb totalsize = ");
    log.size(dtb_size);
    log.byte('\n');

    logRanges("DTB RAM ranges", map.ramSlice());
    logRanges("DTB reserved ranges", map.reservedSlice());
    if (map.skipped_reg != 0) {
        // Not fatal, but it means a reservation may be missing — and a missing
        // reservation is memory the kernel will happily allocate over.
        log.str("  NOTE: skipped ");
        log.dec(map.skipped_reg);
        log.str(" reg properties whose length did not match their cell stride\n");
    }
    log.commit();

    const image_base = @intFromPtr(&__image_start);
    const image_end = @intFromPtr(&__image_end);
    log.str("  loader image ");
    log.hex(image_base);
    log.str(" .. ");
    log.hex(image_end);
    log.str("  ");
    log.size(image_end - image_base);
    log.byte('\n');

    var ext = boot_info.LoaderExtents{
        .image_base = image_base,
        .image_end = image_end,
        .stack_top = @intFromPtr(&__stack_top),
        .stack_size = STACK_SIZE,
        .dtb_base = dtb_phys,
        .dtb_size = dtb_size,
        // Not yet embedded — the @embedFile wiring is a later increment. Zero
        // means "nothing to reserve", and the loader deliberately does NOT
        // pretend to have a root service it cannot provide.
        .root_service_base = 0,
        .root_service_size = 0,
        // Filled in after the arena has been used; see below.
        .arena_base = 0,
        .arena_size = 0,
    };

    // Pass 1. This map exists only to find somewhere to put the arena — the
    // loader has to see free memory before it can carve its own working set out
    // of it. It is scratch: pass 2 overwrites the same static array, so nothing
    // may hold a pointer into it past this point.
    _ = boot_info.buildMMap(&map, ext) catch |err| {
        log.str("  *** preliminary map synthesis failed: ");
        log.str(@errorName(err));
        log.byte('\n');
        psciSystemReset();
    };

    const span = boot_info.largestFreeSpan() orelse {
        log.str("  *** no free span for the page arena\n");
        psciSystemReset();
    };
    var arena = page_allocator.Arena.init(span) catch |err| {
        log.str("  *** page arena unusable: ");
        log.str(@errorName(err));
        log.str(" (largest free span ");
        log.size(span.size);
        log.str(")\n");
        psciSystemReset();
    };
    arena.dump();
    log.commit();

    // Prove the kernel's own table builder works with the MMU off, before
    // anything depends on it. Verified by walking the tables in software;
    // nothing here touches SCTLR, so a malformed table is a log line rather
    // than a dark board.
    if (!selfTestPageTables(&arena)) {
        log.str("  *** page table self-test FAILED; refusing to continue\n");
        psciSystemReset();
    }

    // ── Turn the MMU on ────────────────────────────────────────────────────
    //
    // Everything above this line is hand-written and alignment-safe. Everything
    // below it uses the standard library, which is not safe against Device memory
    // — `std.mem.eql` on a short slice compiles to overlapping unaligned 4-byte
    // loads and faulted here on the ELF magic comparison. See mmu.zig.
    log.str("  enabling MMU at EL2:\n");
    const e2h = mmu.hcrE2H();
    log.str("    HCR_EL2.E2H = ");
    log.dec(e2h);
    log.byte('\n');
    if (e2h != 0) {
        // TCR_EL2's field layout differs entirely between E2H=0 and E2H=1, so
        // programming it under the wrong assumption would silently install a
        // garbage translation regime. Fail loudly instead of guessing; the log
        // above says which case this board is actually in.
        log.str("    *** E2H=1 (VHE) not handled by this path; refusing to continue\n");
        psciSystemReset();
    }

    const ttbr0_root = allocRoot(arena.allocator()) orelse psciSystemReset();
    mmu.buildIdentity(arena.allocator(), ttbr0_root, &map) catch |err| {
        log.str("    *** identity map failed: ");
        log.str(@errorName(err));
        log.byte('\n');
        psciSystemReset();
    };
    log.str("    identity map built at ");
    log.hex(ttbr0_root);
    log.byte('\n');
    arena.dump();

    // Verify the addresses we must keep executing and logging from. This is the
    // last moment a bad table is diagnosable rather than fatal.
    const probes = [_]u64{
        @intFromPtr(&__image_start),
        0x80000 + 0x1000,
        @intFromPtr(&__stack_top) - 8,
        @intFromPtr(&blobs.kernel_elf),
        @intFromPtr(&blobs.root_service_elf),
        arena.base,
        arena.next - paging.PAGE4K,
        log.REGION,
    };
    if (!mmu.verifyIdentity(ttbr0_root, &probes)) {
        log.str("    *** identity map does not translate; refusing to enable the MMU\n");
        log.commit();
        psciSystemReset();
    }
    mmu.dumpState("before");
    // Commit before the cliff: if the next instruction faults with translation
    // broken, this is the last thing that reaches DRAM.
    log.str("    enabling now\n");
    log.commit();

    mmu.enable(ttbr0_root);

    // Reaching here means instruction fetch, the stack and the log region all
    // survived the transition.
    log.str("  MMU ON\n");
    mmu.dumpState("after ");
    log.commit();

    // ── Find a real console ────────────────────────────────────────────────
    //
    // This is the point of the whole exercise: the kernel needs a UART it can hand
    // to userspace, and it can only be handed one that actually decodes. Probe both
    // candidates and record which. Reads only — a probe must not disturb a UART
    // firmware may still be using.
    log.str("  UART probe:\n");
    const soc = probeUart(&arena, ttbr0_root, "SoC PL011  ", uart.SOC_PL011_BASE);
    var rp1 = probeUart(&arena, ttbr0_root, "RP1 uart0  ", uart.RP1_UART0_BASE);

    // RP1 was dead. Find out how expensive making it live actually is, since it is
    // the only UART wired to a cable that exists on this board.
    if (!rp1.usable()) {
        log.str("  PCIe root complex probe (RP1 is unreachable; how bad is it?):\n");
        pcie.map(arena.allocator(), ttbr0_root) catch |err| {
            log.str("    *** could not map controller MMIO: ");
            log.str(@errorName(err));
            log.byte('\n');
        };
        _ = pcie.probe();
        // `pcie.probe` may have trained the link, enumerated RP1, given uart0 a baud
        // clock and pins, and configured it — so the probe above is stale the moment
        // it returns. Re-probing is not defensive tidiness: selecting on the stale
        // result is exactly what silently demoted a *working* RP1 console to the
        // unwired SoC PL011 on the first boot that ever got a console up, costing
        // every log line after the PCIe stage.
        rp1 = uart.probe(uart.RP1_UART0_BASE);
        uart.dumpProbe("RP1 uart0 (re-probed after bring-up)", rp1);
        log.commit();
    }

    // Prefer RP1: it is Linux's ttyAMA0 and the GPIO 14/15 header, i.e. the cable
    // that physically exists. The SoC PL011 is the fallback — it needs no PCIe, so
    // it is the more reliable of the two, but its pins go to a JST-SH connector
    // that is not currently wired, which makes it useful for bring-up and useless
    // for actually watching output.
    if (rp1.usable()) {
        uart.setConsole(uart.RP1_UART0_BASE);
        log.str("    console -> RP1 uart0 (ttyAMA0, GPIO 14/15 header)\n");
    } else if (soc.usable()) {
        uart.setConsole(uart.SOC_PL011_BASE);
        log.str("    console -> SoC PL011 (JST-SH debug connector)\n");
    } else {
        log.str("    *** no usable UART; staying on the DRAM log only\n");
    }
    log.commit();

    if (uart.haveConsole()) {
        // First bytes ever emitted by Stygia on this board's serial line.
        uart.puts("\n[stygia pi5 loader] console is live\n");
        uart.flush();
    }

    // ── Arm the watchdog ───────────────────────────────────────────────────
    //
    // From here on the loader is heading for a handoff, after which its own
    // reset-on-fault vectors no longer apply — the kernel installs its own. This
    // is the only thing that guarantees the board comes back on its own from a
    // kernel panic, a silent hang, or a healthy run that simply never ends. See
    // watchdog.zig.
    log.str("  watchdog:\n");
    watchdog.map(arena.allocator(), ttbr0_root) catch |err| {
        log.str("    *** could not map the PM block: ");
        log.str(@errorName(err));
        log.str("\n    *** continuing WITHOUT a watchdog; a hang will need a power cycle\n");
    };
    watchdog.arm(watchdog.MAX_SECONDS);
    const wdog_ok = watchdog.verifyRunning();
    log.commit();
    if (uart.haveConsole()) {
        uart.puts(if (wdog_ok)
            "[stygia pi5 loader] watchdog armed and counting\n"
        else
            "[stygia pi5 loader] WARNING: watchdog not counting\n");
        uart.flush();
    }

    if (TEST_WATCHDOG) {
        // One-shot validation: hang on purpose. If the board resets by itself and
        // falls back to Pi OS, the watchdog works and every later bare-metal boot
        // is recoverable. Proving this BEFORE the first EL2->EL1 drop matters,
        // because the drop is the step most likely to wedge the board, and without
        // a working watchdog that wedge needs a human.
        log.str("  TEST_WATCHDOG: hanging deliberately; the board should reset itself\n");
        log.commit();
        if (uart.haveConsole()) {
            uart.puts("[stygia pi5 loader] deliberate hang; watchdog should reset us\n");
            uart.flush();
        }
        while (true) asm volatile ("nop");
    }

    // Load the kernel into a real TTBR1 root and copy the root service beside it.
    // Both land in the arena, so both are covered by the arena reservation that
    // pass 2 installs below.
    const ttbr1_root = allocRoot(arena.allocator()) orelse psciSystemReset();
    log.str("  kernel load (ttbr1 ");
    log.hex(ttbr1_root);
    log.str("):\n");
    const loaded = kernel_load.loadKernel(arena.allocator(), ttbr1_root, &blobs.kernel_elf) catch |err| {
        log.str("    *** kernel load failed: ");
        log.str(@errorName(err));
        log.byte('\n');
        psciSystemReset();
    };
    kernel_load.dump(&loaded);

    const rs = kernel_load.copyIntoArena(arena.allocator(), &blobs.root_service_elf) catch |err| {
        log.str("    *** root_service copy failed: ");
        log.str(@errorName(err));
        log.byte('\n');
        psciSystemReset();
    };
    log.str("    root_service copy at ");
    log.hex(rs.phys);
    log.str("  ");
    log.size(rs.len);
    log.byte('\n');
    arena.dump();
    log.commit();

    // Spot-check the freshly built kernel table the same way the self-test checked
    // the throwaway one: translate the entry point and confirm it resolves to the
    // page we copied .text into. A wrong table here is silent until the MMU comes
    // on, at which point it is unrecoverable.
    log.str("  kernel table verification:\n");
    const entry_walk = pi5_paging.walk(ttbr1_root, loaded.entry.addr);
    if (entry_walk) |t| {
        log.str("    entry ");
        log.hex(loaded.entry.addr);
        log.str(" -> ");
        log.hex(t.phys);
        log.str(" ok\n");
    } else {
        log.str("    *** entry VA ");
        log.hex(loaded.entry.addr);
        log.str(" is UNMAPPED in the kernel table\n");
        log.commit();
        psciSystemReset();
    }

    // ── The last allocations ───────────────────────────────────────────────
    //
    // Kernel stack and hyp vector stub. Both must be claimed BEFORE pass 2
    // below, because pass 2 reserves `arena.usedRange()` and publishes
    // everything past `arena.next` as free memory — a page handed out
    // afterwards would be handed to the kernel's physical allocator while the
    // kernel is standing on it.
    log.str("  handoff setup:\n");
    const hand = handoff.prepare(arena.allocator(), ttbr1_root) orelse {
        log.commit();
        psciSystemReset();
    };
    const hyp_stub_phys = handoff.allocHypStub(arena.allocator()) orelse {
        log.commit();
        psciSystemReset();
    };
    arena.dump();
    log.commit();

    // Pass 2. The authoritative map, with the pages just handed out reserved.
    // Skipping this would produce a kernel that boots fine and then allocates
    // over its own page tables at some unrelated later moment.
    ext.root_service_base = rs.phys;
    ext.root_service_size = rs.len;
    ext.arena_base = arena.usedRange().base;
    ext.arena_size = arena.usedRange().size;
    const mmap = boot_info.buildMMap(&map, ext) catch |err| {
        log.str("  *** memory map synthesis failed: ");
        log.str(@errorName(err));
        log.byte('\n');
        psciSystemReset();
    };

    boot_info.dumpReservations();
    boot_info.dumpMMap();
    log.str("  mmap: ");
    log.dec(mmap.num_descriptors);
    log.str(" descriptors, descriptor_size = ");
    log.dec(mmap.descriptor_size);
    log.byte('\n');
    log.commit();

    // BootInfo can only be filled in now: `mmap` is one of its fields and pass 2
    // is what produces it. Nothing here allocates, so the reservation above stays
    // correct. Note the write goes through the struct's PHYSICAL address — the
    // physmap VA we hand the kernel is not mapped in any live table yet. See
    // handoff.zig.
    _ = handoff.writeBootInfo(hand, &loaded, rs, mmap, dtb_phys);

    // ── The cliff ──────────────────────────────────────────────────────────
    //
    // Everything below this line is irreversible. Walk every address the kernel
    // touches first: after the ERET the loader's vectors are gone, a wrong table
    // faults invisibly, and the symptom is indistinguishable from a hang.
    if (!handoff.verify(ttbr0_root, ttbr1_root, hand, &loaded, rs, mmap, hyp_stub_phys)) {
        log.str("  *** pre-ERET verification FAILED; refusing to hand off\n");
        log.commit();
        psciSystemReset();
    }
    handoff.dumpEl2State("EL2 before");
    drainDeferredErrors();
    log.commit();

    // The EL2 configuration ATF did not give us. Must precede the drop: three of
    // the four registers are only writable at EL2, and VMPIDR_EL2 has to be right
    // BEFORE any EL1 code reads MPIDR_EL1. See handoff.prepareEl2ForEl1.
    handoff.prepareEl2ForEl1();
    // Deliberately after the EL2 prep too: prepareEl2ForEl1 issues `tlbi alle1is`
    // and touches system registers, and any of that can surface a straggler.
    drainDeferredErrors();
    handoff.dumpEl2State("EL2 after ");
    log.commit();

    if (uart.haveConsole()) {
        uart.puts("[stygia pi5 loader] dropping to EL1\n");
        uart.flush();
    }

    // Last commit at EL2. If the ERET goes wrong this is the final record.
    log.str("  EL2->EL1 drop (hyp stub ");
    log.hex(hyp_stub_phys);
    log.str("):\n");
    log.commit();

    el2_drop.dropToEl1(hyp_stub_phys);

    // ── EL1 ────────────────────────────────────────────────────────────────
    //
    // Reaching here means the mirrored SCTLR_EL1/TCR_EL1/TTBR0_EL1 translate the
    // loader's own code, stack and log region — SP came across via SP_EL1, so this
    // is the same C frame. Only the identity half of the address space works: the
    // drop does not touch TTBR1_EL1.
    log.str("  at EL");
    log.dec(currentEl());
    log.byte('\n');
    handoff.dumpEl1State("EL1 as dropped");
    log.commit();

    // TTBR1 goes in AFTER the drop, not before, for two reasons.
    //
    // First, `dropToEl1` rewrites TCR_EL1 wholesale from TCR_EL2, so any TCR_EL1
    // programming done at EL2 is discarded — including `setKernelAddrSpace`'s
    // AS=1 (16-bit ASID space), which the drop's own TCR build leaves clear.
    // Running it afterwards is the only ordering in which the register the kernel
    // inherits is the one this call wrote.
    //
    // Second, this is what the UEFI path does (main.zig:460, at EL1) and its
    // `tlbi vmalle1is` then executes in the regime that will actually consume the
    // tables rather than in one that is about to be reconfigured.
    //
    // TTBR0_EL1 already holds the identity root — `dropToEl1` copied it from
    // TTBR0_EL2 — which is what keeps the mmap descriptor array in the loader's
    // .bss and the kernel table root itself readable at their identity addresses,
    // exactly as `memory/init.zig:39,63` requires.
    arch.paging.setKernelAddrSpace(PAddr.fromInt(ttbr1_root));
    handoff.dumpEl1State("EL1 w/ ttbr1  ");
    log.str("stage 4 complete; entering kernel at ");
    log.hex(loaded.entry.addr);
    log.str(" (sp ");
    log.hex(hand.sp_virt.addr);
    log.str(", BootInfo ");
    log.hex(hand.boot_info_virt);
    log.str(")\n");
    log.commit();

    if (uart.haveConsole()) {
        uart.puts("[stygia pi5 loader] entering kernel\n");
        uart.flush();
    }

    // `switchStackAndCall` masks DAIF (`msr daifset, #0x7`) before touching SP, so
    // no stale firmware interrupt can reach VBAR_EL1 — which still points at this
    // loader's EL2 vector table, inherited by the drop, whose handlers read
    // ESR_EL2 and would fault recursively at EL1. The kernel replaces it in
    // `exceptions.install()`, three calls into kMain.
    arch.cpu.switchStackAndCall(hand.sp_virt, hand.boot_info_virt, loaded.entry.addr);
}

/// Build throwaway TTBR0 and TTBR1 address spaces and verify they translate.
///
/// TWO roots, not one, and the first version of this got it wrong in a way worth
/// recording. aarch64 splits the address space across TTBR0_EL1 (low, user) and
/// TTBR1_EL1 (high, kernel), which is what `arch.paging.kernel_shares_user_table
/// == false` is telling us. With T1SZ = 16 the hardware drops VA bits [63:48]
/// before indexing, so a TTBR1 VA like kernel_code's `0xFFFF_0000_0000_0000`
/// extracts L0 index 0 — the SAME slot as identity VA 0. Putting both in one
/// table therefore collides:
///
///   * the 1 GiB identity block installs a BLOCK descriptor at L1[0];
///   * the kernel_code mapping then finds L1[0] already valid, and mapPageBoot
///     does not distinguish a block from a table — it takes the block's output
///     address as the next-level table address and writes a descriptor there.
///
/// The output address was 0, so it wrote into ATF. Observed on hardware: the
/// kernel_code VA resolved to `0x0 [1G]`. Nothing in mapPageBoot is wrong here;
/// the UEFI path never allocates a TTBR0 (firmware already owns it) so the
/// situation cannot arise there. It arises here because this loader has to build
/// both halves from nothing. Worth knowing that mapPageBoot will silently walk
/// INTO a block descriptor if a caller ever overlaps a block and a page.
///
/// Roots are allocated from the arena like any other table, so the pages this
/// consumes get reserved by pass 2 along with everything else. Slightly wasteful
/// — these tables are never used — but allocating them from somewhere special
/// would mean the test stopped exercising the thing it is testing.
fn selfTestPageTables(arena: *page_allocator.Arena) bool {
    const alloc = arena.allocator();

    const ttbr0 = allocRoot(alloc) orelse return false;
    const ttbr1 = allocRoot(alloc) orelse return false;

    log.str("  page table self-test (ttbr0 ");
    log.hex(ttbr0);
    log.str(", ttbr1 ");
    log.hex(ttbr1);
    log.str("):\n");

    const rw: MemoryPerms = .{ .read = true, .write = true };
    const rx: MemoryPerms = .{ .read = true, .exec = true };

    // A scratch page to point the 4 KiB mappings at, so a mismatch distinguishes
    // "mapped the wrong frame" from "did not map anything".
    const scratch = alloc.alignedAlloc(u8, paging.pageAlign(.page4k), paging.PAGE4K) catch {
        log.str("  *** could not allocate a scratch page\n");
        return false;
    };
    const scratch_phys = @intFromPtr(scratch.ptr);

    const one_gib: u64 = 1 << 30;
    const code_va = kernel_code.start;
    const physmap_va = physmap.start + scratch_phys;

    // TTBR0: the 1 GiB identity block that keeps this loader executing across the
    // moment the MMU comes on.
    arch.paging.mapPageBoot(VAddr.fromInt(ttbr0), PAddr.fromInt(0), VAddr.fromInt(0), .page1g, rw, .kernel_data, alloc) catch {
        log.str("  *** 1G identity map failed\n");
        return false;
    };
    // TTBR1: a kernel_code page (the granularity every kernel ELF section uses)
    // and a physmap page (where the stack and boot_info live, and the one region
    // whose descriptors take mapPageBoot's `use_physmap` path).
    arch.paging.mapPageBoot(VAddr.fromInt(ttbr1), PAddr.fromInt(scratch_phys), VAddr.fromInt(code_va), .page4k, rx, .kernel_data, alloc) catch {
        log.str("  *** kernel_code map failed\n");
        return false;
    };
    arch.paging.mapPageBoot(VAddr.fromInt(ttbr1), PAddr.fromInt(scratch_phys), VAddr.fromInt(physmap_va), .page4k, rw, .kernel_data, alloc) catch {
        log.str("  *** physmap map failed\n");
        return false;
    };

    var ok = true;
    // Inside the 1 GiB block at a non-zero offset, so the block's offset bits are
    // exercised rather than just its base.
    ok = pi5_paging.expect(ttbr0, 0x1234_5000, 0x1234_5000, "identity   ") and ok;
    ok = pi5_paging.expect(ttbr1, code_va, scratch_phys, "kernel_code") and ok;
    ok = pi5_paging.expect(ttbr1, physmap_va, scratch_phys, "physmap    ") and ok;

    // Negative checks. Without these the whole self-test would pass against a
    // table full of valid garbage — and DRAM here survives resets, so "valid
    // garbage" is the expected state of an unzeroed page, not a hypothetical.
    if (pi5_paging.walk(ttbr0, one_gib + 0x1000) != null) {
        log.str("    *** unmapped TTBR0 VA resolved; stale descriptors present\n");
        ok = false;
    } else {
        log.str("    unmapped TTBR0 VA correctly faults\n");
    }
    // The collision this test was rewritten to catch: the identity block must not
    // be reachable through the kernel table, nor the kernel page through TTBR0.
    if (pi5_paging.walk(ttbr1, 0x1234_5000) != null) {
        log.str("    *** identity VA resolved in TTBR1; the two roots are shared\n");
        ok = false;
    } else {
        log.str("    TTBR0 and TTBR1 are independent\n");
    }

    arena.dump();
    log.commit();
    return ok;
}

/// Map and probe one UART candidate.
///
/// A failed mapping is reported and treated as "not usable" rather than fatal: the
/// whole point is to discover which of the two works, and refusing to boot because
/// one of them did not would defeat that.
fn probeUart(
    arena: *page_allocator.Arena,
    ttbr0_root: u64,
    name: []const u8,
    base: u64,
) uart.Probe {
    uart.map(arena.allocator(), ttbr0_root, base) catch |err| {
        log.str("    ");
        log.str(name);
        log.str(" *** map failed: ");
        log.str(@errorName(err));
        log.byte('\n');
        return .{
            .base = base,
            .floating = true,
            .primecell = false,
            .enabled = false,
            .baud_set = false,
            .cr = 0,
            .fr = 0,
            .ibrd = 0,
            .fbrd = 0,
        };
    };
    const p = uart.probe(base);
    uart.dumpProbe(name, p);
    return p;
}

/// Allocate and zero one page-table root, returning its physical address.
///
/// mapPageBoot walks the hierarchy by dereferencing table addresses directly.
/// With the MMU off "virtual" and "physical" are the same number, which is
/// exactly the identity case it already handles (`use_physmap` false, since a
/// physical address is never inside the physmap partition).
fn allocRoot(alloc: std.mem.Allocator) ?u64 {
    const root = alloc.alignedAlloc(u8, paging.pageAlign(.page4k), paging.PAGE4K) catch {
        log.str("  *** could not allocate a table root\n");
        return null;
    };
    @memset(root, 0);
    return @intFromPtr(root.ptr);
}

/// Firmware entry.
///
/// `linksection(".text.boot")` is load-bearing, not stylistic: firmware branches
/// to offset 0 of the flat image. Without it Zig places `_start` wherever the
/// optimizer prefers — measured at 0x8031c, i.e. 0x31c bytes in — and the
/// firmware jumps into the middle of an unrelated function. The linker script
/// pulls `.text.boot` first and asserts `_start == 0x80000`, so a regression
/// fails the LINK instead of bricking a boot.
export fn _start() linksection(".text.boot") callconv(.naked) noreturn {
    asm volatile (
    // Park secondaries. Firmware releases only core 0 into the kernel image on
    // this board, but a stray secondary running this loader concurrently would
    // corrupt the log and the descriptor array, and MPIDR is one instruction.
        \\ mrs  x1, mpidr_el1
        \\ and  x1, x1, #0xFF
        \\ cbz  x1, 1f
        \\0:
        \\ wfe
        \\ b    0b
        \\1:
        \\ ldr  x1, =__stack_top
        \\ mov  sp, x1
        // Zero .bss. objcopy -O binary drops it from the image, so nothing on
        // the card initializes it — and DRAM demonstrably survives resets on
        // this board, so it comes up holding the previous boot's values. Stale
        // state here is a live hazard, not a theoretical one.
        \\ ldr  x1, =__bss_start
        \\ ldr  x2, =__bss_end
        \\2:
        \\ cmp  x1, x2
        \\ b.hs 3f
        \\ str  xzr, [x1], #8
        \\ b    2b
        \\3:
        \\ bl   piMain
        // piMain is noreturn. If it ever falls through, stop rather than
        // executing whatever bytes follow in memory.
        \\4:
        \\ wfe
        \\ b    4b
    );
}
