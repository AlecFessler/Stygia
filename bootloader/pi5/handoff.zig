//! The last thing this loader does: build the kernel stack and `BootInfo`, put
//! EL2 into the shape an EL1 kernel expects, and hand over.
//!
//! Everything here mirrors `bootloader/main.zig:386-470`, which is the reference
//! sequence every aarch64 test boot already runs. Three things differ, and each
//! difference is a place where copying the UEFI path verbatim would fault:
//!
//!   1. **`BootInfo` is written through its PHYSICAL address, not a physmap VA.**
//!      main.zig:415 does `@ptrFromInt(boot_info_virt.addr)` and writes the
//!      struct through the physmap, which works there only because UEFI hands off
//!      with the MMU on and TTBR1 already live. Here TTBR1_EL1 is not installed
//!      until after the EL2->EL1 drop, so a physmap VA is unmapped and the first
//!      store would abort. We write through the identity address (translation is
//!      identity at EL2, so PA == VA) and hand the kernel the physmap VA, then
//!      walk the tables to prove the two addresses name the same page.
//!
//!   2. **No `bs.allocatePages` for the hyp vector stub.** `allocateHypVectorStub`
//!      in `bootloader/aarch64_el2_drop.zig` needs UEFI. `allocHypStub` below
//!      takes one page from the bump arena instead. The stub BYTES are reused
//!      verbatim (`el2_drop.hyp_vectors_bytes` is comptime-assembled and
//!      position-independent), because reimplementing an HVC dispatcher to
//!      rediscover its own bugs is not an improvement.
//!
//!   3. **Nobody has run Linux's `el2_setup` for us.** Under AAVMF or KVM, the
//!      thing that hands us EL2 has already given EL2 a sane configuration.
//!      Here ATF hands off with most EL2 registers at their reset values, and
//!      several of those are architecturally UNKNOWN. `prepareEl2ForEl1` sets the
//!      four that would otherwise silently corrupt EL1's view of the machine.
//!
//! Ordering constraint that is easy to get wrong: EVERY arena allocation has to
//! happen before `boot_info.buildMMap`'s second pass, because that pass reserves
//! `arena.usedRange()` and a page handed out afterwards would be published to the
//! kernel as free memory. So `prepare` (which allocates the stack) and
//! `allocHypStub` both run BEFORE pass 2, while `writeBootInfo` — which needs the
//! map pass 2 produces — allocates nothing and runs after.

const std = @import("std");
const stygia = @import("stygia");

const el2_drop = @import("el2_drop");
const kernel_load = @import("kernel_load.zig");
const log = @import("early_log.zig");
const pi5_paging = @import("paging.zig");
const uart = @import("uart.zig");

const arch = stygia.arch.dispatch;
const address = stygia.memory.address;
const paging = stygia.memory.paging;
const protocol = stygia.boot.protocol;
const uefi = std.os.uefi;

const BootInfo = protocol.BootInfo;
const MMap = protocol.MMap;
const MemoryPerms = address.MemoryPerms;
const PAddr = address.PAddr;
const VAddr = address.VAddr;

const physmap = address.AddrSpacePartition.physmap;

/// Everything the final jump needs, plus the physical aliases used to build it.
///
/// Both the physical and the physmap form of each address is kept rather than
/// recomputed at the use site. The whole failure mode this module exists to avoid
/// is confusing the two, and a struct field named `_phys` next to one named
/// `_virt` is harder to mix up than two calls to `VAddr.fromPAddr`.
pub const Handoff = struct {
    /// Base of the 6-page kernel stack, physical.
    stack_base_phys: u64,
    /// One byte past the last stack byte, physical. Not itself mapped.
    stack_top_phys: u64,
    /// One byte past the last stack byte, physmap VA.
    stack_top_virt: VAddr,
    /// The SP handed to the kernel: 16-byte aligned, below `BootInfo`.
    sp_virt: VAddr,
    /// Where we WRITE the struct (identity == physical).
    boot_info_phys: u64,
    /// Where the kernel READS it (physmap VA, passed in x0).
    boot_info_virt: u64,
};

/// Allocate the kernel stack and map every page into the kernel table.
///
/// Mirrors main.zig:387-412 exactly, including the choice to make
/// `stack_top_virt` the address one byte PAST the mapped region: the stack grows
/// down, so SP starts above the highest byte it will ever use. That address is
/// deliberately left unmapped — it is a guard, and `verify` checks that it is.
pub fn prepare(
    alloc: std.mem.Allocator,
    ttbr1_root: u64,
) ?Handoff {
    const stack_pages = alloc.alignedAlloc(
        u8,
        paging.pageAlign(.page4k),
        protocol.STACK_SIZE,
    ) catch {
        log.str("    *** could not allocate the kernel stack (");
        log.size(protocol.STACK_SIZE);
        log.str(")\n");
        return null;
    };

    const stack_base_phys = @intFromPtr(stack_pages.ptr);
    const num_pages = protocol.STACK_SIZE / paging.PAGE4K;
    const rw: MemoryPerms = .{ .read = true, .write = true };

    var cur = PAddr.fromInt(stack_base_phys);
    for (0..num_pages) |_| {
        // Physmap VA, exactly as main.zig:396. The kernel's own physmap pass in
        // memory/init.zig will later re-map this same range with 2 MiB or 1 GiB
        // blocks; that overwrites these leaf entries with an identical PA->VA
        // relationship, which is why the duplication is harmless. (It is also
        // exactly what the UEFI path does, so it is proven rather than argued.)
        arch.paging.mapPageBoot(
            VAddr.fromInt(ttbr1_root),
            cur,
            VAddr.fromPAddr(cur, null),
            .page4k,
            rw,
            .kernel_data,
            alloc,
        ) catch {
            log.str("    *** could not map kernel stack page ");
            log.hex(cur.addr);
            log.byte('\n');
            return null;
        };
        cur = PAddr.fromInt(cur.addr + paging.PAGE4K);
    }

    const stack_top_phys = cur.addr;
    const stack_top_virt = VAddr.fromPAddr(PAddr.fromInt(stack_top_phys), null);
    const boot_info_virt = stack_top_virt.addr - @sizeOf(BootInfo);
    const sp_virt = address.alignStack(VAddr.fromInt(boot_info_virt));

    // physmap.start is 512 GiB aligned, so the physmap alias preserves the page
    // offset and `boot_info_virt - physmap.start` is the address we may write
    // through with the MMU in its current identity configuration. Deriving it by
    // subtraction rather than recomputing from `stack_top_phys` keeps the two
    // forms provably consistent even if the arithmetic above changes.
    const boot_info_phys = boot_info_virt - physmap.start;

    log.str("    kernel stack ");
    log.hex(stack_base_phys);
    log.str(" .. ");
    log.hex(stack_top_phys);
    log.str("  ");
    log.size(protocol.STACK_SIZE);
    log.str(" in ");
    log.dec(num_pages);
    log.str(" pages\n");
    log.str("      physmap  ");
    log.hex(VAddr.fromPAddr(PAddr.fromInt(stack_base_phys), null).addr);
    log.str(" .. ");
    log.hex(stack_top_virt.addr);
    log.byte('\n');
    log.str("      sp       ");
    log.hex(sp_virt.addr);
    log.str("   BootInfo ");
    log.hex(boot_info_virt);
    log.str(" (write via ");
    log.hex(boot_info_phys);
    log.str(", ");
    log.size(@sizeOf(BootInfo));
    log.str(")\n");

    return .{
        .stack_base_phys = stack_base_phys,
        .stack_top_phys = stack_top_phys,
        .stack_top_virt = stack_top_virt,
        .sp_virt = sp_virt,
        .boot_info_phys = boot_info_phys,
        .boot_info_virt = boot_info_virt,
    };
}

/// Fill in `BootInfo` through its physical address.
///
/// `BootInfo` is an `extern struct` and this writes it field by field onto
/// memory the loader owns, so the field DEFAULTS in `kernel/boot/protocol.zig`
/// (`arrived_at_el2 = 0`, the `_pad` arrays) never run. The zero-fill below is
/// what makes that safe: a field added to `BootInfo` after this was written
/// arrives as 0 rather than as whatever the previous boot left in DRAM — and on
/// this board DRAM demonstrably survives a warm reset, so "whatever the previous
/// boot left" is the expected state of an untouched page, not a hypothetical.
///
/// Both blob pointers are PHYSICAL addresses. That is not a shortcut: the kernel
/// resolves them with `VAddr.fromPAddr(PAddr.fromInt(@intFromPtr(ptr)), null)` —
/// `utils/debug_info.zig:47-49` for `elf_blob`, `kernel/main.zig:119-121` for
/// `root_service`. Converting them to VAs here would double-apply the physmap
/// base.
pub fn writeBootInfo(
    h: Handoff,
    loaded: *const kernel_load.LoadedKernel,
    rs: kernel_load.Blob,
    mmap: MMap,
    dtb_phys: u64,
) *BootInfo {
    const bi: *BootInfo = @ptrFromInt(@as(usize, @intCast(h.boot_info_phys)));

    const raw: [*]u8 = @ptrCast(bi);
    @memset(raw[0..@sizeOf(BootInfo)], 0);

    bi.elf_blob = .{
        .ptr = @ptrFromInt(@as(usize, @intCast(loaded.elf.phys))),
        .len = loaded.elf.len,
    };
    bi.root_service = .{
        .ptr = @ptrFromInt(@as(usize, @intCast(rs.phys))),
        .len = rs.len,
    };
    bi.stack_top = h.sp_virt;
    // No ACPI on this board. `aarch64/acpi.zig:412` treats a zero XSDP as
    // "direct-kernel boot, no firmware tables" and skips the XSDT walk entirely,
    // which is exactly the right behaviour here.
    bi.xsdp_phys = PAddr.fromInt(0);
    bi.kaslr_slide = loaded.kaslr_slide;
    bi.mmap = mmap;
    // No framebuffer. `.none` (0xFF) is load-bearing: `kernel/main.zig:71`
    // short-circuits on `size == 0`, but a zeroed `pixel_format` would decode as
    // `.bgr8` and claim a valid format for a nonexistent surface.
    bi.framebuffer = .{
        .base = PAddr.fromInt(0),
        .size = 0,
        .width = 0,
        .height = 0,
        .stride = 0,
        .pixel_format = .none,
        ._pad = .{ 0, 0, 0 },
    };
    // The entire point of this boot path: firmware handed us EL2, and the drop
    // below leaves a working hyp stub at VBAR_EL2, so `vm.hyp_stub_installed`
    // may be set and `vmSupported()` unlocked.
    bi.arrived_at_el2 = 1;
    bi._pad_ael2 = .{ 0, 0, 0, 0, 0, 0, 0 };

    // The DTB address ATF left in x0, threaded down from `piMain`. This is the
    // kernel's ONLY description of the machine on this board: with `xsdp_phys`
    // zero above, `arch.boot.parseFirmwareTables` takes its devicetree arm, and
    // that is what finds the GIC-400, the `/cpus` MPIDRs and the PSCI conduit.
    // A zero here is not a degraded boot, it is no interrupt controller and
    // therefore no scheduler.
    bi.dtb_phys = PAddr.fromInt(dtb_phys);

    // The console the loader already resolved AND probed. Handing over an
    // address rather than letting the kernel find its own is the whole point:
    // the UART on the GPIO 14/15 header is RP1 `uart0` at CPU PA
    // 0x1F_0003_0000, which is reachable only because this loader trained the
    // PCIe link, and whose DT `reg` is a PCI address needing two `ranges` hops
    // that `kernel/boot/fdt.zig` refuses to follow. Left-to-discovery, the
    // kernel would pick the on-SoC PL011 at 0x10_7D00_1000 — a real UART whose
    // pins go to an unwired JST-SH connector, i.e. output nobody can see.
    //
    // Zero when neither candidate probed usable, which the kernel reads as
    // "discover one yourself" — the honest answer, and it still leaves the DT
    // route to the SoC PL011 as a last resort.
    bi.console_base = PAddr.fromInt(uart.consoleBase());
    if (!uart.haveConsole()) {
        log.str("    NOTE: no console to hand over; kernel will discover its own\n");
    }

    // Clean to the Point of Coherency, same as main.zig:434. Strictly this
    // should be unnecessary — we write through an identity VA with attr_indx=1
    // and the kernel reads through a physmap VA with attr_indx=1, so both aliases
    // are Normal WB Inner-Shareable at the same PA on the same core. It is here
    // because the cost is a dozen cache ops and the failure it prevents (a stale
    // line at this PA left by ATF or by the previous boot shadowing the struct)
    // is a kernel that reads a plausible-looking BootInfo full of the wrong
    // numbers.
    arch.cpu.cleanInvalidateDcacheRange(h.boot_info_phys, @sizeOf(BootInfo));

    return bi;
}

/// Copy the EL2 hyp vector stub into a fresh arena page and return its PA.
///
/// The bare-metal counterpart of `el2_drop.allocateHypVectorStub`, which cannot
/// be used here because it allocates through UEFI `BootServices`. The bytes come
/// from the same comptime-assembled table, so the HVC dispatcher the kernel
/// later talks to (`hvc #0xE112` -> write x0 to VBAR_EL2) is bit-identical to the
/// one every aarch64 test boot uses.
///
/// `dropToEl1` asserts 2 KiB alignment (ARM ARM D13.2.148, VBAR_EL2), and at
/// ReleaseSmall that assert compiles away — so the check is repeated here as a
/// real `if`. Arena pages are 4 KiB aligned, so it should never fire.
pub fn allocHypStub(alloc: std.mem.Allocator) ?u64 {
    const page = alloc.alignedAlloc(u8, paging.pageAlign(.page4k), paging.PAGE4K) catch {
        log.str("    *** could not allocate the hyp vector stub page\n");
        return null;
    };
    // Zero the whole page first, so a stray exception landing past the 0x800
    // vector table decodes as `udf #0` rather than as last boot's leftovers.
    @memset(page, 0);
    @memcpy(page[0..el2_drop.hyp_vectors_bytes.len], &el2_drop.hyp_vectors_bytes);

    const pa = @intFromPtr(page.ptr);
    if ((pa & 0x7FF) != 0) {
        log.str("    *** hyp stub page ");
        log.hex(pa);
        log.str(" is not 2 KiB aligned; VBAR_EL2 would truncate it\n");
        return null;
    }

    // Two levels of maintenance, deliberately. `dc civac` (to the Point of
    // Coherency) matters because the stub is FETCHED AT EL2 AFTER `dropToEl1`
    // has turned the EL2 MMU off, at which point EL2 instruction fetch does not
    // go through the same attributes these stores did. `dc cvau` + `ic ivau` (to
    // the Point of Unification) is the ordinary "I just wrote instructions"
    // sequence and is what the UEFI stub allocator does.
    arch.cpu.cleanInvalidateDcacheRange(pa, paging.PAGE4K);
    arch.cpu.syncInstructionCacheRange(pa, paging.PAGE4K);

    log.str("    hyp vector stub at ");
    log.hex(pa);
    log.str("  ");
    log.size(el2_drop.hyp_vectors_bytes.len);
    log.str(" of code\n");
    return pa;
}

/// Give EL2 the configuration Linux's `el2_setup` would have given it.
///
/// `dropToEl1` was written for AAVMF and KVM, where whatever handed us EL2 had
/// already configured it. On this board ATF hands off to a bare-metal EL2 payload
/// and expects that payload to do its own `el2_setup` — Linux does exactly this in
/// `arch/arm64/kernel/head.S :: init_el2_state`. Four registers matter, and every
/// one of them is a silent corruption rather than a fault if left alone:
///
///   * **VPIDR_EL2 / VMPIDR_EL2.** EL1 reads of MIDR_EL1 and MPIDR_EL1 return
///     these, not the real registers, whenever EL2 is implemented. VMPIDR_EL2's
///     reset value is architecturally UNKNOWN. Leave it and the kernel's core
///     identification — `arch.smp`, per-core state, the `Aff0` the loader's own
///     `_start` uses to park secondaries — reads garbage at EL1 while reading
///     correctly at EL2, which is about the most confusing failure available.
///   * **CNTVOFF_EL2.** Reset value UNKNOWN, and `CNTVCT_EL0 = CNTPCT_EL0 -
///     CNTVOFF_EL2`. The kernel's monotonic clock IS `CNTVCT_EL0`
///     (`aarch64/timers.zig:153`), so a non-zero offset does not fault, it just
///     makes every timestamp wrong. Zero means virtual time == physical time,
///     which is what a bare-metal kernel wants.
///   * **CNTHCTL_EL2.{EL1PCEN,EL1PCTEN}.** Reset 0, which TRAPS EL1 accesses to
///     the physical counter and timer to EL2 — i.e. into the stub, whose
///     non-HVC vectors are `b .`. The kernel's preemption timer is the VIRTUAL
///     one (never gated by CNTHCTL_EL2 on this part, which predates FEAT_ECV), so
///     this is belt-and-braces rather than known-required; it costs two
///     instructions and removes a whole class of "hangs on the first CNTPCT
///     read".
///   * **HSTR_EL2 = 0.** No AArch32 CP15 trapping. Reset value should already be
///     0; Linux writes it anyway and so do we.
///
/// Deliberately NOT set: MDCR_EL2. Its trap bits (TPM, TPMCR, TDE, TDA, ...)
/// would each route an EL1 debug or PMU access into the stub, but HPMN cannot be
/// written to a safe value without reading PMCR_EL0.N, and writing HPMN = 0 on a
/// part without FEAT_HPMN0 is CONSTRAINED UNPREDICTABLE. `dumpEl2State` logs the
/// register instead: if `arch.pmu.pmuInit()` turns out to hang, one look at the
/// log says whether MDCR_EL2 is why.
///
/// Last, the EL1&0 TLBs are invalidated. Nothing in this boot has run at EL1, so
/// this looks redundant — but the entries that matter are from the PREVIOUS boot.
/// Pi OS ran at EL1 before the `tryboot` warm reset, DRAM demonstrably survives
/// that reset (it is how the early log works at all), and the ARM ARM leaves TLB
/// contents UNKNOWN across reset rather than invalidated: D5.9.1 makes
/// invalidation software's job, which is why Linux's `__enable_mmu` issues `tlbi
/// vmalle1` before it ever sets SCTLR_EL1.M. `mmu.enable` covered EL2 with `tlbi
/// alle2`, and `setKernelAddrSpace` will issue `tlbi vmalle1is` — but that runs
/// AFTER the ERET, by which point EL1 has already fetched and executed a hundred
/// instructions through whatever the walk caches happened to hold. So do it here,
/// from EL2, before EL1 exists. Both forms: ALLE1IS covers the stage-1 + stage-2
/// EL1&0 regime for the current VMID, VMALLE1IS the stage-1 entries for all ASIDs.
pub fn prepareEl2ForEl1() void {
    asm volatile (
        \\ mrs x0, midr_el1
        \\ msr vpidr_el2, x0
        \\ mrs x0, mpidr_el1
        \\ msr vmpidr_el2, x0
        \\ msr cntvoff_el2, xzr
        \\ mov x0, #3
        \\ msr cnthctl_el2, x0
        \\ msr hstr_el2, xzr
        \\ isb
        \\ dsb ishst
        \\ tlbi alle1is
        \\ tlbi vmalle1is
        \\ dsb ish
        \\ isb
        ::: .{ .memory = true, .x0 = true });
}

fn readSysreg(comptime name: []const u8) u64 {
    var v: u64 = undefined;
    asm volatile ("mrs %[v], " ++ name
        : [v] "=r" (v),
    );
    return v;
}

/// Log the EL2 registers that govern what EL1 will be able to do.
///
/// Pure diagnostics, and the cheapest thing in this file relative to its value:
/// after the ERET the loader's vectors no longer apply, so anything the kernel
/// trips over at EL1 is diagnosed from this log or not at all.
pub fn dumpEl2State(label: []const u8) void {
    log.str("    ");
    log.str(label);
    log.str(": HCR_EL2 = ");
    log.hex(readSysreg("hcr_el2"));
    log.str(", CPTR_EL2 = ");
    log.hex(readSysreg("cptr_el2"));
    log.str(", MDCR_EL2 = ");
    log.hex(readSysreg("mdcr_el2"));
    log.byte('\n');
    log.str("      CNTHCTL_EL2 = ");
    log.hex(readSysreg("cnthctl_el2"));
    log.str(", CNTVOFF_EL2 = ");
    log.hex(readSysreg("cntvoff_el2"));
    log.str(", VMPIDR_EL2 = ");
    log.hex(readSysreg("vmpidr_el2"));
    log.str(", MPIDR_EL1 = ");
    log.hex(readSysreg("mpidr_el1"));
    log.byte('\n');
}

/// Log the EL1 translation state the kernel is about to run on.
pub fn dumpEl1State(label: []const u8) void {
    log.str("    ");
    log.str(label);
    log.str(": SCTLR_EL1 = ");
    log.hex(readSysreg("sctlr_el1"));
    log.str(", TCR_EL1 = ");
    log.hex(readSysreg("tcr_el1"));
    log.byte('\n');
    log.str("      TTBR0_EL1 = ");
    log.hex(readSysreg("ttbr0_el1"));
    log.str(", TTBR1_EL1 = ");
    log.hex(readSysreg("ttbr1_el1"));
    log.str(", MAIR_EL1 = ");
    log.hex(readSysreg("mair_el1"));
    log.byte('\n');
}

/// Walk every address the kernel touches in its first few hundred instructions.
///
/// This is the same bargain `mmu.verifyIdentity` makes before the MMU comes on,
/// applied to the other cliff. After the ERET a wrong table faults with the
/// loader's vectors gone and looks exactly like a hang; the watchdog recovers the
/// board but the log says nothing. A software walk here costs a few log lines and
/// names the wrong entry precisely.
///
/// Returns false if anything that MUST translate does not. Two categories are
/// checked and reported but never fatal:
///
///   * The two blob physmap VAs. They are legitimately UNMAPPED at this point —
///     the kernel physmaps them itself in `memory.init`, which runs before the
///     first read of either (`main.zig:89` precedes `:90` and `:119`). What is
///     checked instead, and is the thing that actually matters, is that both PAs
///     land inside an `.acpi_reclaim_memory` descriptor in the map we are handing
///     over, because that is what makes `memory.init` physmap them at all.
///   * `stack_top_virt`, which must NOT translate: it is one byte past the stack.
pub fn verify(
    ttbr0_root: u64,
    ttbr1_root: u64,
    h: Handoff,
    loaded: *const kernel_load.LoadedKernel,
    rs: kernel_load.Blob,
    mmap: MMap,
    hyp_stub_phys: u64,
) bool {
    var ok = true;

    log.str("  pre-ERET verification (ttbr1 ");
    log.hex(ttbr1_root);
    log.str("):\n");

    // Instruction fetch at the kernel's entry point. Nothing else works if this
    // is wrong, and this is the one address whose failure is instantaneous.
    if (pi5_paging.walk(ttbr1_root, loaded.entry.addr)) |t| {
        log.str("    entry       : ");
        log.hex(loaded.entry.addr);
        log.str(" -> ");
        log.hex(t.phys);
        log.str(" ok\n");
    } else {
        log.str("    *** entry VA ");
        log.hex(loaded.entry.addr);
        log.str(" is UNMAPPED in the kernel table\n");
        ok = false;
    }

    // The stack, at both ends of the region and at the exact SP the kernel starts
    // on. `sp - 16` rather than `sp` because the first thing any prologue does is
    // store below SP.
    ok = pi5_paging.expect(
        ttbr1_root,
        VAddr.fromPAddr(PAddr.fromInt(h.stack_base_phys), null).addr,
        h.stack_base_phys,
        "stack base ",
    ) and ok;
    ok = pi5_paging.expect(
        ttbr1_root,
        h.sp_virt.addr - 16,
        h.sp_virt.addr - 16 - physmap.start,
        "sp - 16    ",
    ) and ok;

    // BootInfo, first and last byte, and the identity alias we wrote through.
    ok = pi5_paging.expect(
        ttbr1_root,
        h.boot_info_virt,
        h.boot_info_phys,
        "BootInfo   ",
    ) and ok;
    ok = pi5_paging.expect(
        ttbr1_root,
        h.boot_info_virt + @sizeOf(BootInfo) - 1,
        h.boot_info_phys + @sizeOf(BootInfo) - 1,
        "BootInfo-hi",
    ) and ok;
    ok = pi5_paging.expect(
        ttbr0_root,
        h.boot_info_phys,
        h.boot_info_phys,
        "BootInfo id",
    ) and ok;

    // The descriptor array lives in the loader's .bss and the kernel reads it
    // through its identity VA — `memory/init.zig:39` collapses the map before
    // `dropIdentityMapping()` at :107, which is the same window the UEFI path
    // relies on. TTBR0_EL1 receives this root from `dropToEl1`, so the identity
    // walk here is the walk the kernel will do.
    const mmap_addr = @intFromPtr(mmap.mmap);
    ok = pi5_paging.expect(ttbr0_root, mmap_addr, mmap_addr, "mmap array ") and ok;
    // memory/init.zig dereferences the kernel table root through its IDENTITY VA
    // too (`VAddr.fromPAddr(root, 0)` at :63) while building the physmap.
    ok = pi5_paging.expect(ttbr0_root, ttbr1_root, ttbr1_root, "ttbr1 root ") and ok;
    // The stub is fetched at EL2 with the EL2 MMU off, so it needs no mapping —
    // but the cache maintenance in `allocHypStub` used this VA, so a hole here
    // would mean that maintenance went somewhere else.
    ok = pi5_paging.expect(ttbr0_root, hyp_stub_phys, hyp_stub_phys, "hyp stub   ") and ok;

    // Guard: one past the top of the stack must fault.
    if (pi5_paging.walk(ttbr1_root, h.stack_top_virt.addr) != null) {
        log.str("    NOTE: stack_top ");
        log.hex(h.stack_top_virt.addr);
        log.str(" is mapped; the guard above the stack is not a hole\n");
    } else {
        log.str("    stack guard : ");
        log.hex(h.stack_top_virt.addr);
        log.str(" correctly faults\n");
    }

    // The blobs. Unmapped now, physmapped by the kernel later — provided the map
    // says `.acpi_reclaim_memory`, which is what this checks.
    ok = checkBlobReachable("elf_blob   ", ttbr1_root, loaded.elf.phys, loaded.elf.len, mmap) and ok;
    ok = checkBlobReachable("root_svc   ", ttbr1_root, rs.phys, rs.len, mmap) and ok;

    return ok;
}

/// Report whether the kernel will be able to read a blob through the physmap.
///
/// Three things have to hold, and only the third is obvious:
///   * the physmap VA range is inside the physmap partition (32 GiB of PA, so
///     this is really a check that the blob is where we think it is);
///   * the first and last byte fall in the SAME descriptor, since a blob
///     straddling a reservation boundary would be half-visible;
///   * that descriptor is `.acpi_reclaim_memory`, which `memory/init.zig:67`
///     physmaps and `:132` refuses to hand to the allocator. `.conventional_memory`
///     would be physmapped AND reallocatable — the blob would be readable right
///     up until something else claimed the page.
fn checkBlobReachable(
    name: []const u8,
    ttbr1_root: u64,
    phys: u64,
    len: u64,
    mmap: MMap,
) bool {
    log.str("    ");
    log.str(name);
    log.str(": ");
    log.hex(phys);
    log.str(" + ");
    log.size(len);

    if (len == 0) {
        log.str("  *** zero length\n");
        return false;
    }

    const last = phys + len - 1;
    const va = VAddr.fromPAddr(PAddr.fromInt(phys), null).addr;
    const va_last = VAddr.fromPAddr(PAddr.fromInt(last), null).addr;
    if (!physmap.contains(va) or !physmap.contains(va_last)) {
        log.str("  *** physmap VA ");
        log.hex(va);
        log.str(" is outside the physmap partition\n");
        return false;
    }

    const d_first = descriptorFor(mmap, phys);
    const d_last = descriptorFor(mmap, last);
    if (d_first == null or d_last == null) {
        log.str("  *** not covered by any descriptor in the map\n");
        return false;
    }
    if (d_first.?.physical_start != d_last.?.physical_start) {
        log.str("  *** straddles two descriptors (");
        log.hex(d_first.?.physical_start);
        log.str(" and ");
        log.hex(d_last.?.physical_start);
        log.str(")\n");
        return false;
    }
    if (d_first.?.type != .acpi_reclaim_memory) {
        log.str("  *** descriptor type is not acpi_reclaim_memory; the kernel will not physmap it\n");
        return false;
    }

    log.str("  -> ");
    log.hex(va);
    log.str(" reclaim, mapped by memory.init");
    // Informational only: at this instant the kernel table has no physmap yet.
    if (pi5_paging.walk(ttbr1_root, va) != null) {
        log.str(" (already present in the kernel table)");
    }
    log.str(" ok\n");
    return true;
}

fn descriptorFor(mmap: MMap, phys: u64) ?*const uefi.tables.MemoryDescriptor {
    for (0..mmap.num_descriptors) |i| {
        const d: *const uefi.tables.MemoryDescriptor =
            @ptrFromInt(@intFromPtr(mmap.mmap) + i * @as(usize, @intCast(mmap.descriptor_size)));
        const end = d.physical_start + d.number_of_pages * paging.PAGE4K;
        if (phys >= d.physical_start and phys < end) return d;
    }
    return null;
}
