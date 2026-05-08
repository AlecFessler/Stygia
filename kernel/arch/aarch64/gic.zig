//! ARM Generic Interrupt Controller (GIC) driver — GICv2/v3 dual-mode.
//!
//! The GIC is the ARM equivalent of x86's APIC (Local APIC + IO APIC).
//! It handles interrupt routing, prioritization, and inter-processor interrupts.
//!
//! This driver supports both GICv2 (MMIO CPU interface) and GICv3 (system
//! register CPU interface). The version is detected at runtime by reading
//! GICD_PIDR2.ArchRev and exposed via the `gicv3` flag.
//!
//! GIC architecture references:
//! - ARM IHI 0069H: GICv3/v4 Architecture Specification
//! - ARM IHI 0048B: GICv2 Architecture Specification
//!
//!   Distributor (GICD_*): Global, one per system.
//!     - Manages SPI (Shared Peripheral Interrupt) enable/disable/routing.
//!     - Base address discovered from ACPI MADT GIC Distributor structure.
//!     - IHI 0069H, Section 8.9: GICD register summary.
//!     - IHI 0048B, Section 4.3: GICD register summary.
//!
//!   Redistributor (GICR_*, GICv3 only): One per core.
//!     - Manages SGI/PPI enable/priority for its core.
//!     - Discovered from ACPI MADT GIC Redistributor structure.
//!     - IHI 0069H, Section 9.5: GICR register summary.
//!
//!   CPU Interface:
//!     - GICv3: ICC_*_EL1 system registers (IHI 0069H, Section 12.11).
//!     - GICv2: GICC_* MMIO registers (IHI 0048B, Section 4.4).
//!     - Per-core, handles interrupt acknowledgement and EOI.
//!
//! Interrupt ID ranges (IHI 0069H, Section 2.2 / IHI 0048B, Section 2.2):
//!   0-15:    SGI (Software Generated Interrupts) — used for IPIs.
//!   16-31:   PPI (Private Peripheral Interrupts) — per-core (e.g., timer).
//!   32-1019: SPI (Shared Peripheral Interrupts) — device IRQs.
//!
//! Dispatch interface mapping:
//!   coreCount()                → count of cores discovered from MADT
//!   coreID()                   → read MPIDR_EL1 Aff0 field
//!   sendIpiToCore(id, vector)  → ICC_SGI1R_EL1 (v3) / GICD_SGIR (v2)
//!   maskIrq(irq)              → GICD_ICENABLER / GICR_ICENABLER (v3)
//!   unmaskIrq(irq)            → GICD_ISENABLER / GICR_ISENABLER (v3)
//!   endOfInterrupt(intid)     → ICC_EOIR1_EL1 (v3) / GICC_EOIR (v2)
//!   acknowledgeInterrupt()    → ICC_IAR1_EL1 (v3) / GICC_IAR (v2)
//!
//! References:
//! - ARM IHI 0069H: GICv3/v4 Architecture Specification
//! - ARM IHI 0048B: GICv2 Architecture Specification
//! - ARM ARM DDI 0487: D13.2.83 (MPIDR_EL1)

const std = @import("std");

// ── GICD register offsets (IHI 0069H, Section 8.9 / IHI 0048B, Section 4.3) ──

/// Distributor register offsets relative to GICD base address.
/// IHI 0069H, Section 8.9, Table 8-1 "GICD register summary".
/// IHI 0048B, Section 4.3.1, Table 4-1 "Distributor register summary".
const GicdReg = enum(u32) {
    /// Distributor Control Register.
    /// IHI 0069H, Section 8.9.4 / IHI 0048B, Section 4.3.2.
    ctlr = 0x0000,
    /// Interrupt Controller Type Register.
    /// IHI 0069H, Section 8.9.5 / IHI 0048B, Section 4.3.3.
    typer = 0x0004,
    /// Distributor Implementer Identification Register.
    /// IHI 0069H, Section 8.9.6 / IHI 0048B, Section 4.3.4.
    iidr = 0x0008,
    /// Interrupt Group Registers (base).
    /// IHI 0069H, Section 8.9.10 / IHI 0048B, Section 4.3.10.
    /// GICD_IGROUPR<n> at offset 0x0080 + 4*n, one bit per INTID.
    /// Bit = 0 → Group 0, bit = 1 → Group 1 (non-secure).
    /// On both GICv2 and GICv3 the first register (IGROUPR0, INTIDs 0-31)
    /// is banked per-CPU, so each core writes its own copy.
    igroupr0 = 0x0080,
    /// Interrupt Set-Enable Registers (base).
    /// IHI 0069H, Section 8.9.7 / IHI 0048B, Section 4.3.5.
    /// GICD_ISENABLER<n> at offset 0x0100 + 4*n, each bit enables one INTID.
    isenabler0 = 0x0100,
    /// Interrupt Clear-Enable Registers (base).
    /// IHI 0069H, Section 8.9.8 / IHI 0048B, Section 4.3.6.
    /// GICD_ICENABLER<n> at offset 0x0180 + 4*n, each bit disables one INTID.
    icenabler0 = 0x0180,
    /// Interrupt Priority Registers (base).
    /// IHI 0069H, Section 8.9.11 / IHI 0048B, Section 4.3.11.
    /// GICD_IPRIORITYR<n> at offset 0x0400 + 4*n, 8 bits per INTID.
    ipriorityr0 = 0x0400,
    /// Interrupt Processor Targets Registers (base, GICv2 only).
    /// IHI 0048B, Section 4.3.12: GICD_ITARGETSR<n> at offset 0x0800 + 4*n,
    /// 8 bits per INTID, each byte is a CPU target bitmask.
    itargetsr0 = 0x0800,
    /// Interrupt Configuration Registers (base).
    /// IHI 0069H, Section 8.9.12 / IHI 0048B, Section 4.3.13.
    /// GICD_ICFGR<n> at offset 0x0C00 + 4*n, 2 bits per INTID.
    icfgr0 = 0x0C00,
    /// Software Generated Interrupt Register (GICv2 only).
    /// IHI 0048B, Section 4.3.15: bits [3:0] = INTID, [23:16] = target CPU list.
    sgir = 0x0F00,
    /// Peripheral ID2 Register — GICv2 variant at offset 0x0FE8.
    /// IHI 0048B, Section 4.3.17. ArchRev in bits [7:4]: 2=GICv2.
    pidr2 = 0x0FE8,
    /// Peripheral ID2 Register — GICv3/v4 variant at offset 0xFFE8.
    /// IHI 0069H, Section 12.8 (GICD_IDREGS). ArchRev in bits [7:4]:
    /// 3=GICv3, 4=GICv4.
    pidr2_v3 = 0xFFE8,
    /// Interrupt Routing Registers (base, GICv3 only).
    /// IHI 0069H, Section 8.9.13.
    /// GICD_IROUTER<n> at offset 0x6100 + 8*n, 64 bits per SPI (INTID 32+).
    irouter0 = 0x6100,
};

// ── GICC register offsets (IHI 0048B, Section 4.4) ─────────────

/// GICv2 CPU Interface register offsets relative to GICC base address.
/// IHI 0048B, Section 4.4, Table 4-2 "CPU interface register summary".
const GiccReg = enum(u32) {
    /// CPU Interface Control Register. IHI 0048B, Section 4.4.1.
    ctlr = 0x0000,
    /// Interrupt Priority Mask Register. IHI 0048B, Section 4.4.2.
    /// Interrupts with priority >= PMR value are masked.
    pmr = 0x0004,
    /// Binary Point Register. IHI 0048B, Section 4.4.3.
    bpr = 0x0008,
    /// Interrupt Acknowledge Register. IHI 0048B, Section 4.4.4.
    /// Acknowledges the highest priority pending Group 0 interrupt.
    iar = 0x000C,
    /// End of Interrupt Register. IHI 0048B, Section 4.4.5.
    /// Signals completion of the Group 0 interrupt.
    eoir = 0x0010,
    /// Aliased Interrupt Acknowledge Register. IHI 0048B, Section 4.4.11.
    /// Acknowledges the highest priority pending Group 1 interrupt. When
    /// GICC_IAR is read and the pending interrupt is Group 1, it returns
    /// the spurious INTID 1022 instead — GICC_AIAR is the correct ack
    /// path for Group 1 interrupts.
    aiar = 0x0020,
    /// Aliased End of Interrupt Register. IHI 0048B, Section 4.4.12.
    /// Signals completion of the Group 1 interrupt previously returned
    /// by GICC_AIAR.
    aeoir = 0x0024,
};

// ── GICR register offsets (IHI 0069H, Section 9.5) ─────────────

/// Redistributor register offsets relative to each GICR frame base.
/// Each redistributor has two 64KB frames: RD_base and SGI_base.
/// IHI 0069H, Section 9.5, Table 9-1 "GICR register summary".
const GicrReg = enum(u32) {
    /// Redistributor Control Register. IHI 0069H, Section 9.5.1.
    ctlr = 0x0000,
    /// Redistributor Type Register. IHI 0069H, Section 9.5.3.
    typer = 0x0008,
    /// Redistributor Wake Register. IHI 0069H, Section 9.5.5.
    waker = 0x0014,
};

/// SGI_base frame offsets (at RD_base + 0x10000).
/// IHI 0069H, Section 9.5, Table 9-2 "GICR_SGI_base register summary".
const GicrSgiReg = enum(u32) {
    /// SGI/PPI Interrupt Group Register. IHI 0069H, Section 9.5.2.
    /// Bit n = 0 → INTID n is Group 0 (secure);
    /// Bit n = 1 → INTID n is Group 1 Non-secure.
    igroupr0 = 0x0080,
    /// SGI/PPI Set-Enable Register. IHI 0069H, Section 9.5.6.
    isenabler0 = 0x0100,
    /// SGI/PPI Clear-Enable Register. IHI 0069H, Section 9.5.7.
    icenabler0 = 0x0180,
    /// SGI/PPI Priority Registers (base). IHI 0069H, Section 9.5.8.
    ipriorityr0 = 0x0400,
};

// ── GICD_CTLR bit definitions ──────────────────────────────────

/// Enable Affinity Routing (ARE_NS) for non-secure state (GICv3 only).
/// When set, SPIs use GICD_IROUTER for affinity-based routing.
/// IHI 0069H, Section 8.9.4, bit 4.
const gicd_ctlr_are_ns: u32 = 1 << 4;

/// Enable Group 1 non-secure interrupts at the Distributor.
/// IHI 0069H, Section 8.9.4, bit 1 / IHI 0048B, Section 4.3.2, bit 1.
const gicd_ctlr_enable_grp1_ns: u32 = 1 << 1;

/// Enable Group 0 interrupts at the Distributor.
/// IHI 0069H, Section 8.9.4, bit 0 / IHI 0048B, Section 4.3.2, bit 0.
const gicd_ctlr_enable_grp0: u32 = 1 << 0;

// ── GICR_WAKER bit definitions (IHI 0069H, Section 9.5.5) ──────

/// ProcessorSleep bit. Software sets this to 0 to wake the redistributor.
/// IHI 0069H, Section 9.5.5, bit 1.
const gicr_waker_processor_sleep: u32 = 1 << 1;

/// ChildrenAsleep bit. Hardware sets this to 0 when redistributor is awake.
/// IHI 0069H, Section 9.5.5, bit 2.
const gicr_waker_children_asleep: u32 = 1 << 2;

// ── Constants ───────────────────────────────────────────────────

/// Maximum number of redistributors (one per core).
const max_redist: usize = 256;

/// True for either spurious interrupt encoding (1022 or 1023). The GIC
/// spec reserves the top 8 INTIDs (1020-1023) as spurious / non-
/// maskable hand-offs (IHI 0048B §2.2.1, IHI 0069H §2.2.1), so we
/// treat any INTID in that range as spurious — nothing valid for the
/// kernel ever lands there.
pub inline fn isSpurious(intid: u32) bool {
    return intid >= 1020;
}

// ── State ───────────────────────────────────────────────────────

/// GICv3 detected flag. When false, the driver uses GICv2 MMIO paths.
/// Set during initDistributor() by reading GICD_PIDR2.ArchRev.
pub var gicv3: bool = false;

/// On GICv2, whether non-secure writes to GICD_IGROUPR0 and the banked
/// GICR equivalents are honoured by the implementation. When `true`, all
/// SGIs/PPIs have been moved to Group 1 NS and the driver uses the
/// aliased IAR/EOIR (GICC_AIAR / GICC_AEOIR) for acknowledgement. When
/// `false`, the implementation left every INTID in Group 0 — we can
/// neither write IGROUPR0 from NS nor ack via the alias (would return
/// spurious 1022), so the driver falls back to the non-aliased
/// IAR/EOIR pair (GICC_IAR / GICC_EOIR).
///
/// IHI 0048B, Section 4.3.10 (GICD_IGROUPR): describes the Secure-only
/// write access on implementations with Security Extensions.
/// IHI 0048B, Section 4.4.4 / 4.4.11: GICC_IAR vs GICC_AIAR spurious
/// returns depending on which Group the pending interrupt is in.
var gicv2_group1_ack: bool = false;

/// GICD base virtual address. Populated by `init(discovery)` from
/// `GicDiscovery.gicd_base`.
var gicd_base: u64 = 0;

/// GICC base virtual address (GICv2 only). Populated by `init(discovery)`
/// from `GicDiscovery.gicc_base`; zero when the ACPI MADT did not expose
/// a GICv2 CPU-interface MMIO window (e.g. GICv3 systems).
/// IHI 0048B, Section 4.4: CPU Interface register map.
var gicc_base: u64 = 0;

/// GICR base virtual addresses, one per core. Populated by `init(discovery)`
/// from `GicDiscovery.gicr_bases`.
var gicr_bases: [max_redist]u64 = [_]u64{0} ** max_redist;

/// Number of redistributors populated in `gicr_bases`. Separate from
/// `core_count` (which tracks enabled CPU cores from MADT GICC entries)
/// so the two counters don't clobber each other. Populated by
/// `init(discovery)` from `GicDiscovery.redist_count`.
var redist_count: u64 = 0;

/// Number of cores discovered from MADT. Populated by `init(discovery)`
/// from `GicDiscovery.core_count`; `coreCount()` reports 1 as a BSP-only
/// fallback when the discovery struct left this zero.
var core_count: u64 = 0;

/// ACPI-discovered GIC topology passed from the MADT parser to `init()`.
///
/// Replaces the earlier implicit contract where `parseMadt` mutated
/// module-global discovery state (`gicd_base`, `gicc_base`, `gicr_bases`,
/// `redist_count`, `core_count`) and the caller had to invoke `gic.init()`
/// afterwards. The handoff is now explicit: the MADT parser builds the
/// struct, the caller hands it to `init(discovery)`, and reordering the
/// two steps is a compile-time error rather than a silent boot hang.
///
/// Fields mirror the discovery setters they replace:
///   - gicd_base: GICD MMIO virtual address (distributor).
///     ACPI 6.5 Table 5-47 (MADT GICD, type 0x0C).
///   - gicc_base: GICv2 CPU-interface MMIO virtual address; zero on
///     GICv3 systems where the CPU interface is accessed via ICC_*_EL1
///     system registers. ACPI 6.5 Table 5-45 (MADT GICC, type 0x0B).
///   - gicr_bases: per-core GICR frame virtual addresses; only the first
///     `redist_count` entries are populated. ACPI 6.5 Table 5-49 (MADT
///     GICR, type 0x0E).
///   - redist_count: number of populated entries in `gicr_bases`.
///   - core_count: enabled core count from MADT GICC entries. Zero when
///     the MADT had no enabled GICC entries; `coreCount()` treats zero
///     as a BSP-only (1-core) fallback.
pub const GicDiscovery = struct {
    gicd_base: u64 = 0,
    gicc_base: u64 = 0,
    gicr_bases: [max_redist]u64 = [_]u64{0} ** max_redist,
    redist_count: u64 = 0,
    core_count: u64 = 0,
};

/// Number of SPI lines supported by this GICD, derived from GICD_TYPER.
var max_spi_intid: u32 = 0;

// ── MMIO helpers ────────────────────────────────────────────────

fn gicdRead(reg: GicdReg) u32 {
    const ptr: *const volatile u32 = @ptrFromInt(gicd_base + @intFromEnum(reg));
    return ptr.*;
}

fn gicdWrite(reg: GicdReg, val: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(gicd_base + @intFromEnum(reg));
    ptr.* = val;
}

fn gicdReadOffset(base_reg: GicdReg, byte_offset: u32) u32 {
    const ptr: *const volatile u32 = @ptrFromInt(gicd_base + @intFromEnum(base_reg) + byte_offset);
    return ptr.*;
}

fn gicdWriteOffset(base_reg: GicdReg, byte_offset: u32, val: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(gicd_base + @intFromEnum(base_reg) + byte_offset);
    ptr.* = val;
}

fn giccRead(reg: GiccReg) u32 {
    const ptr: *const volatile u32 = @ptrFromInt(gicc_base + @intFromEnum(reg));
    return ptr.*;
}

fn giccWrite(reg: GiccReg, val: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(gicc_base + @intFromEnum(reg));
    ptr.* = val;
}

fn gicrRead(core_idx: usize, reg: GicrReg) u32 {
    const ptr: *const volatile u32 = @ptrFromInt(gicr_bases[core_idx] + @intFromEnum(reg));
    return ptr.*;
}

fn gicrWrite(core_idx: usize, reg: GicrReg, val: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(gicr_bases[core_idx] + @intFromEnum(reg));
    ptr.* = val;
}

fn gicrSgiWrite(core_idx: usize, reg: GicrSgiReg, val: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(gicr_bases[core_idx] + 0x10000 + @intFromEnum(reg));
    ptr.* = val;
}

// ── ICC system register accessors (IHI 0069H, Section 12.11) ───

/// Read ICC_SRE_EL1 — System Register Enable.
/// IHI 0069H, Section 12.11.3.
fn readIccSre() u64 {
    var val: u64 = undefined;
    asm volatile ("mrs %[val], S3_0_C12_C12_5"
        : [val] "=r" (val),
    );
    return val;
}

/// Write ICC_SRE_EL1 — System Register Enable.
/// IHI 0069H, Section 12.11.3: bit 0 = SRE (enable system register interface).
fn writeIccSre(val: u64) void {
    asm volatile ("msr S3_0_C12_C12_5, %[val]"
        :
        : [val] "r" (val),
    );
    asm volatile ("isb");
}

/// Write ICC_PMR_EL1 — Priority Mask Register.
/// IHI 0069H, Section 12.11.2: interrupts with priority >= PMR value are masked.
/// Writing 0xFF allows all priority levels.
fn writeIccPmr(val: u64) void {
    asm volatile ("msr S3_0_C4_C6_0, %[val]"
        :
        : [val] "r" (val),
    );
}

/// Write ICC_IGRPEN1_EL1 — Interrupt Group 1 Enable.
/// IHI 0069H, Section 12.11.6: bit 0 = Enable Group 1 interrupts.
fn writeIccIgrpen1(val: u64) void {
    asm volatile ("msr S3_0_C12_C12_7, %[val]"
        :
        : [val] "r" (val),
    );
}

/// Read ICC_IAR1_EL1 — Interrupt Acknowledge Register (Group 1).
/// IHI 0069H, Section 12.11.1: returns the INTID of the highest priority
/// pending Group 1 interrupt, or 1023 (spurious) if none pending.
fn readIccIar1() u32 {
    var val: u64 = undefined;
    asm volatile ("mrs %[val], S3_0_C12_C12_0"
        : [val] "=r" (val),
    );
    return @intCast(val & 0xFFFFFF);
}

/// Write ICC_EOIR1_EL1 — End of Interrupt Register (Group 1).
/// IHI 0069H, Section 12.11.1: write the INTID to signal completion.
fn writeIccEoir1(intid: u32) void {
    const val: u64 = intid;
    asm volatile ("msr S3_0_C12_C12_1, %[val]"
        :
        : [val] "r" (val),
    );
}

/// Write ICC_SGI1R_EL1 — SGI Generation Register (Group 1).
/// IHI 0069H, Section 12.11.8.
fn writeIccSgi1r(val: u64) void {
    asm volatile ("msr S3_0_C12_C11_5, %[val]"
        :
        : [val] "r" (val),
    );
}

/// Write ICC_BPR1_EL1 — Binary Point Register (Group 1).
/// IHI 0069H, Section 12.11.4: controls priority grouping for preemption.
/// A value of 0 means all 8 priority bits are used for preemption grouping.
fn writeIccBpr1(val: u64) void {
    asm volatile ("msr S3_0_C12_C12_3, %[val]"
        :
        : [val] "r" (val),
    );
}

/// Read MPIDR_EL1 — Multiprocessor Affinity Register.
/// ARM ARM D13.2.83: Aff0 [7:0] = core, Aff1 [15:8] = cluster,
/// Aff2 [23:16], Aff3 [39:32].
fn readMpidr() u64 {
    var val: u64 = undefined;
    asm volatile ("mrs %[val], mpidr_el1"
        : [val] "=r" (val),
    );
    return val;
}

// ── Initialization ──────────────────────────────────────────────

/// Initialize the GIC distributor. Called once on the BSP during boot.
///
/// Detects the GIC version by reading GICD_PIDR2.ArchRev (bits [7:4]).
/// IHI 0069H, Section 8.9.15 / IHI 0048B, Section 4.3.17:
///   ArchRev 2 = GICv2, ArchRev 3 = GICv3/v4.
///
/// For GICv3: enables affinity routing (ARE) and Group 1 non-secure
/// interrupts. SPIs are routed via GICD_IROUTER.
///
/// For GICv2: enables Group 1 non-secure interrupts without ARE. SPIs
/// are routed via GICD_ITARGETSR (8-bit CPU target mask per INTID).
///
/// All SPIs are disabled initially — they are unmasked individually when
/// device drivers request them.
///
/// IHI 0069H, Section 8.9.4: GICD_CTLR register (GICv3).
/// IHI 0048B, Section 4.3.2: GICD_CTLR register (GICv2).
/// IHI 0069H, Section 8.9.5 / IHI 0048B, Section 4.3.3:
///   GICD_TYPER — ITLinesNumber field [4:0] gives (max SPI INTID / 32) - 1.
pub fn initDistributor() void {
    if (gicd_base == 0) return;

    // Detect GIC version from GICD_PIDR2.ArchRev [7:4].
    //
    // GICv2 exposes PIDR2 at offset 0x0FE8 (IHI 0048B, Section 4.3.17)
    // and its GICD MMIO window is only 4 KiB wide — offsets >= 0x1000
    // are unassigned memory. Reading GICv3's PIDR2_v3 slot (0xFFE8)
    // on a GICv2 implementation raises a synchronous external abort
    // (QEMU TCG `-M virt` with the default GICv2) or hangs.
    //
    // Probe GICv2 first. If ArchRev[7:4] == 2 we know we are on
    // GICv2 and MUST NOT touch offset 0xFFE8. Only fall through to
    // the GICv3 probe when the v2 slot shows something else (typical
    // on a genuine GICv3: 0xFE8 reads back zero because it's reserved).
    const pidr2_v2_val = gicdRead(.pidr2);
    const arch_rev_v2 = (pidr2_v2_val >> 4) & 0xF;
    var arch_rev: u32 = arch_rev_v2;
    if (arch_rev_v2 != 2) {
        const pidr2_v3_val = gicdRead(.pidr2_v3);
        const arch_rev_v3 = (pidr2_v3_val >> 4) & 0xF;
        if (arch_rev_v3 >= 3) arch_rev = arch_rev_v3;
    }
    gicv3 = (arch_rev >= 3);

    // Disable the distributor while reconfiguring.
    gicdWrite(.ctlr, 0);

    // Read the number of supported SPI interrupt lines.
    // IHI 0069H, Section 8.9.5 / IHI 0048B, Section 4.3.3:
    // GICD_TYPER.ITLinesNumber [4:0].
    const typer = gicdRead(.typer);
    const it_lines = typer & 0x1F;
    max_spi_intid = (it_lines + 1) * 32;

    // Disable all SPIs (INTID 32+). SGIs/PPIs (0-31) are per-core.
    // IHI 0069H, Section 8.9.8 / IHI 0048B, Section 4.3.6: GICD_ICENABLER<n>.
    var n: u32 = 1;
    while (n < (max_spi_intid / 32)) {
        gicdWriteOffset(.icenabler0, n * 4, 0xFFFFFFFF);
        n += 1;
    }

    // Set all SPI priorities to the lowest (0xFF).
    // IHI 0069H, Section 8.9.11 / IHI 0048B, Section 4.3.11:
    // GICD_IPRIORITYR<n>, 8 bits per INTID.
    n = 8; // Start at INTID 32 (byte offset 32 = register index 8).
    while (n < (max_spi_intid / 4)) {
        gicdWriteOffset(.ipriorityr0, n * 4, 0xFFFFFFFF);
        n += 1;
    }

    // Set all SPIs to edge-triggered by default.
    // IHI 0069H, Section 8.9.12 / IHI 0048B, Section 4.3.13:
    // GICD_ICFGR<n>, 2 bits per INTID. Bit [1] = 1 for edge-triggered.
    n = 2; // Start at INTID 32 (register index 2).
    while (n < (max_spi_intid / 16)) {
        gicdWriteOffset(.icfgr0, n * 4, 0xAAAAAAAA);
        n += 1;
    }

    if (gicv3) {
        // GICv3: Route all SPIs to core 0 via GICD_IROUTER.
        // IHI 0069H, Section 8.9.13: GICD_IROUTER<n>, 64-bit, one per SPI.
        // IROUTER starts at INTID 32, so register 0 = INTID 32.
        var intid: u32 = 32;
        while (intid < max_spi_intid) {
            const offset = (intid - 32) * 8;
            const ptr: *volatile u64 = @ptrFromInt(gicd_base + @intFromEnum(GicdReg.irouter0) + offset);
            ptr.* = 0; // Aff0=0 targets core 0.
            intid += 1;
        }

        // Enable distributor with affinity routing and Group 1.
        // IHI 0069H, Section 8.9.4: ARE_NS (bit 4), EnableGrp1NS (bit 1).
        gicdWrite(.ctlr, gicd_ctlr_are_ns | gicd_ctlr_enable_grp1_ns | gicd_ctlr_enable_grp0);
    } else {
        // GICv2: Route all SPIs to CPU 0 via GICD_ITARGETSR.
        // IHI 0048B, Section 4.3.12: GICD_ITARGETSR<n>, 8 bits per INTID,
        // each byte is a CPU target bitmask (bit 0 = CPU 0, etc.).
        // INTIDs 0-31 are read-only (banked per-CPU), start at INTID 32.
        n = 8; // Byte offset 32 = register index 8 (4 INTIDs per register).
        while (n < (max_spi_intid / 4)) {
            gicdWriteOffset(.itargetsr0, n * 4, 0x01010101); // All 4 INTIDs → CPU 0.
            n += 1;
        }

        // Probe whether Non-secure writes to GICD_IGROUPR0 (the banked
        // per-CPU INTIDs 0-31) take effect. IHI 0048B §4.3.10 says that
        // on an implementation with Security Extensions, Non-secure
        // accesses to GICD_IGROUPR0 "have no effect" and the register
        // reads back as zero — so every INTID remains in Group 0, and
        // Group 0 interrupts are unreachable from the Non-secure OS.
        // When the implementation exposes a writable IGROUPR0 (GICv2
        // without Security Extensions, or Secure-view access), we can
        // move every SGI/PPI to Group 1 NS and acknowledge via the
        // aliased IAR/EOIR pair. Otherwise the driver must leave the
        // group assignment alone and ack via the non-aliased pair.
        //
        // The probe writes all 1s, reads back, and captures whether the
        // write was observed. The value is latched into
        // `gicv2_group1_ack` and re-applied below; secondary cores
        // re-use the same decision via `initRedistributor` path.
        gicdWriteOffset(.igroupr0, 0, 0xFFFFFFFF);
        const igroupr0_after = gicdReadOffset(.igroupr0, 0);
        gicv2_group1_ack = igroupr0_after != 0;

        // Enable distributor for whichever Group the implementation lets
        // the Non-secure OS drive. IHI 0048B, Section 4.3.2, Table 4-21
        // (GICD_CTLR, Non-secure view): bit 0 is the single Group 1
        // enable when only the NS view is visible. Under the Secure
        // view bit 0 is EnableGrp0 and bit 1 is EnableGrp1NS; writing
        // both keeps a Group 0 configuration usable when IGROUPR0
        // writes are ignored and Group 1 usable when they are honoured.
        // Linux's gic.c uses GICD_ENABLE = 0x1 for the same purpose.
        gicdWrite(.ctlr, gicd_ctlr_enable_grp1_ns | gicd_ctlr_enable_grp0);
    }
}

/// Wake a redistributor for the given core index (GICv3 only).
///
/// Clears GICR_WAKER.ProcessorSleep and polls until GICR_WAKER.ChildrenAsleep
/// is cleared by hardware, indicating the redistributor is fully awake.
///
/// IHI 0069H, Section 9.5.5: GICR_WAKER.
fn wakeRedistributor(core_idx: usize) void {
    if (gicr_bases[core_idx] == 0) return;

    // Clear ProcessorSleep (bit 1).
    var waker = gicrRead(core_idx, .waker);
    waker &= ~gicr_waker_processor_sleep;
    gicrWrite(core_idx, .waker, waker);

    // Wait for ChildrenAsleep (bit 2) to clear.
    while (gicrRead(core_idx, .waker) & gicr_waker_children_asleep != 0) {
        std.atomic.spinLoopHint();
    }
}

/// Initialize the redistributor for the given core index.
///
/// On GICv3: wakes the redistributor, enables all SGIs (INTID 0-15), and
/// sets default priority for SGIs/PPIs via GICR registers.
///
/// On GICv2: no redistributor exists. SGI/PPI configuration is done via
/// GICD registers (GICD_ISENABLER0, GICD_IPRIORITYR0-7), which are banked
/// per-CPU on GICv2.
///
/// IHI 0069H, Section 9.5.
/// IHI 0048B, Section 4.3.5: GICD_ISENABLER0 is banked per-CPU for INTIDs 0-31.
/// IHI 0048B, Section 4.3.11: GICD_IPRIORITYR0-7 is banked per-CPU for INTIDs 0-31.
pub fn initRedistributor(core_idx: usize) void {
    if (gicd_base == 0) return;
    if (gicv3) {
        wakeRedistributor(core_idx);

        // Assign all SGIs/PPIs to Group 1 Non-secure. After reset
        // GICR_IGROUPR0 is UNKNOWN and some implementations leave every
        // INTID in Group 0. We only enable ICC_IGRPEN1_EL1 on the CPU
        // interface, so any PPI left in Group 0 (notably the scheduler
        // preemption PPI 30) would be silently dropped. IHI 0069H,
        // Section 9.5.2.
        gicrSgiWrite(core_idx, .igroupr0, 0xFFFFFFFF);

        // Enable SGIs (INTID 0-15) and the generic timer PPIs
        // (27 = CNTV, 29 = CNTHP, 30 = CNTP) via GICR_ISENABLER0.
        // IHI 0069H, Section 9.5.6: GICR_ISENABLER0 — bit n enables INTID n.
        // The scheduler uses the EL1 physical timer (CNTP, PPI 30) for
        // preemption; see kernel/arch/aarch64/timers.zig for why CNTV
        // (PPI 27) is unsafe under Pi 5 KVM vGICv2. CNTV is kept enabled
        // in the GIC anyway for guest-support paths.
        //
        // PPI 23 is the PMU overflow request line. ARM ARM DDI 0487 K.a
        // §D13.3.1 "Generating overflow interrupt requests" says the
        // PMU connects to the GIC as a PPI with ID 23 (GICv3-recommended)
        // and is level-sensitive. QEMU `virt` and Cortex-A72/A76 both
        // honour this recommendation. The default GICR_ICFGR1 reset value
        // leaves PPIs as level-sensitive (2-bit field = 0b00), which is
        // exactly what PMU overflow needs, so no ICFGR write is required.
        gicrSgiWrite(core_idx, .isenabler0, 0x0000FFFF | (1 << 23) | (1 << 27) | (1 << 29) | (1 << 30));

        // Set all SGI/PPI priorities to 0x80. On GICv3 ICC_PMR_EL1 is
        // 0xFF and interrupts with priority >= PMR are masked (IHI 0069H,
        // Section 12.11.2), so writing 0xFF into IPRIORITYR would silently
        // suppress every PPI — including the preemption timer. 0x80 is
        // well below the mask.
        // IHI 0069H, Section 9.5.8: GICR_IPRIORITYR<n>. Write via raw
        // pointer arithmetic rather than @enumFromInt on an offset that
        // is not one of GicrSgiReg's named members (the enum is
        // exhaustive, so a synthetic value is undefined behaviour).
        var n: u32 = 0;
        while (n < 8) {
            const addr = gicr_bases[core_idx] + 0x10000 + @intFromEnum(GicrSgiReg.ipriorityr0) + n * 4;
            const ptr: *volatile u32 = @ptrFromInt(addr);
            ptr.* = 0x80808080;
            n += 1;
        }
    } else {
        // GICv2: SGI/PPI registers are in GICD, banked per-CPU.
        //
        // Assign all SGIs/PPIs to Group 1 Non-secure via the banked
        // GICD_IGROUPR0. After reset this register is UNKNOWN (KVM
        // GICv2 emulation + AAVMF leaves every INTID in Group 0). The
        // CPU interface is enabled for Group 1, so any PPI left in
        // Group 0 — notably the CNTP preemption timer PPI 30 — would
        // be silently dropped. IHI 0048B, Section 4.3.10.
        gicdWriteOffset(.igroupr0, 0, 0xFFFFFFFF);

        // Enable SGIs (INTID 0-15), timer PPIs (27, 29, 30), and the PMU
        // overflow PPI (23) via the banked GICD_ISENABLER0. ARM ARM DDI
        // 0487 K.a §D13.3.1 documents PMU overflow as level-sensitive
        // PPI 23 on GICv3-compatible implementations; GICv2's banked
        // GICD_ICFGR1 reset defaults also leave PPIs level-sensitive, so
        // the trigger config does not need to be rewritten here.
        // IHI 0048B, Section 4.3.5.
        gicdWriteOffset(.isenabler0, 0, 0x0000FFFF | (1 << 23) | (1 << 27) | (1 << 29) | (1 << 30));

        // Set all SGI/PPI priorities to 0x80 (see GICv3 note above).
        // IHI 0048B, Section 4.3.11: GICD_IPRIORITYR0-7 (banked per-CPU).
        var n: u32 = 0;
        while (n < 8) {
            gicdWriteOffset(.ipriorityr0, n * 4, 0x80808080);
            n += 1;
        }
    }
}

/// Initialize the CPU interface on the current core.
///
/// On GICv3: enables ICC system register interface, sets priority mask to
/// allow all interrupts, and enables Group 1 interrupt signaling.
///
/// On GICv2: configures the GICC MMIO registers for priority mask, binary
/// point, and enables the CPU interface.
///
/// GICv3 references:
///   IHI 0069H, Section 12.11.3: ICC_SRE_EL1 — SRE bit enables sys reg interface.
///   IHI 0069H, Section 12.11.2: ICC_PMR_EL1 — 0xFF allows all priorities.
///   IHI 0069H, Section 12.11.4: ICC_BPR1_EL1 — binary point for preemption.
///   IHI 0069H, Section 12.11.6: ICC_IGRPEN1_EL1 — bit 0 enables Group 1.
///
/// GICv2 references:
///   IHI 0048B, Section 4.4.2: GICC_PMR — 0xFF allows all priorities.
///   IHI 0048B, Section 4.4.3: GICC_BPR — binary point for preemption.
///   IHI 0048B, Section 4.4.1: GICC_CTLR — bit 0 enables the CPU interface.
pub fn initCpuInterface() void {
    if (gicv3) {
        // Enable system register interface.
        var sre = readIccSre();
        sre |= 0x1; // SRE bit.
        writeIccSre(sre);

        // Set priority mask to allow all interrupt priorities.
        writeIccPmr(0xFF);

        // Set binary point to 0 (no sub-priority grouping).
        writeIccBpr1(0);

        // Enable Group 1 interrupts.
        writeIccIgrpen1(0x1);
    } else {
        if (gicc_base == 0) return;

        // Set priority mask to allow all interrupt priorities.
        // IHI 0048B, Section 4.4.2: GICC_PMR.
        giccWrite(.pmr, 0xFF);

        // Set binary point to 0 (no sub-priority grouping).
        // IHI 0048B, Section 4.4.3: GICC_BPR.
        giccWrite(.bpr, 0);

        // Enable the CPU interface for Group 1 non-secure.
        //
        // IHI 0048B, Section 4.4.1, Table 4-46 (GICC_CTLR, Non-secure view):
        // when accessed from Non-secure state, the bit positions are
        // remapped — bit 0 becomes EnableGrp1 (the "enable" bit for the
        // OS), bit 5 = FIQBypDisGrp1, bit 6 = IRQBypDisGrp1, bit 9 =
        // EOImodeNS. The Secure-view layout (bit 0 = EnableGrp0,
        // bit 1 = EnableGrp1NS) is NOT visible from a Non-secure OS.
        //
        // KVM's in-kernel GICv2 emulation (and TCG GICv2 without the
        // security extensions) only exposes the Non-secure view, so a
        // write of 0x2 lands on a reserved bit and leaves the CPU
        // interface disabled — no Group 1 interrupt is ever forwarded
        // to the core. Writing 0x1 is what Linux's gic.c does
        // (GICC_ENABLE = 0x1). We additionally set bit 1 so that on a
        // GICv2 implementation that does expose the Secure view this
        // also enables Group 1 NS, matching the previous behaviour.
        giccWrite(.ctlr, 0x3);
    }
}

/// Full GIC initialization for the BSP (boot core).
///
/// Installs the ACPI-discovered topology (`d`) into module-local state
/// and then initializes the distributor, the BSP's redistributor (index
/// 0), and the BSP's CPU interface. Secondary cores call
/// initSecondaryCoreGic() instead.
///
/// Taking discovery as an explicit argument (rather than reading globals
/// written earlier by the MADT parser) makes the ordering between MADT
/// parsing and GIC init a compile-time contract: reordering the two
/// steps in `acpi.parseAcpi` is a type error rather than a silent boot
/// hang. See `GicDiscovery` for field semantics.
pub fn init(d: GicDiscovery) void {
    gicd_base = d.gicd_base;
    gicc_base = d.gicc_base;
    const n: usize = @intCast(@min(d.redist_count, @as(u64, max_redist)));
    var i: usize = 0;
    while (i < n) {
        gicr_bases[i] = d.gicr_bases[i];
        i += 1;
    }
    redist_count = n;
    core_count = d.core_count;

    initDistributor();
    initRedistributor(0);
    initCpuInterface();
}

/// Initialize GIC for a secondary core.
///
/// Wakes the core's redistributor and enables the CPU interface.
/// The distributor is already initialized by the BSP.
pub fn initSecondaryCoreGic(core_idx: usize) void {
    initRedistributor(core_idx);
    initCpuInterface();
}

// ── Public API ──────────────────────────────────────────────────

/// Return the number of cores discovered from ACPI MADT.
pub fn coreCount() u64 {
    return if (core_count == 0) 1 else core_count;
}

/// Return the current core's logical ID derived from MPIDR_EL1.
///
/// Uses Aff0 [7:0] for flat topology (single cluster). For multi-cluster
/// systems, this should be extended to incorporate Aff1/Aff2/Aff3.
///
/// ARM ARM D13.2.83: MPIDR_EL1.
pub fn coreID() u64 {
    const mpidr = readMpidr();
    return mpidr & 0xFF; // Aff0.
}

/// Last GICv2 IAR value read on this core, saved for EOI. On GICv2, EOI
/// for an SGI must include the CPUID of the originating CPU (bits
/// [12:10] of the IAR value) alongside the INTID — IHI 0048B §4.4.5
/// "GICC_EOIR" / §4.4.12 "GICC_AEOIR": "Software must write to
/// GICC_EOIR with the same value that was read from GICC_IAR... if
/// the interrupt was an SGI, software must include the CPUID of the
/// requesting CPU." Masking the CPUID away — as earlier revisions did
/// — meant the GIC never clears the per-source pending state for SGIs
/// from CPUs other than 0, and the first cross-core self-IPI
/// (`yield()` → SGI 0 from CPU 0 to CPU 0) produced a correctly-cleared
/// IRQ but the first scheduler IPI from CPU 1 to CPU 0 pended forever,
/// re-raising on every ERET in a tight storm.
///
/// Writing the full IAR value back is always safe: on SPI/PPI the
/// CPUID field is RES0 and the EOI still matches on INTID.
///
/// Per-core variable because several cores may be handling interrupts
/// concurrently and each must EOI its own IAR. The BSP seeds the slot
/// on early boot; `initSecondaryCoreGic` zeros it for each AP.
var gicv2_last_iar: [max_redist]u32 = [_]u32{0} ** max_redist;

/// Acknowledge the highest priority pending interrupt.
///
/// On GICv3: reads ICC_IAR1_EL1 (IHI 0069H, Section 12.11.1).
///
/// On GICv2: reads GICC_IAR or GICC_AIAR depending on which Group the
/// distributor routes SGIs/PPIs to. IHI 0048B §4.3.10 documents that
/// Non-secure writes to GICD_IGROUPR0 "have no effect" on a GICv2 with
/// Security Extensions accessed from NS state — every SGI/PPI stays in
/// Group 0, which a Non-secure OS can neither enable nor acknowledge
/// via the aliased registers. On such an implementation, reading
/// GICC_AIAR returns the spurious INTID 1022 (IHI 0048B §4.4.11) on
/// every tick, the un-acked Group 0 interrupt stays pending, and the
/// CPU spins in an IRQ storm. `initDistributor` probes IGROUPR0 and
/// latches the decision in `gicv2_group1_ack`: true → implementation
/// honoured the write, use aliased (Group 1) ack/eoi path; false →
/// fall back to the non-aliased (Group 0) pair, which is the ack path
/// the GICv2 reset state leaves the OS with.
///
/// The full raw IAR value (including CPUID bits [12:10] for SGIs) is
/// latched in `gicv2_last_iar[coreID]` so `endOfInterrupt` can write
/// the matching full-width EOI value; see `gicv2_last_iar` for the
/// SGI CPUID-routing requirement.
///
/// IHI 0048B, Section 4.4.4: GICC_IAR — INTID in bits [9:0], CPUID in
/// bits [12:10] for SGIs.
/// IHI 0048B, Section 4.4.11: GICC_AIAR — same layout, 1022 on
/// no Group 1 pending.
///
/// Returns the INTID, or `spurious_intid` (1023) if no interrupt is pending.
pub fn acknowledgeInterrupt() u32 {
    if (gicv3) return readIccIar1();
    const raw = if (gicv2_group1_ack) giccRead(.aiar) else giccRead(.iar);
    const core_idx: usize = @intCast(coreID() & 0xFF);
    if (core_idx < max_redist) gicv2_last_iar[core_idx] = raw;
    return raw & 0x3FF; // IHI 0048B: INTID in bits [9:0].
}

/// Signal end of interrupt processing for the given INTID.
///
/// On GICv3: writes ICC_EOIR1_EL1 (IHI 0069H, Section 12.11.1).
///
/// On GICv2: writes GICC_AEOIR when the driver ack'd via GICC_AIAR
/// (Group 1 alias) or GICC_EOIR when the ack came from GICC_IAR
/// (non-aliased). Using the wrong EOI against an INTID that was not
/// acknowledged via the matching IAR is a no-op per IHI 0048B §4.4.12
/// / §4.4.5, which leaves the interrupt active-and-pending and masks
/// every subsequent delivery at the CPU interface — the failure mode
/// that caused the scheduler tick to hang after the very first IRQ on
/// Pi-5 KVM GICv2.
///
/// The write uses the full raw value latched by `acknowledgeInterrupt`
/// so the SGI CPUID bits [12:10] survive the round-trip (IHI 0048B
/// §4.4.5). When the latched value's INTID does not match the caller-
/// supplied INTID (e.g. the caller bailed before calling
/// `acknowledgeInterrupt`), fall back to writing the bare INTID; this
/// matches the previous behaviour on non-SGI paths where CPUID is RES0.
///
/// IHI 0048B, Section 4.4.5: GICC_EOIR.
/// IHI 0048B, Section 4.4.12: GICC_AEOIR.
///
/// Must be called after the interrupt handler completes. For level-triggered
/// SPIs, the peripheral must deassert the interrupt line before EOI to
/// avoid re-triggering.
pub fn endOfInterrupt(intid: u32) void {
    if (gicv3) {
        writeIccEoir1(intid);
        return;
    }
    const core_idx: usize = @intCast(coreID() & 0xFF);
    const latched: u32 = if (core_idx < max_redist) gicv2_last_iar[core_idx] else 0;
    const eoi_val: u32 = if ((latched & 0x3FF) == intid) latched else intid;
    if (gicv2_group1_ack) {
        giccWrite(.aeoir, eoi_val);
    } else {
        giccWrite(.eoir, eoi_val);
    }
}

/// Send an IPI (SGI) to the specified core.
///
/// On GICv3: writes ICC_SGI1R_EL1 with the target affinity and SGI INTID.
/// ICC_SGI1R_EL1 layout (IHI 0069H, Section 12.11.8):
///   [3:0]   — TargetList: bitmask of target cores within the target affinity.
///   [23:16] — Aff1: target cluster.
///   [27:24] — INTID: SGI interrupt number (0-15).
///   [39:32] — Aff2.
///   [40]    — IRM: 0 = use target list, 1 = all except self.
///   [55:48] — Aff3.
///
/// On GICv2: writes GICD_SGIR.
/// IHI 0048B, Section 4.3.15: GICD_SGIR layout:
///   [3:0]   — INTID: SGI interrupt number (0-15).
///   [23:16] — CPUTargetList: bitmask of target CPUs.
///   [25:24] — TargetListFilter: 0 = use CPUTargetList.
///
/// For a flat topology (single cluster, Aff1=Aff2=Aff3=0), only the
/// TargetList and INTID fields matter.
///
/// Pi 5 KVM GICv2 history note (s2_1_25 / s2_2_16 / s2_2_33): when the
/// scheduler preemption tick was sourced from the EL1 virtual timer
/// (CNTV, PPI 27), per-core schedTimerHandler counters showed that
/// secondary cores under Pi 5 KVM with the in-kernel vGICv2 stopped
/// receiving the CNTV event as soon as they dispatched a user (EL0)
/// thread. Sample at 10 s of wall clock running §2.2.16:
///
///   tk5000: c0=5001 c1=2(sw1,eq1) c2=7 c3=0
///
/// Core 0 ticked at ~500 Hz from main's self-yield SGIs, but cores
/// 1-3 effectively never ticked. Cross-core SGIs were delivered
/// correctly in the same run (§2.2.34 passed), isolating the miss to
/// the KVM↔guest CNTV injection path on Pi-class hardware. TCG GICv2
/// / TCG GICv3 / x86 KVM were all unaffected by the same bug.
///
/// Resolved by switching the scheduler preemption timer from CNTV
/// (PPI 27) to CNTP (PPI 30) — see kernel/arch/aarch64/timers.zig
/// and the INTID 30 case in exceptions.zig dispatchIrq. CNTP is
/// routed by the vGICv2 through a path that does not hit the CNTV
/// injection bug, and is available on every host/firmware combo we
/// target. Do not revert the preemption source to CNTV without first
/// validating on Pi 5 KVM.
///
/// Tried-and-not-working workarounds (retained here so the next pass
/// does not re-investigate from scratch):
///   * Unconditional BSP→all-secondaries SGI broadcast on every BSP
///     tick — didn't help the timer-stalled cores AND broke §3_3_7
///     / §2.2.34 by storming the IPC reply path.
///   * Same broadcast gated on `remote.rq.head != null` — same result.
///
/// Further discovery: the Pi 5 KVM vGICv2 drop is broader than just CNTP/CNTV PPIs —
/// empirically, when a secondary vCPU is executing at EL0 (running a
/// user thread), ALL interrupt injections to that vCPU are silently
/// dropped, including SGIs from the BSP (the `broadcastSchedTick`
/// SGI_BCAST_TICK fan-out AND the cross-core `sendIpiToCore` SGI 0
/// scheduler IPI). Trace evidence from s2_2_16 on 4-core Pi KVM:
///
///   [BC c1]           (1x, while core 1 was still running idle)
///   [SGI0 c1]         (1x, dispatches worker to core 1)
///   [BC c2]...        (hundreds, cores 2 & 3 continue to tick)
///   (no more c1 interrupts of any kind)
///
/// Once core 1 ERETs into the worker's EL0 spin loop (pure atomic
/// increment with no syscalls), neither the BSP broadcast SGI 7 nor
/// any newly-fired core 1 CNTP PPI 30 reach the core — it stays in
/// EL0 indefinitely, so no cross-core wake or preemption tick can
/// migrate the worker or deliver a timeslice. Cores 2 & 3, which
/// stayed in EL1 on the idle thread's `wfi`, continued to receive
/// broadcasts normally. §2.2.33 still passes because its helper
/// thread performs `thread_yield` syscalls that voluntarily re-enter
/// EL1 and let queued interrupts drain; §2.2.16 and §2.1.25 fail
/// because their workers / restartable children spin purely at EL0
/// after they migrate to a secondary.
///
/// There is no guest-side workaround for this limitation — the IRQ
/// delivery path is inside KVM/vGICv2 on the host. Tests that require
/// preemptive cross-core scheduling of an EL0-only workload (no
/// syscalls, no faults) do not pass on Pi 5 KVM vGICv2 today. They
/// pass on TCG GICv3, x86 KVM, and are expected to pass on Pi 5
/// bare-metal GICv3 once that bring-up lands.
pub fn sendIpiToCore(core_id: u64, vector: u8) void {
    // SGI INTID must be 0-15.
    const sgi_id: u64 = vector & 0xF;

    if (gicv3) {
        // For flat topology, core_id maps to Aff0 directly.
        // TargetList is a bitmask within the lowest affinity level.
        const target_list: u64 = @as(u64, 1) << @intCast(core_id & 0xF);

        // Build ICC_SGI1R_EL1 value.
        // IHI 0069H, Section 12.11.8.
        const sgi_val: u64 = target_list | // [15:0] TargetList
            (sgi_id << 24); // [27:24] INTID

        writeIccSgi1r(sgi_val);
    } else {
        // GICv2: write GICD_SGIR.
        // IHI 0048B, Section 4.3.15: [3:0] = INTID, [23:16] = CPUTargetList,
        // [25:24] = TargetListFilter (0 = use CPUTargetList).
        const target_mask: u32 = @as(u32, 1) << @intCast(core_id & 0x7);
        const sgir_val: u32 = @as(u32, @intCast(sgi_id)) | (target_mask << 16);
        gicdWrite(.sgir, sgir_val);
    }
}

/// Scheduler-rearm IPI uses SGI 0. SGIs 0-15 are the software-generated
/// band on ARM; 0 is reserved here for the scheduler and 1 for the
/// kprof-dump broadcast.
const sched_sgi_id: u8 = 0;

/// Send the scheduler-rearm IPI to `core_id`. Encapsulates the SGI id
/// so callers don't have to know which id the scheduler listens on.
pub fn sendSchedulerIpi(core_id: u64) void {
    sendIpiToCore(core_id, sched_sgi_id);
}

/// Dedicated SGI INTID reserved for the BSP-driven scheduler-tick
/// broadcast (Pi 5 KVM vGICv2 workaround — see `broadcastSchedTick`
/// below). Must not collide with SGI 0 (the scheduler IPI / yield /
/// cross-core wake vector) because that path has IPC / futex
/// semantics the tick must not disturb. SGI 7 is otherwise unused by
/// the kernel.
pub const SGI_BCAST_TICK: u8 = 7;

/// Next CNTPCT tick at/after which `maybeBroadcastSchedTick` is
/// allowed to fire. Updated with relaxed atomics by whichever BSP
/// interrupt handler wins the compare-exchange; losers skip the
/// broadcast. Zero-initialised — the first caller always fires.
var next_bcast_tick: u64 = 0;

/// Minimum interval between broadcasts, in CNTFRQ ticks. Scaled at
/// run time in `maybeBroadcastSchedTick` from the counter frequency
/// so the guaranteed preemption cadence matches the 2 ms scheduler
/// timeslice regardless of host CNTFRQ.
const BCAST_INTERVAL_NS: u64 = 2_000_000;

/// Broadcast a scheduler tick SGI to every core except the caller.
///
/// Pi 5 KVM's in-kernel vGICv2 silently drops per-core PPI timer
/// injections (both CNTV PPI 27 and CNTP PPI 30) to secondary vCPUs
/// as soon as they dispatch an EL0 thread — see the extended note on
/// `sendIpiToCore` above and the one in `kernel/arch/aarch64/timers.zig`.
/// Switching from CNTV to CNTP fixed BSP ticking but secondaries still
/// never see the timer PPI on Pi KVM. Cross-core SGIs ARE reliably
/// delivered, so this routine rides the BSP's working CNTP tick out to
/// every other core via a dedicated SGI INTID (`SGI_BCAST_TICK`). The
/// dispatcher for that INTID (exceptions.zig) simply runs
/// `schedTimerHandler` on the receiving core, giving each secondary a
/// preemption tick at the BSP's cadence (~500 Hz / 2 ms timeslice).
///
/// Dedicated INTID is critical: prior attempts broadcast SGI 0 (the
/// scheduler IPI / yield / cross-core wake vector) on every BSP tick
/// and stormed the IPC reply path, regressing §3.3.7 / §2.2.34. A
/// distinct SGI with a tick-only handler keeps the IPC SGI path
/// untouched.
///
/// GICv3: write ICC_SGI1R_EL1 with IRM=1 ("interrupts routed to all
/// PEs in the system, excluding the PE that requested the
/// interrupt"). IHI 0069H §12.11.8.
///
/// GICv2: write GICD_SGIR with TargetListFilter=0b01 ("forward the
/// interrupt to all CPU interfaces except that of the processor that
/// requested the interrupt"). IHI 0048B §4.3.15.
pub fn broadcastSchedTick() void {
    const sgi_id: u64 = SGI_BCAST_TICK & 0xF;
    if (gicv3) {
        // IRM bit 40 = 1: all-except-self.
        const irm_bit: u64 = @as(u64, 1) << 40;
        const sgi_val: u64 = (sgi_id << 24) | irm_bit;
        writeIccSgi1r(sgi_val);
    } else {
        // TargetListFilter = 0b01 in bits [25:24]: all-except-self.
        const tlf: u32 = 0b01 << 24;
        const sgir_val: u32 = @as(u32, @intCast(sgi_id)) | tlf;
        gicdWrite(.sgir, sgir_val);
    }
}

/// Rate-limited `broadcastSchedTick`. Only fires if at least
/// `BCAST_INTERVAL_NS` (≈2 ms, matching `SCHED_TIMESLICE_NS`) has
/// elapsed since the last broadcast. Uses CNTPCT_EL0 directly (ARM
/// ARM D13.11.15) rather than the monotonic clock abstraction so it
/// is safe to call from early-boot / IRQ contexts before the arch
/// timer vtable is live, and to keep the check branchless and
/// lock-free.
///
/// The rate limiter is a single global `next_bcast_tick` advanced via
/// compare-exchange: callers read CNTPCT, attempt to CAS
/// `next_bcast_tick` from its current value to `cntpct + interval`,
/// and only issue the SGI if the CAS wins. Concurrent callers on
/// different cores therefore produce at most one broadcast per
/// interval. Relaxed memory ordering is fine because the SGI itself
/// carries no payload and the receiving core re-reads per-core state
/// under its own locks in `schedTimerHandler`.
pub fn maybeBroadcastSchedTick() void {
    // Gate the broadcast to GICv2 only. The workaround targets Pi 5
    // KVM vGICv2's per-core PPI injection drop, which is specific to
    // that stack — TCG GICv3 and bare-metal GICv3 deliver CNTP PPI 30
    // reliably to every core, so the extra SGI just perturbs timing
    // without fixing anything (observed as an s2_2_34 regression on
    // TCG GICv3: the 2 ms-rate SGI 7 raised helper iteration counts
    // above the 10k ceiling even though preempt-on-wake still worked
    // correctly via SGI 0). Restricting to GICv2 keeps the intent of
    // the workaround surgical.
    if (gicv3) return;
    var cntfrq: u64 = undefined;
    asm volatile ("mrs %[v], cntfrq_el0"
        : [v] "=r" (cntfrq),
    );
    if (cntfrq == 0) return;
    var cntpct: u64 = undefined;
    asm volatile ("mrs %[v], cntpct_el0"
        : [v] "=r" (cntpct),
    );
    const interval_ticks: u64 = (BCAST_INTERVAL_NS * cntfrq) / 1_000_000_000;
    while (true) {
        const current = @atomicLoad(u64, &next_bcast_tick, .monotonic);
        if (cntpct < current) return;
        const new_val = cntpct +| interval_ticks;
        if (@cmpxchgWeak(u64, &next_bcast_tick, current, new_val, .monotonic, .monotonic) == null) {
            broadcastSchedTick();
            return;
        }
    }
}

/// Unmask (enable) an interrupt.
///
/// For SPIs (INTID >= 32), writes the corresponding GICD_ISENABLER register.
/// For SGIs/PPIs (INTID 0-31):
///   GICv3 — writes GICR_ISENABLER0 on the current core.
///   GICv2 — writes GICD_ISENABLER0 (banked per-CPU).
///
/// IHI 0069H, Section 8.9.7: GICD_ISENABLER<n>.
/// IHI 0069H, Section 9.5.6: GICR_ISENABLER0.
/// IHI 0048B, Section 4.3.5: GICD_ISENABLER0 (banked per-CPU for INTID 0-31).
pub fn unmaskIrq(intid: u32) void {
    const bit: u32 = @as(u32, 1) << @intCast(intid & 0x1F);
    const reg_offset: u32 = (intid / 32) * 4;

    if (intid < 32) {
        if (gicv3) {
            // SGI/PPI — use redistributor for current core.
            const core_idx: usize = @intCast(coreID());
            const ptr: *volatile u32 = @ptrFromInt(
                gicr_bases[core_idx] + 0x10000 + @intFromEnum(GicrSgiReg.isenabler0),
            );
            ptr.* = bit;
        } else {
            // GICv2: GICD_ISENABLER0 is banked per-CPU for INTID 0-31.
            gicdWriteOffset(.isenabler0, 0, bit);
        }
        return;
    }

    // SPI — use distributor (same for v2 and v3).
    gicdWriteOffset(.isenabler0, reg_offset, bit);
}

/// Mask (disable) an interrupt.
///
/// For SPIs (INTID >= 32), writes the corresponding GICD_ICENABLER register.
/// For SGIs/PPIs (INTID 0-31):
///   GICv3 — writes GICR_ICENABLER0 on the current core.
///   GICv2 — writes GICD_ICENABLER0 (banked per-CPU).
///
/// Writes are bit-significant: a 1 bit clears the matching enable bit, a 0
/// bit is ignored, so unrelated INTIDs in the same 32-bit word are unaffected.
///
/// IHI 0069H, Section 8.9.8: GICD_ICENABLER<n>.
/// IHI 0069H, Section 9.5.7: GICR_ICENABLER0.
/// IHI 0048B, Section 4.3.6: GICD_ICENABLER0 (banked per-CPU for INTID 0-31).
pub fn maskIrq(intid: u32) void {
    const bit: u32 = @as(u32, 1) << @intCast(intid & 0x1F);
    const reg_offset: u32 = (intid / 32) * 4;

    if (intid < 32) {
        if (gicv3) {
            // SGI/PPI — use redistributor for current core.
            const core_idx: usize = @intCast(coreID());
            const ptr: *volatile u32 = @ptrFromInt(
                gicr_bases[core_idx] + 0x10000 + @intFromEnum(GicrSgiReg.icenabler0),
            );
            ptr.* = bit;
        } else {
            // GICv2: GICD_ICENABLER0 is banked per-CPU for INTID 0-31.
            gicdWriteOffset(.icenabler0, 0, bit);
        }
        return;
    }

    // SPI — use distributor (same for v2 and v3).
    gicdWriteOffset(.icenabler0, reg_offset, bit);
}

