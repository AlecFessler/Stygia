//! AArch64 bootstrap initialization.
//!
//! Called from dispatch.init() on the BSP (boot processor) before any other
//! arch code runs. Equivalent of x64/init.zig.
//!
//! Initialization sequence:
//! 1. Install exception vector table (MSR VBAR_EL1).
//! 2. Initialize serial output (PL011 UART).
//! 3. Configure and enable the GIC (interrupts remain masked until the
//!    scheduler enables them).
//!
//! References:
//! - ARM ARM D1.10: Exception vectors
//! - ARM ARM D13.2.118: SCTLR_EL1
//! - ARM ARM D13.2.131: TCR_EL1
//! - ARM ARM D13.2.97: MAIR_EL1

const zag = @import("zag");

const exceptions = zag.arch.aarch64.exceptions;
const paging = zag.arch.aarch64.paging;
const serial = zag.arch.aarch64.serial;

/// BSP early-boot initialization. Called once from dispatch.init() before
/// the scheduler runs.
pub fn init() void {
    // Resolve MAIR attribute indices against whatever layout the
    // firmware/bootloader left in MAIR_EL1. We cannot safely rewrite
    // MAIR_EL1 under a live MMU (Linux arm64 head.S / proc.S only
    // writes MAIR with the MMU disabled), so we adopt the firmware
    // indices and use them for page-table attr_indx fields.
    paging.initMairIndices();
    exceptions.install();
    serial.init();
    // Force TCR_EL1.T0SZ=16 (48-bit user VA, 4-level walk) NOW, after
    // exitBootServices. UEFI on QEMU virt happens to pick T0SZ=16
    // already, but EDK2/AAVMF on real ARM hardware (Cortex-A76 Pi 5)
    // computes T0SZ from the implementation's PA range and routinely
    // picks T0SZ=25 (39-bit VA, 3-level walk). Our `Process.create`
    // builds a fresh 4-level page table rooted at `addr_space_root`;
    // when the scheduler later writes that root to TTBR0 under a 3-level
    // T0SZ, the hardware walker stops at level 0 with a translation
    // fault on the very first user instruction fetch — the symptom
    // hit on Pi KVM (IFSC=0x04, repeating EC=0x20 from the entry PC).
    //
    // It is safe to change T0SZ here because (a) firmware boot services
    // have already exited, so UEFI no longer needs its identity-mapped
    // TTBR0 walks, and (b) the kernel itself never accesses low VAs
    // until the first user process is scheduled, at which point a fresh
    // 4-level table is written to TTBR0.
    paging.forceT0Sz16();
    // Lazy FPU: the kernel itself is built without FP/SIMD (see
    // -Dcpu_features_sub in build.zig drops neon + fp_armv8) so it
    // never emits Q-register loads, and there's no need to leave
    // CPACR_EL1.FPEN globally open. Set it to 0b01 (trap EL0 only,
    // EL1 unrestricted) — switchTo flips between 0b01 and 0b11 from
    // here on as it tracks per-core FPU ownership. ARM ARM D13.2.30.
    armFpTrapEl0();
    // Enable SP alignment checking at EL0 (SCTLR_EL1.SA0, bit 4). Without
    // this, EL0 SP-relative loads with a misaligned SP silently succeed
    // and the §6.8 alignment_fault behaviour cannot be exercised.
    // ARM ARM D13.2.118.
    enableSpAlignmentChecks();
    // NOTE: GIC init is deferred to acpi.parseAcpi() — the distributor
    // and redistributor base addresses come from MADT, which has not
    // been parsed yet at this point.
}

/// Set CPACR_EL1.FPEN bits [21:20] = 0b01 — trap any FP/SIMD access
/// from EL0, allow at EL1 (the kernel is built without FP/SIMD so EL1
/// access never actually fires). Required on every core because PSCI
/// CPU_ON brings the core up with FPEN at its implementation-defined
/// reset value. switchTo manages FPEN from here on.
/// ARM ARM D13.2.30.
fn armFpTrapEl0() void {
    var cpacr: u64 = undefined;
    asm volatile ("mrs %[v], cpacr_el1"
        : [v] "=r" (cpacr),
    );
    cpacr &= ~(@as(u64, 0b11) << 20);
    cpacr |= (@as(u64, 0b01) << 20);
    asm volatile ("msr cpacr_el1, %[v]"
        :
        : [v] "r" (cpacr),
    );
    asm volatile ("isb");
}

/// Set SCTLR_EL1.SA0 (bit 4) and SCTLR_EL1.SA (bit 3) so a misaligned SP
/// used by a memory access raises an SP-alignment exception at EL0/EL1.
/// ARM ARM D13.2.118 (SCTLR_EL1).
fn enableSpAlignmentChecks() void {
    var sctlr: u64 = undefined;
    asm volatile ("mrs %[v], sctlr_el1"
        : [v] "=r" (sctlr),
    );
    sctlr |= (1 << 3) | (1 << 4);
    asm volatile ("msr sctlr_el1, %[v]"
        :
        : [v] "r" (sctlr),
    );
    asm volatile ("isb");
}

