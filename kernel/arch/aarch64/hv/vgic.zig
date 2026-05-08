//! Minimal GICv3 virtual CPU interface backing for the linux_guest VMM.
//!
//! Holds the per-vCPU shadow of `ICH_*_EL2` and `CNTV_*_EL0` register
//! state that the hyp stubs (`hvc_vgic_prepare_entry`, `hvc_vgic_save_exit`,
//! `hvc_vtimer_load_guest`, `hvc_vtimer_save_guest`) load and snapshot
//! around each guest run. The full GICD/GICR MMIO emulator lives elsewhere
//! (currently the linux_guest VMM main.zig stubs the distributor); this
//! file is the kernel-side state container only.
//!
//! Per spec §[virtual_machine].vm_inject_irq the VM's emulated interrupt
//! controller maintains pending state per virtual IRQ line. On aarch64
//! that is the GIC distributor's set/clear-pending register pair
//! (GICv3 §12.9.11 / §12.9.28). This module also owns the in-kernel
//! distributor model — `Vgic` — a packed pending bitmap indexed by
//! INTID. Routing of pending state into the guest's CPU interface (via
//! list-register programming on stage-2 entry) is wired up by the vCPU
//! run loop; this struct supplies only the distributor side.
//!
//! References:
//! - Arm IHI 0069H (GICv3/v4 architecture spec) §2.2.1, §4.5 Shared
//!   Peripheral Interrupts, §12.8 Distributor register map, §12.9.11
//!   GICD_ICPENDR<n>, §12.9.28 GICD_ISPENDR<n>.

const std = @import("std");

pub const MAX_LRS: u8 = 16;

/// Maximum SPI count we expose. INTIDs 32..(32+MAX_SPIS-1).
/// 256 is the smallest cap that comfortably covers a Linux-ish guest's
/// SPI footprint while keeping the pending bitmap a single cache line.
pub const MAX_SPIS: u16 = 256;

/// Total distributor INTID count = 32 (SGI/PPI) + MAX_SPIS.
/// Per Arm IHI 0069H §2.2.1: INTIDs 0..15 are SGIs (banked per PE),
/// INTIDs 16..31 are PPIs (banked per PE), and INTIDs 32..1019 are
/// SPIs. We emulate the full SGI/PPI range alongside MAX_SPIS shared
/// peripheral interrupts. SGI/PPI live in the redistributor but are
/// addressable through the distributor's pending registers as well.
pub const TOTAL_DIST_INTIDS: u16 = 32 + MAX_SPIS;

/// Number of u32 words in the pending bitmap. Each GICD_ISPENDR<n>
/// register is 32 bits and covers INTIDs `32n..32n+31` per Arm IHI
/// 0069H §12.9.28.
pub const NUM_PENDING_WORDS: u16 = (TOTAL_DIST_INTIDS + 31) / 32;

/// EL2 sysreg shadow handed to the `hvc_vgic_prepare_entry` /
/// `hvc_vgic_save_exit` hyp stubs. `extern struct` with hardcoded
/// field offsets because the stub uses `ldr/str [x1, #IMM]`.
///
/// The stubs always load/store all 16 LR slots — slots beyond
/// `num_lrs` are left zero (LR.State = 0b00 Invalid, GICv3 §11.2.5,
/// which is "no pending/active entry") so they are architecturally
/// harmless on hosts with fewer LRs.
pub const VcpuHwShadow = extern struct {
    /// ICH_LR0..15_EL2 (ARM ARM D13.8.51, Table D13-65).
    lrs: [MAX_LRS]u64 align(16) = .{0} ** MAX_LRS,
    /// ICH_HCR_EL2 — caller forces `EN=1` before the hvc.
    hcr: u64 = 0,
    /// ICH_VMCR_EL2 (GICv3 §12.5.27).
    vmcr: u64 = 0,
    /// ICH_AP0R0_EL2 (GICv3 §12.5.2 / ARM ARM D13.8.42).
    ap0r0: u64 = 0,
    /// ICH_AP1R0_EL2 (GICv3 §12.5.5 / ARM ARM D13.8.46).
    ap1r0: u64 = 0,
    /// ICH_MISR_EL2 snapshot from `hvc_vgic_save_exit` (D13.8.47).
    misr: u64 = 0,
    /// Number of implemented list registers (1..16). Read by both stubs.
    num_lrs: u64 = 0,
};

/// Per-vCPU virtual-timer shadow. Same calling convention as
/// `VcpuHwShadow` — extern struct with field offsets pinned to the hyp
/// stub asm.
pub const VtimerState = extern struct {
    /// CNTVOFF_EL2 — set on first entry to current CNTPCT_EL0 so guest
    /// CNTVCT_EL0 reads zero at boot. ARM ARM D13.11.20.
    cntvoff_el2: u64 = 0,
    /// CNTV_CTL_EL0 — ENABLE/IMASK/ISTATUS bits. ARM ARM D13.11.17.
    cntv_ctl_el0: u64 = 0,
    /// CNTV_CVAL_EL0 — virtual timer compare value. ARM ARM D13.11.18.
    cntv_cval_el0: u64 = 0,
    /// CNTKCTL_EL1 — EL0 access control. ARM ARM D13.11.26.
    cntkctl_el1: u64 = 0,
    /// 0 → first entry; the load stub will seed CNTVOFF from CNTPCT
    /// then set this to 1.
    primed: u64 = 0,
};

comptime {
    std.debug.assert(@offsetOf(VcpuHwShadow, "lrs") == 0x00);
    std.debug.assert(@offsetOf(VcpuHwShadow, "hcr") == 0x80);
    std.debug.assert(@offsetOf(VcpuHwShadow, "vmcr") == 0x88);
    std.debug.assert(@offsetOf(VcpuHwShadow, "ap0r0") == 0x90);
    std.debug.assert(@offsetOf(VcpuHwShadow, "ap1r0") == 0x98);
    std.debug.assert(@offsetOf(VcpuHwShadow, "misr") == 0xA0);
    std.debug.assert(@offsetOf(VcpuHwShadow, "num_lrs") == 0xA8);
    std.debug.assert(@offsetOf(VtimerState, "cntvoff_el2") == 0x00);
    std.debug.assert(@offsetOf(VtimerState, "cntv_ctl_el0") == 0x08);
    std.debug.assert(@offsetOf(VtimerState, "cntv_cval_el0") == 0x10);
    std.debug.assert(@offsetOf(VtimerState, "cntkctl_el1") == 0x18);
    std.debug.assert(@offsetOf(VtimerState, "primed") == 0x20);
}

/// Encode a Group-1, pending, virtual-only LR for INTID `intid`.
/// ARM ARM D13.8.51 ICH_LR<n>_EL2:
///   bits[31:0]   vINTID
///   bits[60]     Group  (1 = Group 1)
///   bits[63:62]  State  (01 = Pending)
pub fn lrPendingGroup1(intid: u32) u64 {
    const STATE_PENDING: u64 = 1 << 62;
    const GROUP_1: u64 = 1 << 60;
    return STATE_PENDING | GROUP_1 | @as(u64, intid);
}

/// Read State[63:62] from an LR value.
pub inline fn lrState(lr: u64) u2 {
    return @truncate(lr >> 62);
}

/// In-kernel emulated GIC distributor state. Mirrors the small surface
/// of the GICv3 distributor that `vm_inject_irq` exercises today: the
/// per-INTID pending bit. The full distributor MMIO emulator
/// (GICD_CTLR, IROUTER, IPRIORITYR, ICFGR, etc.) and per-vCPU
/// redistributor / list-register programming are reserved for the
/// vCPU run loop bring-up; they read out of `pending` to decide which
/// virtual interrupts to inject on guest entry (Arm IHI 0069H §11.2
/// ICH_LR<n>_EL2).
///
/// The distributor is single-writer from the kernel's perspective —
/// `vm_inject_irq` is gated by the syscall-level domain lock on the
/// VM's owning capability domain. Concurrent vCPU run loops on other
/// cores will eventually need a finer-grained guard; until then the
/// per-VM domain lock suffices.
pub const Vgic = extern struct {
    /// One bit per INTID. Bit `(intid % 32)` of `pending[intid / 32]`
    /// mirrors the corresponding bit of GICD_ISPENDR<intid/32> per
    /// Arm IHI 0069H §12.9.28: writing 1 sets the interrupt pending,
    /// writing 1 to GICD_ICPENDR<n> (§12.9.11) clears it.
    pending: [NUM_PENDING_WORDS]u32 = .{0} ** NUM_PENDING_WORDS,

    /// Zero-initialise the distributor. Called from `allocVmArchState`
    /// after the backing cell is allocated. The PMM `create` contract
    /// already zeros the page, so this is belt-and-suspenders that
    /// matches the GICv3 reset state for GICD_ISPENDR<n>/GICD_ICPENDR<n>
    /// (Arm IHI 0069H §12.8 reset column = 0x0000_0000).
    pub fn init(self: *Vgic) void {
        @memset(&self.pending, 0);
    }

    /// Set the pending bit for `intid`. Mirrors a write of 1 to the
    /// matching bit in GICD_ISPENDR<intid/32> per Arm IHI 0069H
    /// §12.9.28. Caller has already validated `intid < TOTAL_DIST_INTIDS`.
    ///
    /// Atomic-or rather than plain RMW so a `vm_inject_irq` from any
    /// core can race a vCPU run-loop scan on another core without
    /// losing concurrent updates.
    pub fn assertIrq(self: *Vgic, intid: u16) void {
        std.debug.assert(intid < TOTAL_DIST_INTIDS);
        const word: u16 = intid / 32;
        const bit: u5 = @truncate(intid % 32);
        _ = @atomicRmw(u32, &self.pending[word], .Or, @as(u32, 1) << bit, .release);
    }

    /// Clear the pending bit for `intid`. Mirrors a write of 1 to the
    /// matching bit in GICD_ICPENDR<intid/32> per Arm IHI 0069H
    /// §12.9.11. Caller has already validated `intid < TOTAL_DIST_INTIDS`.
    pub fn deassertIrq(self: *Vgic, intid: u16) void {
        std.debug.assert(intid < TOTAL_DIST_INTIDS);
        const word: u16 = intid / 32;
        const bit: u5 = @truncate(intid % 32);
        _ = @atomicRmw(u32, &self.pending[word], .And, ~(@as(u32, 1) << bit), .release);
    }

    /// Read the current pending state of `intid`. Used by the vCPU
    /// run loop to populate list-registers on stage-2 entry.
    pub fn isPending(self: *const Vgic, intid: u16) bool {
        if (intid >= TOTAL_DIST_INTIDS) return false;
        const word: u16 = intid / 32;
        const bit: u5 = @truncate(intid % 32);
        const w = @atomicLoad(u32, &self.pending[word], .acquire);
        return (w & (@as(u32, 1) << bit)) != 0;
    }

    /// Atomically clear the pending bit for `intid` and return whether
    /// it was set before the clear. Used by the vCPU run loop to claim
    /// a pending interrupt for delivery without losing wakeups from a
    /// concurrent `assertIrq` on another core.
    pub fn takePending(self: *Vgic, intid: u16) bool {
        if (intid >= TOTAL_DIST_INTIDS) return false;
        const word: u16 = intid / 32;
        const bit: u5 = @truncate(intid % 32);
        const mask: u32 = @as(u32, 1) << bit;
        const prev = @atomicRmw(u32, &self.pending[word], .And, ~mask, .acquire);
        return (prev & mask) != 0;
    }
};
