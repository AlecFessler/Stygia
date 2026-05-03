//! Minimal GICv3 virtual CPU interface backing for the linux_guest VMM.
//!
//! Holds the per-vCPU shadow of `ICH_*_EL2` and `CNTV_*_EL0` register
//! state that the hyp stubs (`hvc_vgic_prepare_entry`, `hvc_vgic_save_exit`,
//! `hvc_vtimer_load_guest`, `hvc_vtimer_save_guest`) load and snapshot
//! around each guest run. The full GICD/GICR MMIO emulator lives elsewhere
//! (currently the linux_guest VMM main.zig stubs the distributor); this
//! file is the kernel-side state container only.

pub const MAX_LRS: u8 = 16;

/// Maximum SPI count we expose. INTIDs 32..(32+MAX_SPIS-1).
pub const MAX_SPIS: u16 = 256;

/// Total distributor INTID count = 32 (SGI/PPI) + MAX_SPIS.
/// Note: SGI/PPI state is per-vCPU (lives in the redistributor); SPIs
/// start at INTID 32. GICv3 §2.2.1.
pub const TOTAL_DIST_INTIDS: u16 = 32 + MAX_SPIS;

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
    const std = @import("std");
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
