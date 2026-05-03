//! AArch64 EL2 world-switch machinery.
//!
//! This is the middle layer of the three-file split described in `vm.zig`:
//! it owns the EL2 vector table, the HVC dispatcher and its handler stubs,
//! and the host-side `vmResume` wrapper that brackets a guest run with
//! FPSIMD save/restore before issuing `hvc #1` into `hvc_vcpu_run`.
//!
//! Layering:
//!   * depends on `vm.zig` for layer-neutral types and the HVC ABI wrapper
//!     (`hypCall`, `HypCallId`) used by the `vmResume` path.
//!   * depends on `stage2.zig` for `controlBlock` / `VmControlBlock`
//!     (the per-VM HCR override bits and VMID read during entry).
//!   * nothing else in the kernel depends on hyp.zig directly aside from
//!     `dispatch/vm.zig`, which calls `installHypVectors` from the BSP
//!     boot handoff path.
//!
//! Architectural references:
//!   - ARM ARM (DDI 0487) D1.11 Exception entry/return
//!   - ARM ARM D1.10.2    VBAR_ELx vector table layout
//!   - ARM ARM D13.2.46   HCR_EL2
//!   - ARM ARM D13.2.150  VTCR_EL2
//!   - ARM ARM D13.2.151  VTTBR_EL2
//!   - ARM ARM D7.7       TLB maintenance instructions (TLBI IPAS2E1IS, …)
//!   - 102142 §2.3        "Entry to and exit from a guest"

const std = @import("std");
const zag = @import("zag");

const aarch64_paging = zag.arch.aarch64.paging;
const gic = zag.arch.aarch64.gic;
const memory_init = zag.memory.init;
const stage2 = zag.arch.aarch64.stage2;
const vm = zag.arch.aarch64.vm;

const FxsaveArea = vm.FxsaveArea;
const GuestState = vm.GuestState;
const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;
const VmExitInfo = vm.VmExitInfo;

// ===========================================================================
// Vector-table install (BSP boot handoff)
// ===========================================================================

/// HVC immediate the kernel uses to ask the bootloader-installed EL2 stub
/// to load VBAR_EL2 from X0 and ERET. The value is arbitrary but must not
/// collide with PSCI/SMCCC-defined immediates (those use HVC #0 with a
/// function-id register convention; this path encodes the selector in the
/// instruction's imm16 so the stub can demux without touching guest-facing
/// argument registers). ARM ARM C5.6.103 (HVC) places the immediate at
/// ESR_EL2.ISS[15:0] on a sync-lower-EL trap.
///
/// `bootloader/aarch64_el2_drop.zig` hardcodes the same value (0xE112)
/// into its naked-asm stub as the `movz x10, #0xE112` literal; both sides
/// must agree.
const HVC_IMM_INSTALL_VBAR_EL2: u16 = 0xE112;

/// Install the kernel's EL2 vector table at VBAR_EL2 via an HVC to the
/// bootloader's minimal EL2 stub.
///
/// The bootloader leaves a tiny stub table at VBAR_EL2 whose sync-lower
/// A64 handler (bootloader/aarch64_el2_drop.zig) decodes the HVC imm16
/// and, on HVC_IMM_INSTALL_VBAR_EL2, writes X0 into VBAR_EL2. That lets
/// us hand EL2 a full vector table that branches into
/// `hyp_sync_lower_a64` without needing EL2 register access from EL1.
///
/// VBAR_EL2 holds a PHYSICAL address; the naked `__hyp_vectors` symbol
/// is linked at a kernel high-half VA, so we walk the kernel page tables
/// to resolve its PA first. The table is 2 KiB aligned (ARM ARM D1.10.2
/// — VBAR_ELx bits [10:0] are RES0).
pub fn installHypVectors() void {
    // Requires both a CPU that implements EL2 and a live EL2 stub sitting
    // at VBAR_EL2 willing to honour our install HVC. The bootloader
    // (bootloader/aarch64_el2_drop.zig) writes VBAR_EL2 to a
    // runtime-allocated stub in RuntimeServicesCode memory before
    // ERETing to EL1; that stub recognises the HVC immediate
    // `HVC_IMM_INSTALL_VBAR_EL2` and rewrites VBAR_EL2 with x0. On the
    // UEFI path that stub is always live; on a non-UEFI / EL1-entry
    // path `hyp_stub_installed` remains false and we short-circuit.
    //
    // `vm.vmSupported()` returns `vm_supported AND hyp_stub_installed`,
    // which is exactly the conjunction we need: if EL2 is absent OR the
    // hyp stub was never installed, skip.
    if (!vm.vmSupported()) return;
    // VBAR_EL2 is per-core and the bootloader's EL2 stub was only
    // installed on the BSP before it ERETed to EL1. On secondaries
    // (brought up via PSCI CPU_ON), VBAR_EL2 holds whatever firmware
    // left there, so issuing the install HVC from an AP would trap into
    // an unknown/unmapped handler and hang the core. Until a dedicated
    // per-core EL2 bringup path lands, only the BSP runs the install
    // HVC; VM runs are pinned to the BSP. ARM ARM D13.2.143 —
    // VBAR_EL2 is per-PE state.
    // TODO(smp): install vectors on every core once AP EL2 bringup lands.
    if (gic.coreID() != 0) return;
    if (@atomicLoad(bool, &vm.hyp_vectors_installed, .acquire)) return;

    const vec_va: u64 = @intFromPtr(&__hyp_vectors);
    const page_paddr = aarch64_paging.resolveVaddr(
        memory_init.kernel_addr_space_root,
        VAddr.fromInt(vec_va),
    ) orelse return;
    const vec_pa = page_paddr.addr | (vec_va & 0xFFF);
    std.debug.assert(vec_pa & 0x7FF == 0);

    const hvc_insn = comptime std.fmt.comptimePrint(
        "hvc #{d}",
        .{HVC_IMM_INSTALL_VBAR_EL2},
    );
    asm volatile (hvc_insn
        :
        : [vbar] "{x0}" (vec_pa),
        : .{ .memory = true, .x9 = true, .x10 = true });

    @atomicStore(bool, &vm.hyp_vectors_installed, true, .release);
}

// ===========================================================================
// Kernel VA → PA resolver
// ===========================================================================

/// Walk the kernel page tables to resolve a kernel VA to its PA. Used by
/// the vm world-switch code and by hyp-call wrappers because EL2 runs
/// with SCTLR_EL2.M=0 and any pointer handed to a hyp stub is
/// dereferenced as a raw PA. `PAddr.fromVAddr(VAddr, null)` only works
/// for physmap addresses; slab-allocated kernel objects (VCpu, arch
/// scratch buffers, guest-state mirrors) live in the kernel heap
/// partition and need a proper walk. ARM ARM D5.2 table walk.
pub fn resolveKernelVaToPa(vaddr: u64) u64 {
    const base = vaddr & ~@as(u64, 0xFFF);
    const offset = vaddr & 0xFFF;
    const page_pa = aarch64_paging.resolveVaddr(
        memory_init.kernel_addr_space_root,
        VAddr.fromInt(base),
    ) orelse @panic("resolveKernelVaToPa: unmapped kernel VA");
    return page_pa.addr | offset;
}

// ===========================================================================
// World-switch context structs
// ===========================================================================

/// World-switch context passed by PA to the EL2 hyp dispatcher. Field
/// offsets are HARDCODED in the HVC stubs below (hvc_vcpu_run /
/// guest_exit_entry) — keep them in sync with the comment tables in
/// those functions. Enforced at comptime below.
pub const WorldSwitchCtx = extern struct {
    /// Physical address of the GuestState the dispatcher should swap
    /// in on entry and back out on exit.
    guest_state_pa: u64 = 0,
    /// Physical address of the HostSave struct (host callee-saved
    /// GPRs + host EL1 sysreg snapshot).
    host_save_pa: u64 = 0,
    /// Physical address of the stage-2 root (for reference; the
    /// dispatcher loads `vttbr_el2` directly).
    stage2_root_pa: u64 = 0,
    /// VTTBR_EL2 value: VMID << 48 | stage2_root_pa.
    vttbr_el2: u64 = 0,
    /// VTCR_EL2 value: stage-2 translation control.
    vtcr_el2: u64 = 0,
    /// HCR_EL2 value to load on guest entry.
    hcr_el2: u64 = 0,
    /// Populated on guest exit: ESR_EL2, FAR_EL2, HPFAR_EL2.
    exit_esr: u64 = 0,
    exit_far: u64 = 0,
    exit_hpfar: u64 = 0,
    /// Stashed host ELR_EL2 / SPSR_EL2 (= host return address and
    /// PSTATE from the `hvc #0` that entered this path). The exit
    /// path restores these before its final ERET so control lands
    /// on the instruction after the host's hvc.
    host_elr_el2: u64 = 0,
    host_spsr_el2: u64 = 0,
    _pad: u64 = 0,
};

comptime {
    std.debug.assert(@offsetOf(WorldSwitchCtx, "guest_state_pa") == 0x00);
    std.debug.assert(@offsetOf(WorldSwitchCtx, "host_save_pa") == 0x08);
    std.debug.assert(@offsetOf(WorldSwitchCtx, "stage2_root_pa") == 0x10);
    std.debug.assert(@offsetOf(WorldSwitchCtx, "vttbr_el2") == 0x18);
    std.debug.assert(@offsetOf(WorldSwitchCtx, "vtcr_el2") == 0x20);
    std.debug.assert(@offsetOf(WorldSwitchCtx, "hcr_el2") == 0x28);
    std.debug.assert(@offsetOf(WorldSwitchCtx, "exit_esr") == 0x30);
    std.debug.assert(@offsetOf(WorldSwitchCtx, "exit_far") == 0x38);
    std.debug.assert(@offsetOf(WorldSwitchCtx, "exit_hpfar") == 0x40);
    std.debug.assert(@offsetOf(WorldSwitchCtx, "host_elr_el2") == 0x48);
    std.debug.assert(@offsetOf(WorldSwitchCtx, "host_spsr_el2") == 0x50);

    // GuestState offsets hardcoded in the HVC stubs below.
    std.debug.assert(@offsetOf(GuestState, "x0") == 0x00);
    std.debug.assert(@offsetOf(GuestState, "x30") == 0xF0);
    std.debug.assert(@offsetOf(GuestState, "sp_el0") == 0xF8);
    std.debug.assert(@offsetOf(GuestState, "sp_el1") == 0x100);
    std.debug.assert(@offsetOf(GuestState, "pc") == 0x108);
    std.debug.assert(@offsetOf(GuestState, "pstate") == 0x110);
    std.debug.assert(@offsetOf(GuestState, "sctlr_el1") == 0x118);
    std.debug.assert(@offsetOf(GuestState, "ttbr0_el1") == 0x120);
    std.debug.assert(@offsetOf(GuestState, "ttbr1_el1") == 0x128);
    std.debug.assert(@offsetOf(GuestState, "tcr_el1") == 0x130);
    std.debug.assert(@offsetOf(GuestState, "mair_el1") == 0x138);
    std.debug.assert(@offsetOf(GuestState, "amair_el1") == 0x140);
    std.debug.assert(@offsetOf(GuestState, "cpacr_el1") == 0x148);
    std.debug.assert(@offsetOf(GuestState, "contextidr_el1") == 0x150);
    std.debug.assert(@offsetOf(GuestState, "tpidr_el0") == 0x158);
    std.debug.assert(@offsetOf(GuestState, "tpidr_el1") == 0x160);
    std.debug.assert(@offsetOf(GuestState, "tpidrro_el0") == 0x168);
    std.debug.assert(@offsetOf(GuestState, "vbar_el1") == 0x170);
    std.debug.assert(@offsetOf(GuestState, "elr_el1") == 0x178);
    std.debug.assert(@offsetOf(GuestState, "spsr_el1") == 0x180);
    std.debug.assert(@offsetOf(GuestState, "esr_el1") == 0x188);
    std.debug.assert(@offsetOf(GuestState, "far_el1") == 0x190);
}

/// HostSave layout — matches offsets hardcoded in the HVC stubs below.
/// Holds the host's callee-saved GPRs and EL1 sysregs across a guest run.
pub const HostSave = extern struct {
    x19: u64 = 0,
    x20: u64 = 0,
    x21: u64 = 0,
    x22: u64 = 0,
    x23: u64 = 0,
    x24: u64 = 0,
    x25: u64 = 0,
    x26: u64 = 0,
    x27: u64 = 0,
    x28: u64 = 0,
    x29: u64 = 0,
    x30: u64 = 0,
    sp_el1: u64 = 0,
    sp_el0: u64 = 0,
    tpidr_el1: u64 = 0,
    sctlr_el1: u64 = 0,
    tcr_el1: u64 = 0,
    ttbr0_el1: u64 = 0,
    ttbr1_el1: u64 = 0,
    mair_el1: u64 = 0,
    vbar_el1: u64 = 0,
    cpacr_el1: u64 = 0,
    contextidr_el1: u64 = 0,
    tpidr_el0: u64 = 0,
    tpidrro_el0: u64 = 0,
    cntkctl_el1: u64 = 0,
    elr_el1: u64 = 0,
    spsr_el1: u64 = 0,
    esr_el1: u64 = 0,
    far_el1: u64 = 0,
};

comptime {
    std.debug.assert(@offsetOf(HostSave, "x19") == 0x00);
    std.debug.assert(@offsetOf(HostSave, "x30") == 0x58);
    std.debug.assert(@offsetOf(HostSave, "sp_el1") == 0x60);
    std.debug.assert(@offsetOf(HostSave, "sp_el0") == 0x68);
    std.debug.assert(@offsetOf(HostSave, "tpidr_el1") == 0x70);
    std.debug.assert(@offsetOf(HostSave, "sctlr_el1") == 0x78);
    std.debug.assert(@offsetOf(HostSave, "tcr_el1") == 0x80);
    std.debug.assert(@offsetOf(HostSave, "far_el1") == 0xE8);
}

/// Host FPSIMD save slot used by the eager save/restore path in `vmResume`.
///
/// Layout matches `FxsaveArea` so the same save/load asm sequences work for
/// both host and guest state:
///
///   [0x000 .. 0x200)  V0..V31  — 32 × 128-bit SIMD regs, byte offset = idx*16
///   [0x200 .. 0x208)  FPCR     — FP control (D13.2.48)
///   [0x208 .. 0x210)  FPSR     — FP status  (D13.2.52)
///
/// ARM ARM B1.2.2 defines the V-register file; the kernel's host threads
/// can use FPSIMD (CPACR_EL1.FPEN was set at boot — see init.zig and
/// smp.zig) so the live host FP register file on entry to `vmResume` is
/// meaningful and must be preserved across the guest run.
pub const HostFpState = extern struct {
    v: [32][16]u8 align(16) = @splat(@splat(0)),
    fpcr: u64 = 0,
    fpsr: u64 = 0,
};

/// Per-vCPU scratch the EL2 hyp stub reads/writes through PAs. Owned by
/// the VCpu object (see `kernel/arch/aarch64/kvm/vcpu.zig`) so concurrent
/// vCPUs don't share storage. All fields must live in physmap-backed
/// memory so `PAddr.fromVAddr(..., null)` is a valid VA→PA translation.
///
/// `host_fp` is a scratch slot used by the eager FPSIMD save/restore
/// wrapper around `hypCall(.vcpu_run, ...)` — it only needs to live as long
/// as a single vmResume call, but storing it per-vCPU keeps `vmResume`
/// reentrancy-safe without per-cpu TLS plumbing.
pub const ArchScratch = extern struct {
    ctx: WorldSwitchCtx = .{},
    host_save: HostSave = .{},
    host_fp: HostFpState align(16) = .{},
};

// ===========================================================================
// VTCR_EL2 helper
// ===========================================================================

/// VTCR_EL2 value for our stage-2 config (ARM ARM D13.2.150).
///
/// Field map:
///   T0SZ[5:0]   : input address size = 64 - T0SZ. We use STAGE2_T0SZ=34
///                 → 30-bit (1 GiB) IPA. The stage-2 walker in `stage2.zig`
///                 is hardcoded to a 2-level walk (level 2 root → level 3
///                 leaf) that matches exactly this (T0SZ,SL0) pair; see
///                 the block comment above `stage2L2Idx` in stage2.zig.
///                 A future wave will widen this to a 4-level walker and
///                 derive T0SZ from ID_AA64MMFR0_EL1.PARange at init time.
///   SL0[7:6]    : starting level. With 4K granule + T0SZ in [25..33] a
///                 value of 0 starts the walk at level 2 (1 GiB region,
///                 level-2 root, level-3 leaves). ARM ARM D8-2540 Table.
///   IRGN0[9:8]  : inner cacheability of stage-2 table walks = 0b01
///                 (Normal memory, Inner Write-Back Write-Allocate
///                 Cacheable).
///   ORGN0[11:10]: outer cacheability, same encoding.
///   SH0[13:12]  : shareability = 0b11 (Inner Shareable). Mandatory for
///                 SMP-coherent stage-2 walks.
///   TG0[15:14]  : granule size = 0b00 (4 KiB) — matches the descriptor
///                 layout used by `mapGuestPage` in stage2.zig.
///   PS[18:16]   : physical address size for the stage-2 output.
///                 0b010 = 40 bits, the baseline assumed by the port.
///   HA/HD       : left 0. Hardware access/dirty flag update is a later
///                 optimisation that also needs stage-2 descriptor format
///                 changes to land first.
pub fn vtcrEl2Value() u64 {
    const t0sz: u64 = stage2.STAGE2_T0SZ; // 34 → 1 GiB IPA (matches 2-level walker)
    const sl0: u64 = 0; // start at level 2 (w/ 4K, T0SZ=34)
    const irgn0: u64 = 0b01; // Normal WB WA cacheable
    const orgn0: u64 = 0b01;
    const sh0: u64 = 0b11; // Inner shareable
    const tg0: u64 = 0b00; // 4 KiB granule
    const ps: u64 = 0b010; // 40-bit PA
    return t0sz |
        (sl0 << 6) |
        (irgn0 << 8) |
        (orgn0 << 10) |
        (sh0 << 12) |
        (tg0 << 14) |
        (ps << 16);
}

// ===========================================================================
// Guest entry / exit
// ===========================================================================

/// Enter the guest. Called from the vCPU thread entry point; returns the
/// decoded exit info when the guest exits.
///
/// High-level flow (mirrors x64 `vmx.vmResume`/`svm.vmResume`):
///   1. Disable interrupts.
///   2. Save host callee-saved GPRs and FPSIMD state.
///   3. Switch in per-VM EL2 state:
///        - HCR_EL2      (trap config, see vm_structures block)
///        - VTCR_EL2     (stage-2 format)
///        - VTTBR_EL2    (VMID | stage-2 root PA)
///        - CPTR_EL2     (FPSIMD / SVE trap config)
///        - MDCR_EL2     (debug / PMU trap share)
///        - CNTVOFF_EL2  (per-VM virtual timer offset)
///        - VBAR_EL2     (ensures exits land in our vector)
///   4. Load guest EL1 sysregs from GuestState (SCTLR_EL1, TTBR*_EL1, ...).
///   5. Prepare vGIC list registers (`vgic.prepareEntry`).
///   6. Load guest x0..x30, sp_el0, sp_el1.
///   7. MSR ELR_EL2, <pc>;  MSR SPSR_EL2, <pstate>;  ERET.
///   8. -- guest runs until an exception is taken to EL2 --
///   9. Entry lands in an asm stub which saves x0..x30 into GuestState,
///      reads ESR_EL2/FAR_EL2/HPFAR_EL2 into VmExitInfo, saves guest
///      EL1 sysregs back into GuestState, snapshots vGIC state via
///      `vgic.saveExit`, restores host GPRs/FPSIMD, and returns.
///
/// `vm_structures` is the physical base of the per-VM arch block allocated
/// by `stage2.vmAllocStructures()`. It holds the stage-2 root, HCR_EL2
/// value, VMID, and any cached register values that never change after
/// vm_create.
///
/// References:
///   - ARM ARM D1.11        Exception entry/return
///   - ARM ARM D13.2.46     HCR_EL2
///   - ARM ARM D13.2.151    VTTBR_EL2
///   - ARM ARM D13.2.150    VTCR_EL2
///   - 102142  §2.3         "Entry to and exit from a guest"
pub fn vmResume(
    guest_state: *GuestState,
    vm_structures: PAddr,
    guest_fxsave: *align(16) FxsaveArea,
    arch_scratch: *align(16) ArchScratch,
) VmExitInfo {
    const ctx = &arch_scratch.ctx;
    const host_save = &arch_scratch.host_save;
    ctx.* = .{};
    host_save.* = .{};

    // Per-VM state (vmid + HCR_EL2 overrides) live in the control
    // block page immediately following the stage-2 root. Pulling
    // them from `vm_structures` here keeps vmResume's interface down
    // to the same four arguments x86's does (guest_state,
    // vm_structures, guest_fxsave) plus the per-vCPU arch_scratch.
    const cb = stage2.controlBlock(vm_structures);

    // EL2 runs with SCTLR_EL2.M=0 so the hyp stubs dereference these
    // pointers as raw PAs. The VCpu (and its embedded guest_state /
    // arch_scratch) lives in the slab-allocated kernel heap, not the
    // physmap range, so we must page-walk rather than doing the direct
    // subtraction in `PAddr.fromVAddr`.
    const gs_pa_addr = resolveKernelVaToPa(@intFromPtr(guest_state));
    const hs_pa_addr = resolveKernelVaToPa(@intFromPtr(host_save));
    const ctx_pa_addr = resolveKernelVaToPa(@intFromPtr(ctx));
    const gs_pa = PAddr.fromInt(gs_pa_addr);
    const hs_pa = PAddr.fromInt(hs_pa_addr);
    const ctx_pa = PAddr.fromInt(ctx_pa_addr);

    ctx.guest_state_pa = gs_pa.addr;
    ctx.host_save_pa = hs_pa.addr;
    ctx.stage2_root_pa = vm_structures.addr;
    // VTTBR_EL2 layout (ARM ARM D13.2.151):
    //   [63:48] VMID  — stage-2 TLB tag, managed by kvm/vmid.zig
    //   [47:1]  BADDR — stage-2 root PA (bits [47:x], with `x` dictated
    //                   by VTCR_EL2.T0SZ+SL0). For T0SZ=34 SL0=0 the
    //                   root is a single 4 KiB table, so bits [11:1] of
    //                   BADDR are RES0 and our page-aligned PA fits
    //                   directly.
    //   [0]     CnP   — 0; we don't claim common-not-private.
    ctx.vttbr_el2 = (@as(u64, cb.vmid) << 48) | vm_structures.addr;
    ctx.vtcr_el2 = vtcrEl2Value();
    // HCR_EL2 is the union of the per-VM override-set bits with the Linux
    // baseline, minus any override-clear bits. `sysregPassthrough` feeds
    // this: by default we deny (trap) everything the baseline traps, and
    // only dropping a bit into `hcr_override_clear` opens that trap up for
    // the VM. `hcr_override_set` is reserved for future traps that are not
    // in the baseline.
    ctx.hcr_el2 = (vm.HCR_EL2_LINUX_GUEST | cb.hcr_override_set) & ~cb.hcr_override_clear;

    // ---- Eager FPSIMD save/restore around the world switch ----
    //
    // Must stay fused to the hvc so no host Zig code runs between
    // "save host FP" and the guest entry, and similarly nothing between
    // guest exit and "restore host FP". If anything touches V-regs in
    // between we would either clobber host FP state or leak guest FP
    // state into the host.
    //
    // Layout assumptions (asserted at comptime above for ArchScratch and
    // at the FxsaveArea type def):
    //   HostFpState :  V0..V31 @ 0x000, FPCR @ 0x200, FPSR @ 0x208
    //   FxsaveArea  :  V0..V31 @ 0x000, FPCR @ 0x200, FPSR @ 0x208
    //
    // ARM ARM B1.2.2 (V-reg file), D13.2.48 (FPCR), D13.2.52 (FPSR).
    const host_fp_ptr: [*]u8 = @ptrCast(&arch_scratch.host_fp);
    const guest_fp_ptr: [*]u8 = @ptrCast(guest_fxsave);
    asm volatile (
        \\  // Save host V0..V31 to [host_fp + 0x000..0x200]
        \\  stp     q0, q1,   [%[hfp], #0x000]
        \\  stp     q2, q3,   [%[hfp], #0x020]
        \\  stp     q4, q5,   [%[hfp], #0x040]
        \\  stp     q6, q7,   [%[hfp], #0x060]
        \\  stp     q8, q9,   [%[hfp], #0x080]
        \\  stp     q10, q11, [%[hfp], #0x0A0]
        \\  stp     q12, q13, [%[hfp], #0x0C0]
        \\  stp     q14, q15, [%[hfp], #0x0E0]
        \\  stp     q16, q17, [%[hfp], #0x100]
        \\  stp     q18, q19, [%[hfp], #0x120]
        \\  stp     q20, q21, [%[hfp], #0x140]
        \\  stp     q22, q23, [%[hfp], #0x160]
        \\  stp     q24, q25, [%[hfp], #0x180]
        \\  stp     q26, q27, [%[hfp], #0x1A0]
        \\  stp     q28, q29, [%[hfp], #0x1C0]
        \\  stp     q30, q31, [%[hfp], #0x1E0]
        \\  mrs     x2, fpcr
        \\  str     x2, [%[hfp], #0x200]
        \\  mrs     x2, fpsr
        \\  str     x2, [%[hfp], #0x208]
        \\
        \\  // Load guest V0..V31 from [gfp + 0x000..0x200]
        \\  ldr     x2, [%[gfp], #0x200]
        \\  msr     fpcr, x2
        \\  ldr     x2, [%[gfp], #0x208]
        \\  msr     fpsr, x2
        \\  ldp     q0, q1,   [%[gfp], #0x000]
        \\  ldp     q2, q3,   [%[gfp], #0x020]
        \\  ldp     q4, q5,   [%[gfp], #0x040]
        \\  ldp     q6, q7,   [%[gfp], #0x060]
        \\  ldp     q8, q9,   [%[gfp], #0x080]
        \\  ldp     q10, q11, [%[gfp], #0x0A0]
        \\  ldp     q12, q13, [%[gfp], #0x0C0]
        \\  ldp     q14, q15, [%[gfp], #0x0E0]
        \\  ldp     q16, q17, [%[gfp], #0x100]
        \\  ldp     q18, q19, [%[gfp], #0x120]
        \\  ldp     q20, q21, [%[gfp], #0x140]
        \\  ldp     q22, q23, [%[gfp], #0x160]
        \\  ldp     q24, q25, [%[gfp], #0x180]
        \\  ldp     q26, q27, [%[gfp], #0x1A0]
        \\  ldp     q28, q29, [%[gfp], #0x1C0]
        \\  ldp     q30, q31, [%[gfp], #0x1E0]
        \\
        \\  // World switch: x0 = vcpu_run id (1), x1 = ctx PA.
        \\  // The hyp stub preserves %[hfp] / %[gfp] (both map to
        \\  // callee-saved x19..x28 via the Zig asm constraint) across
        \\  // the round trip because the EL2 exit path reloads host
        \\  // x19..x30 from host_save before returning.
        \\  mov     x0, #1
        \\  mov     x1, %[ctxpa]
        \\  hvc     #0
        \\
        \\  // Save guest V0..V31 back into [gfp]
        \\  stp     q0, q1,   [%[gfp], #0x000]
        \\  stp     q2, q3,   [%[gfp], #0x020]
        \\  stp     q4, q5,   [%[gfp], #0x040]
        \\  stp     q6, q7,   [%[gfp], #0x060]
        \\  stp     q8, q9,   [%[gfp], #0x080]
        \\  stp     q10, q11, [%[gfp], #0x0A0]
        \\  stp     q12, q13, [%[gfp], #0x0C0]
        \\  stp     q14, q15, [%[gfp], #0x0E0]
        \\  stp     q16, q17, [%[gfp], #0x100]
        \\  stp     q18, q19, [%[gfp], #0x120]
        \\  stp     q20, q21, [%[gfp], #0x140]
        \\  stp     q22, q23, [%[gfp], #0x160]
        \\  stp     q24, q25, [%[gfp], #0x180]
        \\  stp     q26, q27, [%[gfp], #0x1A0]
        \\  stp     q28, q29, [%[gfp], #0x1C0]
        \\  stp     q30, q31, [%[gfp], #0x1E0]
        \\  mrs     x2, fpcr
        \\  str     x2, [%[gfp], #0x200]
        \\  mrs     x2, fpsr
        \\  str     x2, [%[gfp], #0x208]
        \\
        \\  // Restore host V0..V31 + FPCR/FPSR from [hfp]
        \\  ldr     x2, [%[hfp], #0x200]
        \\  msr     fpcr, x2
        \\  ldr     x2, [%[hfp], #0x208]
        \\  msr     fpsr, x2
        \\  ldp     q0, q1,   [%[hfp], #0x000]
        \\  ldp     q2, q3,   [%[hfp], #0x020]
        \\  ldp     q4, q5,   [%[hfp], #0x040]
        \\  ldp     q6, q7,   [%[hfp], #0x060]
        \\  ldp     q8, q9,   [%[hfp], #0x080]
        \\  ldp     q10, q11, [%[hfp], #0x0A0]
        \\  ldp     q12, q13, [%[hfp], #0x0C0]
        \\  ldp     q14, q15, [%[hfp], #0x0E0]
        \\  ldp     q16, q17, [%[hfp], #0x100]
        \\  ldp     q18, q19, [%[hfp], #0x120]
        \\  ldp     q20, q21, [%[hfp], #0x140]
        \\  ldp     q22, q23, [%[hfp], #0x160]
        \\  ldp     q24, q25, [%[hfp], #0x180]
        \\  ldp     q26, q27, [%[hfp], #0x1A0]
        \\  ldp     q28, q29, [%[hfp], #0x1C0]
        \\  ldp     q30, q31, [%[hfp], #0x1E0]
        :
        : [hfp] "r" (host_fp_ptr),
          [gfp] "r" (guest_fp_ptr),
          [ctxpa] "r" (ctx_pa.addr),
        : .{
          // The hvc round-trip lands in hvc_vcpu_run / guest_exit_entry
          // which freely clobber all caller-saved AArch64 GPRs
          // (x0..x17) as temporaries. x19..x30 are restored by the
          // guest_exit_entry epilogue from host_save. Mark the full
          // caller-saved set here so the compiler does not assume any
          // of them survive the asm block.
          .memory = true,
          .x0 = true,
          .x1 = true,
          .x2 = true,
          .x3 = true,
          .x4 = true,
          .x5 = true,
          .x6 = true,
          .x7 = true,
          .x8 = true,
          .x9 = true,
          .x10 = true,
          .x11 = true,
          .x12 = true,
          .x13 = true,
          .x14 = true,
          .x15 = true,
          .x16 = true,
          .x17 = true,
          .x18 = true,
          // Full V register clobber matches the save/restore bracket.
          .v0 = true,
          .v1 = true,
          .v2 = true,
          .v3 = true,
          .v4 = true,
          .v5 = true,
          .v6 = true,
          .v7 = true,
          .v8 = true,
          .v9 = true,
          .v10 = true,
          .v11 = true,
          .v12 = true,
          .v13 = true,
          .v14 = true,
          .v15 = true,
          .v16 = true,
          .v17 = true,
          .v18 = true,
          .v19 = true,
          .v20 = true,
          .v21 = true,
          .v22 = true,
          .v23 = true,
          .v24 = true,
          .v25 = true,
          .v26 = true,
          .v27 = true,
          .v28 = true,
          .v29 = true,
          .v30 = true,
          .v31 = true,
        });

    return vm.decodeEsrEl2(ctx.exit_esr, ctx.exit_far, ctx.exit_hpfar);
}

// ===========================================================================
// EL2 hyp world-switch handlers
// ===========================================================================
//
// These mirror the x64 inline-asm vmResume structure (see x64/intel/vmx.zig)
// but with one architectural twist: ARMv8 EL1↔EL2 transitions are mediated
// by the EL2 vector table, not by a single instruction. The UEFI bootloader
// installs a minimal EL2 hyp stub at VBAR_EL2 (see
// `bootloader/aarch64_el2_drop.zig`). Its sync-lower A64 slot decodes the
// HVC imm16 and, on `HVC_IMM_INSTALL_VBAR_EL2`, writes X0 into VBAR_EL2.
// `installHypVectors()` uses that hand-off to swap the stub for the
// `__hyp_vectors` table defined below, at which point HVCs land in
// `hyp_sync_lower_a64` and the full world-switch dispatcher is live.
//
// Symbols defined here (referenced from `__hyp_vectors`):
//   hyp_sync_lower_a64   — dispatcher: tpidr_el2 != 0 → guest exit;
//                          else decode ESR_EL2.EC == HVC and dispatch x0.
//   hvc_noop             — id=0 round-trip smoke test (returns x1 ^ 1).
//   hvc_vcpu_run         — id=1 entry path: save host, load guest, ERET.
//   guest_exit_entry     — exit path: save guest, restore host, ERET.
//   hyp_halt             — wfe loop for unrecognised exceptions.
//
// All four handlers run with EL2 MMU off, so:
//   - PAs only — no high-VA dereferences.
//   - SP_EL2 is expected to be set up by whoever installs the vector table.
//   - tpidr_el2 doubles as "currently active WorldSwitchCtx PA" marker.

/// Kernel EL2 vector table. 16 slots × 0x80 bytes each, 2 KiB aligned.
///
/// ARM ARM D1.10.2 vector layout (offset → vector):
///   0x000 sync  EL2t     0x080 irq  EL2t     0x100 fiq  EL2t     0x180 serror EL2t
///   0x200 sync  EL2h     0x280 irq  EL2h     0x300 fiq  EL2h     0x380 serror EL2h
///   0x400 sync  lowerA64 0x480 irq  lowerA64 0x500 fiq  lowerA64 0x580 serror lowerA64
///   0x600 sync  lowerA32 0x680 irq  lowerA32 0x700 fiq  lowerA32 0x780 serror lowerA32
///
/// Only the "sync lower A64" slot is wired up: it branches into
/// `hyp_sync_lower_a64`, which decodes HVC-vs-guest-exit via tpidr_el2.
/// Every other slot is a tight `b .` loop — the kernel never raises
/// async exceptions to EL2 and the direct-kernel path does not support
/// AArch32 guests, so any entry there is a bug we want to observe as a
/// hang rather than a silent wild branch.
export fn __hyp_vectors() align(2048) linksection(".hyp_vectors") callconv(.naked) noreturn {
    asm volatile (
    // +0x000 sync EL2t
        \\        b       .
        \\        .balign 0x80
        // +0x080 irq EL2t
        \\        b       .
        \\        .balign 0x80
        // +0x100 fiq EL2t
        \\        b       .
        \\        .balign 0x80
        // +0x180 serror EL2t
        \\        b       .
        \\        .balign 0x80
        // +0x200 sync EL2h
        \\        b       .
        \\        .balign 0x80
        // +0x280 irq EL2h
        \\        b       .
        \\        .balign 0x80
        // +0x300 fiq EL2h
        \\        b       .
        \\        .balign 0x80
        // +0x380 serror EL2h
        \\        b       .
        \\        .balign 0x80
        // +0x400 sync lower A64 — host hvc or guest exit
        \\        b       hyp_sync_lower_a64
        \\        .balign 0x80
        // +0x480 irq lower A64
        \\        b       .
        \\        .balign 0x80
        // +0x500 fiq lower A64
        \\        b       .
        \\        .balign 0x80
        // +0x580 serror lower A64
        \\        b       .
        \\        .balign 0x80
        // +0x600..+0x780 lower AArch32 (unused)
        \\        b       .
        \\        .balign 0x80
        \\        b       .
        \\        .balign 0x80
        \\        b       .
        \\        .balign 0x80
        \\        b       .
    );
}

export fn hyp_sync_lower_a64() linksection(".hyp_text") callconv(.naked) noreturn {
    asm volatile (
        \\  // If tpidr_el2 != 0 we were running a guest; this is a VM exit.
        \\  mrs     x18, tpidr_el2
        \\  cbnz    x18, guest_exit_entry
        \\
        \\  // Host hypercall path. Decode ESR_EL2.EC; we only support EC=0x16.
        \\  mrs     x18, esr_el2
        \\  lsr     x18, x18, #26
        \\  and     x18, x18, #0x3F
        \\  cmp     x18, #0x16
        \\  b.ne    hyp_halt
        \\
        \\  // Dispatch by x0.
        \\  cmp     x0, #0
        \\  b.eq    hvc_noop
        \\  cmp     x0, #1
        \\  b.eq    hvc_vcpu_run
        \\  cmp     x0, #2
        \\  b.eq    hvc_tlbi_ipa
        \\  cmp     x0, #3
        \\  b.eq    hvc_vgic_detect_lrs
        \\  cmp     x0, #4
        \\  b.eq    hvc_vgic_prepare_entry
        \\  cmp     x0, #5
        \\  b.eq    hvc_vgic_save_exit
        \\  cmp     x0, #6
        \\  b.eq    hvc_vtimer_load_guest
        \\  cmp     x0, #7
        \\  b.eq    hvc_vtimer_save_guest
        \\  // Unknown id — return -1.
        \\  mov     x0, #-1
        \\  eret
    );
}

// hvc_tlbi_ipa — M4 stage-2 IPA invalidation from the EL1 kernel.
//
// On entry:
//   x0 = HypCallId.tlbi_ipa (2) — discarded.
//   x1 = guest IPA (byte address) of the stage-2 leaf that was mutated.
//
// `TLBI IPAS2E1IS` takes a 36-bit IPA page number in bits [35:0] of its
// register operand (ARM ARM K.a D7.7.7 "TLBI IPAS2E1IS, Xt"). We shift
// the byte IPA right by 12 to get that page number. The sequence is:
//
//   dsb ishst        — order prior stage-2 table stores before the TLBI
//   tlbi ipas2e1is   — invalidate the specific IPA across the IS domain
//                      (all EL0/EL1 entries that used stage-2 for this
//                      IPA under the current VMID)
//   dsb ish          — wait for the TLBI broadcast to complete everywhere
//   tlbi vmalle1is   — nuke stage-1 walk caches that may have consumed
//                      the stale stage-2 descriptor on any IS core
//                      (cheap; strictly required only for combined
//                      stage-1+stage-2 walks, ARM ARM D5.10.2)
//   dsb ish          — wait for the stage-1 TLBI to settle
//   isb              — context synchronization so the kernel sees the
//                      post-invalidate state on return
//
// The VMID programmed in VTTBR_EL2 selects which VM the IPA belongs to;
// the caller (EL1 kernel) must have already written VTTBR_EL2 for the
// target VM via the world-switch entry path — or be invalidating a VM
// whose VMID is otherwise already loaded, which is the common case
// because `mapGuestPage`/`unmapGuestPage` are driven from VMM syscalls
// on the owning process's core while VTTBR_EL2 holds that VM's VMID.
export fn hvc_tlbi_ipa() linksection(".hyp_text") callconv(.naked) noreturn {
    asm volatile (
        \\  lsr     x1, x1, #12
        \\  dsb     ishst
        \\  tlbi    ipas2e1is, x1
        \\  dsb     ish
        \\  tlbi    vmalle1is
        \\  dsb     ish
        \\  isb
        \\  mov     x0, #0
        \\  eret
    );
}

export fn hvc_noop() linksection(".hyp_text") callconv(.naked) noreturn {
    asm volatile (
        \\  // Return arg^1 so the caller can verify the round-trip changed x0.
        \\  eor     x0, x1, #1
        \\  eret
    );
}

// ===========================================================================
// M5 vGIC / vtimer EL2 sysreg stubs
// ===========================================================================
//
// ICH_*_EL2 (GICv3 §12.5, ARM ARM D13.8) and CNTVOFF_EL2 (ARM ARM D13.11.9)
// are EL2-only and trap to an undefined-instruction exception if issued from
// EL1. The EL1 kernel therefore shuttles the vGIC list-register / priority /
// control state and the virtual-timer offset through the stubs below using
// pinned-layout shadow structs (`vgic.VcpuHwShadow`, `vtimer.VtimerState`).
//
// Struct offsets below are enforced by `comptime` asserts in those modules;
// changing a field order there will break compilation rather than silently
// corrupt EL2 state.

// hvc_vgic_detect_lrs — return the implemented list-register count.
//
// Reads ICH_VTR_EL2.ListRegs (bits[4:0]), adds 1, returns in x0.
// ICH_VTR_EL2 has encoding S3_4_C12_C11_1 (ARM ARM D13.8.50).
export fn hvc_vgic_detect_lrs() linksection(".hyp_text") callconv(.naked) noreturn {
    asm volatile (
        \\  mrs     x0, S3_4_C12_C11_1      // ICH_VTR_EL2
        \\  and     x0, x0, #0x1F
        \\  add     x0, x0, #1
        \\  eret
    );
}

// hvc_vgic_prepare_entry — flush VcpuHwShadow → ICH_*_EL2 registers.
//
// On entry:
//   x0 = HypCallId.vgic_prepare_entry (4) — discarded.
//   x1 = pointer to vgic.VcpuHwShadow.
//
// Shadow layout (vgic.VcpuHwShadow, enforced by comptime asserts):
//   0x00..0x78  lrs[0..15]   (16 × u64)
//   0x80        hcr          (ICH_HCR_EL2, caller sets EN=1)
//   0x88        vmcr         (ICH_VMCR_EL2)
//   0x90        ap0r0        (ICH_AP0R0_EL2)
//   0x98        ap1r0        (ICH_AP1R0_EL2)
//
// Writes all 16 LRs unconditionally; slots beyond num_lrs are zero in
// the shadow which the spec treats as "no pending vintid" (GICv3 §11.2.5,
// LR.State field = 0b00 Invalid).
//
// Sysreg encodings (ARM ARM D13.8.51 / Table D13-65):
//   ICH_LR0..7_EL2  = S3_4_C12_C12_{0..7}
//   ICH_LR8..15_EL2 = S3_4_C12_C13_{0..7}
//   ICH_AP0R0_EL2   = S3_4_C12_C8_0  (D13.8.42)
//   ICH_AP1R0_EL2   = S3_4_C12_C9_0  (D13.8.46)
//   ICH_VMCR_EL2    = S3_4_C12_C11_7 (D13.8.49)
//   ICH_HCR_EL2     = S3_4_C12_C11_0 (D13.8.45)
export fn hvc_vgic_prepare_entry() linksection(".hyp_text") callconv(.naked) noreturn {
    // num_lrs (x3) is read from shadow offset 0xA8; we guard each LR
    // write with `cmp x3, #n; b.ls 9f` so hosts that implement fewer
    // than 16 LRs (e.g. cortex-a72 TCG with 4) don't trigger UNDEFINED
    // on the high-numbered ICH_LR<n>_EL2 sysregs. GICv3 §12.5.30
    // ICH_VTR_EL2.ListRegs + 1 = implemented LRs.
    asm volatile (
        \\  ldr     x3, [x1, #0xA8]         // num_lrs
        \\  ldr     x2, [x1, #0x00]
        \\  msr     S3_4_C12_C12_0, x2
        \\  cmp     x3, #1
        \\  b.ls    9f
        \\  ldr     x2, [x1, #0x08]
        \\  msr     S3_4_C12_C12_1, x2
        \\  cmp     x3, #2
        \\  b.ls    9f
        \\  ldr     x2, [x1, #0x10]
        \\  msr     S3_4_C12_C12_2, x2
        \\  cmp     x3, #3
        \\  b.ls    9f
        \\  ldr     x2, [x1, #0x18]
        \\  msr     S3_4_C12_C12_3, x2
        \\  cmp     x3, #4
        \\  b.ls    9f
        \\  ldr     x2, [x1, #0x20]
        \\  msr     S3_4_C12_C12_4, x2
        \\  cmp     x3, #5
        \\  b.ls    9f
        \\  ldr     x2, [x1, #0x28]
        \\  msr     S3_4_C12_C12_5, x2
        \\  cmp     x3, #6
        \\  b.ls    9f
        \\  ldr     x2, [x1, #0x30]
        \\  msr     S3_4_C12_C12_6, x2
        \\  cmp     x3, #7
        \\  b.ls    9f
        \\  ldr     x2, [x1, #0x38]
        \\  msr     S3_4_C12_C12_7, x2
        \\  cmp     x3, #8
        \\  b.ls    9f
        \\  ldr     x2, [x1, #0x40]
        \\  msr     S3_4_C12_C13_0, x2
        \\  cmp     x3, #9
        \\  b.ls    9f
        \\  ldr     x2, [x1, #0x48]
        \\  msr     S3_4_C12_C13_1, x2
        \\  cmp     x3, #10
        \\  b.ls    9f
        \\  ldr     x2, [x1, #0x50]
        \\  msr     S3_4_C12_C13_2, x2
        \\  cmp     x3, #11
        \\  b.ls    9f
        \\  ldr     x2, [x1, #0x58]
        \\  msr     S3_4_C12_C13_3, x2
        \\  cmp     x3, #12
        \\  b.ls    9f
        \\  ldr     x2, [x1, #0x60]
        \\  msr     S3_4_C12_C13_4, x2
        \\  cmp     x3, #13
        \\  b.ls    9f
        \\  ldr     x2, [x1, #0x68]
        \\  msr     S3_4_C12_C13_5, x2
        \\  cmp     x3, #14
        \\  b.ls    9f
        \\  ldr     x2, [x1, #0x70]
        \\  msr     S3_4_C12_C13_6, x2
        \\  cmp     x3, #15
        \\  b.ls    9f
        \\  ldr     x2, [x1, #0x78]
        \\  msr     S3_4_C12_C13_7, x2
        \\9:
        \\  ldr     x2, [x1, #0x90]         // ap0r0
        \\  msr     S3_4_C12_C8_0, x2
        \\  ldr     x2, [x1, #0x98]         // ap1r0
        \\  msr     S3_4_C12_C9_0, x2
        \\  ldr     x2, [x1, #0x88]         // vmcr
        \\  msr     S3_4_C12_C11_7, x2
        \\  // Enable last so LRs/AP/VMCR are coherent before delivery.
        \\  ldr     x2, [x1, #0x80]         // hcr (EN forced on by caller)
        \\  msr     S3_4_C12_C11_0, x2
        \\  mov     x0, #0
        \\  eret
    );
}

// hvc_vgic_save_exit — snapshot ICH_*_EL2 → VcpuHwShadow on exit.
//
// On entry:
//   x0 = HypCallId.vgic_save_exit (5) — discarded.
//   x1 = pointer to vgic.VcpuHwShadow.
//
// Reads all 16 LRs, AP0R0, AP1R0 into the shadow. Then disables the
// virtual CPU interface by writing ICH_HCR_EL2 = 0 so a maintenance
// IRQ cannot fire into the host running window (GICv3 §12.5.7 "En").
export fn hvc_vgic_save_exit() linksection(".hyp_text") callconv(.naked) noreturn {
    // Mirror of hvc_vgic_prepare_entry — only read the implemented
    // LR slots. See that function for the rationale.
    asm volatile (
        \\  ldr     x3, [x1, #0xA8]         // num_lrs
        \\  mrs     x2, S3_4_C12_C12_0
        \\  str     x2, [x1, #0x00]
        \\  cmp     x3, #1
        \\  b.ls    9f
        \\  mrs     x2, S3_4_C12_C12_1
        \\  str     x2, [x1, #0x08]
        \\  cmp     x3, #2
        \\  b.ls    9f
        \\  mrs     x2, S3_4_C12_C12_2
        \\  str     x2, [x1, #0x10]
        \\  cmp     x3, #3
        \\  b.ls    9f
        \\  mrs     x2, S3_4_C12_C12_3
        \\  str     x2, [x1, #0x18]
        \\  cmp     x3, #4
        \\  b.ls    9f
        \\  mrs     x2, S3_4_C12_C12_4
        \\  str     x2, [x1, #0x20]
        \\  cmp     x3, #5
        \\  b.ls    9f
        \\  mrs     x2, S3_4_C12_C12_5
        \\  str     x2, [x1, #0x28]
        \\  cmp     x3, #6
        \\  b.ls    9f
        \\  mrs     x2, S3_4_C12_C12_6
        \\  str     x2, [x1, #0x30]
        \\  cmp     x3, #7
        \\  b.ls    9f
        \\  mrs     x2, S3_4_C12_C12_7
        \\  str     x2, [x1, #0x38]
        \\  cmp     x3, #8
        \\  b.ls    9f
        \\  mrs     x2, S3_4_C12_C13_0
        \\  str     x2, [x1, #0x40]
        \\  cmp     x3, #9
        \\  b.ls    9f
        \\  mrs     x2, S3_4_C12_C13_1
        \\  str     x2, [x1, #0x48]
        \\  cmp     x3, #10
        \\  b.ls    9f
        \\  mrs     x2, S3_4_C12_C13_2
        \\  str     x2, [x1, #0x50]
        \\  cmp     x3, #11
        \\  b.ls    9f
        \\  mrs     x2, S3_4_C12_C13_3
        \\  str     x2, [x1, #0x58]
        \\  cmp     x3, #12
        \\  b.ls    9f
        \\  mrs     x2, S3_4_C12_C13_4
        \\  str     x2, [x1, #0x60]
        \\  cmp     x3, #13
        \\  b.ls    9f
        \\  mrs     x2, S3_4_C12_C13_5
        \\  str     x2, [x1, #0x68]
        \\  cmp     x3, #14
        \\  b.ls    9f
        \\  mrs     x2, S3_4_C12_C13_6
        \\  str     x2, [x1, #0x70]
        \\  cmp     x3, #15
        \\  b.ls    9f
        \\  mrs     x2, S3_4_C12_C13_7
        \\  str     x2, [x1, #0x78]
        \\9:
        \\  mrs     x2, S3_4_C12_C8_0       // ap0r0
        \\  str     x2, [x1, #0x90]
        \\  mrs     x2, S3_4_C12_C9_0       // ap1r0
        \\  str     x2, [x1, #0x98]
        \\  mrs     x2, S3_4_C12_C11_2      // ICH_MISR_EL2
        \\  str     x2, [x1, #0xA0]
        \\
        \\  // Disable the virtual CPU interface for the host window.
        \\  msr     S3_4_C12_C11_0, xzr     // ICH_HCR_EL2 = 0
        \\  mov     x0, #0
        \\  eret
    );
}

// hvc_vtimer_load_guest — program per-vCPU virtual timer from shadow.
//
// On entry:
//   x0 = HypCallId.vtimer_load_guest (6) — discarded.
//   x1 = pointer to vtimer.VtimerState.
//
// Shadow layout (vtimer.VtimerState, enforced by comptime asserts):
//   0x00 cntvoff_el2
//   0x08 cntv_ctl_el0
//   0x10 cntv_cval_el0
//   0x18 cntkctl_el1
//   0x20 primed (u64; 0 = needs seeding from CNTPCT_EL0)
//
// First-entry path: if primed == 0, snapshot CNTPCT_EL0 (ARM ARM
// D13.11.15) into cntvoff_el2 so CNTVCT_EL0 = 0 at guest boot
// (D13.11.9 CNTVCT_EL0 = CNTPCT_EL0 - CNTVOFF_EL2), and set primed=1.
// Then program CNTVOFF_EL2, CNTKCTL_EL1, CNTV_CVAL_EL0, CNTV_CTL_EL0
// in that order (D13.11.17 ISTATUS is re-evaluated on every read, so
// writing CTL last ensures IMASK/ENABLE see the fresh CVAL).
export fn hvc_vtimer_load_guest() linksection(".hyp_text") callconv(.naked) noreturn {
    asm volatile (
        \\  ldr     x3, [x1, #0x20]         // primed
        \\  cbnz    x3, 1f
        \\  mrs     x2, cntpct_el0
        \\  str     x2, [x1, #0x00]         // cntvoff_el2 = CNTPCT
        \\  mov     x3, #1
        \\  str     x3, [x1, #0x20]         // primed = 1
        \\1:
        \\  ldr     x2, [x1, #0x00]
        \\  msr     cntvoff_el2, x2
        \\  ldr     x2, [x1, #0x18]
        \\  msr     cntkctl_el1, x2
        \\  ldr     x2, [x1, #0x10]
        \\  msr     cntv_cval_el0, x2
        \\  ldr     x2, [x1, #0x08]
        \\  msr     cntv_ctl_el0, x2
        \\  mov     x0, #0
        \\  eret
    );
}

// hvc_vtimer_save_guest — snapshot virtual timer sysregs into shadow.
//
// On entry:
//   x0 = HypCallId.vtimer_save_guest (7) — discarded.
//   x1 = pointer to vtimer.VtimerState.
//
// Reads CNTV_CTL_EL0, CNTV_CVAL_EL0, CNTKCTL_EL1 into the shadow (the
// guest's EL1 may have written CNTKCTL, D13.11.26). CNTVOFF_EL2 is
// EL2-only so the host's shadow remains authoritative and is not read
// back. Finally writes CNTV_CTL_EL0 = 0x2 (IMASK=1, ENABLE=0) so a
// post-exit virtual-timer match cannot fire into the host context
// (D13.11.17; mirrors Linux arch_timer.c timer_save_state).
export fn hvc_vtimer_save_guest() linksection(".hyp_text") callconv(.naked) noreturn {
    asm volatile (
        \\  mrs     x2, cntv_ctl_el0
        \\  str     x2, [x1, #0x08]
        \\  mrs     x2, cntv_cval_el0
        \\  str     x2, [x1, #0x10]
        \\  mrs     x2, cntkctl_el1
        \\  str     x2, [x1, #0x18]
        \\  mov     x2, #0x2
        \\  msr     cntv_ctl_el0, x2
        \\  mov     x0, #0
        \\  eret
    );
}

// hvc_vcpu_run — Phase B: world-switch entry.
//
// On entry:
//   x1 = PA of a WorldSwitchCtx (offsets pinned by comptime asserts above).
//   x0 = HypCallId.vcpu_run (1) — discarded.
//
// Saves host callee-saved GPRs + EL1 sysregs into ctx.host_save, programs
// per-VM EL2 state (HCR/VTCR/VTTBR/CNTVOFF), loads guest EL1 sysregs and
// GPRs from ctx.guest_state, sets tpidr_el2 = ctx_pa as the "guest active"
// marker, and ERETs to the guest at guest.pc / guest.pstate.
export fn hvc_vcpu_run() linksection(".hyp_text") callconv(.naked) noreturn {
    asm volatile (
        \\  // x1 = ctx PA. Preserve it in x18 across sysreg work.
        \\  mov     x18, x1
        \\
        \\  // Stash host ELR_EL2 / SPSR_EL2 into the ctx so the exit path can
        \\  // ERET back to the host kernel (after the `hvc #0` in hypCall).
        \\  // Without this the exit ERET would use whatever the guest exit
        \\  // wrote into these regs.
        \\  mrs     x3, elr_el2
        \\  str     x3, [x18, #0x48]
        \\  mrs     x3, spsr_el2
        \\  str     x3, [x18, #0x50]
        \\
        \\  // ---- Save host callee-saved GPRs + EL1 sysregs to host_save ----
        \\  ldr     x2, [x18, #0x08]        // host_save_pa
        \\  stp     x19, x20, [x2, #0x00]
        \\  stp     x21, x22, [x2, #0x10]
        \\  stp     x23, x24, [x2, #0x20]
        \\  stp     x25, x26, [x2, #0x30]
        \\  stp     x27, x28, [x2, #0x40]
        \\  stp     x29, x30, [x2, #0x50]
        \\
        \\  mrs     x3, sp_el1
        \\  str     x3, [x2, #0x60]
        \\  mrs     x3, sp_el0
        \\  str     x3, [x2, #0x68]
        \\  mrs     x3, tpidr_el1
        \\  str     x3, [x2, #0x70]
        \\  mrs     x3, sctlr_el1
        \\  str     x3, [x2, #0x78]
        \\  mrs     x3, tcr_el1
        \\  str     x3, [x2, #0x80]
        \\  mrs     x3, ttbr0_el1
        \\  str     x3, [x2, #0x88]
        \\  mrs     x3, ttbr1_el1
        \\  str     x3, [x2, #0x90]
        \\  mrs     x3, mair_el1
        \\  str     x3, [x2, #0x98]
        \\  mrs     x3, vbar_el1
        \\  str     x3, [x2, #0xA0]
        \\  mrs     x3, cpacr_el1
        \\  str     x3, [x2, #0xA8]
        \\  mrs     x3, contextidr_el1
        \\  str     x3, [x2, #0xB0]
        \\  mrs     x3, tpidr_el0
        \\  str     x3, [x2, #0xB8]
        \\  mrs     x3, tpidrro_el0
        \\  str     x3, [x2, #0xC0]
        \\  mrs     x3, cntkctl_el1
        \\  str     x3, [x2, #0xC8]
        \\  mrs     x3, elr_el1
        \\  str     x3, [x2, #0xD0]
        \\  mrs     x3, spsr_el1
        \\  str     x3, [x2, #0xD8]
        \\  mrs     x3, esr_el1
        \\  str     x3, [x2, #0xE0]
        \\  mrs     x3, far_el1
        \\  str     x3, [x2, #0xE8]
        \\
        \\  // ---- Program per-VM EL2 state ----
        \\  ldr     x3, [x18, #0x28]        // hcr_el2
        \\  msr     hcr_el2, x3
        \\  ldr     x3, [x18, #0x20]        // vtcr_el2
        \\  msr     vtcr_el2, x3
        \\  ldr     x3, [x18, #0x18]        // vttbr_el2
        \\  msr     vttbr_el2, x3
        \\  msr     cntvoff_el2, xzr
        \\  isb
        \\
        \\  // Stage-2 TLB invalidate for the fresh VMID (cheap; just VMALLS12E1IS).
        \\  tlbi    vmalls12e1is
        \\  dsb     ish
        \\  isb
        \\
        \\  // ---- Load guest EL1 sysregs from GuestState ----
        \\  ldr     x2, [x18, #0x00]        // guest_state_pa
        \\  ldr     x3, [x2, #0x118]        // sctlr_el1
        \\  msr     sctlr_el1, x3
        \\  ldr     x3, [x2, #0x120]        // ttbr0_el1
        \\  msr     ttbr0_el1, x3
        \\  ldr     x3, [x2, #0x128]        // ttbr1_el1
        \\  msr     ttbr1_el1, x3
        \\  ldr     x3, [x2, #0x130]        // tcr_el1
        \\  msr     tcr_el1, x3
        \\  ldr     x3, [x2, #0x138]        // mair_el1
        \\  msr     mair_el1, x3
        \\  ldr     x3, [x2, #0x148]        // cpacr_el1
        \\  msr     cpacr_el1, x3
        \\  ldr     x3, [x2, #0x150]        // contextidr_el1
        \\  msr     contextidr_el1, x3
        \\  ldr     x3, [x2, #0x158]        // tpidr_el0
        \\  msr     tpidr_el0, x3
        \\  ldr     x3, [x2, #0x160]        // tpidr_el1
        \\  msr     tpidr_el1, x3
        \\  ldr     x3, [x2, #0x168]        // tpidrro_el0
        \\  msr     tpidrro_el0, x3
        \\  ldr     x3, [x2, #0x170]        // vbar_el1
        \\  msr     vbar_el1, x3
        \\  ldr     x3, [x2, #0x178]        // elr_el1
        \\  msr     elr_el1, x3
        \\  ldr     x3, [x2, #0x180]        // spsr_el1
        \\  msr     spsr_el1, x3
        \\  ldr     x3, [x2, #0x188]        // esr_el1
        \\  msr     esr_el1, x3
        \\  ldr     x3, [x2, #0x190]        // far_el1
        \\  msr     far_el1, x3
        \\  ldr     x3, [x2, #0x0F8]        // sp_el0
        \\  msr     sp_el0, x3
        \\  ldr     x3, [x2, #0x100]        // sp_el1
        \\  msr     sp_el1, x3
        \\  isb
        \\
        \\  // ---- Program ELR_EL2 / SPSR_EL2 from guest.pc / guest.pstate ----
        \\  ldr     x3, [x2, #0x108]        // guest.pc
        \\  msr     elr_el2, x3
        \\  ldr     x3, [x2, #0x110]        // guest.pstate
        \\  msr     spsr_el2, x3
        \\
        \\  // ---- Mark active ctx so exits take the guest_exit path ----
        \\  msr     tpidr_el2, x18
        \\  isb
        \\
        \\  // ---- Load guest GPRs x0..x30 from GuestState ----
        \\  // x2 holds guest_state_pa; keep it live until the last load.
        \\  ldp     x0, x1, [x2, #0x00]
        \\  ldp     x3, x4, [x2, #0x18]
        \\  ldp     x5, x6, [x2, #0x28]
        \\  ldp     x7, x8, [x2, #0x38]
        \\  ldp     x9, x10, [x2, #0x48]
        \\  ldp     x11, x12, [x2, #0x58]
        \\  ldp     x13, x14, [x2, #0x68]
        \\  ldp     x15, x16, [x2, #0x78]
        \\  ldp     x17, x18, [x2, #0x88]
        \\  ldp     x19, x20, [x2, #0x98]
        \\  ldp     x21, x22, [x2, #0xA8]
        \\  ldp     x23, x24, [x2, #0xB8]
        \\  ldp     x25, x26, [x2, #0xC8]
        \\  ldp     x27, x28, [x2, #0xD8]
        \\  ldp     x29, x30, [x2, #0xE8]
        \\  // x2 is still live; reload final (x2) value last.
        \\  ldr     x2, [x2, #0x10]
        \\  eret
    );
}

// guest_exit_entry — Phase C: world-switch exit.
//
// On entry: guest was running at EL1, took an exception to EL2.
//   tpidr_el2 = PA of the active WorldSwitchCtx.
//   All GPRs still hold guest values.
//
// Saves guest GPRs and EL1 sysregs into ctx.guest_state, populates
// ctx.exit_{esr,far,hpfar}, restores host EL1 sysregs and callee-saved
// GPRs, clears tpidr_el2, restores host ELR_EL2/SPSR_EL2 stashed at entry,
// and ERETs back to the host (instruction after `hvc #0` in hypCall).
export fn guest_exit_entry() linksection(".hyp_text") callconv(.naked) noreturn {
    asm volatile (
        \\  // Reclaim ctx pointer from tpidr_el2 without clobbering x0..x17.
        \\  // Use SP_EL2 as a two-slot scratch to free up x17/x18.
        \\  sub     sp, sp, #16
        \\  str     x18, [sp]
        \\  mrs     x18, tpidr_el2          // x18 = ctx_pa
        \\  str     x17, [sp, #8]
        \\  ldr     x17, [x18, #0x00]       // x17 = guest_state_pa
        \\
        \\  // Store guest x0..x16 into GuestState x0..x16 slots.
        \\  stp     x0, x1, [x17, #0x00]
        \\  stp     x2, x3, [x17, #0x10]
        \\  stp     x4, x5, [x17, #0x20]
        \\  stp     x6, x7, [x17, #0x30]
        \\  stp     x8, x9, [x17, #0x40]
        \\  stp     x10, x11, [x17, #0x50]
        \\  stp     x12, x13, [x17, #0x60]
        \\  stp     x14, x15, [x17, #0x70]
        \\  // x16 and guest-x17 (stashed on stack at sp+8).
        \\  ldr     x0, [sp, #8]            // guest x17
        \\  stp     x16, x0, [x17, #0x80]
        \\  // guest x18 stashed at sp+0.
        \\  ldr     x0, [sp, #0]            // guest x18
        \\  str     x0, [x17, #0x90]
        \\  add     sp, sp, #16
        \\  // x19..x30 are still guest values (we haven't touched them yet).
        \\  stp     x19, x20, [x17, #0x98]
        \\  stp     x21, x22, [x17, #0xA8]
        \\  stp     x23, x24, [x17, #0xB8]
        \\  stp     x25, x26, [x17, #0xC8]
        \\  stp     x27, x28, [x17, #0xD8]
        \\  stp     x29, x30, [x17, #0xE8]
        \\
        \\  // ---- Save guest pc/pstate from ELR/SPSR_EL2 ----
        \\  mrs     x0, elr_el2
        \\  str     x0, [x17, #0x108]
        \\  mrs     x0, spsr_el2
        \\  str     x0, [x17, #0x110]
        \\
        \\  // ---- Save guest EL1 sysregs back into GuestState ----
        \\  mrs     x0, sp_el0
        \\  str     x0, [x17, #0x0F8]
        \\  mrs     x0, sp_el1
        \\  str     x0, [x17, #0x100]
        \\  mrs     x0, sctlr_el1
        \\  str     x0, [x17, #0x118]
        \\  mrs     x0, ttbr0_el1
        \\  str     x0, [x17, #0x120]
        \\  mrs     x0, ttbr1_el1
        \\  str     x0, [x17, #0x128]
        \\  mrs     x0, tcr_el1
        \\  str     x0, [x17, #0x130]
        \\  mrs     x0, mair_el1
        \\  str     x0, [x17, #0x138]
        \\  mrs     x0, cpacr_el1
        \\  str     x0, [x17, #0x148]
        \\  mrs     x0, contextidr_el1
        \\  str     x0, [x17, #0x150]
        \\  mrs     x0, tpidr_el0
        \\  str     x0, [x17, #0x158]
        \\  mrs     x0, tpidr_el1
        \\  str     x0, [x17, #0x160]
        \\  mrs     x0, tpidrro_el0
        \\  str     x0, [x17, #0x168]
        \\  mrs     x0, vbar_el1
        \\  str     x0, [x17, #0x170]
        \\  mrs     x0, elr_el1
        \\  str     x0, [x17, #0x178]
        \\  mrs     x0, spsr_el1
        \\  str     x0, [x17, #0x180]
        \\  mrs     x0, esr_el1
        \\  str     x0, [x17, #0x188]
        \\  mrs     x0, far_el1
        \\  str     x0, [x17, #0x190]
        \\
        \\  // ---- Populate ctx.exit_esr / exit_far / exit_hpfar ----
        \\  mrs     x0, esr_el2
        \\  str     x0, [x18, #0x30]
        \\  mrs     x0, far_el2
        \\  str     x0, [x18, #0x38]
        \\  mrs     x0, hpfar_el2
        \\  str     x0, [x18, #0x40]
        \\
        \\  // ---- Reload host EL1 sysregs from host_save ----
        \\  ldr     x2, [x18, #0x08]        // host_save_pa
        \\  ldr     x3, [x2, #0x60]
        \\  msr     sp_el1, x3
        \\  ldr     x3, [x2, #0x68]
        \\  msr     sp_el0, x3
        \\  ldr     x3, [x2, #0x70]
        \\  msr     tpidr_el1, x3
        \\  ldr     x3, [x2, #0x78]
        \\  msr     sctlr_el1, x3
        \\  ldr     x3, [x2, #0x80]
        \\  msr     tcr_el1, x3
        \\  ldr     x3, [x2, #0x88]
        \\  msr     ttbr0_el1, x3
        \\  ldr     x3, [x2, #0x90]
        \\  msr     ttbr1_el1, x3
        \\  ldr     x3, [x2, #0x98]
        \\  msr     mair_el1, x3
        \\  ldr     x3, [x2, #0xA0]
        \\  msr     vbar_el1, x3
        \\  ldr     x3, [x2, #0xA8]
        \\  msr     cpacr_el1, x3
        \\  ldr     x3, [x2, #0xB0]
        \\  msr     contextidr_el1, x3
        \\  ldr     x3, [x2, #0xB8]
        \\  msr     tpidr_el0, x3
        \\  ldr     x3, [x2, #0xC0]
        \\  msr     tpidrro_el0, x3
        \\  ldr     x3, [x2, #0xC8]
        \\  msr     cntkctl_el1, x3
        \\  ldr     x3, [x2, #0xD0]
        \\  msr     elr_el1, x3
        \\  ldr     x3, [x2, #0xD8]
        \\  msr     spsr_el1, x3
        \\  ldr     x3, [x2, #0xE0]
        \\  msr     esr_el1, x3
        \\  ldr     x3, [x2, #0xE8]
        \\  msr     far_el1, x3
        \\
        \\  // ---- Disable stage-2 so host EL1 runs unpaginated-by-S2 ----
        \\  // HCR_EL2 = RW(31)=1 only, same as boot default.
        \\  mov     x3, #1
        \\  lsl     x3, x3, #31
        \\  msr     hcr_el2, x3
        \\  msr     vttbr_el2, xzr
        \\  isb
        \\  tlbi    vmalle1
        \\  dsb     ish
        \\  isb
        \\
        \\  // ---- Restore host callee-saved GPRs x19..x30 ----
        \\  ldp     x19, x20, [x2, #0x00]
        \\  ldp     x21, x22, [x2, #0x10]
        \\  ldp     x23, x24, [x2, #0x20]
        \\  ldp     x25, x26, [x2, #0x30]
        \\  ldp     x27, x28, [x2, #0x40]
        \\  ldp     x29, x30, [x2, #0x50]
        \\
        \\  // Clear active-ctx marker and return 0 (success) in x0.
        \\  msr     tpidr_el2, xzr
        \\  mov     x0, #0
        \\
        \\  // Restore host ELR_EL2 / SPSR_EL2 stashed by hvc_vcpu_run on entry
        \\  // (the guest exit clobbered them with guest pc/pstate, which we
        \\  // already saved into GuestState above).
        \\  ldr     x3, [x18, #0x48]        // host return elr
        \\  msr     elr_el2, x3
        \\  ldr     x3, [x18, #0x50]        // host return spsr
        \\  msr     spsr_el2, x3
        \\  eret
    );
}

export fn hyp_halt() linksection(".hyp_text") callconv(.naked) noreturn {
    asm volatile (
        \\1:wfe
        \\  b       1b
    );
}
