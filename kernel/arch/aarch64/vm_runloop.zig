//! aarch64 vCPU run-loop driver.
//!
//! Stitches the per-arch EL2 world-switch (`hyp.vmResume`) to the
//! kernel's per-vCPU storage (`hv.vcpu.VcpuArchState`) and the per-VM
//! control state (stage-2 root + control block) pinned on
//! `VirtualMachine.arch_state` via `hv.vm.allocVmArchState`. Exit
//! reasons are decoded by `vm.zig`'s ESR_EL2 walker into the cross-arch
//! `vm_hw.VmExitInfo`; this module folds that into the spec-v3
//! §[vm_exit_state] sub-code + 3-vreg payload the scheduler hands to
//! `sched.port.fireVmExit`.

const std = @import("std");
const stygia = @import("stygia");

const hv_vcpu = stygia.arch.aarch64.hv.vcpu;
const hv_vm = stygia.arch.aarch64.hv.vm;
const hyp = stygia.arch.aarch64.hyp;
const kprof = stygia.kprof.trace_id;
const psci = stygia.arch.aarch64.hv.psci;
const vgic = stygia.arch.aarch64.hv.vgic;
const vm_hw = stygia.arch.aarch64.vm;

/// GICv3 PPI 27 = virtual timer (CNTV) interrupt. Linux's arm_arch_timer
/// driver wires `arch_timer_handler_virt` to PPI 27 by default.
const VTIMER_PPI: u32 = 27;

/// CNTV_CTL_EL0 bit definitions (ARM ARM D13.11.17).
const CNTV_CTL_ENABLE: u64 = 1 << 0;
const CNTV_CTL_IMASK: u64 = 1 << 1;
const CNTV_CTL_ISTATUS: u64 = 1 << 2;

const ExecutionContext = stygia.sched.execution_context.ExecutionContext;
const GuestState = vm_hw.GuestState;
const PAddr = stygia.memory.address.PAddr;
const VirtualMachine = stygia.hv.virtual_machine.VirtualMachine;
const VmExitInfo = vm_hw.VmExitInfo;

/// VM-exit delivery descriptor returned by `enterGuest`. Mirror of the
/// dispatch-tier alias in `stygia.arch.dispatch.vm.VmExitDelivery` — the
/// type lives here so the dispatch layer remains a pure aliasing shim.
/// Layout follows spec §[vm_exit_state] aarch64 sub-codes.
pub const VmExitDelivery = struct {
    subcode: u8,
    payload: [3]u64,
};

// §[vm_exit_state] aarch64 sub-codes (mirror of the table in the spec).
const SUBCODE_STAGE2_FAULT: u8 = 0;
const SUBCODE_HVC: u8 = 1;
const SUBCODE_SMC: u8 = 2;
const SUBCODE_SYSREG: u8 = 3;
const SUBCODE_WFI_WFE: u8 = 4;
const SUBCODE_UNKNOWN_EC: u8 = 5;
const SUBCODE_SYNC_EL1: u8 = 6;
const SUBCODE_HALT: u8 = 7;
const SUBCODE_SHUTDOWN: u8 = 8;
const SUBCODE_UNKNOWN: u8 = 9;
const SUBCODE_INITIAL_STATE: u8 = 10;

/// Enter the guest bound to `vcpu_ec` and return on the next VM exit.
/// Returns `null` if the VM or its arch state is missing (creator
/// teardown raced us, or the platform doesn't support EL2).
pub fn enterGuest(vcpu_ec: *ExecutionContext) ?VmExitDelivery {
    kprof.enter(.vm_enter);
    defer kprof.exit(.vm_enter);

    if (!vm_hw.vmSupported()) return null;

    const arch_state = hv_vcpu.archStateOf(vcpu_ec) orelse return null;

    if (!arch_state.started) return null;

    // Defer real `hvc_vcpu_run` until the VMM has supplied initial
    // guest state via reply. Otherwise we would ERET into a zeroed PC
    // and trip a stage-1 instruction-abort immediately. The synthetic-
    // exit fallback is the spec-test path before reply→GuestState
    // writeback is wired; once that lands, this guard flips on reply.
    const vm_ref = vcpu_ec.vm orelse return null;
    // caller-pinned: the vCPU EC holds a SlabRef on its VM for its lifetime;
    // the run loop is the only consumer that needs the live pointer.
    const vm_ptr = vm_ref.lock(@src()) catch return null;
    const cb_pa_opt = controlBlockPaFor(vm_ptr);
    const stage2_root = vm_ptr.guest_pt_root;
    // Capture the cell pointer under the VM lock; the cell is freed
    // only by `freeVmArchState` in the VM teardown path, which cannot
    // run while a vCPU EC holds a SlabRef on the VM (that's the
    // creator-domain lifetime contract). Safe to use post-unlock.
    const cell_opt: ?*hv_vm.CtrlStateCell = hv_vm.cellOf(vm_ptr);
    vm_ref.unlock();

    const cb_pa = cb_pa_opt orelse return null;
    if (stage2_root.addr == 0) return null;

    // EL2 runs with SCTLR_EL2.M=0 — every pointer handed to the world
    // switch is dereferenced as a raw PA. The vgic + vtimer shadows
    // live in the slab/heap (kernel VA); we walk the kernel page
    // tables to resolve their PAs once and pass them through
    // `WorldSwitchCtx` so `hvc_vcpu_run` / `guest_exit_entry` can
    // load/save them inline rather than via four extra HVC trips.
    const vgic_shadow_pa = hyp.resolveKernelVaToPa(@intFromPtr(&arch_state.vgic_shadow));
    const vtimer_pa = hyp.resolveKernelVaToPa(@intFromPtr(&arch_state.vtimer));

    // Lazy-init num_lrs on first run via ICH_VTR_EL2 readback. The
    // hyp stub `hvc_vgic_detect_lrs` reads `(ICH_VTR_EL2.ListRegs + 1)`
    // and returns it in x0. Cortex-A72 TCG implements 4; the spec
    // allows 1..16. We size the shadow to MAX_LRS so the same struct
    // works across hosts; only `num_lrs` of them are actually
    // load/saved by the inline LR loops in hvc_vcpu_run.
    if (arch_state.vgic_shadow.num_lrs == 0) {
        arch_state.vgic_shadow.num_lrs = vm_hw.hypCall(.vgic_detect_lrs, 0);
        // Force ICH_HCR_EL2.En = 1 so virtual interrupts in the LRs
        // actually deliver. Other ICH_HCR bits left zero — Linux
        // doesn't depend on maintenance-IRQ generation for vtimer.
        arch_state.vgic_shadow.hcr = 1;
    }

    // PSCI inline-handle loop: hvc with x0 ∈ PSCI range gets resolved
    // here without a vm_exit round-trip; every other exit reason
    // surfaces to the VMM. Mirrors x86's MMIO inline-handle path.
    while (true) {
        // If the guest's virtual timer would have fired (ISTATUS=1
        // observed at last exit), inject PPI 27 into LR0 so Linux's
        // arch_timer driver runs its tick on the next entry. Mask
        // the timer so it doesn't keep firing while pending — Linux
        // unmasks via cntv_ctl write once it ACKs and re-arms CVAL.
        if ((arch_state.vtimer.cntv_ctl_el0 & CNTV_CTL_ENABLE) != 0 and
            (arch_state.vtimer.cntv_ctl_el0 & CNTV_CTL_ISTATUS) != 0 and
            (arch_state.vtimer.cntv_ctl_el0 & CNTV_CTL_IMASK) == 0)
        {
            arch_state.vgic_shadow.lrs[0] = vgic.lrPendingGroup1(VTIMER_PPI);
            arch_state.vtimer.cntv_ctl_el0 |= CNTV_CTL_IMASK;
        }

        // §[vm_inject_irq] aarch64: any IRQ asserted via `vmInjectIrq`
        // lives as a pending bit on the per-VM vGIC distributor (Arm
        // IHI 0069H §12.9.28). The CPU interface only sees interrupts
        // through list-registers (Arm IHI 0069H §11.2 ICH_LR<n>_EL2),
        // so pre-entry we must walk the pending bitmap and stage the
        // highest-priority pending INTIDs into free LR slots. Without
        // this scan `vmInjectIrq` is a no-op for the guest beyond the
        // hard-coded vtimer PPI path above.
        //
        // Priority + grouping note: GICv3 lets the distributor program
        // per-INTID priority via GICD_IPRIORITYR<n>; the in-kernel
        // distributor model is bare-bones today (pending bit only),
        // so "highest priority" reduces to "lowest INTID" — Linux's
        // GIC driver writes IPRIORITYR but our run-loop hasn't grown
        // the priority shadow yet, and SGIs/PPIs (low INTIDs) outrank
        // SPIs (high INTIDs) in the architectural default precedence
        // anyway (Arm IHI 0069H §4.8). All entries are staged as
        // Group-1 virtual interrupts (the EL1-bound class Linux
        // arms via ICC_IGRPEN1_EL1=1).
        if (cell_opt) |cell| {
            // Find the lowest free LR. Slots already populated by the
            // vtimer fast-path above keep their entries — the priority
            // inversion of staging vtimer first is intentional (vtimer
            // maps to PPI 27 and is the boot-time hot interrupt).
            var lr_slot: usize = 0;
            const num_lrs: usize = @intCast(arch_state.vgic_shadow.num_lrs);
            while (lr_slot < num_lrs and vgic.lrState(arch_state.vgic_shadow.lrs[lr_slot]) != 0) : (lr_slot += 1) {}

            if (lr_slot < num_lrs) {
                // Walk pending bitmap word-by-word, low INTID first.
                var word_idx: u16 = 0;
                outer: while (word_idx < vgic.NUM_PENDING_WORDS) : (word_idx += 1) {
                    const w = @atomicLoad(u32, &cell.vgic.pending[word_idx], .acquire);
                    if (w == 0) continue;
                    var bit: u5 = 0;
                    while (true) {
                        if ((w & (@as(u32, 1) << bit)) != 0) {
                            const intid: u16 = word_idx * 32 + bit;
                            if (cell.vgic.takePending(intid)) {
                                arch_state.vgic_shadow.lrs[lr_slot] = vgic.lrPendingGroup1(@as(u32, intid));
                                lr_slot += 1;
                                if (lr_slot >= num_lrs) break :outer;
                            }
                        }
                        if (bit == 31) break;
                        bit += 1;
                    }
                }
            }
        }

        // Pre-entry: flush vGIC list-registers + vtimer state via separate
        // HVCs (kept distinct from `hvc_vcpu_run` so the world-switch path
        // matches the f33af271 layout that booted Linux to busybox under
        // TCG; the inlined variant deadlocks TCG when ICH_HCR_EL2 ops run
        // while stage-2 is still active).
        _ = vm_hw.hypCall(.vgic_prepare_entry, vgic_shadow_pa);
        _ = vm_hw.hypCall(.vtimer_load_guest, vtimer_pa);

        const exit_info = hyp.vmResume(
            &arch_state.guest_state,
            stage2_root,
            cb_pa,
            &arch_state.guest_fpsimd,
            &arch_state.arch_scratch,
        );

        // Post-exit: snapshot vtimer, then vGIC. Order mirrors KVM's
        // arch_timer.c timer_save_state / vgic_save_exit: timer first
        // so a pending CNTV match doesn't fire into host EL1 while the
        // vGIC restore runs.
        _ = vm_hw.hypCall(.vtimer_save_guest, vtimer_pa);
        _ = vm_hw.hypCall(.vgic_save_exit, vgic_shadow_pa);
        arch_state.last_exit = exit_info;

        switch (exit_info) {
            .hvc => |h| {
                // Only HVC #0 carries an SMCCC function ID in x0; other
                // immediates are out-of-band and forwarded to the VMM.
                if (h.imm == 0 and psci.isPsciFid(@truncate(arch_state.guest_state.x0))) {
                    switch (psci.dispatch(&arch_state.guest_state)) {
                        .handled => {
                            // ELR_EL2 already advanced past HVC by hardware;
                            // PC has been reloaded from ELR_EL2 into
                            // GuestState.pc by the world-switch save path,
                            // so re-enter the guest immediately.
                            continue;
                        },
                        .forward_to_vmm => {},
                    }
                }
                return decodeDelivery(exit_info, &arch_state.guest_state);
            },
            .unknown => |raw| {
                // `irq_exit_entry` writes `IRQ_EXIT_SENTINEL` (all-ones)
                // into ctx.exit_esr to flag an async exit (IRQ / FIQ /
                // SError). The pending physical IRQ was taken by the
                // host's EL1 vector during the EL2→EL1 ERET (HCR_EL2.IMO
                // was cleared on the exit path), so re-enter the guest
                // at the same PC — ELR_EL2 was the about-to-execute
                // instruction, so PC is correct as-is. Without this,
                // every async exit decodes as `unknown` and the VMM
                // would advance PC by 4, silently skipping a guest
                // instruction per host-tick.
                if (raw == hyp.IRQ_EXIT_SENTINEL) continue;
                return decodeDelivery(exit_info, &arch_state.guest_state);
            },
            .wfi_wfe => {
                // Inline-handle WFI/WFE — advance past the hint and
                // re-enter. ARM ARM B1.5: WFI is a hint, not a state
                // change. With HCR.TWI=1 every guest WFI traps; we
                // skip it because we have no virtual-timer injection
                // yet — letting WFI block (TWI=0 + halt) or surfacing
                // each iteration to the VMM both wedge the boot.
                arch_state.guest_state.pc +%= 4;
                continue;
            },
            .stage2_fault => |s| {
                // Inline-handle PL011 MMIO so the guest console TX loop
                // doesn't roundtrip to the VMM per character. Mirrors x64's
                // tryHandleMmio for kernel-emulated LAPIC/IOAPIC.
                const iss_valid = (s.flags & vm_hw.VmExitInfo.Stage2Fault.FLAG_ISS_VALID) != 0;
                const is_write = (s.flags & vm_hw.VmExitInfo.Stage2Fault.FLAG_IS_WRITE) != 0;
                if (vcpu_ec.vm) |vm_ref_inner| {
                    if (vm_ref_inner.lock(@src())) |vm_ptr_inner| {
                        const handled = hv_vm.tryHandleStage2Mmio(vm_ptr_inner, vcpu_ec, s.guest_phys, iss_valid, is_write, s.srt);
                        vm_ref_inner.unlock();
                        if (handled) {
                            // Advance past the trapping instruction. A64
                            // instructions are always 32-bit (ARM ARM B2.5.4),
                            // so unconditional +4 is safe.
                            arch_state.guest_state.pc +%= 4;
                            continue;
                        }
                    } else |_| {}
                }
                return decodeDelivery(exit_info, &arch_state.guest_state);
            },
            // §[vm_policy] aarch64 sysreg lookup. ID registers (per
            // ARM ARM C5.3 and §[vm_policy] semantics) consult
            // `id_reg_responses`; all other sysregs consult
            // `sysreg_policies`. On match the kernel resolves the trap
            // inline (return canned value on MRS, swallow MSR per the
            // spec's "applied masked by write_mask" / "writes to ID
            // registers are silently ignored" rules), advances PC by
            // the fixed 32-bit A64 instruction width, and re-enters.
            // On miss the trap surfaces to the VMM as `.sysreg_trap`
            // per §[vm_exit_state].
            .sysreg_trap => |t| {
                if (vcpu_ec.vm) |vm_ref_inner| {
                    if (vm_ref_inner.lock(@src())) |vm_ptr_inner| {
                        const handled = tryHandleSysregPolicy(vm_ptr_inner, &arch_state.guest_state, t);
                        vm_ref_inner.unlock();
                        if (handled) {
                            arch_state.guest_state.pc +%= 4;
                            continue;
                        }
                    } else |_| {}
                }
                return decodeDelivery(exit_info, &arch_state.guest_state);
            },
            else => return decodeDelivery(exit_info, &arch_state.guest_state),
        }
    }
}

fn controlBlockPaFor(vm_ptr: *VirtualMachine) ?PAddr {
    const erased = vm_ptr.arch_state orelse return null;
    const cell: *hv_vm.CtrlStateCell = @ptrCast(@alignCast(erased));
    if (cell.control_block_pa.addr == 0) return null;
    return cell.control_block_pa;
}

// ---------------------------------------------------------------------------
// §[vm_exit_state] aarch64 vreg layout
// ---------------------------------------------------------------------------
//
// vregs 1..31 = x0..x30 (kernel iret frame holds x1..x30 via the
// per-EC `ctx`; x0 rides on the syscall return word).
// vregs 32..127 spill onto the user stack starting at [sp + 8].

const VREG32_PC_OFF: u64 = 8; // (32-31)*8
const VREG33_PSTATE_OFF: u64 = 16;
const VREG34_SP_EL0_OFF: u64 = 24;
const VREG35_SP_EL1_OFF: u64 = 32;
// vregs 36..54 — 19 EL1 sysregs starting at [sp+40] (8 bytes each).
const VREG36_SCTLR_EL1_OFF: u64 = 40;
const VREG37_TTBR0_EL1_OFF: u64 = 48;
const VREG38_TTBR1_EL1_OFF: u64 = 56;
const VREG39_TCR_EL1_OFF: u64 = 64;
const VREG40_MAIR_EL1_OFF: u64 = 72;
const VREG41_AMAIR_EL1_OFF: u64 = 80;
const VREG42_CPACR_EL1_OFF: u64 = 88;
const VREG43_CONTEXTIDR_EL1_OFF: u64 = 96;
const VREG44_TPIDR_EL0_OFF: u64 = 104;
const VREG45_TPIDR_EL1_OFF: u64 = 112;
const VREG46_TPIDRRO_EL0_OFF: u64 = 120;
const VREG47_VBAR_EL1_OFF: u64 = 128;
const VREG48_ELR_EL1_OFF: u64 = 136;
const VREG49_SPSR_EL1_OFF: u64 = 144;
const VREG50_ESR_EL1_OFF: u64 = 152;
const VREG51_FAR_EL1_OFF: u64 = 160;
const VREG52_AFSR0_EL1_OFF: u64 = 168;
const VREG53_AFSR1_EL1_OFF: u64 = 176;
const VREG54_MDSCR_EL1_OFF: u64 = 184;
// vreg 55..73: MIDR/MPIDR/REVIDR + ID_AA64* — read-only, projected as
// zero from GuestState (no fields stored). Receivers that care fetch
// these via VmPolicy.id_reg_responses instead.
// vreg 74..81: timer regs.
const VREG74_CNTV_CVAL_EL0_OFF: u64 = 344;
const VREG75_CNTV_CTL_EL0_OFF: u64 = 352;
// vregs 76..78 (CNTV_TVAL/CNTP_CVAL/CNTP_CTL): not in GuestState; project zero.
const VREG79_CNTP_TVAL_EL0_OFF: u64 = 384;
const VREG80_CNTKCTL_EL1_OFF: u64 = 392;
const VREG81_CNTVOFF_EL2_OFF: u64 = 400;
// vregs 82..115 reserved for debug/PMU regs not stored in GuestState.
const VREG117_EXIT_SUBCODE_OFF: u64 = 688;
const VREG118_EXIT_PAYLOAD_0_OFF: u64 = 696;
const VREG119_EXIT_PAYLOAD_1_OFF: u64 = 704;
const VREG120_EXIT_PAYLOAD_2_OFF: u64 = 712;

// Last byte read by `snapshotReplyVregs`. Receivers that haven't reserved
// at least this much stack above their `user_sp` cannot supply a full
// snapshot without faulting.
const WIDE_VREG_END_OFF: u64 = VREG81_CNTVOFF_EL2_OFF + 8;

fn loadU64(sp: u64, off: u64) u64 {
    const ptr: *const u64 = @ptrFromInt(sp + off);
    return ptr.*;
}
fn storeU64(sp: u64, off: u64, value: u64) void {
    const ptr: *u64 = @ptrFromInt(sp + off);
    ptr.* = value;
}

/// Plain-data snapshot of the receiver's §[vm_exit_state] vregs,
/// captured outside the sender EC's `_gen_lock` so a fault on user-stack
/// reads can't strand the lock bit. `applyReplyStateToVcpu` projects
/// this snapshot onto the vCPU's GuestState under the sender lock.
pub const ReplyVregSnapshot = extern struct {
    // Register-backed vregs 1..31 = x0..x30 (snapshot kept aligned to
    // GuestState's GPR field order so the projection is a memcpy-shape).
    x: [31]u64 = .{0} ** 31,
    pc: u64 = 0,
    pstate: u64 = 0,
    sp_el0: u64 = 0,
    sp_el1: u64 = 0,
    sctlr_el1: u64 = 0,
    ttbr0_el1: u64 = 0,
    ttbr1_el1: u64 = 0,
    tcr_el1: u64 = 0,
    mair_el1: u64 = 0,
    amair_el1: u64 = 0,
    cpacr_el1: u64 = 0,
    contextidr_el1: u64 = 0,
    tpidr_el0: u64 = 0,
    tpidr_el1: u64 = 0,
    tpidrro_el0: u64 = 0,
    vbar_el1: u64 = 0,
    elr_el1: u64 = 0,
    spsr_el1: u64 = 0,
    esr_el1: u64 = 0,
    far_el1: u64 = 0,
    afsr0_el1: u64 = 0,
    afsr1_el1: u64 = 0,
    mdscr_el1: u64 = 0,
    cntv_cval_el0: u64 = 0,
    cntv_ctl_el0: u64 = 0,
    cntkctl_el1: u64 = 0,
    cntvoff_el2: u64 = 0,
    /// Exit sub-code the receiver wrote at vreg 117 — the spec
    /// `initial_state` value (10 on aarch64) signals "stay not-started"
    /// so `applyReplyStateToVcpu` keeps `arch_state.started = false`.
    exit_subcode: u64 = 0,
};

/// Snapshot the receiver's §[vm_exit_state] vregs into a kernel-stack
/// buffer. Reads receiver-side state only. Receiver MUST be the running
/// EC on the current core (so its address space is live).
///
/// Caller MUST only invoke this for vm_exit-typed replies. The receiver
/// opted into the wide window contract by recv'ing a vm_exit; if their
/// stack reservation is too small the user-VA reads fault and
/// `memory.fault.handlePageFault` aborts the syscall — safe because we
/// run BEFORE acquiring the sender's `_gen_lock`.
pub fn snapshotReplyVregs(receiver: *ExecutionContext) ReplyVregSnapshot {
    var snap: ReplyVregSnapshot = .{};
    const recv_frame = receiver.iret_frame orelse receiver.ctx;

    // vregs 1..31 = x0..x30 — sourced from the kernel's saved iret frame.
    snap.x[0] = recv_frame.regs.x0;
    snap.x[1] = recv_frame.regs.x1;
    snap.x[2] = recv_frame.regs.x2;
    snap.x[3] = recv_frame.regs.x3;
    snap.x[4] = recv_frame.regs.x4;
    snap.x[5] = recv_frame.regs.x5;
    snap.x[6] = recv_frame.regs.x6;
    snap.x[7] = recv_frame.regs.x7;
    snap.x[8] = recv_frame.regs.x8;
    snap.x[9] = recv_frame.regs.x9;
    snap.x[10] = recv_frame.regs.x10;
    snap.x[11] = recv_frame.regs.x11;
    snap.x[12] = recv_frame.regs.x12;
    snap.x[13] = recv_frame.regs.x13;
    snap.x[14] = recv_frame.regs.x14;
    snap.x[15] = recv_frame.regs.x15;
    snap.x[16] = recv_frame.regs.x16;
    snap.x[17] = recv_frame.regs.x17;
    snap.x[18] = recv_frame.regs.x18;
    snap.x[19] = recv_frame.regs.x19;
    snap.x[20] = recv_frame.regs.x20;
    snap.x[21] = recv_frame.regs.x21;
    snap.x[22] = recv_frame.regs.x22;
    snap.x[23] = recv_frame.regs.x23;
    snap.x[24] = recv_frame.regs.x24;
    snap.x[25] = recv_frame.regs.x25;
    snap.x[26] = recv_frame.regs.x26;
    snap.x[27] = recv_frame.regs.x27;
    snap.x[28] = recv_frame.regs.x28;
    snap.x[29] = recv_frame.regs.x29;
    snap.x[30] = recv_frame.regs.x30;

    const sp = recv_frame.sp_el0;

    snap.pc = loadU64(sp, VREG32_PC_OFF);
    snap.pstate = loadU64(sp, VREG33_PSTATE_OFF);
    snap.sp_el0 = loadU64(sp, VREG34_SP_EL0_OFF);
    snap.sp_el1 = loadU64(sp, VREG35_SP_EL1_OFF);
    snap.sctlr_el1 = loadU64(sp, VREG36_SCTLR_EL1_OFF);
    snap.ttbr0_el1 = loadU64(sp, VREG37_TTBR0_EL1_OFF);
    snap.ttbr1_el1 = loadU64(sp, VREG38_TTBR1_EL1_OFF);
    snap.tcr_el1 = loadU64(sp, VREG39_TCR_EL1_OFF);
    snap.mair_el1 = loadU64(sp, VREG40_MAIR_EL1_OFF);
    snap.amair_el1 = loadU64(sp, VREG41_AMAIR_EL1_OFF);
    snap.cpacr_el1 = loadU64(sp, VREG42_CPACR_EL1_OFF);
    snap.contextidr_el1 = loadU64(sp, VREG43_CONTEXTIDR_EL1_OFF);
    snap.tpidr_el0 = loadU64(sp, VREG44_TPIDR_EL0_OFF);
    snap.tpidr_el1 = loadU64(sp, VREG45_TPIDR_EL1_OFF);
    snap.tpidrro_el0 = loadU64(sp, VREG46_TPIDRRO_EL0_OFF);
    snap.vbar_el1 = loadU64(sp, VREG47_VBAR_EL1_OFF);
    snap.elr_el1 = loadU64(sp, VREG48_ELR_EL1_OFF);
    snap.spsr_el1 = loadU64(sp, VREG49_SPSR_EL1_OFF);
    snap.esr_el1 = loadU64(sp, VREG50_ESR_EL1_OFF);
    snap.far_el1 = loadU64(sp, VREG51_FAR_EL1_OFF);
    snap.afsr0_el1 = loadU64(sp, VREG52_AFSR0_EL1_OFF);
    snap.afsr1_el1 = loadU64(sp, VREG53_AFSR1_EL1_OFF);
    snap.mdscr_el1 = loadU64(sp, VREG54_MDSCR_EL1_OFF);
    snap.cntv_cval_el0 = loadU64(sp, VREG74_CNTV_CVAL_EL0_OFF);
    snap.cntv_ctl_el0 = loadU64(sp, VREG75_CNTV_CTL_EL0_OFF);
    snap.cntkctl_el1 = loadU64(sp, VREG80_CNTKCTL_EL1_OFF);
    snap.cntvoff_el2 = loadU64(sp, VREG81_CNTVOFF_EL2_OFF);
    snap.exit_subcode = loadU64(sp, VREG117_EXIT_SUBCODE_OFF);

    return snap;
}

/// Project a `ReplyVregSnapshot` onto a vCPU's GuestState. Pure memory
/// writes — no user-VA access, so safe under the sender's `_gen_lock`.
/// Spec §[reply] initial-state handshake: when the receiver wrote
/// `initial_state` (sub-code 10 on aarch64) into vreg 117, the kernel
/// keeps `arch_state.started = false` so the next `enterGuest` falls
/// back to synthetic-exit re-delivery instead of ERETing with the
/// zero-initialized state. Any other sub-code projects the full state
/// and flips `started = true`.
pub fn applyReplyStateToVcpu(vcpu_ec: *ExecutionContext, snap: *const ReplyVregSnapshot) void {
    const arch_state = hv_vcpu.archStateOf(vcpu_ec) orelse return;
    const gs = &arch_state.guest_state;

    // x0..x30 — projected from the snapshot's contiguous gpr block.
    gs.x0 = snap.x[0];
    gs.x1 = snap.x[1];
    gs.x2 = snap.x[2];
    gs.x3 = snap.x[3];
    gs.x4 = snap.x[4];
    gs.x5 = snap.x[5];
    gs.x6 = snap.x[6];
    gs.x7 = snap.x[7];
    gs.x8 = snap.x[8];
    gs.x9 = snap.x[9];
    gs.x10 = snap.x[10];
    gs.x11 = snap.x[11];
    gs.x12 = snap.x[12];
    gs.x13 = snap.x[13];
    gs.x14 = snap.x[14];
    gs.x15 = snap.x[15];
    gs.x16 = snap.x[16];
    gs.x17 = snap.x[17];
    gs.x18 = snap.x[18];
    gs.x19 = snap.x[19];
    gs.x20 = snap.x[20];
    gs.x21 = snap.x[21];
    gs.x22 = snap.x[22];
    gs.x23 = snap.x[23];
    gs.x24 = snap.x[24];
    gs.x25 = snap.x[25];
    gs.x26 = snap.x[26];
    gs.x27 = snap.x[27];
    gs.x28 = snap.x[28];
    gs.x29 = snap.x[29];
    gs.x30 = snap.x[30];

    gs.pc = snap.pc;
    gs.pstate = snap.pstate;
    gs.sp_el0 = snap.sp_el0;
    gs.sp_el1 = snap.sp_el1;

    gs.sctlr_el1 = snap.sctlr_el1;
    gs.ttbr0_el1 = snap.ttbr0_el1;
    gs.ttbr1_el1 = snap.ttbr1_el1;
    gs.tcr_el1 = snap.tcr_el1;
    gs.mair_el1 = snap.mair_el1;
    gs.amair_el1 = snap.amair_el1;
    gs.cpacr_el1 = snap.cpacr_el1;
    gs.contextidr_el1 = snap.contextidr_el1;
    gs.tpidr_el0 = snap.tpidr_el0;
    gs.tpidr_el1 = snap.tpidr_el1;
    gs.tpidrro_el0 = snap.tpidrro_el0;
    gs.vbar_el1 = snap.vbar_el1;
    gs.elr_el1 = snap.elr_el1;
    gs.spsr_el1 = snap.spsr_el1;
    gs.esr_el1 = snap.esr_el1;
    gs.far_el1 = snap.far_el1;
    gs.afsr0_el1 = snap.afsr0_el1;
    gs.afsr1_el1 = snap.afsr1_el1;
    gs.mdscr_el1 = snap.mdscr_el1;

    gs.cntv_cval_el0 = snap.cntv_cval_el0;
    gs.cntv_ctl_el0 = snap.cntv_ctl_el0;
    gs.cntkctl_el1 = snap.cntkctl_el1;
    gs.cntvoff_el2 = snap.cntvoff_el2;

    if (snap.exit_subcode == stygia.hv.virtual_machine.INITIAL_STATE_SUBCODE) return;
    arch_state.started = true;
}

/// Write the suspending vCPU's GuestState onto the receiver's
/// §[vm_exit_state] vreg slots. Companion to `applyReplyStateToVcpu`.
pub fn populateVmExitVregs(
    receiver: *ExecutionContext,
    vcpu_ec: *ExecutionContext,
    subcode: u8,
    payload: [3]u64,
) void {
    const arch_state = hv_vcpu.archStateOf(vcpu_ec) orelse return;
    const gs = &arch_state.guest_state;
    const recv_frame = receiver.iret_frame orelse receiver.ctx;

    // vregs 1..31 = x0..x30 — register-backed.
    recv_frame.regs.x0 = gs.x0;
    recv_frame.regs.x1 = gs.x1;
    recv_frame.regs.x2 = gs.x2;
    recv_frame.regs.x3 = gs.x3;
    recv_frame.regs.x4 = gs.x4;
    recv_frame.regs.x5 = gs.x5;
    recv_frame.regs.x6 = gs.x6;
    recv_frame.regs.x7 = gs.x7;
    recv_frame.regs.x8 = gs.x8;
    recv_frame.regs.x9 = gs.x9;
    recv_frame.regs.x10 = gs.x10;
    recv_frame.regs.x11 = gs.x11;
    recv_frame.regs.x12 = gs.x12;
    recv_frame.regs.x13 = gs.x13;
    recv_frame.regs.x14 = gs.x14;
    recv_frame.regs.x15 = gs.x15;
    recv_frame.regs.x16 = gs.x16;
    recv_frame.regs.x17 = gs.x17;
    recv_frame.regs.x18 = gs.x18;
    recv_frame.regs.x19 = gs.x19;
    recv_frame.regs.x20 = gs.x20;
    recv_frame.regs.x21 = gs.x21;
    recv_frame.regs.x22 = gs.x22;
    recv_frame.regs.x23 = gs.x23;
    recv_frame.regs.x24 = gs.x24;
    recv_frame.regs.x25 = gs.x25;
    recv_frame.regs.x26 = gs.x26;
    recv_frame.regs.x27 = gs.x27;
    recv_frame.regs.x28 = gs.x28;
    recv_frame.regs.x29 = gs.x29;
    recv_frame.regs.x30 = gs.x30;

    const sp = recv_frame.sp_el0;

    storeU64(sp, VREG32_PC_OFF, gs.pc);
    storeU64(sp, VREG33_PSTATE_OFF, gs.pstate);
    storeU64(sp, VREG34_SP_EL0_OFF, gs.sp_el0);
    storeU64(sp, VREG35_SP_EL1_OFF, gs.sp_el1);

    storeU64(sp, VREG36_SCTLR_EL1_OFF, gs.sctlr_el1);
    storeU64(sp, VREG37_TTBR0_EL1_OFF, gs.ttbr0_el1);
    storeU64(sp, VREG38_TTBR1_EL1_OFF, gs.ttbr1_el1);
    storeU64(sp, VREG39_TCR_EL1_OFF, gs.tcr_el1);
    storeU64(sp, VREG40_MAIR_EL1_OFF, gs.mair_el1);
    storeU64(sp, VREG41_AMAIR_EL1_OFF, gs.amair_el1);
    storeU64(sp, VREG42_CPACR_EL1_OFF, gs.cpacr_el1);
    storeU64(sp, VREG43_CONTEXTIDR_EL1_OFF, gs.contextidr_el1);
    storeU64(sp, VREG44_TPIDR_EL0_OFF, gs.tpidr_el0);
    storeU64(sp, VREG45_TPIDR_EL1_OFF, gs.tpidr_el1);
    storeU64(sp, VREG46_TPIDRRO_EL0_OFF, gs.tpidrro_el0);
    storeU64(sp, VREG47_VBAR_EL1_OFF, gs.vbar_el1);
    storeU64(sp, VREG48_ELR_EL1_OFF, gs.elr_el1);
    storeU64(sp, VREG49_SPSR_EL1_OFF, gs.spsr_el1);
    storeU64(sp, VREG50_ESR_EL1_OFF, gs.esr_el1);
    storeU64(sp, VREG51_FAR_EL1_OFF, gs.far_el1);
    storeU64(sp, VREG52_AFSR0_EL1_OFF, gs.afsr0_el1);
    storeU64(sp, VREG53_AFSR1_EL1_OFF, gs.afsr1_el1);
    storeU64(sp, VREG54_MDSCR_EL1_OFF, gs.mdscr_el1);

    storeU64(sp, VREG74_CNTV_CVAL_EL0_OFF, gs.cntv_cval_el0);
    storeU64(sp, VREG75_CNTV_CTL_EL0_OFF, gs.cntv_ctl_el0);
    storeU64(sp, VREG80_CNTKCTL_EL1_OFF, gs.cntkctl_el1);
    storeU64(sp, VREG81_CNTVOFF_EL2_OFF, gs.cntvoff_el2);

    storeU64(sp, VREG117_EXIT_SUBCODE_OFF, @as(u64, subcode));
    storeU64(sp, VREG118_EXIT_PAYLOAD_0_OFF, payload[0]);
    storeU64(sp, VREG119_EXIT_PAYLOAD_1_OFF, payload[1]);
    storeU64(sp, VREG120_EXIT_PAYLOAD_2_OFF, payload[2]);
}

/// Dispatch-shim entrypoint: project the vCPU's full §[vm_exit_state]
/// onto the receiver's vregs only when the VMM has supplied initial
/// state (post-first-reply). Synthetic pre-started exits skip the
/// broad projection.
pub fn populateVmExitVregsIfStarted(
    receiver: *ExecutionContext,
    sender: *ExecutionContext,
    subcode: u8,
) void {
    const arch_state = hv_vcpu.archStateOf(sender) orelse return;
    if (!arch_state.started) return;
    populateVmExitVregs(receiver, sender, subcode, arch_state.last_exit_payload);
    receiver.pending_event_rip = 0;
    receiver.pending_event_rip_valid = false;
}

fn decodeDelivery(exit: VmExitInfo, gs: *const GuestState) VmExitDelivery {
    _ = gs;
    return switch (exit) {
        .stage2_fault => |s| .{
            .subcode = SUBCODE_STAGE2_FAULT,
            .payload = .{
                s.guest_phys,
                s.guest_virt,
                @as(u64, s.access_size) |
                    (@as(u64, s.srt) << 8) |
                    (@as(u64, s.fsc) << 16) |
                    (@as(u64, s.flags) << 24),
            },
        },
        .hvc => |h| .{
            .subcode = SUBCODE_HVC,
            .payload = .{ @as(u64, h.imm), 0, 0 },
        },
        .smc => |s| .{
            .subcode = SUBCODE_SMC,
            .payload = .{ @as(u64, s.imm), 0, 0 },
        },
        .sysreg_trap => |t| .{
            .subcode = SUBCODE_SYSREG,
            .payload = .{
                @as(u64, t.iss) |
                    (@as(u64, t.op0) << 32) |
                    (@as(u64, t.op1) << 34) |
                    (@as(u64, t.crn) << 37) |
                    (@as(u64, t.crm) << 41) |
                    (@as(u64, t.op2) << 45) |
                    (@as(u64, t.rt) << 48) |
                    (@as(u64, @intFromBool(t.is_read)) << 53),
                0,
                0,
            },
        },
        .wfi_wfe => |w| .{
            .subcode = SUBCODE_WFI_WFE,
            .payload = .{ @as(u64, @intFromBool(w.is_wfe)), 0, 0 },
        },
        .unknown_ec => |ec| .{
            .subcode = SUBCODE_UNKNOWN_EC,
            .payload = .{ @as(u64, ec), 0, 0 },
        },
        .synchronous_el1 => |esr| .{
            .subcode = SUBCODE_SYNC_EL1,
            .payload = .{ esr, 0, 0 },
        },
        .halt => .{ .subcode = SUBCODE_HALT, .payload = .{ 0, 0, 0 } },
        .shutdown => .{ .subcode = SUBCODE_SHUTDOWN, .payload = .{ 0, 0, 0 } },
        .unknown => |raw| .{
            .subcode = SUBCODE_UNKNOWN,
            .payload = .{ raw, 0, 0 },
        },
    };
}

/// Resolve the kernel-private `VmPolicy` table backing `vm`. Lives in
/// the per-VM CtrlStateCell so userspace cannot reach into it; copied
/// from `policy_pf` at create time and mutated via `applyVmPolicyTable`.
/// Returns `null` when no arch state has been seeded yet (e.g. a
/// teardown raced the run loop).
fn vmPolicyFor(vm_ptr: *VirtualMachine) ?*const vm_hw.VmPolicy {
    return hv_vm.vmPolicyFor(vm_ptr);
}

/// Write a guest GPR by index (Rt encoding, 0..31). Writes to index
/// 31 are silently dropped — that encoding is the zero register on
/// MRS Xt destinations (ARM ARM B1.2.1).
fn writeGuestGpr(gs: *vm_hw.GuestState, idx: u8, val: u64) void {
    switch (idx) {
        0 => gs.x0 = val,    1 => gs.x1 = val,    2 => gs.x2 = val,    3 => gs.x3 = val,
        4 => gs.x4 = val,    5 => gs.x5 = val,    6 => gs.x6 = val,    7 => gs.x7 = val,
        8 => gs.x8 = val,    9 => gs.x9 = val,    10 => gs.x10 = val,  11 => gs.x11 = val,
        12 => gs.x12 = val,  13 => gs.x13 = val,  14 => gs.x14 = val,  15 => gs.x15 = val,
        16 => gs.x16 = val,  17 => gs.x17 = val,  18 => gs.x18 = val,  19 => gs.x19 = val,
        20 => gs.x20 = val,  21 => gs.x21 = val,  22 => gs.x22 = val,  23 => gs.x23 = val,
        24 => gs.x24 = val,  25 => gs.x25 = val,  26 => gs.x26 = val,  27 => gs.x27 = val,
        28 => gs.x28 = val,  29 => gs.x29 = val,  30 => gs.x30 = val,
        else => {},
    }
}

/// Read a guest GPR by index. Index 31 reads as zero (the WZR/XZR
/// encoding on MSR Xt sources per ARM ARM B1.2.1).
fn readGuestGpr(gs: *const vm_hw.GuestState, idx: u8) u64 {
    return switch (idx) {
        0 => gs.x0,    1 => gs.x1,    2 => gs.x2,    3 => gs.x3,
        4 => gs.x4,    5 => gs.x5,    6 => gs.x6,    7 => gs.x7,
        8 => gs.x8,    9 => gs.x9,    10 => gs.x10,  11 => gs.x11,
        12 => gs.x12,  13 => gs.x13,  14 => gs.x14,  15 => gs.x15,
        16 => gs.x16,  17 => gs.x17,  18 => gs.x18,  19 => gs.x19,
        20 => gs.x20,  21 => gs.x21,  22 => gs.x22,  23 => gs.x23,
        24 => gs.x24,  25 => gs.x25,  26 => gs.x26,  27 => gs.x27,
        28 => gs.x28,  29 => gs.x29,  30 => gs.x30,
        else => 0,
    };
}

/// Resolve the (op0, op1, crn, crm, op2) sysreg tuple to a pointer at
/// the matching `GuestState` field. Returns `null` for sysregs without
/// a kernel-side shadow — caller swallows the masked write per the
/// §[vm_policy] aarch64 contract (no host-visible side effect; the
/// trap was still inline-handled, just no slot to persist into).
///
/// Encoding follows Arm ARM C5.3 system register identification
/// (op0:2, op1:3, crn:4, crm:4, op2:3 — packed into a u16 key for
/// switch dispatch).
fn sysregShadowOf(gs: *vm_hw.GuestState, op0: u2, op1: u3, crn: u4, crm: u4, op2: u3) ?*u64 {
    const key: u16 =
        (@as(u16, op0) << 14) |
        (@as(u16, op1) << 11) |
        (@as(u16, crn) << 7) |
        (@as(u16, crm) << 3) |
        @as(u16, op2);
    // (op0, op1, crn, crm, op2) → encoded key. Each comment cites the
    // Arm ARM section that fixes the encoding. Coverage matches the
    // GuestState fields above; sysregs the kernel doesn't shadow
    // (e.g. AMAIR_EL1 is IMPL DEF passthrough) return null.
    return switch (key) {
        // SCTLR_EL1: op0=3, op1=0, crn=1, crm=0, op2=0. ARM ARM D13.2.110.
        encSysreg(3, 0, 1, 0, 0) => &gs.sctlr_el1,
        // CPACR_EL1: op0=3, op1=0, crn=1, crm=0, op2=2. ARM ARM D13.2.28.
        encSysreg(3, 0, 1, 0, 2) => &gs.cpacr_el1,
        // TTBR0_EL1: op0=3, op1=0, crn=2, crm=0, op2=0. ARM ARM D13.2.145.
        encSysreg(3, 0, 2, 0, 0) => &gs.ttbr0_el1,
        // TTBR1_EL1: op0=3, op1=0, crn=2, crm=0, op2=1. ARM ARM D13.2.146.
        encSysreg(3, 0, 2, 0, 1) => &gs.ttbr1_el1,
        // TCR_EL1:   op0=3, op1=0, crn=2, crm=0, op2=2. ARM ARM D13.2.135.
        encSysreg(3, 0, 2, 0, 2) => &gs.tcr_el1,
        // AFSR0_EL1: op0=3, op1=0, crn=5, crm=1, op2=0. ARM ARM D13.2.13.
        encSysreg(3, 0, 5, 1, 0) => &gs.afsr0_el1,
        // AFSR1_EL1: op0=3, op1=0, crn=5, crm=1, op2=1. ARM ARM D13.2.14.
        encSysreg(3, 0, 5, 1, 1) => &gs.afsr1_el1,
        // ESR_EL1:   op0=3, op1=0, crn=5, crm=2, op2=0. ARM ARM D13.2.40.
        encSysreg(3, 0, 5, 2, 0) => &gs.esr_el1,
        // FAR_EL1:   op0=3, op1=0, crn=6, crm=0, op2=0. ARM ARM D13.2.46.
        encSysreg(3, 0, 6, 0, 0) => &gs.far_el1,
        // MAIR_EL1:  op0=3, op1=0, crn=10, crm=2, op2=0. ARM ARM D13.2.83.
        encSysreg(3, 0, 10, 2, 0) => &gs.mair_el1,
        // AMAIR_EL1: op0=3, op1=0, crn=10, crm=3, op2=0. ARM ARM D13.2.11.
        encSysreg(3, 0, 10, 3, 0) => &gs.amair_el1,
        // VBAR_EL1:  op0=3, op1=0, crn=12, crm=0, op2=0. ARM ARM D13.2.152.
        encSysreg(3, 0, 12, 0, 0) => &gs.vbar_el1,
        // CONTEXTIDR_EL1: op0=3, op1=0, crn=13, crm=0, op2=1. ARM ARM D13.2.26.
        encSysreg(3, 0, 13, 0, 1) => &gs.contextidr_el1,
        // TPIDR_EL1: op0=3, op1=0, crn=13, crm=0, op2=4. ARM ARM D13.2.140.
        encSysreg(3, 0, 13, 0, 4) => &gs.tpidr_el1,
        // TPIDR_EL0: op0=3, op1=3, crn=13, crm=0, op2=2. ARM ARM D13.2.139.
        encSysreg(3, 3, 13, 0, 2) => &gs.tpidr_el0,
        // TPIDRRO_EL0: op0=3, op1=3, crn=13, crm=0, op2=3. ARM ARM D13.2.141.
        encSysreg(3, 3, 13, 0, 3) => &gs.tpidrro_el0,
        // ELR_EL1:   op0=3, op1=0, crn=4, crm=0, op2=1. ARM ARM C5.2.8.
        encSysreg(3, 0, 4, 0, 1) => &gs.elr_el1,
        // SPSR_EL1:  op0=3, op1=0, crn=4, crm=0, op2=0. ARM ARM C5.2.18.
        encSysreg(3, 0, 4, 0, 0) => &gs.spsr_el1,
        // MDSCR_EL1: op0=2, op1=0, crn=0, crm=2, op2=2. ARM ARM D13.3.15.
        encSysreg(2, 0, 0, 2, 2) => &gs.mdscr_el1,
        // CNTKCTL_EL1: op0=3, op1=0, crn=14, crm=1, op2=0. ARM ARM D13.11.26.
        encSysreg(3, 0, 14, 1, 0) => &gs.cntkctl_el1,
        // CNTV_CVAL_EL0: op0=3, op1=3, crn=14, crm=3, op2=2. ARM ARM D13.11.18.
        encSysreg(3, 3, 14, 3, 2) => &gs.cntv_cval_el0,
        // CNTV_CTL_EL0:  op0=3, op1=3, crn=14, crm=3, op2=1. ARM ARM D13.11.17.
        encSysreg(3, 3, 14, 3, 1) => &gs.cntv_ctl_el0,
        else => null,
    };
}

/// Comptime-evaluable version of the sysreg key encoding used by the
/// switch arms in `sysregShadowOf`. Matches the runtime computation
/// bit-for-bit so the constant labels in the switch are exactly the
/// keys the dispatch loop computes.
fn encSysreg(op0: u2, op1: u3, crn: u4, crm: u4, op2: u3) u16 {
    return (@as(u16, op0) << 14) |
        (@as(u16, op1) << 11) |
        (@as(u16, crn) << 7) |
        (@as(u16, crm) << 3) |
        @as(u16, op2);
}

/// §[vm_policy] aarch64 sysreg lookup. The trapped tuple
/// `(op0, op1, crn, crm, op2)` is matched first against
/// `id_reg_responses[0..num_id_reg_responses]`: a hit on a read
/// (`is_read=true`) returns the entry's `value` into Xt; a hit on a
/// write swallows the MSR silently per "writes to ID registers are
/// silently ignored". On miss, the same tuple is matched against
/// `sysreg_policies[0..num_sysreg_policies]`: a read returns
/// `read_value`; a write applies `value & write_mask` to the
/// matching `GuestState` shadow per the spec's "applied masked by
/// write_mask" rule. Sysregs without a `GuestState` slot (e.g. impl-
/// def passthroughs) are inline-swallowed with no shadow update.
///
/// Returns true if any entry matched (caller advances PC and re-
/// enters); false if the trap must surface to the VMM.
///
/// Acquire-load on `num_*` pairs with the release-store in
/// `applyVmPolicyTable` so a concurrent `vm_set_policy` from another
/// core never races us into an OOB index — entries before the count
/// are always visible by the time we read the count.
fn tryHandleSysregPolicy(
    vm_ptr: *VirtualMachine,
    gs: *vm_hw.GuestState,
    t: vm_hw.VmExitInfo.SysregTrap,
) bool {
    const policy = vmPolicyFor(vm_ptr) orelse return false;

    // ID register table — keyed on (op0, op1, crn, crm, op2).
    {
        const n = @atomicLoad(u32, &policy.num_id_reg_responses, .acquire);
        const max: u32 = vm_hw.VmPolicy.MAX_ID_REG_RESPONSES;
        const limit: u32 = if (n > max) max else n;
        var i: u32 = 0;
        while (i < limit) : (i += 1) {
            const e = policy.id_reg_responses[i];
            if (e.op0 == @as(u8, t.op0) and
                e.op1 == @as(u8, t.op1) and
                e.crn == @as(u8, t.crn) and
                e.crm == @as(u8, t.crm) and
                e.op2 == @as(u8, t.op2))
            {
                if (t.is_read) {
                    writeGuestGpr(gs, t.rt, e.value);
                }
                // Writes to ID registers are silently ignored
                // (spec §[vm_policy] aarch64 semantics).
                return true;
            }
        }
    }

    // Sysreg policy table — keyed on (op0, op1, crn, crm, op2).
    {
        const n = @atomicLoad(u32, &policy.num_sysreg_policies, .acquire);
        const max: u32 = vm_hw.VmPolicy.MAX_SYSREG_POLICIES;
        const limit: u32 = if (n > max) max else n;
        var i: u32 = 0;
        while (i < limit) : (i += 1) {
            const e = policy.sysreg_policies[i];
            if (e.op0 == @as(u8, t.op0) and
                e.op1 == @as(u8, t.op1) and
                e.crn == @as(u8, t.crn) and
                e.crm == @as(u8, t.crm) and
                e.op2 == @as(u8, t.op2))
            {
                if (t.is_read) {
                    writeGuestGpr(gs, t.rt, e.read_value);
                } else if (sysregShadowOf(gs, t.op0, t.op1, t.crn, t.crm, t.op2)) |shadow| {
                    // §[vm_policy] aarch64 "applied masked by
                    // write_mask": `(shadow & ~mask) | (guest & mask)`
                    // updates only the bits the policy permits, leaving
                    // other bits at their pre-trap value. The shadow
                    // is reloaded into the live sysreg by the existing
                    // restore path on the next vmentry (the world-
                    // switch save/restore stage in `vm_runloop` treats
                    // GuestState as the ground truth between exits).
                    const guest_val = readGuestGpr(gs, t.rt);
                    const masked = guest_val & e.write_mask;
                    shadow.* = (shadow.* & ~e.write_mask) | masked;
                }
                // Sysregs without a GuestState shadow swallow the
                // write inline with no host-visible side effect —
                // mirrors the spec's "no vm_exit delivered" half of
                // the matched-write contract for unshadowed regs.
                return true;
            }
        }
    }

    return false;
}
