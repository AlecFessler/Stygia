//! Aarch64 VCpu dispatch backing.
//!
//! Per-vCPU arch state lives in a single 4 KiB PMM page hung off the EC's
//! `vcpu_arch_state` slot. Mirrors `kernel/arch/x64/hv/vcpu.zig` field-for-
//! field where x86 has FXSAVE/last_exit/payload/started; aarch64 swaps in
//! GuestState (vm.zig) + FPSIMD area + ArchScratch (hyp.zig) for the
//! world-switch context. The vGIC per-vCPU state is reserved for the
//! follow-up wave that wires GICv3 emulation.

const std = @import("std");
const zag = @import("zag");

const hyp = zag.arch.aarch64.hyp;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const vgic = zag.arch.aarch64.hv.vgic;
const vm_hw = zag.arch.aarch64.vm;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const FxsaveArea = vm_hw.FxsaveArea;
const GuestState = vm_hw.GuestState;
const VirtualMachine = zag.hv.virtual_machine.VirtualMachine;
const VmExitInfo = vm_hw.VmExitInfo;

pub const VcpuArchState = struct {
    /// Full guest GPR + EL1 sysreg snapshot. Round-trips across each
    /// `vmResume` call. Page-aligned so the world-switch save/restore asm
    /// can address it via a single base pointer.
    guest_state: GuestState align(paging.PAGE4K) = .{},
    /// FPSIMD V0..V31 + FPCR/FPSR backing for the guest. 16-byte aligned
    /// per the FXSAVE-shaped layout in `vm.FxsaveArea`.
    guest_fpsimd: FxsaveArea align(16) = .{0} ** 576,
    /// Scratch frame the world-switch path uses to bridge host ↔ guest
    /// register state (WorldSwitchCtx + HostSave + HostFpState).
    arch_scratch: hyp.ArchScratch align(16) = .{},
    /// Most-recent decoded VM-exit. Populated after every `vmResume`
    /// return so the surrounding run loop / VMM can re-decode without
    /// re-reading ESR_EL2 fields.
    last_exit: VmExitInfo = .{ .unknown = 0 },
    /// 3-vreg payload (§[vm_exit_state] vregs 118..120) for the most-
    /// recent vm_exit; staged here by the run loop so `port.deliverEvent`
    /// can write it into the receiver's vregs without re-decoding the
    /// exit reason. Sub-code rides on `ec.event_subcode`.
    last_exit_payload: [3]u64 = .{ 0, 0, 0 },
    /// Monotonic-clock timestamp (ns) at the most recent pre-vmResume
    /// timer tick. Reserved for the upcoming vGIC virtual-timer auto-
    /// inject path (mirror of x64's `last_tick_ns`).
    last_tick_ns: u64 = 0,
    /// True once the VMM has supplied an initial guest state via the
    /// reply path. The first vm_exit delivered after `create_vcpu` is
    /// synthetic (zeroed `GuestState`); the run loop must not actually
    /// execute the world switch until the VMM replies with valid initial
    /// PC / SCTLR_EL1 / SP_EL1 / etc., or ERET to a zeroed PC traps the
    /// guest immediately. Flipped true by `applyReplyStateToVcpu` on the
    /// first non-`initial_state` reply.
    started: bool = false,
    /// Per-vCPU GICv3 virtual CPU interface state. Loaded into
    /// `ICH_*_EL2` before each `vmResume` via `hvc_vgic_prepare_entry`,
    /// snapshotted back via `hvc_vgic_save_exit`. The run loop sets
    /// `lrs[0]` to a pending PPI 27 (vtimer) when the guest's CNTV
    /// would have fired, so Linux's arch_timer IRQ delivers correctly.
    vgic_shadow: vgic.VcpuHwShadow align(16) = .{},
    /// Per-vCPU virtual-timer state. Loaded via `hvc_vtimer_load_guest`
    /// before each entry, saved via `hvc_vtimer_save_guest` after each
    /// exit. CNTVOFF is seeded on first entry so guest CNTVCT starts
    /// at 0.
    vtimer: vgic.VtimerState align(16) = .{},
};

comptime {
    // VcpuArchState rides on a single 4 KiB PMM page. The first field is
    // page-aligned via `align(paging.PAGE4K)`; the struct must fit in
    // one page.
    std.debug.assert(@sizeOf(VcpuArchState) <= paging.PAGE4K);
    std.debug.assert(@alignOf(VcpuArchState) == paging.PAGE4K);
}

/// Allocate per-vCPU arch state and pin it on `vcpu_ec.vcpu_arch_state`.
/// Spec §[create_vcpu]: caller is `hv.virtual_machine.allocVcpu`, which
/// already knows the EC is a fresh vCPU bound to `vm`.
///
/// On platforms without EL2/stage-2 reachable from the kernel,
/// allocation still succeeds — `enterGuest` short-circuits via
/// `vm_hw.vmSupported()` before any world-switch attempt.
pub fn allocVcpuArchState(vm: *VirtualMachine, vcpu_ec: *ExecutionContext) !void {
    _ = vm;

    // Allocate one 4 KiB PMM page and place VcpuArchState at offset 0.
    // PMM.create requires `@sizeOf(T) == PAGE4K`; VcpuArchState is
    // smaller than a page, so allocate the raw page wrapper instead.
    const page = pmm.global_pmm.?.create(paging.PageMem(.page4k)) catch return error.OutOfMemory;
    const cell: *VcpuArchState = @ptrCast(@alignCast(page));
    cell.* = .{};
    vcpu_ec.vcpu_arch_state = @ptrCast(cell);
}

/// Free per-vCPU arch state pinned on `vcpu_ec.vcpu_arch_state`. Caller
/// has already torn down any references to the vCPU; safe to free the
/// page back to the PMM.
pub fn freeVcpuArchState(vcpu_ec: *ExecutionContext) void {
    const erased = vcpu_ec.vcpu_arch_state orelse return;
    const page: *paging.PageMem(.page4k) = @ptrCast(@alignCast(erased));
    pmm.global_pmm.?.destroy(page);
    vcpu_ec.vcpu_arch_state = null;
}

/// Resolve the per-vCPU arch state pinned on `vcpu_ec`, or `null` if the
/// EC is not a vCPU (or `allocVcpuArchState` has not yet run).
pub fn archStateOf(vcpu_ec: *ExecutionContext) ?*VcpuArchState {
    const erased = vcpu_ec.vcpu_arch_state orelse return null;
    return @ptrCast(@alignCast(erased));
}
