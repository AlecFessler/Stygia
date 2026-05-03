const std = @import("std");
const zag = @import("zag");

const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const vm_hw = zag.arch.x64.vm;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const GuestState = vm_hw.GuestState;
const FxsaveArea = vm_hw.FxsaveArea;
const VirtualMachine = zag.hv.virtual_machine.VirtualMachine;
const VmExitInfo = vm_hw.VmExitInfo;

/// Per-vCPU arch state. Lives in a single 4 KiB page allocated by
/// `allocVcpuArchState`; pinned on the EC's `vcpu_arch_state` slot.
/// The page is zeroed at alloc, with FCW/MXCSR seeded into `guest_fxsave`
/// per `vm_hw.fxsaveInit`.
///
/// Layout is page-sized + page-aligned so the PMM `create`/`destroy`
/// contract applies. FXSAVE requires 16-byte alignment for the fxsave
/// area; the field's `align(16)` annotation plus the page-aligned base
/// guarantee that.
pub const VcpuArchState = struct {
    guest_state: GuestState align(paging.PAGE4K) = .{},
    guest_fxsave: FxsaveArea align(16) = vm_hw.fxsaveInit(),
    /// Most-recent decoded VM-exit. Populated after every `vmResume`
    /// return so the surrounding run loop / VMM can re-decode without
    /// re-reading VMCS/VMCB fields.
    last_exit: VmExitInfo = .{ .unknown = 0 },
    /// 3-vreg payload (§[vm_exit_state] vregs 71..73) for the most-
    /// recent vm_exit; staged here by the run loop so `port.deliverEvent`
    /// can write it into the receiver's vregs without re-decoding the
    /// exit reason. Sub-code rides on `ec.event_subcode`.
    last_exit_payload: [3]u64 = .{ 0, 0, 0 },
    /// Monotonic-clock timestamp (ns) at the most recent pre-VMRUN
    /// `Lapic.tick`. Drives the emulated APIC timer's countdown across
    /// VM exits; reset when this field is 0 (first entry).
    last_tick_ns: u64 = 0,
    /// Vector to auto-inject as IRQ0-equivalent every 4ms in the
    /// pre-VMRUN hook. 0 disables. Set by the VMM via vreg 64 reply
    /// — once the VMM has armed it, the kernel keeps re-firing the
    /// vector even when the guest stops generating vm_exits (so
    /// /init's user-mode-only progress doesn't strand jiffies). The
    /// kernel-side throttle keeps the rate at ~250 Hz.
    auto_inject_vector: u8 = 0,
    /// Monotonic-clock timestamp (ns) at the last auto-inject fire.
    last_auto_inject_ns: u64 = 0,
    /// True once the VMM has supplied an initial guest state via the
    /// reply path. The first vm_exit delivered after `create_vcpu` is
    /// synthetic (zeroed `GuestState`); the run loop must not actually
    /// execute VMLAUNCH until the VMM replies with valid initial CR0/
    /// CR3/CR4/EFER/segments etc., or the processor will fault on
    /// VM-entry consistency checks (Intel SDM Vol 3C §27.2; AMD APM
    /// Vol 2 §15.5.1). Flipped true by the reply path's GuestState
    /// writeback once that lands; until then the run loop falls back
    /// to firing synthetic exits, preserving the spec-test contract.
    started: bool = false,
};

comptime {
    // VcpuArchState rides on a 4 KiB PMM page. The first field is
    // page-aligned via `align(paging.PAGE4K)`; the struct must fit
    // entirely within one page.
    std.debug.assert(@sizeOf(VcpuArchState) <= paging.PAGE4K);
    std.debug.assert(@alignOf(VcpuArchState) == paging.PAGE4K);
}

/// Allocate per-vCPU arch state and pin it on `vcpu_ec.vcpu_arch_state`.
/// Spec §[create_vcpu]: caller is `hv.virtual_machine.allocVcpu`,
/// which already knows the EC is a fresh vCPU bound to `vm`.
///
/// On platforms without VMX/SVM support, returns `error.NoDevice` so
/// `create_virtual_machine` / `create_vcpu` can surface E_NODEV instead
/// of allocating per-vCPU state for a VM that will never run.
pub fn allocVcpuArchState(vm: *VirtualMachine, vcpu_ec: *ExecutionContext) !void {
    if (!vm_hw.vmSupported()) return error.NoDevice;
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
