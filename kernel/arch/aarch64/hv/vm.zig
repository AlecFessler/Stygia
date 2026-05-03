const std = @import("std");
const zag = @import("zag");

const hv = zag.arch.aarch64.hv;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const vgic_mod = hv.vgic;
const vm_hw = zag.arch.aarch64.vm;

const MemoryPerms = zag.memory.address.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageFrame = zag.memory.page_frame.PageFrame;
const VAddr = zag.memory.address.VAddr;
const VmarPageSize = zag.memory.vmar.PageSize;
const VirtualMachine = zag.hv.virtual_machine.VirtualMachine;

// ── Spec-v3 dispatch backings ────────────────────────────────────────
//
// Stage-2 mapping, world-switch entry/exit, and EL2 vector install are
// still TODO — those land when the aarch64 KVM run loop is restored.
// What's wired here is the minimum surface `hv.virtual_machine`
// reaches on `create_virtual_machine` / `create_vcpu`: VmPolicy bound
// validation, stage-2 root + per-VM control state allocation. Run-time
// guest entry routines stay panics until the EL2 scaffolding returns.

/// Validate a `VmPolicy` struct seeded into the policy page frame.
/// Spec §[create_virtual_machine] tests 05/06/07: the page frame must
/// be at least `sizeof(VmPolicy)` bytes, and the table-count fields
/// must not exceed their static array bounds. The struct lives at
/// offset 0 of the frame and is read through the kernel physmap.
pub fn validateVmPolicy(policy_pf: *PageFrame) !void {
    const page_bytes: u64 = switch (policy_pf.sz) {
        .sz_4k => 0x1000,
        .sz_2m => 0x20_0000,
        .sz_1g => 0x4000_0000,
        ._reserved => 0,
    };
    const frame_bytes: u64 = page_bytes * @as(u64, policy_pf.page_count);
    if (frame_bytes < @sizeOf(vm_hw.VmPolicy)) return error.InvalidPolicy;

    const phys_va = VAddr.fromPAddr(policy_pf.phys_base, null);
    const policy_ptr: *const vm_hw.VmPolicy = @ptrFromInt(phys_va.addr);
    if (policy_ptr.num_id_reg_responses > vm_hw.VmPolicy.MAX_ID_REG_RESPONSES)
        return error.InvalidPolicy;
    if (policy_ptr.num_sysreg_policies > vm_hw.VmPolicy.MAX_SYSREG_POLICIES)
        return error.InvalidPolicy;
}

/// Per-VM emulated-device state held inline on `VirtualMachine.arch_devices`.
/// On aarch64 the vGIC state lives elsewhere (per-vCPU + per-VM CtrlStateCell),
/// so this is an empty struct present only for cross-arch type uniformity. The
/// x86-64 backend embeds the kernel-emulated LAPIC + IOAPIC pair here.
pub const VmDevices = struct {};

/// Per-arch wire-up hook invoked from generic `hv.virtual_machine.allocVm`.
/// No-op on aarch64 — see `arch/x64/hv/vm.zig` for the LAPIC<->IOAPIC pointer
/// init this exists to mirror.
pub fn initVmDevices(devices: *VmDevices) void {
    _ = devices;
}

/// Per-VM control-state envelope returned from `allocVmArchState`.
/// Page-sized + page-aligned to fit the PMM's `create`/`destroy`
/// contract; the only payload today is a placeholder slot. Future
/// per-VM EL2 state (VTTBR_EL2, VTCR_EL2, vGIC distributor state,
/// HCR_EL2 bits, etc.) is the natural occupant of the rest of the page.
pub const CtrlStateCell = extern struct {
    _placeholder: u64 align(paging.PAGE4K) = 0,
    _pad: [paging.PAGE4K - @sizeOf(u64)]u8 = undefined,
};

comptime {
    std.debug.assert(@sizeOf(CtrlStateCell) == paging.PAGE4K);
    std.debug.assert(@alignOf(CtrlStateCell) == paging.PAGE4K);
}

/// Allocate the stage-2 / nested page-table root for `vm`. On aarch64
/// this becomes VTTBR_EL2's translation-table base; for now allocate a
/// zeroed 4 KiB page out of the PMM so `hv.virtual_machine.allocVm`
/// has a valid PAddr to install. The page is freed by `freeStage2Root`.
pub fn allocStage2Root(vm: *VirtualMachine) !PAddr {
    _ = vm;
    const page = pmm.global_pmm.?.create(paging.PageMem(.page4k)) catch
        return error.OutOfMemory;
    return PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
}

pub fn freeStage2Root(vm: *VirtualMachine) void {
    if (vm.guest_pt_root.addr == 0) return;
    const va = VAddr.fromPAddr(vm.guest_pt_root, null);
    const page: *paging.PageMem(.page4k) = @ptrFromInt(va.addr);
    pmm.global_pmm.?.destroy(page);
    vm.guest_pt_root = PAddr.fromInt(0);
}

/// Allocate per-VM control state. Mirrors the x64 dispatch so that
/// `allocVm` ends with a non-null `vm.arch_state`. Real per-VM EL2
/// programming (VTCR/HCR seed values, vGIC redistributor base, etc.)
/// will populate the cell when the EL2 scaffolding returns.
pub fn allocVmArchState(vm: *VirtualMachine, policy_pf: *PageFrame) !*anyopaque {
    _ = vm;
    _ = policy_pf;
    const cell = pmm.global_pmm.?.create(CtrlStateCell) catch
        return error.OutOfMemory;
    cell.* = .{};
    return @ptrCast(cell);
}

pub fn freeVmArchState(vm: *VirtualMachine) void {
    const erased = vm.arch_state orelse return;
    const cell: *CtrlStateCell = @ptrCast(@alignCast(erased));
    pmm.global_pmm.?.destroy(cell);
    vm.arch_state = null;
}

// Stage-2 map / unmap / shootdown primitives are no-ops on aarch64
// today: there's no VTTBR_EL2 walker yet, but the spec tests for
// `map_guest` / `unmap_guest` exercise the cross-cutting caps
// bookkeeping (overlap checks, mapcnt accounting, error gates) rather
// than actual guest execution. Returning success here lets the
// bookkeeping run end-to-end; an actual stage-2 walk slots in once the
// EL2 scaffolding is restored.
pub fn stage2MapPage(
    vm: *VirtualMachine,
    guest_phys: u64,
    host_phys: PAddr,
    sz: VmarPageSize,
    perms: MemoryPerms,
) !void {
    _ = vm;
    _ = guest_phys;
    _ = host_phys;
    _ = sz;
    _ = perms;
}

pub fn stage2UnmapPage(vm: *VirtualMachine, guest_phys: u64, sz: VmarPageSize) void {
    _ = vm;
    _ = guest_phys;
    _ = sz;
}

pub fn invalidateStage2Range(
    vm: *VirtualMachine,
    guest_phys: u64,
    sz: VmarPageSize,
    page_count: u32,
) void {
    _ = vm;
    _ = guest_phys;
    _ = sz;
    _ = page_count;
}

/// Apply a typed slice of VM policy entries. The aarch64 vCPU run
/// loop isn't restored yet, so the policy seed lives only in the
/// VmPolicy page-frame; no per-VM cache to invalidate. Per-spec
/// bound checks against MAX_* (kind-dependent) are still enforced so
/// vm_set_policy E_INVAL gates fire as written.
pub fn applyVmPolicyTable(vm: *VirtualMachine, kind: u8, count: u8, entries: []const u64) i64 {
    _ = vm;
    _ = entries;
    const errors = zag.syscall.errors;

    // Spec §[vm_set_policy] aarch64 layout: kind 0 = id_reg_responses
    // (max MAX_ID_REG_RESPONSES), kind 1 = sysreg_policies (max
    // MAX_SYSREG_POLICIES). Reject any other kind with E_INVAL.
    const max: u32 = switch (kind) {
        0 => vm_hw.VmPolicy.MAX_ID_REG_RESPONSES,
        1 => vm_hw.VmPolicy.MAX_SYSREG_POLICIES,
        else => return errors.E_INVAL,
    };
    if (@as(u32, count) > max) return errors.E_INVAL;
    return 0;
}

pub fn vmInjectIrq(vm: *VirtualMachine, irq_num: u32, assert: bool) i64 {
    _ = vm;
    _ = assert;
    if (irq_num >= vgic_mod.TOTAL_DIST_INTIDS)
        return zag.syscall.errors.E_INVAL;
    return 0;
}
