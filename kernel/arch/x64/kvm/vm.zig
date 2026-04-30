const std = @import("std");
const zag = @import("zag");

const ioapic_mod = zag.arch.x64.kvm.ioapic;
const mmio_decode = zag.arch.x64.mmio_decode;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const vm_hw = zag.arch.x64.vm;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const Ioapic = zag.arch.x64.kvm.ioapic.Ioapic;
const Lapic = zag.arch.x64.kvm.lapic.Lapic;
const MemoryPerms = zag.memory.address.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageFrame = zag.memory.page_frame.PageFrame;
const VAddr = zag.memory.address.VAddr;
const VarPageSize = zag.capdom.var_range.PageSize;
const VirtualMachine = zag.capdom.virtual_machine.VirtualMachine;

/// Per-VM emulated-device state held inline on `VirtualMachine.arch_devices`.
/// On x86-64 this is the kernel-emulated LAPIC + IOAPIC pair; the run-loop
/// walks `vm.arch_devices.lapic` for pending vectors and `vm.arch_devices.ioapic`
/// for pin asserts. The aarch64 backend exposes an empty struct (vGIC state
/// lives elsewhere). Held here rather than in the dispatch layer so generic
/// code can hold the field by per-arch type without reaching into x64 namespaces.
pub const VmDevices = struct {
    /// Kernel-emulated Local APIC. xAPIC mode, single vCPU. MMIO region
    /// 0xFEE00000-0xFEE00FFF.
    lapic: Lapic = .{},
    /// Kernel-emulated I/O APIC. Intel 82093AA, 24 redirection entries.
    ioapic: Ioapic = .{},
};

/// Wire up the bidirectional LAPIC<->IOAPIC pointers on a freshly
/// allocated VM. Called from generic `capdom.virtual_machine.allocVm`
/// via the dispatch shim so the cross-pointer init isn't duplicated
/// in the generic layer.
pub fn initVmDevices(devices: *VmDevices) void {
    devices.ioapic.init(&devices.lapic);
    devices.lapic.init(&devices.ioapic);
}

/// Kernel-emulated LAPIC/IOAPIC MMIO base addresses. Linux's xAPIC code
/// hits these page-aligned regions for ICR/EOI/IRR programming and IRQ
/// routing — handled inline so the run loop never punts these exits to
/// the VMM (a CPU-bound 1376-exits-per-second hot loop in pre-restoration
/// builds).
const LAPIC_BASE: u64 = 0xFEE0_0000;
const IOAPIC_BASE: u64 = 0xFEC0_0000;

// ── Spec-v3 dispatch backings ────────────────────────────────────────
//
// Wire-up is intentionally minimal: it fans out to the existing low-
// level VMX/SVM primitives (alloc/free of EPT/NPT root + VMCS/VMCB
// pages). vCPU run-time bring-up (loadGuestState/enterGuest/etc.) and
// guest stage-2 page-table population (stage2MapPage) still TODO —
// those are exercised by later spec-v3 tests, not create_virtual_machine
// or create_vcpu themselves.

pub fn allocStage2Root(vm: *VirtualMachine) !PAddr {
    // Caller (`capdom.virtual_machine.allocVm`) writes the returned
    // PAddr into `vm.guest_pt_root` and then calls allocVmArchState,
    // which patches the same root into the VMCS / VMCB.
    _ = vm;
    if (!vm_hw.vmSupported()) return error.NoDevice;
    return vm_hw.allocStage2RootPage() orelse error.OutOfMemory;
}

pub fn freeStage2Root(vm: *VirtualMachine) void {
    // Only walk if a non-zero root was actually installed — error paths
    // in `allocVm` may call us after a partial setup.
    if (vm.guest_pt_root.addr == 0) return;
    vm_hw.freeStage2RootPage(vm.guest_pt_root);
    vm.guest_pt_root = PAddr.fromInt(0);
}

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
    if (policy_ptr.num_cpuid_responses > vm_hw.VmPolicy.MAX_CPUID_POLICIES)
        return error.InvalidPolicy;
    if (policy_ptr.num_cr_policies > vm_hw.VmPolicy.MAX_CR_POLICIES)
        return error.InvalidPolicy;
}

pub fn allocVmArchState(vm: *VirtualMachine, policy_pf: *PageFrame) !*anyopaque {
    _ = policy_pf;
    if (!vm_hw.vmSupported()) return error.NoDevice;

    // EPT/NPT root has been allocated by allocStage2Root above and
    // stored in `vm.guest_pt_root`. Both Intel (`vmx.allocVmcsWithEpt`)
    // and AMD (`svm.allocVmcbWithNpt`) wire the externally-allocated
    // stage-2 root into the per-VM control state.
    const ctrl_phys = vm_hw.allocVmCtrlState(vm.guest_pt_root) orelse
        return error.NoDevice;

    // Pin the per-VM control PAddr in a heap-resident *anyopaque so
    // the dispatch contract returns a stable pointer. The pointer is
    // currently a tagged-PAddr cell (single u64) and is freed by
    // freeVmArchState. If/when the per-VM control state grows to a
    // larger struct (kernel LAPIC/IOAPIC state, exit_box, etc.) this
    // is the seam to swap to a slab allocation.
    const cell = pmm.global_pmm.?.create(CtrlStateCell) catch {
        vm_hw.vmFreeStructures(ctrl_phys);
        return error.OutOfMemory;
    };
    cell.* = .{ .ctrl_phys = ctrl_phys };
    return @ptrCast(cell);
}

pub fn freeVmArchState(vm: *VirtualMachine) void {
    const erased = vm.arch_state orelse return;
    const cell: *CtrlStateCell = @ptrCast(@alignCast(erased));
    vm_hw.vmFreeStructures(cell.ctrl_phys);
    pmm.global_pmm.?.destroy(cell);
    vm.arch_state = null;
}

/// Per-VM control-state envelope returned from `allocVmArchState`.
/// Page-sized + page-aligned so it fits the PMM's `create`/`destroy`
/// contract; the only payload today is the VMCS/VMCB physical address.
/// Future arch-specific per-VM state (kernel LAPIC/IOAPIC,
/// MSRPM/IOPM bookkeeping, exit_box, etc.) is the natural occupant of
/// the rest of the page.
pub const CtrlStateCell = extern struct {
    ctrl_phys: PAddr align(paging.PAGE4K),
    _pad: [paging.PAGE4K - @sizeOf(PAddr)]u8 = undefined,
};

comptime {
    std.debug.assert(@sizeOf(CtrlStateCell) == paging.PAGE4K);
    std.debug.assert(@alignOf(CtrlStateCell) == paging.PAGE4K);
}

// Stage-2 paging: routes to the existing low-level VMX/SVM EPT/NPT
// primitives. The dispatch contract takes a `*VirtualMachine` so the
// arch backend can fetch the per-VM control state (VMCS/VMCB) from
// `vm.arch_state`'s CtrlStateCell — `mapEptPage`/`unmapEptPage` then
// VMPTRLD that PAddr to read the EPTP and walk the EPT. Spec
// §[virtual_machine].map_guest / unmap_guest. The `sz` parameter is
// currently honored only for 4K (the only encoding the underlying
// EPT walker installs as a leaf today); larger page sizes will need
// 2M/1G leaf support before they can be passed through.

fn ctrlPhysFor(vm: *VirtualMachine) ?PAddr {
    const erased = vm.arch_state orelse return null;
    const cell: *CtrlStateCell = @ptrCast(@alignCast(erased));
    return cell.ctrl_phys;
}

pub fn stage2MapPage(
    vm: *VirtualMachine,
    guest_phys: u64,
    host_phys: PAddr,
    sz: VarPageSize,
    perms: MemoryPerms,
) !void {
    _ = sz;
    const ctrl_phys = ctrlPhysFor(vm) orelse return error.NoDevice;
    const rights: u8 = @bitCast(perms);
    try vm_hw.mapGuestPage(ctrl_phys, guest_phys, host_phys, rights);
}

pub fn stage2UnmapPage(vm: *VirtualMachine, guest_phys: u64, sz: VarPageSize) void {
    _ = sz;
    const ctrl_phys = ctrlPhysFor(vm) orelse return;
    vm_hw.unmapGuestPage(ctrl_phys, guest_phys);
}

pub fn invalidateStage2Range(
    vm: *VirtualMachine,
    guest_phys: u64,
    sz: VarPageSize,
    page_count: u32,
) void {
    // `unmapGuestPage` already invokes INVEPT/INVNPT on the current core
    // for each leaf removed; cross-core shootdown lives in a future TLB
    // shootdown machinery (no live vCPUs in the spec-v3 smoke path).
    _ = vm;
    _ = guest_phys;
    _ = sz;
    _ = page_count;
}

/// Spec §[vm_set_policy] x86-64 — replace `cpuid_responses` (kind=0) or
/// `cr_policies` (kind=1) on `vm`. The VmPolicy struct lives at offset 0
/// of `vm.policy_pf` and is read on guest exits; this routine writes the
/// new entries into that struct atomically (kernel-owned mapping; no
/// concurrent reader since vCPU exits run on the same kernel-mode core
/// that owns the syscall). Each entry is 3 vregs:
///   kind=0: [3i+0]={leaf u32, subleaf u32}; [3i+1]={eax u32, ebx u32};
///           [3i+2]={ecx u32, edx u32}.
///   kind=1: [3i+0]={cr_num u8, _pad u8[7]}; [3i+1]=read_value u64;
///           [3i+2]=write_mask u64.
pub fn applyVmPolicyTable(vm: *VirtualMachine, kind: u8, count: u8, entries: []const u64) i64 {
    const errors = zag.syscall.errors;

    // Spec §[vm_set_policy] test 03: count > MAX_<kind> ⇒ E_INVAL. The
    // bound is per-(kind, arch); on x86-64 kind=0 is bounded by
    // MAX_CPUID_POLICIES, kind=1 by MAX_CR_POLICIES.
    const max: u32 = switch (kind) {
        0 => vm_hw.VmPolicy.MAX_CPUID_POLICIES,
        1 => vm_hw.VmPolicy.MAX_CR_POLICIES,
        else => return errors.E_INVAL,
    };
    if (@as(u32, count) > max) return errors.E_INVAL;

    // Both x86-64 kinds occupy 3 vregs/entry per §[vm_set_policy]. The
    // dispatch layer hands us the full vreg space above [1]; reject
    // wires whose payload cannot supply `count * 3` vregs of entry data.
    const VREGS_PER_ENTRY: usize = 3;
    const need: usize = @as(usize, count) * VREGS_PER_ENTRY;
    if (entries.len < need) return errors.E_INVAL;

    // The seeded VmPolicy lives at offset 0 of `policy_pf`; the kernel
    // physmap exposes it via VAddr.fromPAddr. policy_pf is held for the
    // VM's lifetime by capdom (§[create_virtual_machine]) so the pointer
    // stays valid for as long as the VM is reachable from the syscall.
    // self-alive: policy_pf refcount is held by the VM for its lifetime.
    const pf_ref = vm.policy_pf orelse return errors.E_NODEV;
    const pf = pf_ref.ptr;
    const phys_va = VAddr.fromPAddr(pf.phys_base, null);
    const policy_ptr: *vm_hw.VmPolicy = @ptrFromInt(phys_va.addr);

    switch (kind) {
        0 => {
            var i: usize = 0;
            while (i < @as(usize, count)) {
                const w0 = entries[i * VREGS_PER_ENTRY + 0];
                const w1 = entries[i * VREGS_PER_ENTRY + 1];
                const w2 = entries[i * VREGS_PER_ENTRY + 2];
                policy_ptr.cpuid_responses[i] = .{
                    .leaf = @truncate(w0),
                    .subleaf = @truncate(w0 >> 32),
                    .eax = @truncate(w1),
                    .ebx = @truncate(w1 >> 32),
                    .ecx = @truncate(w2),
                    .edx = @truncate(w2 >> 32),
                };
                i += 1;
            }
            policy_ptr.num_cpuid_responses = @as(u32, count);
        },
        1 => {
            var i: usize = 0;
            while (i < @as(usize, count)) {
                const w0 = entries[i * VREGS_PER_ENTRY + 0];
                const w1 = entries[i * VREGS_PER_ENTRY + 1];
                const w2 = entries[i * VREGS_PER_ENTRY + 2];
                policy_ptr.cr_policies[i] = .{
                    .cr_num = @truncate(w0),
                    .read_value = w1,
                    .write_mask = w2,
                };
                i += 1;
            }
            policy_ptr.num_cr_policies = @as(u32, count);
        },
        else => unreachable,
    }

    return 0;
}

/// Inject (assert/de-assert) a virtual IRQ line on the VM's emulated
/// IOAPIC. The kernel-internal IOAPIC (kvm/ioapic.zig) exposes
/// `NUM_REDIR_ENTRIES` (24) redirection entries per Intel 82093AA
/// Section 3.0; any `irq_num` beyond that range cannot be emulated
/// and must be rejected with E_INVAL per Spec §[vm_inject_irq] test 02.
/// Returns 0 on success.
/// If `guest_phys` falls inside the kernel-emulated LAPIC or IOAPIC
/// MMIO page, decode the instruction at guest RIP, dispatch the access
/// to the matching controller, write any read result back into the
/// guest GPR, advance RIP past the decoded instruction, and return
/// true so the run loop can re-enter the guest inline. Returns false
/// if `guest_phys` is outside both ranges or the instruction can't be
/// decoded — the exit then falls through to the VMM as a normal
/// `ept_violation` delivery.
pub fn tryHandleMmio(vm: *VirtualMachine, vcpu_ec: *ExecutionContext, guest_phys: u64) bool {
    if (guest_phys >= LAPIC_BASE and guest_phys < LAPIC_BASE + 0x1000) {
        return handleLapicMmio(vm, vcpu_ec, guest_phys);
    }
    if (guest_phys >= IOAPIC_BASE and guest_phys < IOAPIC_BASE + 0x1000) {
        return handleIoapicMmio(vm, vcpu_ec, guest_phys);
    }
    return false;
}

fn handleLapicMmio(vm: *VirtualMachine, vcpu_ec: *ExecutionContext, guest_phys: u64) bool {
    const arch_state = zag.arch.x64.kvm.vcpu.archStateOf(vcpu_ec) orelse return false;
    const gs = &arch_state.guest_state;
    const op = mmio_decode.decode(vm, gs) orelse return false;
    const offset: u32 = @truncate(guest_phys - LAPIC_BASE);
    if (op.is_write) {
        vm.arch_devices.lapic.mmioWrite(offset, op.value);
    } else {
        const value = vm.arch_devices.lapic.mmioRead(offset);
        mmio_decode.writeGpr(gs, op.reg, @as(u64, value));
    }
    gs.rip += op.len;
    return true;
}

fn handleIoapicMmio(vm: *VirtualMachine, vcpu_ec: *ExecutionContext, guest_phys: u64) bool {
    const arch_state = zag.arch.x64.kvm.vcpu.archStateOf(vcpu_ec) orelse return false;
    const gs = &arch_state.guest_state;
    const op = mmio_decode.decode(vm, gs) orelse return false;
    const offset: u32 = @truncate(guest_phys - IOAPIC_BASE);
    if (op.is_write) {
        vm.arch_devices.ioapic.mmioWrite(offset, op.value);
    } else {
        const value = vm.arch_devices.ioapic.mmioRead(offset);
        mmio_decode.writeGpr(gs, op.reg, @as(u64, value));
    }
    gs.rip += op.len;
    return true;
}

pub fn vmInjectIrq(vm: *VirtualMachine, irq_num: u32, assert: bool) i64 {
    if (irq_num >= ioapic_mod.NUM_REDIR_ENTRIES)
        return zag.syscall.errors.E_INVAL;
    const irq_pin: u5 = @intCast(irq_num);
    if (assert) {
        vm.arch_devices.ioapic.assertIrq(irq_pin);
    } else {
        vm.arch_devices.ioapic.deassertIrq(irq_pin);
    }
    return 0;
}
