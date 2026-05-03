const builtin = @import("builtin");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const MemoryPerms = zag.memory.address.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageFrame = zag.memory.page_frame.PageFrame;
const VarPageSize = zag.memory.var_range.PageSize;
const VirtualMachine = zag.hv.virtual_machine.VirtualMachine;

// Generic-kernel-facing VM dispatch. Arch-internal primitives (guest-page
// mapping, interrupt injection, world-switch, sysreg passthrough, etc.)
// are reached directly by the per-arch VMM code — they don't belong in
// dispatch because no generic-kernel callers need them. This module
// exposes only what the scheduler, process layer, and syscall layer use.

// --- Init ---------------------------------------------------------------

pub fn vmInit() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.vm.vmInit(),
        .aarch64 => aarch64.vm.vmInit(),
        else => unreachable,
    }
}

/// Per-core hardware-virtualization init. On x86 this enables VMX/SVM
/// (VMXON / EFER.SVME) and arms per-core save areas; on aarch64 it
/// installs the EL2 vector and stage-2 init for cores that came up at
/// EL2. Called by `sched.scheduler.perCoreInit` after the core's APIC
/// (or GIC) is online.
pub fn vmPerCoreInit() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.vm.vmPerCoreInit(),
        .aarch64 => aarch64.vm.vmPerCoreInit(),
        else => unreachable,
    }
}

/// BSP post-bootloader handoff. On aarch64, when UEFI's firmware drops
/// us at EL2 (only observable by the bootloader, which signals via
/// `boot_info.arrived_at_el2`), arm the hyp-stub gate and install the
/// kernel's EL2 vector table — must run before secondaries start since
/// only the BSP inherits the bootloader's EL2 vector stub. No-op on x86.
pub fn bspBootHandoff(arrived_at_el2: bool) void {
    switch (builtin.cpu.arch) {
        .x86_64 => {},
        .aarch64 => if (arrived_at_el2) {
            aarch64.vm.hyp_stub_installed = true;
            aarch64.hyp.installHypVectors();
        },
        else => unreachable,
    }
}

// ── Spec v3 VM dispatch primitives ───────────────────────────────────
// Fine-grained per-VM and per-vCPU control surface tied to the spec-v3
// VirtualMachine / ExecutionContext objects.

/// Allocate per-VM arch state (VMCS/VMCB region for the VM-level
/// fields, stage-2 control structures, kernel-emulated interrupt
/// controller state). `policy_pf` carries the create-time VM policy
/// page. Spec §[virtual_machine].create_virtual_machine.
pub fn allocVmArchState(vm: *VirtualMachine, policy_pf: *PageFrame) !*anyopaque {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.hv.vm.allocVmArchState(vm, policy_pf),
        .aarch64 => aarch64.hv.vm.allocVmArchState(vm, policy_pf),
        else => unreachable,
    };
}

/// Validate a `VmPolicy` struct seeded into `policy_pf` against the
/// per-arch VmPolicy layout invariants defined in §[vm_policy]:
///   - page frame must be at least `sizeof(VmPolicy)` bytes
///   - `num_cpuid_responses` (x86) / `num_id_reg_responses` (aarch64)
///     must not exceed the static array bound
///   - `num_cr_policies` (x86) / `num_sysreg_policies` (aarch64) must
///     not exceed the static array bound
/// Returns `error.InvalidPolicy` when any of the bounds checks fail.
/// Spec §[create_virtual_machine] tests 05, 06, 07.
pub fn validateVmPolicy(policy_pf: *PageFrame) !void {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.hv.vm.validateVmPolicy(policy_pf),
        .aarch64 => aarch64.hv.vm.validateVmPolicy(policy_pf),
        else => unreachable,
    };
}

/// Free per-VM arch state allocated by `allocVmArchState`. Caller has
/// already torn down all vCPUs and stage-2 mappings.
pub fn freeVmArchState(vm: *VirtualMachine) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.hv.vm.freeVmArchState(vm),
        .aarch64 => aarch64.hv.vm.freeVmArchState(vm),
        else => unreachable,
    }
}

/// Per-VM emulated-device state embedded inline on
/// `VirtualMachine.arch_devices`. x86-64: LAPIC + IOAPIC pair. aarch64:
/// empty (vGIC state lives in the per-vCPU/per-VM control cells). The
/// type is selected at comptime so the generic `VirtualMachine` struct
/// holds a per-arch field without naming arch-specific modules.
pub const VmDevices = switch (builtin.cpu.arch) {
    .x86_64 => x64.hv.vm.VmDevices,
    .aarch64 => aarch64.hv.vm.VmDevices,
    else => unreachable,
};

/// Wire up per-VM emulated-device cross-pointers on a freshly allocated
/// VM. On x86-64 this binds the LAPIC and IOAPIC to each other so EOI
/// can re-deliver level-triggered IRQs and pin asserts can write into
/// LAPIC IRR. No-op on aarch64.
pub fn initVmDevices(devices: *VmDevices) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.hv.vm.initVmDevices(devices),
        .aarch64 => aarch64.hv.vm.initVmDevices(devices),
        else => unreachable,
    }
}

/// Allocate per-vCPU arch state (VMCS / VMCB save area, sysreg bank).
/// Stored on the vCPU EC. Spec §[virtual_machine].create_vcpu.
pub fn allocVcpuArchState(vm: *VirtualMachine, vcpu_ec: *ExecutionContext) !void {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.hv.vcpu.allocVcpuArchState(vm, vcpu_ec),
        .aarch64 => aarch64.hv.vcpu.allocVcpuArchState(vm, vcpu_ec),
        else => unreachable,
    };
}

/// Free per-vCPU arch state pinned on `vcpu_ec.vcpu_arch_state`.
/// Counterpart to `allocVcpuArchState`; called on EC destruction.
pub fn freeVcpuArchState(vcpu_ec: *ExecutionContext) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.hv.vcpu.freeVcpuArchState(vcpu_ec),
        .aarch64 => aarch64.hv.vcpu.freeVcpuArchState(vcpu_ec),
        else => unreachable,
    }
}

/// Result of `enterGuest`: which sub-code + 3-vreg payload the kernel
/// should attach to the vm_exit event delivered on the vCPU's
/// `exit_port`. Layout follows spec §[vm_exit_state] x86-64 / aarch64
/// sub-codes; the surrounding code is responsible for routing through
/// `sched.port.fireVmExit`. The struct itself is defined per-arch so
/// that the per-arch run-loop doesn't need to reach upward into
/// dispatch; the layouts are identical by design.
pub const VmExitDelivery = switch (builtin.cpu.arch) {
    .x86_64 => x64.vm_runloop.VmExitDelivery,
    .aarch64 => struct { subcode: u8, payload: [3]u64 },
    else => unreachable,
};

/// Enter the guest bound to `vcpu_ec` via VMLAUNCH/VMRESUME (Intel) or
/// VMRUN (AMD), running the guest until the next VM exit. On exit the
/// guest's GPR / sregs / MSRs are saved back into the vCPU's GuestState
/// and the exit reason is decoded into a `VmExitDelivery` describing
/// which §[vm_exit_state] sub-code to surface and which 3-vreg payload
/// to attach.
///
/// Returns `null` on platforms without hardware virtualization support;
/// the caller must surface the synthetic-exit fallback in that case.
pub fn enterGuest(vcpu_ec: *ExecutionContext) ?VmExitDelivery {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.vm_runloop.enterGuest(vcpu_ec),
        .aarch64 => null,
        else => unreachable,
    };
}

/// Allocate the stage-2 / nested page-table root for `vm` (EPT root on
/// Intel, NPT root on AMD, stage-2 TTBR on aarch64). Returned PAddr
/// is stored in `VirtualMachine.guest_pt_root`.
pub fn allocStage2Root(vm: *VirtualMachine) !PAddr {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.hv.vm.allocStage2Root(vm),
        .aarch64 => aarch64.hv.vm.allocStage2Root(vm),
        else => unreachable,
    };
}

/// Free the stage-2 root and any intermediate tables.
pub fn freeStage2Root(vm: *VirtualMachine) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.hv.vm.freeStage2Root(vm),
        .aarch64 => aarch64.hv.vm.freeStage2Root(vm),
        else => unreachable,
    }
}

/// Map a single guest page in the VM's stage-2 tables.
/// Spec §[virtual_machine].map_guest.
pub fn stage2MapPage(
    vm: *VirtualMachine,
    guest_phys: u64,
    host_phys: PAddr,
    sz: VarPageSize,
    perms: MemoryPerms,
) !void {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.hv.vm.stage2MapPage(vm, guest_phys, host_phys, sz, perms),
        .aarch64 => aarch64.hv.vm.stage2MapPage(vm, guest_phys, host_phys, sz, perms),
        else => unreachable,
    };
}

/// Unmap a single guest page from stage-2 at `guest_phys`.
/// Spec §[virtual_machine].unmap_guest.
pub fn stage2UnmapPage(vm: *VirtualMachine, guest_phys: u64, sz: VarPageSize) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.hv.vm.stage2UnmapPage(vm, guest_phys, sz),
        .aarch64 => aarch64.hv.vm.stage2UnmapPage(vm, guest_phys, sz),
        else => unreachable,
    }
}

/// Stage-2 TLB shootdown across cores currently running this VM's
/// vCPUs. Required after stage-2 unmaps or permission downgrades.
pub fn invalidateStage2Range(
    vm: *VirtualMachine,
    guest_phys: u64,
    sz: VarPageSize,
    page_count: u32,
) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.hv.vm.invalidateStage2Range(vm, guest_phys, sz, page_count),
        .aarch64 => aarch64.hv.vm.invalidateStage2Range(vm, guest_phys, sz, page_count),
        else => unreachable,
    }
}

/// Apply a typed slice of VM policy entries to the VM (MSR bitmap,
/// sysreg passthrough table, exception passthrough mask, etc. — see
/// Spec §[vm_policy] for the per-kind encoding). `count` is the
/// caller-supplied entry count from syscall word bits 13-20; `entries`
/// carries the entry payload as raw u64 vregs. Returns 0 on success
/// or a negative error code.
pub fn applyVmPolicyTable(vm: *VirtualMachine, kind: u8, count: u8, entries: []const u64) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.hv.vm.applyVmPolicyTable(vm, kind, count, entries),
        .aarch64 => aarch64.hv.vm.applyVmPolicyTable(vm, kind, count, entries),
        else => unreachable,
    };
}

/// Inject (or de-assert) a virtual interrupt into the VM's emulated
/// interrupt controller. Returns 0 on success or E_INVAL if `irq_num`
/// exceeds the maximum line supported by the per-arch emulated
/// controller. Spec §[virtual_machine].vm_inject_irq tests 02/04/05.
pub fn vmInjectIrq(vm: *VirtualMachine, irq_num: u32, assert: bool) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.hv.vm.vmInjectIrq(vm, irq_num, assert),
        .aarch64 => aarch64.hv.vm.vmInjectIrq(vm, irq_num, assert),
        else => unreachable,
    };
}

/// Plain-data snapshot of the receiver's §[vm_exit_state] vregs.
/// Captured outside the sender EC's `_gen_lock` so a fault on the
/// SMAP-bracketed user-stack reads can't strand the lock bit. Per-arch
/// layout — only the matching arch's apply path consumes it.
pub const ReplyVregSnapshot = switch (builtin.cpu.arch) {
    .x86_64 => x64.vm_runloop.ReplyVregSnapshot,
    .aarch64 => extern struct {}, // aarch64 KVM is not in the spec-v3 critical path
    else => unreachable,
};

/// Snapshot the receiver's §[vm_exit_state] vregs into a kernel-stack
/// buffer. Reads receiver-side state only (kernel iret frame + SMAP-
/// bracketed user-stack loads). Run BEFORE acquiring the sender's
/// `_gen_lock` so a page fault on the user reads can abort the syscall
/// without leaking the sender lock bit.
pub fn snapshotReplyVregs(receiver: *ExecutionContext) ReplyVregSnapshot {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.vm_runloop.snapshotReplyVregs(receiver),
        .aarch64 => .{},
        else => unreachable,
    };
}

/// Project a `ReplyVregSnapshot` onto a vCPU's per-arch GuestState,
/// gated by the originating EC's `write` cap. Pure memory writes — no
/// user-VA access, so safe under the sender's `_gen_lock`. Called by
/// `sched.port.consumeReply` when a vm_exit reply lands on a vCPU
/// sender. Non-vCPU senders short-circuit inside the per-arch impl.
pub fn applyReplyStateToVcpu(vcpu_ec: *ExecutionContext, snap: *const ReplyVregSnapshot) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.vm_runloop.applyReplyStateToVcpu(vcpu_ec, snap),
        .aarch64 => {}, // aarch64 KVM is not in the spec-v3 critical path
        else => unreachable,
    }
}

/// Stash the [3]u64 exit payload onto the vCPU's per-arch state so the
/// rendezvous-resume / `deliverEvent` path can pick it up at delivery
/// time without re-threading the payload through `suspendOnPort`.
/// No-op when `ec` has no per-arch vCPU state (non-vCPU ECs).
pub fn stashLastExitPayload(ec: *ExecutionContext, payload: [3]u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => {
            if (x64.hv.vcpu.archStateOf(ec)) |arch_state| {
                arch_state.last_exit_payload = payload;
            }
        },
        .aarch64 => {}, // aarch64 KVM is not in the spec-v3 critical path
        else => unreachable,
    }
}

/// Project the vCPU's full guest state into the receiver's vreg slots
/// per §[vm_exit_state] for that arch, but only once the VMM has
/// supplied initial state (post-first-reply). The synthetic
/// pre-started exit delivers only sub-code + zeroed GPRs so receivers
/// that haven't reserved the full vreg window aren't stomped.
/// Called by `sched.port.fireRouted` on `event_type = vm_exit` when
/// the originating EC handle had the `read` cap.
pub fn populateVmExitVregsIfStarted(
    receiver: *ExecutionContext,
    sender: *ExecutionContext,
    subcode: u8,
) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.vm_runloop.populateVmExitVregsIfStarted(receiver, sender, subcode),
        .aarch64 => {}, // aarch64 KVM is not in the spec-v3 critical path
        else => unreachable,
    }
}

