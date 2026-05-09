const stygia = @import("stygia");

const capability = stygia.caps.capability;
const errors = stygia.syscall.errors;
const vm_obj = stygia.hv.virtual_machine;

const CapabilityDomainCaps = stygia.caps.capability_domain.CapabilityDomainCaps;
const ExecutionContext = stygia.sched.execution_context.ExecutionContext;
const PortCaps = stygia.sched.port.PortCaps;
const VmCaps = vm_obj.VmCaps;
const Word0 = capability.Word0;

/// Mask of the bits the caller is allowed to set in `create_virtual_machine`'s
/// caps argument. Spec §[virtual_machine].create_virtual_machine packs caps
/// into bits 0-15; bits 16-63 are reserved.
const CREATE_VM_CAPS_MASK: u64 = 0xFFFF;

/// Mask of the bits the caller is allowed to set in `create_vcpu`'s
/// caps argument. Bits 0-15 = caps, bits 32-33 = priority. Bits 16-31
/// and 34-63 are reserved.
const CREATE_VCPU_CAPS_MASK: u64 = 0x0000_0003_0000_FFFF;

/// Mask of the bits the caller is allowed to set in `vm_inject_irq`'s
/// `assert` argument. Bit 0 only.
const INJECT_IRQ_ASSERT_MASK: u64 = 0x1;

/// Bit position of `vm_ceiling` within self-handle `field0`.
/// Per §[capability_domain] Self handle layout — field0 has idc_rx at
/// bits 32-39, so vm_ceiling occupies bits 48-55 with `policy` at bit
/// 48 (shifted up by 8 from the [2] ceilings_inner layout).
const VM_CEILING_FIELD0_SHIFT: u6 = 48;
const VM_CEILING_MASK: u64 = 0xFF;

/// Bit position of `restart_policy_ceiling.vm_restart_max` within
/// self-handle `field1`. Per §[capability_domain] Self handle layout
/// (matches §[create_capability_domain] `[3] ceilings_outer`):
/// `restart_policy_ceiling` occupies field1 bits 16-31, with
/// `vm_restart_max` at bit 23 of field1 (= bit 7 of the 16-bit
/// restart_policy_ceiling sub-word).
const VM_RESTART_MAX_FIELD1_SHIFT: u6 = 23;

/// Allocates a VM with its own guest physical address space and
/// initializes kernel-emulated LAPIC/IOAPIC state. vCPUs are created
/// separately via `create_vcpu`.
///
/// ```
/// create_virtual_machine([1] caps, [2] policy_page_frame) -> [1] handle
///   syscall_num = 27
///
///   [1] caps: u64 packed as
///     bits  0-15: caps       — caps on the VM handle returned to the caller
///     bits 16-63: _reserved
///
///   [2] policy_page_frame: page frame handle containing a VmPolicy struct at
///                          offset 0 (static CPUID responses and CR access
///                          policies applied to all vCPUs on exits; layout in
///                          §[vm_policy])
/// ```
///
/// Self-handle cap required: `crvm`.
///
/// The kernel retains a reference on `policy_page_frame` for the lifetime
/// of the VM.
///
/// Returns E_NOMEM if insufficient kernel memory; returns E_NODEV if the
/// platform does not support hardware virtualization; returns E_FULL if
/// the caller's handle table has no free slot.
///
/// [test 01] returns E_PERM if the caller's self-handle lacks `crvm`.
/// [test 02] returns E_PERM if caps is not a subset of the caller's `vm_ceiling`.
/// [test 03] returns E_NODEV if the platform does not support hardware virtualization.
/// [test 04] returns E_BADCAP if [2] is not a valid page frame handle.
/// [test 05] returns E_INVAL if `policy_page_frame` is smaller than `sizeof(VmPolicy)`.
/// [test 06] returns E_INVAL if `VmPolicy.num_cpuid_responses` exceeds `MAX_CPUID_POLICIES`.
/// [test 07] returns E_INVAL if `VmPolicy.num_cr_policies` exceeds `MAX_CR_POLICIES`.
/// [test 08] returns E_INVAL if any reserved bits are set in [1].
/// [test 09] on success, the caller receives a VM handle with caps = `[1].caps`.
pub fn createVirtualMachine(caller: *anyopaque, caps: u64, policy_page_frame: u64) i64 {
    if (caps & ~CREATE_VM_CAPS_MASK != 0) return errors.E_INVAL;
    if (policy_page_frame & ~capability.HANDLE_ARG_MASK != 0) return errors.E_INVAL;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const cd_ref = ec.domain;
    const lr = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = lr.ptr;

    const self_word0 = cd.user_table[0].word0;
    const self_caps: CapabilityDomainCaps = @bitCast(Word0.caps(self_word0));
    const vm_ceiling: u16 = @truncate((cd.user_table[0].field0 >> VM_CEILING_FIELD0_SHIFT) & VM_CEILING_MASK);
    // `vm_restart_max` is a single bit; read as u1 for the > comparison
    // against the requested `restart_policy` (also 1 bit).
    const vm_restart_max: u1 = @truncate((cd.user_table[0].field1 >> VM_RESTART_MAX_FIELD1_SHIFT) & 0x1);

    const pf_slot: u12 = @truncate(policy_page_frame);
    const pf_resolved = capability.resolveHandleOnDomain(cd, pf_slot, .page_frame) != null;

    cd_ref.unlockIrqRestore(lr.irq_state);

    if (!self_caps.crvm) return errors.E_PERM;

    // The requested caps word is the 16-bit cap layout from
    // §[virtual_machine]: bit 0 = `policy`, bit 1 = `restart_policy`.
    // `vm_ceiling` (self-handle field0 bits 48-55 per §[capability_domain]
    // Self handle layout) gates only `policy`; `restart_policy` is gated
    // separately by `restart_policy_ceiling.vm_restart_max` per
    // §[restart_semantics] test 04 — enforced just below in the same
    // shape as `ec_restart_max` in `kernel/syscall/execution_context.zig`.
    const requested: u16 = @truncate(caps);
    const requested_policy = requested & 0x1;
    const ceiling_policy = vm_ceiling & 0x1;
    if (requested_policy & ~ceiling_policy != 0) return errors.E_PERM;

    // Spec §[restart_semantics] test 04: returns E_PERM if
    // `caps.restart_policy = 1` and the calling domain's
    // `restart_policy_ceiling.vm_restart_max = 0`. Mirrors the
    // `ec_restart_max` enforcement at `execution_context.zig` (caller's
    // `restart_policy_ceiling` is the authoritative gate regardless of
    // whether the new handle is minted in the caller's own table — VM
    // handles are non-transferable so there is no second domain).
    const requested_restart_policy: u1 = @truncate((requested >> 1) & 0x1);
    if (requested_restart_policy > vm_restart_max) return errors.E_PERM;

    if (!pf_resolved) return errors.E_BADCAP;

    return vm_obj.createVirtualMachine(ec, caps, policy_page_frame);
}

/// Creates a vCPU execution context bound to a VM. The vCPU is created
/// suspended on its exit port with zeroed guest state; the creator
/// installs initial guest state through the same mechanism used to handle
/// vm exits — recv on the exit port, modify the vregs, reply with a
/// resume action.
///
/// ```
/// create_vcpu([1] caps, [2] vm_handle, [3] affinity, [4] exit_port) -> [1] handle
///   syscall_num = 28
///
///   [1] caps: u64 packed as
///     bits  0-15: caps       — caps on the EC handle returned to the caller
///     bits 32-33: priority   — scheduling priority, 0-3, bounded by caller's priority ceiling
///     bits 34-63: _reserved
///
///   [2] vm_handle:  VM handle the vCPU binds to
///   [3] affinity:   64-bit core mask; bit N = 1 allows the vCPU to run on core N.
///                   0 = any core (kernel chooses)
///   [4] exit_port:  port handle where vm_exit events for this vCPU are delivered
/// ```
///
/// Caps required: caller's self-handle must have `crec`. Holding the VM
/// handle implies the authority to spawn vCPUs in it.
///
/// The vCPU EC is bound to the capability domain that holds the VM
/// handle. `create_vcpu` binds `exit_port` as the destination for its
/// vm_exit events. Immediately upon creation, the kernel enqueues a
/// vm_exit-style delivery on `exit_port` representing the initial "not
/// yet started" condition: the reply cap is valid, all guest-state vregs
/// are zero, and the exit sub-code is the initial-state sub-code. The
/// creator recvs this event, writes the real initial guest state into the
/// vregs, and replies with a resume action to enter guest mode. All
/// subsequent guest exits flow through the same port and the same
/// reply-cap lifecycle.
///
/// Returns E_NOMEM if insufficient kernel memory; returns E_FULL if the
/// caller's handle table has no free slot.
///
/// [test 01] returns E_PERM if the caller's self-handle lacks `crec`.
/// [test 02] returns E_PERM if caps is not a subset of the VM's owning domain's `ec_inner_ceiling`.
/// [test 03] returns E_PERM if priority exceeds the caller's priority ceiling.
/// [test 04] returns E_BADCAP if [2] is not a valid VM handle.
/// [test 05] returns E_BADCAP if [4] is not a valid port handle.
/// [test 06] returns E_INVAL if [3] affinity has bits set outside the system's core count.
/// [test 07] returns E_INVAL if any reserved bits are set in [1].
/// [test 08] on success, the caller receives an EC handle with caps = `[1].caps`.
/// [test 09] on success, `suspend` on the returned EC handle returns E_INVAL, and after `recv` on [4] consumes the initial vm_exit and `reply` on its reply handle, a subsequent `recv` on [4] returns a vm_exit whose vreg layout matches §[vm_exit_state] for VM [2]'s architecture.
/// [test 10] on success, the EC's priority is set to `[1].priority`.
/// [test 11] on success, the EC's affinity is set to `[3]`.
/// [test 12] immediately after creation, an initial vm_exit event is delivered on `[4] exit_port` with zeroed guest state in the vregs and the initial-state sub-code.
pub fn createVcpu(
    caller: *anyopaque,
    caps: u64,
    vm_handle: u64,
    affinity: u64,
    exit_port: u64,
) i64 {
    if (caps & ~CREATE_VCPU_CAPS_MASK != 0) return errors.E_INVAL;
    if (vm_handle & ~capability.HANDLE_ARG_MASK != 0) return errors.E_INVAL;
    if (exit_port & ~capability.HANDLE_ARG_MASK != 0) return errors.E_INVAL;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const cd_ref = ec.domain;
    const lr = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = lr.ptr;

    const self_caps: CapabilityDomainCaps = @bitCast(Word0.caps(cd.user_table[0].word0));
    // pri ceiling lives in the self-handle's caps word, bits 14-15
    // (§[capability_domain]). Compare to the requested priority in
    // bits 32-33 of `caps`.
    const pri_ceiling: u2 = self_caps.pri;
    const requested_pri: u2 = @truncate((caps >> 32) & 0x3);

    const vm_slot: u12 = @truncate(vm_handle);
    const vm_resolved = capability.resolveHandleOnDomain(cd, vm_slot, .virtual_machine) != null;

    const port_slot: u12 = @truncate(exit_port);
    const port_entry = capability.resolveHandleOnDomain(cd, port_slot, .port);
    const port_caps_word = if (port_entry != null)
        Word0.caps(cd.user_table[port_slot].word0)
    else
        @as(u16, 0);
    const port_caps: PortCaps = @bitCast(port_caps_word);

    cd_ref.unlockIrqRestore(lr.irq_state);

    if (!self_caps.crec) return errors.E_PERM;
    if (@as(u8, requested_pri) > @as(u8, pri_ceiling)) return errors.E_PERM;
    if (!vm_resolved) return errors.E_BADCAP;
    if (port_entry == null) return errors.E_BADCAP;
    if (!port_caps.bind) return errors.E_PERM;

    return vm_obj.createVcpu(ec, caps, vm_handle, affinity, exit_port);
}

/// Installs page_frames into the VM's guest physical address space.
/// Subsequent guest accesses to `guest_addr` translate via the
/// second-stage page tables to the corresponding page_frame.
///
/// ```
/// map_guest([1] vm, [2 + 2i] guest_addr, [2 + 2i + 1] page_frame) -> void
///   syscall_num = 29
///
///   syscall word bits 12-19: N (number of (guest_addr, page_frame) pairs)
///
///   [1] vm: VM handle
///   [2 + 2i] guest_addr: guest physical address
///   [2 + 2i + 1] page_frame: page_frame handle to install at that guest_addr
///
///   for i in 0..N-1.
/// ```
///
/// [test 01] returns E_BADCAP if [1] is not a valid VM handle.
/// [test 02] returns E_BADCAP if any [2 + 2i + 1] is not a valid page_frame handle.
/// [test 03] returns E_INVAL if N is 0.
/// [test 04] returns E_INVAL if any guest_addr is not aligned to its paired page_frame's `sz`.
/// [test 05] returns E_INVAL if any two pairs' ranges overlap.
/// [test 06] returns E_INVAL if any pair's range overlaps an existing mapping in the VM's guest physical address space.
/// [test 07] on success, a guest read from `guest_addr` returns the paired page_frame's contents, and a guest access whose required rwx is not a subset of `page_frame.r/w/x` delivers a `vm_exit` event on the vCPU's bound exit_port with sub-code = `ept` (x86-64) or `stage2_fault` (aarch64).
pub fn mapGuest(caller: *anyopaque, vm: u64, pairs: []const u64) i64 {
    if (vm & ~capability.HANDLE_ARG_MASK != 0) return errors.E_INVAL;
    if (pairs.len == 0 or (pairs.len & 1) != 0) return errors.E_INVAL;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const cd_ref = ec.domain;
    const lr = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = lr.ptr;

    const vm_slot: u12 = @truncate(vm);
    const vm_resolved = capability.resolveHandleOnDomain(cd, vm_slot, .virtual_machine) != null;

    cd_ref.unlockIrqRestore(lr.irq_state);

    if (!vm_resolved) return errors.E_BADCAP;

    return vm_obj.mapGuest(ec, vm, pairs);
}

/// Removes page_frame mappings from a VM's guest physical address space.
///
/// ```
/// unmap_guest([1] vm, [2 + i] page_frame for i in 0..N-1) -> void
///   syscall_num = 30
///
///   syscall word bits 12-19: N (number of page_frames to unmap)
///
///   [1] vm: VM handle
///   [2 + i] page_frame: page_frame handle to unmap from the VM
/// ```
///
/// [test 01] returns E_BADCAP if [1] is not a valid VM handle.
/// [test 02] returns E_BADCAP if any [2 + i] is not a valid page_frame handle.
/// [test 03] returns E_INVAL if N is 0.
/// [test 04] returns E_NOENT if any page_frame is not currently mapped in [1].
/// [test 05] on success, each page_frame's installation in [1]'s guest physical address space is removed; subsequent guest accesses to those guest_addr ranges deliver a `vm_exit` event on the vCPU's bound exit_port with sub-code = `ept` (x86-64) or `stage2_fault` (aarch64).
pub fn unmapGuest(caller: *anyopaque, vm: u64, page_frames: []const u64) i64 {
    if (vm & ~capability.HANDLE_ARG_MASK != 0) return errors.E_INVAL;
    if (page_frames.len == 0) return errors.E_INVAL;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const cd_ref = ec.domain;
    const lr = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = lr.ptr;

    const vm_slot: u12 = @truncate(vm);
    const vm_resolved = capability.resolveHandleOnDomain(cd, vm_slot, .virtual_machine) != null;

    cd_ref.unlockIrqRestore(lr.irq_state);

    if (!vm_resolved) return errors.E_BADCAP;

    return vm_obj.unmapGuest(ec, vm, page_frames);
}

/// Replaces a single VmPolicy table on the VM, atomically. Tables for
/// other kinds are unchanged. The kind selector is overloaded across
/// architectures; see the per-arch tables below.
///
/// ```
/// vm_set_policy([1] vm, [2..] entries) -> void
///   syscall_num = 31
///
///   syscall word bit 12:     kind
///   syscall word bits 13-20: count (number of entries supplied)
///
///   [1] vm: VM handle
/// ```
///
/// VM cap required on [1]: `policy`.
///
/// [test 01] returns E_BADCAP if [1] is not a valid VM handle.
/// [test 02] returns E_PERM if [1] does not have the `policy` cap.
/// [test 03] returns E_INVAL if count exceeds the active (kind, arch)'s MAX_* constant from §[vm_policy].
/// [test 04] returns E_INVAL if any reserved bits are set in [1] or any entry.
pub fn vmSetPolicy(caller: *anyopaque, syscall_word: u64, vm: u64, entries: []const u64) i64 {
    if (vm & ~capability.HANDLE_ARG_MASK != 0) return errors.E_INVAL;

    // Spec §[virtual_machine].vm_set_policy: syscall word bit 12 = kind,
    // bits 13-20 = count (number of entries). The 8-bit `kind` argument
    // to the inner layer carries the single kind bit; the per-arch table
    // encoding determines how the inner layer interprets it.
    const kind: u8 = @truncate((syscall_word >> 12) & 0x1);
    const count: u8 = @truncate((syscall_word >> 13) & 0xFF);

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const cd_ref = ec.domain;
    const lr = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = lr.ptr;

    const vm_slot: u12 = @truncate(vm);
    const vm_entry = capability.resolveHandleOnDomain(cd, vm_slot, .virtual_machine);
    const vm_caps_word = if (vm_entry != null)
        Word0.caps(cd.user_table[vm_slot].word0)
    else
        @as(u16, 0);
    const vm_caps: VmCaps = @bitCast(vm_caps_word);

    cd_ref.unlockIrqRestore(lr.irq_state);

    if (vm_entry == null) return errors.E_BADCAP;
    if (!vm_caps.policy) return errors.E_PERM;

    return vm_obj.applyVmPolicyTable(ec, vm, kind, count, entries);
}

/// Asserts or deasserts a virtual IRQ line on the VM's emulated interrupt
/// controller. Routing to vCPUs follows the guest's configured
/// redirection (IOAPIC RTE on x86-64, GIC distributor on aarch64).
///
/// ```
/// vm_inject_irq([1] vm, [2] irq_num, [3] assert) -> void
///   syscall_num = 32
///
///   [1] vm:      VM handle
///   [2] irq_num: u64 virtual IRQ line number
///   [3] assert:  u64 packed as
///     bit 0: 1 = assert, 0 = deassert
///     bits 1-63: _reserved
/// ```
///
/// No cap required beyond holding [1].
///
/// [test 01] returns E_BADCAP if [1] is not a valid VM handle.
/// [test 02] returns E_INVAL if [2] exceeds the maximum IRQ line supported by the VM's emulated interrupt controller.
/// [test 03] returns E_INVAL if any reserved bits are set in [1] or [3].
/// [test 04] on success with [3].assert = 1, IRQ line [2] is asserted on the VM's emulated interrupt controller; if a vCPU is unmasked for the line, an interrupt event is delivered to the vCPU on its next runnable opportunity (observable as an exception/interrupt vm_exit or as a guest interrupt handler invocation per the guest's IDT/GIC configuration).
/// [test 05] on success with [3].assert = 0 immediately after a prior `vm_inject_irq([1], [2], assert = 1)`, no interrupt vm_exit corresponding to line [2] is delivered to any vCPU even when the vCPU's interrupt window opens or it becomes runnable with the line unmasked.
pub fn vmInjectIrq(caller: *anyopaque, vm: u64, irq_num: u64, assert: u64) i64 {
    if (vm & ~capability.HANDLE_ARG_MASK != 0) return errors.E_INVAL;
    if (assert & ~INJECT_IRQ_ASSERT_MASK != 0) return errors.E_INVAL;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const cd_ref = ec.domain;
    const lr = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = lr.ptr;

    const vm_slot: u12 = @truncate(vm);
    const vm_resolved = capability.resolveHandleOnDomain(cd, vm_slot, .virtual_machine) != null;

    cd_ref.unlockIrqRestore(lr.irq_state);

    if (!vm_resolved) return errors.E_BADCAP;

    return vm_obj.vmInjectIrq(ec, vm, irq_num, assert);
}
