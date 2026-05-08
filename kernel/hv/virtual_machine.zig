//! Virtual Machine — guest execution environment with its own guest
//! physical address space. Execution contexts enter guest mode within
//! a VM to run. See spec §[virtual_machine].
//!
//! Capability-domain lifetime; the VM handle is non-transferable so
//! exactly one user-visible handle exists (held by the binding
//! capability domain). vCPU ECs back-reference the VM through their
//! `vm` field. UAF protection on those back-refs comes from
//! `_gen_lock`.

const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const arch_smp = zag.arch.dispatch.smp;
const capability = zag.caps.capability;
const cd_mod = zag.caps.capability_domain;
const ec_mod = zag.sched.execution_context;
const errors = zag.syscall.errors;
const page_frame_mod = zag.memory.page_frame;
const port_mod = zag.sched.port;
const vm_dispatch = zag.arch.dispatch.vm;

const CapabilityDomain = zag.caps.capability_domain.CapabilityDomain;
const CapabilityType = zag.caps.capability.CapabilityType;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const GenLock = zag.memory.allocators.secure_slab.GenLock;
const KernelHandle = zag.caps.capability.KernelHandle;
const MemoryPerms = zag.memory.address.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageFrame = zag.memory.page_frame.PageFrame;
const PageFrameCaps = zag.memory.page_frame.PageFrameCaps;
const Port = zag.sched.port.Port;
const Priority = zag.sched.execution_context.Priority;
const SecureSlab = zag.memory.allocators.secure_slab.SecureSlab;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const VAddr = zag.memory.address.VAddr;
const VmarPageSize = zag.memory.vmar.PageSize;
const Word0 = zag.caps.capability.Word0;

/// Cap bits in `Capability.word0[48..63]` for VM handles.
/// Spec §[virtual_machine]: bit 0 = `policy`, bit 1 = `restart_policy`;
/// bits 2-15 are reserved. VM handles are non-transferable so there are
/// no `move`/`copy` bits.
pub const VmCaps = packed struct(u16) {
    policy: bool = false,
    restart_policy: u1 = 0,
    _reserved: u14 = 0,
};

/// Maximum number of distinct `map_guest` page_frame installations a
/// single VM can hold concurrently. Sized small for the spec-v3 smoke
/// path; the bookkeeping array is colocated in `VirtualMachine` so the
/// per-install entry cost is just one slot.
pub const MAX_GUEST_INSTALLS: usize = 64;

/// One installed (host_phys → guest_addr) pair from a `map_guest` call.
/// `unmap_guest` resolves by `pf` handle; the entry stays valid until
/// the matching `unmap_guest` removes it.
pub const GuestInstall = struct {
    pf: ?SlabRef(PageFrame) = null,
    guest_addr: u64 = 0,
    page_count: u32 = 0,
    sz: VmarPageSize = .sz_4k,
};

pub const VirtualMachine = struct {
    /// Slab generation lock. Validates `SlabRef(VirtualMachine)`
    /// liveness AND guards every mutable field below.
    _gen_lock: GenLock = .{},

    /// Owning capability domain. VM cannot outlive its owner —
    /// `destroyVm` runs ahead of any domain teardown.
    domain: SlabRef(CapabilityDomain),

    /// Physical address of the guest's second-stage / nested page-
    /// table root (EPT root on Intel, NPT root on AMD, stage-2 root
    /// on aarch64). Mutated by `map_guest` / `unmap_guest`.
    guest_pt_root: PAddr,

    /// Arch-specific per-VM control state — VMCS / VMCB / stage-2
    /// translation regime, kernel-emulated LAPIC/IOAPIC/timer state,
    /// intercept/passthrough configuration, etc. Allocated out-of-
    /// band, layout per arch. Type-erased here; concrete type in
    /// `arch.dispatch.vm`.
    arch_state: ?*anyopaque = null,

    /// Page frame holding the seeded `VmPolicy`. Per spec the kernel
    /// retains a reference on this page frame for the VM's lifetime so
    /// the policy backing pages cannot be freed under guest exits that
    /// consult them.
    policy_pf: ?SlabRef(PageFrame) = null,

    /// VM policy bits (per spec field0 / cap word `policy`). Encoding
    /// TBD as VM creation cap bits get fleshed out — placeholder.
    policy: u8 = 0,

    /// Bookkeeping for `map_guest` installations. `unmap_guest` resolves
    /// by page_frame handle (§[unmap_guest] test 04 returns E_NOENT for
    /// unmapped frames), so we need to remember `(pf, guest_addr)` pairs
    /// per VM. Slots with `pf == null` are free.
    installs: [MAX_GUEST_INSTALLS]GuestInstall = [_]GuestInstall{.{}} ** MAX_GUEST_INSTALLS,

    /// Per-arch emulated-device state. On x86-64 this carries the
    /// kernel-emulated LAPIC + IOAPIC pair consumed by the run loop's
    /// pre-VMRUN hook (`vm_runloop.enterGuest`) and `vm_inject_irq`. On
    /// aarch64 it is an empty struct (vGIC state lives elsewhere). Held
    /// inline so the type is per-arch without the generic struct naming
    /// arch-specific modules — see `arch.dispatch.vm.VmDevices`.
    arch_devices: vm_dispatch.VmDevices = .{},
};

pub const Allocator = SecureSlab(VirtualMachine, 256);
pub var slab_instance: Allocator = undefined;

pub fn initSlab(
    data_range: zag.utils.range.Range,
    ptrs_range: zag.utils.range.Range,
    links_range: zag.utils.range.Range,
) void {
    slab_instance = Allocator.init(data_range, ptrs_range, links_range);
}

/// Public release-handle entry point invoked from the cross-cutting
/// `caps.capability.delete` path. VM handles are non-transferable;
/// delete tears down vCPUs, guest memory, and arch state.
pub fn releaseHandle(vm: *VirtualMachine) void {
    destroyVm(vm);
}

/// Variant of `releaseHandle` for the `destroyCapabilityDomain` path:
/// the owning CD slab slot has already been freed by the caller, so
/// the `vm.domain.ptr.vm = null` back-pointer clear that `destroyVm`
/// performs is omitted — that write would race a reallocation of the
/// CD slot.
pub fn releaseHandleAfterDomainDestroyed(vm: *VirtualMachine) void {
    if (vm.policy_pf) |pf_ref| {
        decPageFrameRef(pf_ref.ptr);
        vm.policy_pf = null;
    }
    vm_dispatch.freeVmArchState(vm);
    vm_dispatch.freeStage2Root(vm);
    const gen = vm._gen_lock.currentGen();
    slab_instance.destroy(vm, gen) catch {};
}

// ── External API ─────────────────────────────────────────────────────

/// `create_virtual_machine` syscall handler. Spec §[virtual_machine].
pub fn createVirtualMachine(caller: *ExecutionContext, caps: u64, policy_pf: u64) i64 {
    if (caps >> 16 != 0) return errors.E_INVAL;
    if (policy_pf >> 12 != 0) return errors.E_INVAL;

    const requested_caps: u16 = @truncate(caps);

    const dlr = caller.domain.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const domain = dlr.ptr;
    defer caller.domain.unlockIrqRestore(dlr.irq_state);

    // Spec: handle is non-transferable, exactly one per domain.
    if (domain.vm != null) return errors.E_FULL;

    const self_caps_struct: cd_mod.CapabilityDomainCaps = @bitCast(readSelfCaps(domain));
    if (!self_caps_struct.crvm) return errors.E_PERM;

    // Spec §[virtual_machine] VmCap layout: bit 0 = `policy`, bit 1 =
    // `restart_policy`. `vm_ceiling` (self-handle field0 bits 48-55 per
    // §[capability_domain] Self handle layout — shifted up by 8 from
    // the [2] ceilings_inner layout to make room for idc_rx at bits
    // 32-39) gates only `policy`; `restart_policy` is gated separately
    // by `restart_policy_ceiling.vm_restart_max` per §[restart_semantics]
    // and is enforced below.
    const vm_ceiling: u8 = @truncate(readSelfField0(domain) >> 48);
    const requested_policy: u16 = requested_caps & 0x1;
    const ceiling_policy: u16 = vm_ceiling & 0x1;
    if ((requested_policy & ~ceiling_policy) != 0) return errors.E_PERM;

    // Spec §[restart_semantics] test 04: `caps.restart_policy` (bit 1)
    // must not exceed the calling domain's
    // `restart_policy_ceiling.vm_restart_max` — a 1-bit field at
    // self-handle field1 bit 23 (= bit 7 of the 16-bit
    // restart_policy_ceiling sub-word at field1[16..31]).
    const requested_vm_restart: u1 = @truncate((requested_caps >> 1) & 0x1);
    const vm_restart_max: u1 = @truncate((readSelfField1(domain) >> 23) & 0x1);
    if (requested_vm_restart > vm_restart_max) return errors.E_PERM;

    const policy_pf_obj = lookupPageFrame(domain, @truncate(policy_pf)) orelse
        return errors.E_BADCAP;

    // Spec §[create_virtual_machine] tests 05/06/07: reject policy
    // page frames smaller than `sizeof(VmPolicy)` and reject seeded
    // policies whose num_*_responses fields exceed the static array
    // bounds. The struct lives at offset 0 of the page frame; the
    // arch dispatch reads it through the kernel physmap.
    vm_dispatch.validateVmPolicy(policy_pf_obj) catch
        return errors.E_INVAL;

    // Spec §[create_virtual_machine]: E_NODEV if the platform does not
    // support hardware virtualization. The arch dispatch surfaces this
    // through `error.NoDevice` from the alloc stubs when VT-x/SVM/etc.
    // is unavailable or unimplemented. allocVm's inferred error set
    // varies by arch (the aarch64 stubs never raise NoDevice), so we
    // compare on @errorName rather than a switch arm to keep the
    // unreached comparison from tripping per-arch error-set diffs.
    const new_vm = allocVm(domain, policy_pf_obj) catch |err| {
        if (std.mem.eql(u8, @errorName(err), "NoDevice")) return errors.E_NODEV;
        return errors.E_NOMEM;
    };

    const vm_gen = new_vm._gen_lock.currentGen();
    const erased = capability.ErasedSlabRef{
        .ptr = @ptrCast(new_vm),
        .gen = @intCast(vm_gen),
    };

    const slot = cd_mod.mintHandle(
        domain,
        erased,
        .virtual_machine,
        requested_caps,
        0,
        0,
    ) catch {
        destroyVm(new_vm);
        return errors.E_FULL;
    };

    domain.vm = SlabRef(VirtualMachine).init(new_vm, vm_gen);
    // Spec §[error_codes] / §[capabilities]: pack Word0 so the type
    // tag in bits 12..15 disambiguates a real handle word from the
    // small-positive error range 1..15.
    return @intCast(capability.Word0.pack(slot, .virtual_machine, requested_caps));
}

/// `create_vcpu` syscall handler. Spec §[virtual_machine].create_vcpu.
pub fn createVcpu(
    caller: *ExecutionContext,
    caps: u64,
    vm_handle: u64,
    affinity: u64,
    exit_port: u64,
) i64 {
    // caps[1]: bits 0-15 caps, bits 32-33 priority, others reserved.
    if (caps & ~@as(u64, 0x0000_0003_0000_FFFF) != 0) return errors.E_INVAL;
    if (vm_handle >> 12 != 0) return errors.E_INVAL;
    if (exit_port >> 12 != 0) return errors.E_INVAL;

    const requested_caps: u16 = @truncate(caps);
    const requested_priority: Priority = @enumFromInt(@as(u2, @truncate((caps >> 32) & 0x3)));

    const dlr = caller.domain.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const domain = dlr.ptr;
    defer caller.domain.unlockIrqRestore(dlr.irq_state);

    const self_caps_struct: cd_mod.CapabilityDomainCaps = @bitCast(readSelfCaps(domain));
    if (!self_caps_struct.crec) return errors.E_PERM;
    if (@intFromEnum(requested_priority) > self_caps_struct.pri) return errors.E_PERM;

    const ec_inner_ceiling: u8 = @truncate(readSelfField0(domain));
    if ((requested_caps & ec_inner_ceiling) != requested_caps) return errors.E_PERM;

    if (affinity != 0) {
        const cores = arch_smp.coreCount();
        const valid_mask: u64 = if (cores >= 64)
            std.math.maxInt(u64)
        else
            (@as(u64, 1) << @as(u6, @intCast(cores))) - 1;
        if (affinity & ~valid_mask != 0) return errors.E_INVAL;
    }

    const vm = lookupVirtualMachine(domain, @truncate(vm_handle)) orelse
        return errors.E_BADCAP;

    const port = lookupPort(domain, @truncate(exit_port)) orelse
        return errors.E_BADCAP;

    // Spec §[port] lifetime: the vCPU pins exit_port via
    // bind_refcount for as long as the vCPU exists (vm_exit events
    // fire spontaneously on the bound port — same lifetime class as
    // event_routes and bind-cap holders). The matching dec runs in
    // `destroyExecutionContextLocked`. observed_zero is structurally
    // impossible — `lookupPort` resolved against the caller's CD
    // whose handle pins the port.
    const vcpu_ec = allocVcpu(vm, domain, affinity, port) catch
        return errors.E_NOMEM;
    vcpu_ec.priority = requested_priority;

    // Inc + list-link under one port-lock acquire. Published into
    // vcpu_list_head only after the inc, so cascade walks see a
    // consistent view.
    {
        const irq = port._gen_lock.lockIrqSave(@src());
        port_mod.incBindRef(port) catch unreachable;
        vcpu_ec.vcpu_list_next = port.vcpu_list_head;
        port.vcpu_list_head = vcpu_ec;
        port._gen_lock.unlockIrqRestore(irq);
    }

    const ec_gen = vcpu_ec._gen_lock.currentGen();
    const erased = capability.ErasedSlabRef{
        .ptr = @ptrCast(vcpu_ec),
        .gen = @intCast(ec_gen),
    };

    const slot = cd_mod.mintHandle(
        domain,
        erased,
        .execution_context,
        requested_caps,
        @intFromEnum(requested_priority),
        affinity,
    ) catch return errors.E_FULL;

    // Spec §[virtual_machine].create_vcpu test 12: an initial vm_exit
    // event is delivered immediately so the creator installs real
    // entry state through the standard recv/reply lifecycle.
    port_mod.fireVmExit(vcpu_ec, INITIAL_STATE_SUBCODE, .{ 0, 0, 0 });

    // Spec §[error_codes] / §[capabilities]: pack Word0 so the type
    // tag in bits 12..15 disambiguates a real handle word from the
    // small-positive error range 1..15.
    return @intCast(capability.Word0.pack(slot, .execution_context, requested_caps));
}

/// `map_guest` syscall handler. Spec §[virtual_machine].map_guest.
pub fn mapGuest(caller: *ExecutionContext, vm_handle: u64, pairs: []const u64) i64 {
    if (vm_handle >> 12 != 0) return errors.E_INVAL;
    if (pairs.len == 0 or pairs.len % 2 != 0) return errors.E_INVAL;

    const dlr = caller.domain.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const domain = dlr.ptr;
    defer caller.domain.unlockIrqRestore(dlr.irq_state);

    const vm = lookupVirtualMachine(domain, @truncate(vm_handle)) orelse
        return errors.E_BADCAP;

    const pair_count = pairs.len / 2;

    // Pre-validate every pair before any stage-2 mutation. Partial
    // installs would leave un-named mappings (`unmap_guest` resolves
    // by page_frame handle, not guest_addr) so an unwound failure
    // could still alter the address space.
    var i: usize = 0;
    while (i < pair_count) {
        const guest_addr = pairs[2 * i];
        const pf_handle_word = pairs[2 * i + 1];
        if (pf_handle_word >> 12 != 0) return errors.E_INVAL;
        const pf = lookupPageFrame(domain, @truncate(pf_handle_word)) orelse
            return errors.E_BADCAP;
        const stride = pageStride(pf.sz);
        if (guest_addr % stride != 0) return errors.E_INVAL;

        var j: usize = 0;
        while (j < i) {
            const other_pf = lookupPageFrame(domain, @truncate(pairs[2 * j + 1])) orelse
                return errors.E_BADCAP;
            if (rangesOverlap(guest_addr, pf, pairs[2 * j], other_pf)) return errors.E_INVAL;
            j += 1;
        }

        // Spec §[map_guest] test 06: the new pair must not overlap any
        // page_frame already installed in this VM's guest physical
        // address space.
        for (&vm.installs) |*entry| {
            // caller-pinned: PF refcount kept by VM for its install
            // bookkeeping; caller holds vm's gen-lock context.
            const entry_pf_ref = entry.pf orelse continue;
            if (installRangesOverlap(guest_addr, pf, entry.guest_addr, entry_pf_ref.ptr)) return errors.E_INVAL;
        }
        i += 1;
    }

    i = 0;
    while (i < pair_count) {
        const pf_slot: u12 = @truncate(pairs[2 * i + 1]);
        const pf = lookupPageFrame(domain, pf_slot) orelse return errors.E_BADCAP;
        const pf_caps: PageFrameCaps = @bitCast(Word0.caps(domain.user_table[pf_slot].word0));
        const rc = installPageFrame(vm, pairs[2 * i], pf, pageFramePerms(pf_caps));
        if (rc != 0) return rc;
        i += 1;
    }

    return 0;
}

/// `unmap_guest` syscall handler. Spec §[virtual_machine].unmap_guest.
pub fn unmapGuest(caller: *ExecutionContext, vm_handle: u64, page_frames: []const u64) i64 {
    if (vm_handle >> 12 != 0) return errors.E_INVAL;
    if (page_frames.len == 0) return errors.E_INVAL;

    const dlr = caller.domain.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const domain = dlr.ptr;
    defer caller.domain.unlockIrqRestore(dlr.irq_state);

    const vm = lookupVirtualMachine(domain, @truncate(vm_handle)) orelse
        return errors.E_BADCAP;

    for (page_frames) |pf_handle_word| {
        if (pf_handle_word >> 12 != 0) return errors.E_INVAL;
        const pf = lookupPageFrame(domain, @truncate(pf_handle_word)) orelse
            return errors.E_BADCAP;
        const rc = uninstallPageFrame(vm, pf);
        if (rc != 0) return rc;
    }

    return 0;
}

/// `vm_inject_irq` syscall handler. Spec §[virtual_machine].vm_inject_irq.
/// Thin wrapper around `dispatch.vm.vmInjectIrq` — the syscall trampoline
/// has already validated the VM handle and stripped the `assert` flag's
/// reserved bits.
pub fn vmInjectIrq(
    caller: *ExecutionContext,
    vm_handle: u64,
    irq_num: u64,
    assert: u64,
) i64 {
    if (vm_handle >> 12 != 0) return errors.E_INVAL;

    const dlr = caller.domain.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const domain = dlr.ptr;
    defer caller.domain.unlockIrqRestore(dlr.irq_state);

    const slot: u12 = @truncate(vm_handle);
    const vm = lookupVirtualMachine(domain, slot) orelse return errors.E_BADCAP;

    // §[vm_inject_irq] [2] is a u64 line number; reject anything that
    // can't fit in u32 up front (no plausible emulated controller has
    // billions of lines). Per-arch dispatch then enforces the actual
    // upper bound for the VM's emulated controller.
    if (irq_num > std.math.maxInt(u32)) return errors.E_INVAL;
    const irq32: u32 = @truncate(irq_num);
    const assert_bit: bool = (assert & 0x1) != 0;
    return vm_dispatch.vmInjectIrq(vm, irq32, assert_bit);
}

/// `vm_set_policy` syscall handler. Spec §[virtual_machine].vm_set_policy.
/// Proxies to `dispatch.vm.applyVmPolicyTable` for the per-arch encoding.
/// `count` is the spec-defined entry count from syscall word bits 13-20;
/// the per-arch handler bounds-checks it against the active (kind, arch)
/// MAX_* and validates the entries slice carries the right number of
/// vregs.
pub fn applyVmPolicyTable(
    caller: *ExecutionContext,
    vm_handle: u64,
    kind: u8,
    count: u8,
    entries: []const u64,
) i64 {
    if (vm_handle >> 12 != 0) return errors.E_INVAL;

    const dlr = caller.domain.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const domain = dlr.ptr;
    defer caller.domain.unlockIrqRestore(dlr.irq_state);

    const slot: u12 = @truncate(vm_handle);
    _ = lookupHandle(domain, slot, .virtual_machine) orelse return errors.E_BADCAP;

    const vm_caps: VmCaps = @bitCast(Word0.caps(domain.user_table[slot].word0));
    if (!vm_caps.policy) return errors.E_PERM;

    const vm = lookupVirtualMachine(domain, slot) orelse return errors.E_BADCAP;
    return vm_dispatch.applyVmPolicyTable(vm, kind, count, entries);
}

// ── Internal API ─────────────────────────────────────────────────────

/// Initial-state vm_exit sub-code per spec §[vm_exit_state] — the
/// "vCPU has not yet entered guest mode" value the kernel injects at
/// `create_vcpu` and after a reply that left the vCPU not-started.
/// Per-arch table values: x86-64 = 13, aarch64 = 10.
pub const INITIAL_STATE_SUBCODE: u8 = switch (@import("builtin").cpu.arch) {
    .x86_64 => 13,
    .aarch64 => 10,
    else => @compileError("unsupported arch"),
};

/// Allocate a VM bound to `domain`. Allocates stage-2 page-table root
/// from PMM, allocates arch control structure, retains a reference on
/// `policy_pf`. Spec §[virtual_machine].create_virtual_machine.
fn allocVm(domain: *CapabilityDomain, policy_pf: *PageFrame) !*VirtualMachine {
    const pending = try slab_instance.create();
    const new_vm = pending.ptr;

    // Slab zero-on-free covers arch_state=null, policy_pf=null, policy=0.
    new_vm.domain = SlabRef(CapabilityDomain).init(domain, domain._gen_lock.currentGen());

    new_vm.guest_pt_root = vm_dispatch.allocStage2Root(new_vm) catch |err| {
        slab_instance.destroyAlreadyMarked(new_vm);
        return err;
    };

    new_vm.arch_state = vm_dispatch.allocVmArchState(new_vm, policy_pf) catch |err| {
        vm_dispatch.freeStage2Root(new_vm);
        slab_instance.destroyAlreadyMarked(new_vm);
        return err;
    };

    // Initialize emulated APIC pair. Bidirectional: LAPIC notifies IOAPIC
    // on EOI to re-deliver level-triggered IRQs; IOAPIC writes vectors
    // into LAPIC IRR on pin assert. No-op on aarch64.
    vm_dispatch.initVmDevices(&new_vm.arch_devices);

    incPageFrameRef(policy_pf);
    new_vm.policy_pf = SlabRef(PageFrame).init(policy_pf, policy_pf._gen_lock.currentGen());

    _ = slab_instance.publish(pending);
    return new_vm;
}

/// Final teardown — frees guest memory mappings, tears down emulated
/// devices, frees arch state and stage-2 root, drops the held
/// `policy_pf` reference, clears `domain.vm`, returns slab slot.
fn destroyVm(vm: *VirtualMachine) void {
    if (vm.policy_pf) |pf_ref| {
        // caller-pinned: PF refcount kept by VM for its lifetime.
        decPageFrameRef(pf_ref.ptr);
        vm.policy_pf = null;
    }
    vm_dispatch.freeVmArchState(vm);
    vm_dispatch.freeStage2Root(vm);
    // caller-pinned: VM's domain owns it.
    vm.domain.ptr.vm = null;
    const gen = vm._gen_lock.currentGen();
    slab_instance.destroy(vm, gen) catch {};
}

/// Find the install bookkeeping slot that holds `pf`, or null. Slot
/// search is linear over `MAX_GUEST_INSTALLS`; sized for spec-v3 smoke
/// VMs, will need a hash table when guest RAM grows.
fn findInstall(vm: *VirtualMachine, pf: *PageFrame) ?*GuestInstall {
    for (&vm.installs) |*entry| {
        if (entry.pf) |pf_ref| {
            // Identity compare: SlabRef.ptr == raw pointer.
            if (pf_ref.ptr == pf) return entry;
        }
    }
    return null;
}

/// Allocate the next free install slot, or null if the array is full.
fn allocInstall(vm: *VirtualMachine) ?*GuestInstall {
    for (&vm.installs) |*entry| {
        if (entry.pf == null) return entry;
    }
    return null;
}

/// Install `pf` at `guest_addr` in stage-2 tables; increments mapcnt.
/// Per-page loop: each page in the page_frame is mapped contiguously
/// at `guest_addr + i * pf.sz`. `perms` carries the cap-derived stage-2
/// rwx envelope — guest accesses outside this envelope take a stage-2
/// fault per spec §[virtual_machine].map_guest test 07.
fn installPageFrame(vm: *VirtualMachine, guest_addr: u64, pf: *PageFrame, perms: MemoryPerms) i64 {
    const slot = allocInstall(vm) orelse return errors.E_FULL;

    const stride = pageStride(pf.sz);
    var i: u32 = 0;
    while (i < pf.page_count) {
        const ga = guest_addr + @as(u64, i) * stride;
        const ha = PAddr.fromInt(pf.phys_base.addr + @as(u64, i) * stride);
        vm_dispatch.stage2MapPage(vm, ga, ha, pf.sz, perms) catch {
            // Roll back: unmap any pages we already installed.
            var j: u32 = 0;
            while (j < i) {
                const ga_j = guest_addr + @as(u64, j) * stride;
                vm_dispatch.stage2UnmapPage(vm, ga_j, pf.sz);
                j += 1;
            }
            return errors.E_NOMEM;
        };
        i += 1;
    }

    slot.* = .{
        .pf = SlabRef(PageFrame).init(pf, pf._gen_lock.currentGen()),
        .guest_addr = guest_addr,
        .page_count = pf.page_count,
        .sz = pf.sz,
    };
    incPageFrameMap(pf);
    return 0;
}

/// Remove `pf`'s installation from stage-2 tables; decrements mapcnt;
/// queues TLB shootdown to cores running this VM's vCPUs. Resolves
/// the page_frame's installed guest_addr via the per-VM bookkeeping
/// table populated by `installPageFrame`.
fn uninstallPageFrame(vm: *VirtualMachine, pf: *PageFrame) i64 {
    const slot = findInstall(vm, pf) orelse return errors.E_NOENT;

    const guest_addr = slot.guest_addr;
    const stride = pageStride(slot.sz);

    var i: u32 = 0;
    while (i < slot.page_count) {
        const ga = guest_addr + @as(u64, i) * stride;
        vm_dispatch.stage2UnmapPage(vm, ga, slot.sz);
        i += 1;
    }

    vm_dispatch.invalidateStage2Range(vm, guest_addr, slot.sz, slot.page_count);
    slot.* = .{};
    decPageFrameMap(pf);
    return 0;
}

/// Allocate a vCPU EC bound to this VM with `exit_port` set. The
/// vCPU EC is bound to the capability domain that holds the VM
/// handle (per spec); on a multi-domain handoff the holder is the
/// VM's owning domain.
fn allocVcpu(
    vm: *VirtualMachine,
    creator_domain: *CapabilityDomain,
    affinity: u64,
    exit_port: *Port,
) !*ExecutionContext {
    _ = creator_domain;

    // caller-pinned: VM's domain owns the VM and outlives it (destroyVm
    // runs ahead of any domain teardown).
    const vcpu_ec = try ec_mod.allocExecutionContext(
        vm.domain.ptr, // caller-pinned
        VAddr.fromInt(0),
        0,
        affinity,
        .normal,
        vm,
        exit_port,
    );

    try vm_dispatch.allocVcpuArchState(vm, vcpu_ec);

    return vcpu_ec;
}

// ── Helpers ──────────────────────────────────────────────────────────

fn readSelfCaps(domain: *CapabilityDomain) u16 {
    return Word0.caps(domain.user_table[0].word0);
}

fn readSelfField0(domain: *CapabilityDomain) u64 {
    return domain.user_table[0].field0;
}

fn readSelfField1(domain: *CapabilityDomain) u64 {
    return domain.user_table[0].field1;
}

fn lookupHandle(domain: *CapabilityDomain, slot: u12, expected: CapabilityType) ?*KernelHandle {
    if (@as(u16, slot) >= capability.MAX_HANDLES_PER_DOMAIN) return null;
    const entry = &domain.kernel_table[slot];
    if (entry.ref.ptr == null) return null;
    if (Word0.typeTag(domain.user_table[slot].word0) != expected) return null;
    return entry;
}

fn lookupVirtualMachine(domain: *CapabilityDomain, slot: u12) ?*VirtualMachine {
    const handle = lookupHandle(domain, slot, .virtual_machine) orelse return null;
    const ref = capability.typedRef(VirtualMachine, handle.*) orelse return null;
    return ref.ptr;
}

fn lookupPageFrame(domain: *CapabilityDomain, slot: u12) ?*PageFrame {
    const handle = lookupHandle(domain, slot, .page_frame) orelse return null;
    const ref = capability.typedRef(PageFrame, handle.*) orelse return null;
    return ref.ptr;
}

fn lookupPort(domain: *CapabilityDomain, slot: u12) ?*Port {
    const handle = lookupHandle(domain, slot, .port) orelse return null;
    const ref = capability.typedRef(Port, handle.*) orelse return null;
    return ref.ptr;
}

/// Translate a guest-physical address to a kernel-mode physmap pointer
/// using the VM's `installs[]` bookkeeping. Walks the install table
/// looking for the region that covers `[gpa, gpa+len)` and returns a
/// kernel-VA pointer at `pf.phys_base + (gpa - install.guest_addr)`.
/// Returns null if no install covers the requested range.
///
/// Used by per-arch in-kernel device emulation (LAPIC/IOAPIC MMIO,
/// instruction fetch on EPT/stage-2 violations) to read/write guest
/// memory via the kernel physmap. Reads through the returned pointer
/// don't need SMAP bracketing — physmap is a kernel-mode VA range.
pub fn guestPhysToHost(vm: *const VirtualMachine, gpa: u64, len: usize) ?[*]u8 {
    for (vm.installs) |inst| {
        const pf_ref = inst.pf orelse continue;
        const pf = pf_ref.ptr;
        const stride = pageStride(inst.sz);
        const region_size = stride * @as(u64, inst.page_count);
        if (gpa < inst.guest_addr) continue;
        const offset = gpa - inst.guest_addr;
        if (offset >= region_size) continue;
        if (region_size - offset < @as(u64, len)) continue;
        const host_pa = zag.memory.address.PAddr.fromInt(pf.phys_base.addr + offset);
        const host_va = zag.memory.address.VAddr.fromPAddr(host_pa, null);
        return @ptrFromInt(host_va.addr);
    }
    return null;
}

fn pageStride(sz: VmarPageSize) u64 {
    return switch (sz) {
        .sz_4k => 0x1000,
        .sz_2m => 0x20_0000,
        .sz_1g => 0x4000_0000,
        ._reserved => 0x1000,
    };
}

fn rangesOverlap(addr_a: u64, pf_a: *PageFrame, addr_b: u64, pf_b: *PageFrame) bool {
    const end_a = addr_a + pageStride(pf_a.sz) * pf_a.page_count;
    const end_b = addr_b + pageStride(pf_b.sz) * pf_b.page_count;
    return addr_a < end_b and addr_b < end_a;
}

/// Variant of `rangesOverlap` that compares an incoming pair against an
/// already-installed entry from `vm.installs` (whose `pf` pointer may be
/// the same as the new pair's pf — that is exactly the overlap the spec
/// rejects).
fn installRangesOverlap(new_addr: u64, new_pf: *PageFrame, installed_addr: u64, installed_pf: *PageFrame) bool {
    const end_new = new_addr + pageStride(new_pf.sz) * new_pf.page_count;
    const end_installed = installed_addr + pageStride(installed_pf.sz) * installed_pf.page_count;
    return new_addr < end_installed and installed_addr < end_new;
}

/// Translate a holder's PageFrame `r/w/x` cap bits into stage-2
/// permissions. Spec §[virtual_machine].map_guest test 07: a guest
/// access whose required rwx is not a subset of these bits delivers a
/// vm_exit (`ept` on x86-64, `stage2_fault` on aarch64).
fn pageFramePerms(caps_bits: PageFrameCaps) MemoryPerms {
    return .{
        .read = caps_bits.r,
        .write = caps_bits.w,
        .exec = caps_bits.x,
    };
}

/// Holder-side refcount + mapcnt accessors. Thin wrappers over the
/// canonical helpers in `kernel/memory/page_frame.zig` — using those
/// directly ensures the conjunctive (refcount==0 AND mapcnt==0)
/// teardown path runs the canonical `destroyPageFrame`, which both
/// frees the slab slot AND returns the buddy block to PMM. Earlier
/// forks here only freed the slab slot, leaking the backing physical
/// pages on every VM destroy / `unmap_guest`.
fn incPageFrameRef(pf: *PageFrame) void {
    // Caller pins `pf` via either an existing VM-held SlabRef
    // (createVm: caller-resolved policy_pf handle) or the active VM's
    // map_guest install. A concurrent destroy that drove refcount to
    // Sticky must have torn down those refs first, so observed_zero is
    // structurally unreachable here.
    page_frame_mod.incHandleRef(pf) catch unreachable;
}

fn decPageFrameRef(pf: *PageFrame) void {
    page_frame_mod.releaseHandle(pf);
}

fn incPageFrameMap(pf: *PageFrame) void {
    // Mirrors `kernel/memory/vmar.zig:mappingInstall`: a plain atomic
    // RMW. The pf is pinned by a SlabRef in `vm.installs` while we
    // raise the count; the conjunctive teardown gate is checked under
    // `_gen_lock` by `releaseMapping` on the matching dec.
    _ = @atomicRmw(u32, &pf.mapcnt, .Add, 1, .seq_cst);
}

fn decPageFrameMap(pf: *PageFrame) void {
    page_frame_mod.releaseMapping(pf);
}
