const std = @import("std");
const stygia = @import("stygia");

const hv = stygia.arch.aarch64.hv;
const hv_vcpu = hv.vcpu;
const paging = stygia.memory.paging;
const pmm = stygia.memory.pmm;
const serial = stygia.arch.aarch64.serial;
const stage2_mod = stygia.arch.aarch64.stage2;
const vgic_mod = hv.vgic;
const vm_hw = stygia.arch.aarch64.vm;

const ExecutionContext = stygia.sched.execution_context.ExecutionContext;
const MemoryPerms = stygia.memory.address.MemoryPerms;
const PAddr = stygia.memory.address.PAddr;
const PageFrame = stygia.memory.page_frame.PageFrame;
const VAddr = stygia.memory.address.VAddr;
const VmarPageSize = stygia.memory.vmar.PageSize;
const VirtualMachine = stygia.hv.virtual_machine.VirtualMachine;

// PL011 IPA range Linux's amba-pl011 driver is wired to in our minimal
// FDT. Inline-handling stage-2 faults on this page in the kernel keeps
// the boot-time char-by-char busybox console out of the multi-second
// VMM-roundtrip path under TCG.
const PL011_IPA_BASE: u64 = 0x0900_0000;
const PL011_IPA_SIZE: u64 = 0x1000;
const UARTDR_OFFSET: u64 = 0x000;
const UARTFR_OFFSET: u64 = 0x018;
const UARTFR_RXFE: u32 = 1 << 4;
const UARTFR_TXFE: u32 = 1 << 7;

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
/// contract. Holds the PA of the per-VM control block (allocated
/// alongside as a separate PMM page; the old order-1 contiguous
/// "vm_structures" allocation isn't available in spec-v3's PMM, so the
/// stage-2 root and the control block are two separate pages and the
/// run loop threads both PAddrs through `hyp.vmResume`) plus the
/// in-kernel emulated GIC distributor that `vm_inject_irq` mutates.
/// Per spec §[vm_inject_irq] the vGIC pending bitmap must outlive any
/// single syscall, so it lives here rather than on a syscall stack.
pub const CtrlStateCell = extern struct {
    /// Kernel-private copy of the VmPolicy seeded into the user-supplied
    /// `policy_pf`. Placed first so the natural u64 alignment of its
    /// internal fields lines up against the page-aligned struct base
    /// without compiler-inserted gap pads. Userspace retains its own
    /// writable mapping of `policy_pf` after `create_virtual_machine`,
    /// so reading directly from there would let userspace forge
    /// `num_*=0xFFFFFFFF` to drive the run-loop into OOB entry reads.
    /// This kernel copy is the single source of truth: `applyVmPolicyTable`
    /// writes here, the run-loop reads here, userspace cannot reach in.
    /// Concurrent reads from a vCPU on another core are gated by a
    /// store-release on `num_*` paired with a load-acquire on the
    /// reader side per the §[vm_policy] aarch64 publish ordering.
    policy: vm_hw.VmPolicy align(paging.PAGE4K) = .{},
    /// PAddr of the per-VM control block (allocated separately as a
    /// PMM page; `vmResume` threads both this PA and the stage-2 root).
    control_block_pa: PAddr = .{ .addr = 0 },
    /// In-kernel emulated GIC distributor. `vm_inject_irq` flips
    /// pending bits here per Arm IHI 0069H §12.9.11/§12.9.28; the
    /// vCPU run loop reads them on stage-2 entry to populate
    /// list-registers (Arm IHI 0069H §11.2 ICH_LR<n>_EL2).
    vgic: vgic_mod.Vgic = .{},
    _pad: [paging.PAGE4K - @sizeOf(vm_hw.VmPolicy) - @sizeOf(PAddr) - @sizeOf(vgic_mod.Vgic)]u8 = undefined,
};

comptime {
    std.debug.assert(@sizeOf(CtrlStateCell) == paging.PAGE4K);
    std.debug.assert(@alignOf(CtrlStateCell) == paging.PAGE4K);
}

/// Resolve the per-VM CtrlStateCell from `vm.arch_state`. Returns null
/// when no arch-state has been seeded yet (e.g. `create_virtual_machine`
/// failed mid-init); callers route that to the appropriate spec error.
pub fn cellOf(vm: *VirtualMachine) ?*CtrlStateCell {
    const erased = vm.arch_state orelse return null;
    return @ptrCast(@alignCast(erased));
}

/// Allocate the stage-2 / nested page-table root for `vm`. On aarch64
/// this becomes VTTBR_EL2's translation-table base; for now allocate a
/// zeroed 4 KiB page out of the PMM so `hv.virtual_machine.allocVm`
/// has a valid PAddr to install. The page is freed by `freeStage2Root`.
///
/// Spec §[create_virtual_machine] test 03: surface `error.NoDevice`
/// when EL2 is unreachable so `hv.virtual_machine.createVirtualMachine`
/// can return E_NODEV. UEFI-booted aarch64 advertises EL2 in
/// ID_AA64PFR0_EL1 but enters at EL1 with no way to install our
/// `__hyp_vectors` table, leaving `hyp_stub_installed=false` —
/// `vmSupported()` returns false, no world-switch is reachable, and
/// any later `vcpu_run` would trap unhandled. Fail the create here so
/// userspace observes E_NODEV up front rather than getting a handle
/// it can never enter.
pub fn allocStage2Root(vm: *VirtualMachine) !PAddr {
    _ = vm;
    if (!vm_hw.vmSupported()) return error.NoDevice;
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

/// Allocate per-VM control state: a CtrlStateCell to pin the PA of
/// the control block, plus a separate PMM page for the control block
/// itself (zero-initialized → sysregPassthrough writes land in known
/// zero-bit positions). `vm.guest_pt_root` was already populated by
/// `allocStage2Root` earlier in `allocVm`, so the run loop has both
/// pieces it needs by the time `enterGuest` first runs.
pub fn allocVmArchState(vm: *VirtualMachine, policy_pf: *PageFrame) !*anyopaque {
    _ = vm;
    const cell = pmm.global_pmm.?.create(CtrlStateCell) catch
        return error.OutOfMemory;
    const cb_page = pmm.global_pmm.?.create(paging.PageMem(.page4k)) catch {
        pmm.global_pmm.?.destroy(cell);
        return error.OutOfMemory;
    };
    cell.* = .{
        .control_block_pa = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(cb_page)), null),
    };
    // Belt-and-suspenders: the PMM `create` contract zero-initialises
    // the page (matching the GICv3 reset state for GICD_ISPENDR<n> /
    // GICD_ICPENDR<n>; Arm IHI 0069H §12.8 reset column = 0x0000_0000),
    // but call `init` explicitly so the contract is local to this file.
    cell.vgic.init();

    // Copy the user-supplied VmPolicy into kernel-private storage at
    // create time. `validateVmPolicy` (called by the syscall layer
    // before us) already bounded the table counts; clamp again here as
    // a defensive truncation in case userspace mutated the page between
    // validation and copy. The kernel copy is the only source consulted
    // on guest exits / `applyVmPolicyTable` writes — userspace cannot
    // forge `num_*` to drive an OOB read.
    const phys_va = VAddr.fromPAddr(policy_pf.phys_base, null);
    const src: *const vm_hw.VmPolicy = @ptrFromInt(phys_va.addr);
    const id_n = @min(src.num_id_reg_responses, vm_hw.VmPolicy.MAX_ID_REG_RESPONSES);
    const sys_n = @min(src.num_sysreg_policies, vm_hw.VmPolicy.MAX_SYSREG_POLICIES);
    var i: u32 = 0;
    while (i < id_n) : (i += 1) {
        cell.policy.id_reg_responses[i] = src.id_reg_responses[i];
    }
    cell.policy.num_id_reg_responses = id_n;
    i = 0;
    while (i < sys_n) : (i += 1) {
        cell.policy.sysreg_policies[i] = src.sysreg_policies[i];
    }
    cell.policy.num_sysreg_policies = sys_n;
    return @ptrCast(cell);
}

pub fn freeVmArchState(vm: *VirtualMachine) void {
    const cell = cellOf(vm) orelse return;
    if (cell.control_block_pa.addr != 0) {
        const va = VAddr.fromPAddr(cell.control_block_pa, null);
        const cb_page: *paging.PageMem(.page4k) = @ptrFromInt(va.addr);
        pmm.global_pmm.?.destroy(cb_page);
    }
    pmm.global_pmm.?.destroy(cell);
    vm.arch_state = null;
}

// Stage-2 map / unmap / shootdown primitives wire `hv.virtual_machine`'s
// portable map_guest / unmap_guest dispatch to the per-arch stage-2
// walker (kernel/arch/aarch64/stage2.zig).
pub fn stage2MapPage(
    vm: *VirtualMachine,
    guest_phys: u64,
    host_phys: PAddr,
    sz: VmarPageSize,
    perms: MemoryPerms,
) !void {
    _ = sz;
    if (!vm_hw.vmSupported()) return;
    if (vm.guest_pt_root.addr == 0) return;
    const rights: u8 = @bitCast(perms);
    try stage2_mod.mapGuestPage(vm.guest_pt_root, guest_phys, host_phys, rights);
}

pub fn stage2UnmapPage(vm: *VirtualMachine, guest_phys: u64, sz: VmarPageSize) void {
    _ = sz;
    if (!vm_hw.vmSupported()) return;
    if (vm.guest_pt_root.addr == 0) return;
    stage2_mod.unmapGuestPage(vm.guest_pt_root, guest_phys);
}

pub fn invalidateStage2Range(
    vm: *VirtualMachine,
    guest_phys: u64,
    sz: VmarPageSize,
    page_count: u32,
) void {
    _ = vm;
    _ = sz;
    if (!vm_hw.vmSupported()) return;
    var i: u32 = 0;
    while (i < page_count) {
        stage2_mod.invalidateStage2Ipa(guest_phys + @as(u64, i) * paging.PAGE4K);
        i += 1;
    }
}

/// Spec §[vm_set_policy] aarch64 — replace `id_reg_responses` (kind=0)
/// or `sysreg_policies` (kind=1) on `vm`. The kernel-private VmPolicy
/// copy lives in the per-VM `CtrlStateCell` and is the sole source the
/// run loop consults on guest exits; userspace cannot reach into it.
///
/// Each entry's vreg layout is documented in §[vm_set_policy] aarch64:
///   kind=0: `[2+2i+0]` = `{op0 u8, op1 u8, crn u8, crm u8, op2 u8, _pad u8[3]}`;
///           `[2+2i+1]` = `value u64`.
///   kind=1: `[2+3i+0]` = `{op0 u8, op1 u8, crn u8, crm u8, op2 u8, _pad u8[3]}`;
///           `[2+3i+1]` = `read_value u64`;
///           `[2+3i+2]` = `write_mask u64`.
///
/// (op0/op1/crn/crm/op2) tuple follows Arm ARM C5.3 sysreg encoding.
///
/// Publication ordering: aarch64 is weak memory; a vCPU on another core
/// observes `num_*` independently of the entry array unless the writer
/// pairs an entry-fence with a store-release on `num_*`. Plain stores
/// would let the reader see `num=N` before entry `[N-1]` is visible
/// and walk an uninitialized slot. Stores below use `@atomicStore`
/// with `.release` ordering on `num_*`; readers in the run loop pair
/// with `.acquire` loads.
///
/// Reserved-bit enforcement: the entry word containing the (op0..op2)
/// tuple has a `_pad u8[3]` field at bytes [5..7], which packs into
/// bits [40..63] of the u64 vreg. Per §[vm_set_policy] test 04 these
/// must be zero on entry; reject E_INVAL otherwise.
pub fn applyVmPolicyTable(vm: *VirtualMachine, kind: u8, count: u8, entries: []const u64) i64 {
    const errors = stygia.syscall.errors;

    // Spec §[vm_set_policy] aarch64 layout: kind 0 = id_reg_responses
    // (max MAX_ID_REG_RESPONSES), kind 1 = sysreg_policies (max
    // MAX_SYSREG_POLICIES). Reject any other kind with E_INVAL.
    const max: u32 = switch (kind) {
        0 => vm_hw.VmPolicy.MAX_ID_REG_RESPONSES,
        1 => vm_hw.VmPolicy.MAX_SYSREG_POLICIES,
        else => return errors.E_INVAL,
    };
    if (@as(u32, count) > max) return errors.E_INVAL;

    // Per-entry vreg width per §[vm_set_policy] aarch64: kind=0 is
    // 2 vregs/entry, kind=1 is 3. The dispatch layer hands us the
    // full vreg space above [1]; reject wires whose payload cannot
    // supply the required number of vregs of entry data.
    const vregs_per_entry: usize = switch (kind) {
        0 => 2,
        1 => 3,
        else => unreachable,
    };
    const need: usize = @as(usize, count) * vregs_per_entry;
    if (entries.len < need) return errors.E_INVAL;

    // §[vm_set_policy] test 04: reject reserved bits in the entry
    // word containing the sysreg tuple. The encoding occupies bits
    // [0..39]; bits [40..63] are the `_pad u8[3]` field and must be
    // zero. Both kinds share this layout for their first per-entry
    // word.
    const TUPLE_RESERVED_MASK: u64 = ~@as(u64, 0) << 40;
    {
        var i: usize = 0;
        while (i < @as(usize, count)) : (i += 1) {
            const w0 = entries[i * vregs_per_entry + 0];
            if ((w0 & TUPLE_RESERVED_MASK) != 0) return errors.E_INVAL;
        }
    }

    const cell = cellOf(vm) orelse return errors.E_NODEV;
    const policy_ptr: *vm_hw.VmPolicy = &cell.policy;

    switch (kind) {
        0 => {
            var i: usize = 0;
            while (i < @as(usize, count)) : (i += 1) {
                const w0 = entries[i * vregs_per_entry + 0];
                const w1 = entries[i * vregs_per_entry + 1];
                policy_ptr.id_reg_responses[i] = .{
                    .op0 = @truncate(w0),
                    .op1 = @truncate(w0 >> 8),
                    .crn = @truncate(w0 >> 16),
                    .crm = @truncate(w0 >> 24),
                    .op2 = @truncate(w0 >> 32),
                    .value = w1,
                };
            }
            // Release-store: pair with the run loop's acquire-load on
            // `num_id_reg_responses` so a vCPU on another core never
            // observes a higher count than the entries it would read.
            @atomicStore(u32, &policy_ptr.num_id_reg_responses, @as(u32, count), .release);
        },
        1 => {
            var i: usize = 0;
            while (i < @as(usize, count)) : (i += 1) {
                const w0 = entries[i * vregs_per_entry + 0];
                const w1 = entries[i * vregs_per_entry + 1];
                const w2 = entries[i * vregs_per_entry + 2];
                policy_ptr.sysreg_policies[i] = .{
                    .op0 = @truncate(w0),
                    .op1 = @truncate(w0 >> 8),
                    .crn = @truncate(w0 >> 16),
                    .crm = @truncate(w0 >> 24),
                    .op2 = @truncate(w0 >> 32),
                    .read_value = w1,
                    .write_mask = w2,
                };
            }
            @atomicStore(u32, &policy_ptr.num_sysreg_policies, @as(u32, count), .release);
        },
        else => unreachable,
    }

    return 0;
}

/// Resolve the kernel-private VmPolicy backing `vm`. Lives in the
/// per-VM CtrlStateCell so userspace cannot reach into it (the
/// user-supplied `policy_pf` is only consulted at create time, then
/// copied here). Returns null when no arch state has been seeded yet.
pub fn vmPolicyFor(vm: *VirtualMachine) ?*const vm_hw.VmPolicy {
    const cell = cellOf(vm) orelse return null;
    return &cell.policy;
}

/// Assert (or de-assert) a virtual IRQ line on the VM's emulated GIC
/// distributor. The kernel-internal vGIC (hv/vgic.zig) tracks pending
/// state for INTIDs 0..(TOTAL_DIST_INTIDS-1) covering SGIs (0..15),
/// PPIs (16..31), and SPIs (32..(31+MAX_SPIS)) per Arm IHI 0069H §2.2.1.
/// Any `irq_num` beyond that range cannot be emulated and must be
/// rejected with E_INVAL per spec §[vm_inject_irq] test 02. Returns 0
/// on success.
///
/// On assert this mirrors a guest write of 1 to the matching bit of
/// GICD_ISPENDR<n> per Arm IHI 0069H §12.9.28; on de-assert it mirrors
/// a write of 1 to GICD_ICPENDR<n> per §12.9.11. Routing of the
/// pending state into the guest's CPU interface (via list-register
/// programming on stage-2 entry) is the vCPU run loop's responsibility.
pub fn vmInjectIrq(vm: *VirtualMachine, irq_num: u32, assert: bool) i64 {
    const errors = stygia.syscall.errors;
    if (irq_num >= vgic_mod.TOTAL_DIST_INTIDS)
        return errors.E_INVAL;

    const intid: u16 = @intCast(irq_num);

    // The vGIC lives in the per-VM CtrlStateCell allocated by
    // `allocVmArchState`. If `arch_state` is null the VM was created
    // before the arch-state allocation succeeded — surface that as
    // E_NODEV to keep the error space disjoint from the irq_num
    // bounds rejection above.
    const cell = cellOf(vm) orelse return errors.E_NODEV;

    if (assert) {
        cell.vgic.assertIrq(intid);
    } else {
        cell.vgic.deassertIrq(intid);
    }
    return 0;
}

/// Inline-handle a stage-2 fault from the run loop without bouncing to
/// the VMM. Currently only PL011 UART accesses, which Linux hits once
/// per character of console output and the busy-wait FIFO check —
/// every roundtrip through the VMM under TCG costs many ms, which
/// stretches the boot to the 10-minute range. Returns true if the
/// fault was inline-handled (caller advances PC and re-enters guest);
/// false if the fault must surface to the VMM.
pub fn tryHandleStage2Mmio(
    vm: *VirtualMachine,
    vcpu_ec: *ExecutionContext,
    guest_phys: u64,
    iss_valid: bool,
    is_write: bool,
    srt: u8,
) bool {
    _ = vm;
    if (!iss_valid) return false;
    if (guest_phys < PL011_IPA_BASE or guest_phys >= PL011_IPA_BASE + PL011_IPA_SIZE) return false;
    const arch_state = hv_vcpu.archStateOf(vcpu_ec) orelse return false;
    const gs = &arch_state.guest_state;
    const offset = guest_phys - PL011_IPA_BASE;
    if (is_write) {
        if (offset == UARTDR_OFFSET) {
            const ch: u8 = @intCast(readGuestGpr(gs, srt) & 0xFF);
            const buf: [1]u8 = .{ch};
            serial.printRaw(buf[0..]);
        }
        // Other PL011 writes (baud, line control, IMSC, ICR, …) are
        // accepted by hardware and have no host-visible effect we care
        // about for a TX-only console; just swallow.
        return true;
    }
    // Reads.
    const value: u64 = switch (offset) {
        UARTDR_OFFSET => 0,
        UARTFR_OFFSET => UARTFR_RXFE | UARTFR_TXFE,
        // PrimeCell ID page top-half — Linux's amba bus probe.
        0xFE0 => 0x11,
        0xFE4 => 0x10,
        0xFE8 => 0x34,
        0xFEC => 0x00,
        0xFF0 => 0x0D,
        0xFF4 => 0xF0,
        0xFF8 => 0x05,
        0xFFC => 0xB1,
        else => 0,
    };
    writeGuestGpr(gs, srt, value);
    return true;
}

inline fn readGuestGpr(gs: *const vm_hw.GuestState, idx: u8) u64 {
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

inline fn writeGuestGpr(gs: *vm_hw.GuestState, idx: u8, val: u64) void {
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
