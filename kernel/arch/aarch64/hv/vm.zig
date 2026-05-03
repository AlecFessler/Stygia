const std = @import("std");
const zag = @import("zag");

const hv = zag.arch.aarch64.hv;
const hv_vcpu = hv.vcpu;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const serial = zag.arch.aarch64.serial;
const stage2_mod = zag.arch.aarch64.stage2;
const vgic_mod = hv.vgic;
const vm_hw = zag.arch.aarch64.vm;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const MemoryPerms = zag.memory.address.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageFrame = zag.memory.page_frame.PageFrame;
const VAddr = zag.memory.address.VAddr;
const VmarPageSize = zag.memory.vmar.PageSize;
const VirtualMachine = zag.hv.virtual_machine.VirtualMachine;

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

// GICv3 distributor + redistributor IPA windows the FDT advertises.
// Without a vGIC, every Linux probe of these regions trapped through
// the VMM, which dropped the access and resumed — adding multiple
// minutes to the early init under TCG. Inline-handling them here
// produces the same observable behaviour (read=0, write swallowed)
// without the round-trip.
const GICD_IPA_BASE: u64 = 0x0800_0000;
const GICD_IPA_SIZE: u64 = 0x0001_0000;
const GICR_IPA_BASE: u64 = 0x080A_0000;
const GICR_IPA_SIZE: u64 = 0x0002_0000;

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
/// run loop threads both PAddrs through `hyp.vmResume`).
pub const CtrlStateCell = extern struct {
    control_block_pa: PAddr align(paging.PAGE4K) = .{ .addr = 0 },
    _pad: [paging.PAGE4K - @sizeOf(PAddr)]u8 = undefined,
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

/// Allocate per-VM control state: a CtrlStateCell to pin the PA of
/// the control block, plus a separate PMM page for the control block
/// itself (zero-initialized → sysregPassthrough writes land in known
/// zero-bit positions). `vm.guest_pt_root` was already populated by
/// `allocStage2Root` earlier in `allocVm`, so the run loop has both
/// pieces it needs by the time `enterGuest` first runs.
pub fn allocVmArchState(vm: *VirtualMachine, policy_pf: *PageFrame) !*anyopaque {
    _ = vm;
    _ = policy_pf;
    const cell = pmm.global_pmm.?.create(CtrlStateCell) catch
        return error.OutOfMemory;
    const cb_page = pmm.global_pmm.?.create(paging.PageMem(.page4k)) catch {
        pmm.global_pmm.?.destroy(cell);
        return error.OutOfMemory;
    };
    cell.* = .{
        .control_block_pa = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(cb_page)), null),
    };
    return @ptrCast(cell);
}

pub fn freeVmArchState(vm: *VirtualMachine) void {
    const erased = vm.arch_state orelse return;
    const cell: *CtrlStateCell = @ptrCast(@alignCast(erased));
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
    const arch_state = hv_vcpu.archStateOf(vcpu_ec) orelse return false;
    const gs = &arch_state.guest_state;

    // PL011.
    if (guest_phys >= PL011_IPA_BASE and guest_phys < PL011_IPA_BASE + PL011_IPA_SIZE) {
        const offset = guest_phys - PL011_IPA_BASE;
        if (is_write) {
            if (offset == UARTDR_OFFSET) {
                const ch: u8 = @intCast(readGuestGpr(gs, srt) & 0xFF);
                const buf: [1]u8 = .{ch};
                serial.printRaw(buf[0..]);
            }
            return true;
        }
        const value: u64 = switch (offset) {
            UARTDR_OFFSET => 0,
            UARTFR_OFFSET => UARTFR_RXFE | UARTFR_TXFE,
            0xFE0 => 0x11, // PrimeCell IDs (PL011 r1p5 §4.3 Table 4-2).
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

    // GICv3 distributor + redistributor — drop accesses and pretend
    // it's quiescent (read = 0, write swallowed). The vGIC isn't
    // wired yet; without inline handling Linux's GIC probe round-
    // trips through the VMM ~hundreds of times during init.
    const in_gicd = guest_phys >= GICD_IPA_BASE and guest_phys < GICD_IPA_BASE + GICD_IPA_SIZE;
    const in_gicr = guest_phys >= GICR_IPA_BASE and guest_phys < GICR_IPA_BASE + GICR_IPA_SIZE;
    if (in_gicd or in_gicr) {
        if (!is_write) writeGuestGpr(gs, srt, 0);
        return true;
    }

    return false;
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
