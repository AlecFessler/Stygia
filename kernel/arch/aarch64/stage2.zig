//! AArch64 stage-2 translation tables and per-VM control block.
//!
//! Third file of the `vm.zig` / `hyp.zig` / `stage2.zig` split — see
//! `vm.zig`'s module doc comment for the full layering picture.
//!
//! This file owns:
//!   * The stage-2 descriptor format and the 2-level walker.
//!   * The order-1 "arch structures" allocation that pairs the stage-2
//!     root page with a `VmControlBlock` (HCR overrides + VMID) page.
//!   * `mapGuestPage` / `unmapGuestPage` / `invalidateStage2Ipa`.
//!   * `sysregPassthrough` — the HCR_EL2 override manipulator the KVM
//!     layer drives through the `vm_sysreg_passthrough` syscall.
//!
//! Dependencies:
//!   * `vm.zig` for the HCR_EL2 bit constants and the `hypCall` wrapper
//!     that routes `invalidateStage2Ipa` through `hvc_tlbi_ipa`.
//!   * Nothing in `hyp.zig` — the cycle between hyp (which reads this
//!     module's `VmControlBlock` in `vmResume`) and this module is
//!     broken by keeping the `hypCall` ABI wrapper in `vm.zig`.
//!
//! Architectural references:
//!   - ARM ARM K.a D5.2    Translation table walks
//!   - ARM ARM K.a D5.3.3  Stage-2 descriptor format
//!   - ARM ARM K.a D5.4    Stage 2 translation
//!   - ARM ARM K.a D5.5.5  Stage 2 memory region attributes (MemAttr)
//!   - ARM ARM K.a D13.2.46 HCR_EL2 (trap config)
//!   - ARM ARM K.a D13.2.151 VTTBR_EL2
//!   - 102142 §4            "Stage 2 translation"

const std = @import("std");
const zag = @import("zag");

const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const vm = zag.arch.aarch64.vm;

const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

// ===========================================================================
// Stage-2 translation table
// ===========================================================================
//
// Layout choice: 1 GiB IPA, 4 KiB granule, 2-level walk starting at
// Level 2. Rationale:
//   - ARM ARM D5.2, Table D5-14 (4KB granule parameter table) — with
//     TG0=00 and SL0=00, the walk starts at "initial lookup level 2"
//     and the input address size is derived from T0SZ. A T0SZ of 34
//     yields 64-34 = 30 input bits, i.e. 1 GiB of guest IPA, which is
//     enough for every v1 test VM we care about without having to
//     concatenate multiple root pages.
//   - Level 2 entries each cover 2 MiB (bits [29:21]); a single 4 KiB
//     root page holds 512 such entries (= 1 GiB). Leaf pages are at
//     level 3 (4 KiB each, bits [20:12]).
//   - Memory attributes are encoded directly in the descriptor (stage-2
//     does not consult MAIR_ELx — see ARM ARM D5.5.5 and 102142 §4.1).
//
// Descriptor format (ARM ARM D5.3.3 stage-2 descriptor):
//   [0]     valid
//   [1]     1 = table/page, 0 = block/invalid
//   [5:2]   MemAttr[3:0]   stage-2 memory type (D5.5 Table D5-37)
//   [7:6]   S2AP[1:0]      stage-2 access permissions (D5.4 Table D5-31)
//   [9:8]   SH[1:0]        shareability
//   [10]    AF             access flag (must be 1 or fault)
//   [11]    RES0 (nG does not apply to stage-2)
//   [47:12] output address
//   [50:48] RES0
//   [52]    Contiguous
//   [53]    RES0
//   [54]    XN             stage-2 execute-never
//   [58:55] software use / ignored
//   [63:59] PBHA / ignored
//
// Concept map to x86:
//   EPT root          → VTTBR_EL2 base
//   EPT pointer       → VTTBR_EL2 encoding (root PA | VMID)
//   EPT PML4/PDPT/PD  → stage-2 Level 0/1/2 tables
//   EPT PTE           → stage-2 Level 3 descriptor (4K leaf)
//   EPT RWX bits      → S2AP + XN
//   EPT memory type   → MemAttr
//
// References:
//   - ARM ARM K.a D5.4 "Stage 2 translation" (overview)
//   - ARM ARM K.a D5.5.5 "Stage 2 memory region attributes" (MemAttr)
//   - 102142 §4 "Stage 2 translation"

/// Stage-2 leaf memory type. Selects `MemAttr[3:0]` on the Stage2Entry
/// per ARM ARM K.a D5.5.5 Table D5-37 "Stage 2 MemAttr[3:0]":
///
///   0b1111 — Normal, Inner+Outer Write-Back, Write-Allocate, non-transient
///   0b0000 — Device-nGnRnE (strongly-ordered MMIO, no gathering, no
///            reordering, no early ack)
///
/// Used by `mapGuestPage` to let the caller request a device mapping
/// for stage-2 MMIO windows the VMM intends to emulate — guest writes
/// to a Device-nGnRnE page are guaranteed to fault to the hypervisor
/// in program order, which is the ARM equivalent of x86 EPT's "UC"
/// type for an MMIO page.
pub const Stage2MemAttr = enum(u4) {
    normal_wb = 0b1111,
    device_nGnRnE = 0b0000,
};

/// Well-known guest-physical MMIO windows for the "virt" machine layout
/// Zag's VMM currently exposes to guests. Used by `stage2MemAttrForIpa`
/// to pick Device-nGnRnE for pages the VMM is going to emulate. This is
/// intentionally a closed enumeration — any VMM-specific device memory
/// the user wires up through `vm_guest_map` still lands as Normal WB
/// unless the map reply grows an explicit `memattr` flag (TODO #125).
///
/// References:
///   - ARM DDI 0183G     PL011 UART (base 0x09000000 on virt)
///   - virtio-mmio spec  §4.2.2 (0x0a000000..0x0a000e00 on virt)
///   - GICv3 §12         GICD / GICR bases live in `kvm.vgic` and are
///                       already matched by `Vm.tryHandleMmio` before
///                       the stage-2 mapping path is ever reached.
pub const PL011_MMIO_BASE: u64 = 0x09000000;
pub const PL011_MMIO_SIZE: u64 = 0x1000;
pub const VIRTIO_MMIO_BASE: u64 = 0x0a000000;
pub const VIRTIO_MMIO_SIZE: u64 = 0x0e00;

/// Pick the stage-2 memory type for `guest_phys` by IPA window match.
/// Anything outside a known device window is treated as Normal WB.
///
/// TODO(#125): extend `VmReplyAction.map_memory` with an explicit
/// `memattr` field so the VMM can mark arbitrary pages as device
/// without needing kernel awareness of their IPA. Until then, this
/// closed table covers the set of devices every v1 guest actually
/// touches (vGIC is handled inline before we get here).
pub fn stage2MemAttrForIpa(guest_phys: u64) Stage2MemAttr {
    if (guest_phys >= PL011_MMIO_BASE and guest_phys < PL011_MMIO_BASE + PL011_MMIO_SIZE) {
        return .device_nGnRnE;
    }
    if (guest_phys >= VIRTIO_MMIO_BASE and guest_phys < VIRTIO_MMIO_BASE + VIRTIO_MMIO_SIZE) {
        return .device_nGnRnE;
    }
    return .normal_wb;
}

/// 1 GiB IPA → T0SZ = 64 - 30 = 34. Exposed so the VmControlBlock
/// setup (VTCR_EL2) can cite a single source of truth.
pub const STAGE2_T0SZ: u6 = 34;

/// Bit shifts per level, from leaf upwards. Matches the naming used by
/// `kernel/arch/aarch64/paging.zig` for stage-1 (l0sh=12, l1sh=21, ...).
const stage2_leaf_shift: u6 = 12; // level 3 (4 KiB leaf)
const stage2_mid_shift: u6 = 21; // level 2 (2 MiB each)

/// Stage-2 descriptor. Separate from the stage-1 `PageEntry` because the
/// stage-2 encoding is non-trivially different (no AP[2:1], no AttrIndx,
/// MemAttr replaces MAIR indirection, XN at bit 54, no nG).
/// ARM ARM D5.3.3.
const Stage2Entry = packed struct(u64) {
    valid: bool = false,
    /// At a non-leaf level: 1 = table descriptor.
    /// At a leaf level (level 3 with 4 KB granule): 1 = page descriptor.
    /// Both use bit 1 = 1 because the leaf is level 3, not a block.
    is_table_or_page: bool = false,
    /// MemAttr[3:0] — stage-2 memory type. For Normal WB RAM use 0b1111
    /// (Inner/Outer WB non-transient). For Device-nGnRnE MMIO use 0b0000.
    /// ARM ARM D5.5.5, Table D5-37.
    mem_attr: u4 = 0,
    /// S2AP[1:0] — stage-2 access permissions. D5.4 Table D5-31:
    ///   0b00 = none, 0b01 = RO, 0b10 = WO, 0b11 = RW.
    s2ap: u2 = 0,
    /// SH[1:0] — shareability. 0b11 = Inner Shareable, required for SMP.
    sh: u2 = 0,
    /// AF — access flag. Must be set (or the first access traps).
    af: bool = false,
    /// Bit 11: RES0 at stage-2 (the nG bit only applies to stage-1).
    _res11: bool = false,
    /// Output address bits [47:12] of the next-level table (non-leaf)
    /// or the final physical page (leaf).
    addr: u36 = 0,
    _res50_48: u3 = 0,
    /// Contiguous hint; zero for single-page leaves.
    contiguous: bool = false,
    _res53: bool = false,
    /// XN — stage-2 execute-never. Set for non-executable guest mappings.
    xn: bool = false,
    _sw: u4 = 0,
    _ignored: u5 = 0,
    _res63: u1 = 0,

    fn setPAddr(self: *Stage2Entry, p: PAddr) void {
        std.debug.assert(std.mem.isAligned(p.addr, paging.PAGE4K));
        self.addr = @intCast(p.addr >> 12);
    }

    fn getPAddr(self: *const Stage2Entry) PAddr {
        return PAddr.fromInt(@as(u64, self.addr) << 12);
    }
};

const STAGE2_ENTRIES_PER_TABLE: usize = 512;

/// Index of `guest_phys` into the level-2 root table (bits [29:21]).
inline fn stage2L2Idx(guest_phys: u64) u9 {
    return @truncate(guest_phys >> stage2_mid_shift);
}

/// Index of `guest_phys` into a level-3 table (bits [20:12]).
inline fn stage2L3Idx(guest_phys: u64) u9 {
    return @truncate(guest_phys >> stage2_leaf_shift);
}

/// Tear down a stage-2 root: walk every L2 entry, free its L3 table,
/// then free the root. Leaks here would be contained to the destroyed
/// VM (and caught on the next VMID rollover) but we walk-and-free to
/// keep the PMM honest. TLB invalidation for the departing VMID is
/// the caller's job.
pub fn freeVmStructures(p: PAddr) void {
    if (p.addr == 0) return;
    const root: *[STAGE2_ENTRIES_PER_TABLE]Stage2Entry =
        @ptrFromInt(VAddr.fromPAddr(p, null).addr);
    for (root) |*entry| {
        if (!entry.valid) continue;
        // Every non-leaf entry installed by `mapGuestPage` is a table
        // descriptor pointing at a level-3 page. The L3 page contains
        // leaves only, so freeing it is enough.
        freeTablePage(entry.getPAddr());
        entry.* = .{};
    }
    freeTablePage(p);
}

/// Allocate a 4 KiB page from the global PMM and return its PA. Pages
/// come back already zeroed — the PMM zero-on-free invariant covers it.
fn allocTablePage() ?PAddr {
    const pmm_mgr = &pmm.global_pmm.?;
    const page = pmm_mgr.create(paging.PageMem(.page4k)) catch return null;
    const va = VAddr.fromInt(@intFromPtr(page));
    return PAddr.fromVAddr(va, null);
}

/// Free a 4 KiB table page that was previously allocated by `allocTablePage`.
fn freeTablePage(p: PAddr) void {
    const pmm_mgr = &pmm.global_pmm.?;
    const va = VAddr.fromPAddr(p, null);
    const page: *paging.PageMem(.page4k) = @ptrFromInt(va.addr);
    pmm_mgr.destroy(page);
}

/// Per-VM control block allocated alongside the stage-2 root. Holds
/// per-VM state the world-switch entry path and `sysregPassthrough`
/// need to read/write via a plain `PAddr` handle, matching the x86
/// shape where `sysregPassthrough` operates on the VMCB at
/// `vm_structures`. The block lives at `vm_structures + PAGE4K` within
/// the order-1 allocation returned by `vmAllocStructures`.
///
/// Mutations go through `setHcrOverride` / `setVmid` so the deny-by-default
/// invariant (allow=true drops the bit into `hcr_override_clear`,
/// allow=false restores the baseline's trap-on state) lives with the
/// struct. Fields stay `pub` so the world-switch entry path can read
/// them without a getter.
///
/// References:
///   - ARM ARM D13.2.46  HCR_EL2 (see `HCR_EL2_LINUX_GUEST`)
///   - ARM ARM D13.2.151 VTTBR_EL2 VMID field
pub const VmControlBlock = extern struct {
    /// Bits to force ON in HCR_EL2 on top of `HCR_EL2_LINUX_GUEST`.
    /// Reserved for future traps not in the baseline.
    hcr_override_set: u64 = 0,
    /// Bits to clear in HCR_EL2 relative to `HCR_EL2_LINUX_GUEST`. A
    /// `sysregPassthrough` call that allows one of the baseline's
    /// trap groups drops the matching bit here so the world-switch
    /// programs HCR_EL2 without it.
    hcr_override_clear: u64 = 0,
    /// Stage-2 VMID to program into `VTTBR_EL2.VMID[63:48]` on the
    /// next guest entry. Updated by `kvm.vmid.refresh` from the Vm
    /// object's cached generation. Zero means "not yet assigned" —
    /// `vmResume` will fall back to the Vm's cached value in that
    /// case; normal flows call `vmid.refresh` before every entry so
    /// the field is current.
    vmid: u8 = 0,
    _pad: [paging.PAGE4K - 17]u8 = .{0} ** (paging.PAGE4K - 17),

    /// Drop (`allow=true`) or reinstate (`allow=false`) the HCR_EL2
    /// bits named by `mask`, relative to `HCR_EL2_LINUX_GUEST`. The
    /// world-switch programs `HCR_EL2 = (LINUX_GUEST | hcr_override_set)
    /// & ~hcr_override_clear`, so clearing a baseline-trap bit opens
    /// that trap group for the guest.
    pub fn setHcrOverride(self: *VmControlBlock, mask: u64, allow: bool) void {
        if (allow) {
            self.hcr_override_clear |= mask;
        } else {
            self.hcr_override_clear &= ~mask;
        }
    }
};

comptime {
    std.debug.assert(@sizeOf(VmControlBlock) == paging.PAGE4K);
    std.debug.assert(@offsetOf(VmControlBlock, "hcr_override_set") == 0);
    std.debug.assert(@offsetOf(VmControlBlock, "hcr_override_clear") == 8);
    std.debug.assert(@offsetOf(VmControlBlock, "vmid") == 16);
}

/// Allocate the per-VM arch block. Returns the physical address of a
/// contiguous 8 KiB (order-1) allocation whose:
///
///   - first page is the stage-2 L2 root — 512 level-2 entries, each
///     covering 2 MiB = 1 GiB total IPA — loaded directly into
///     `VTTBR_EL2.BADDR`.
///   - second page is a `VmControlBlock` holding HCR_EL2 override
///     bits and the cached VMID. `sysregPassthrough(vm_structures,
///     ...)` writes into this page; the world-switch entry reads it
///     via `controlBlock(vm_structures)`.
///
/// The caller treats the returned PAddr as an opaque handle; its
/// numeric value is also the stage-2 root PA, which keeps
/// `mapGuestPage` / `unmapGuestPage` / `invalidateStage2Ipa` unchanged.
/// Return a mutable pointer to the `VmControlBlock` embedded in the
/// 8 KiB arch structures allocation at `vm_structures + PAGE4K`.
pub fn controlBlock(vm_structures: PAddr) *VmControlBlock {
    const cb_pa = PAddr.fromInt(vm_structures.addr + paging.PAGE4K);
    return @ptrFromInt(VAddr.fromPAddr(cb_pa, null).addr);
}

/// Install a 4 KiB stage-2 mapping `guest_phys → host_phys` with the
/// supplied rights (bit 0 = read, bit 1 = write, bit 2 = exec). The
/// stage-2 memory type is chosen from the IPA via
/// `stage2MemAttrForIpa`: known emulated-MMIO windows (PL011,
/// virtio-mmio) map as Device-nGnRnE so guest writes fault
/// synchronously; everything else maps as Normal WB for guest RAM.
/// See ARM ARM K.a D5.5.5 Table D5-37 for the legal MemAttr encodings.
///
/// This is the dispatch-level signature that matches
/// `x64.vm.mapGuestPage` 1:1; IPA-dependent memattr selection is an
/// aarch64 internal and is not surfaced to the portable dispatch
/// layer.
///
/// Walks the level-2 root, allocates a level-3 page if the L2 slot is
/// empty, then writes the leaf descriptor. Issues a per-IPA
/// `TLBI IPAS2E1IS, ipa>>12; DSB ISH` afterwards via
/// `stage2InvalidateIpa` so stale speculative stage-2 walks cannot hit
/// the new descriptor with an old value.
pub fn mapGuestPage(
    vm_structures: PAddr,
    guest_phys: u64,
    host_phys: PAddr,
    rights: u8,
) !void {
    if (guest_phys >= (1 << 30)) return error.IpaOutOfRange;
    std.debug.assert(std.mem.isAligned(guest_phys, paging.PAGE4K));
    std.debug.assert(std.mem.isAligned(host_phys.addr, paging.PAGE4K));

    const memattr = stage2MemAttrForIpa(guest_phys);

    const root_va = VAddr.fromPAddr(vm_structures, null).addr;
    const root: *[STAGE2_ENTRIES_PER_TABLE]Stage2Entry = @ptrFromInt(root_va);

    const l2_idx = stage2L2Idx(guest_phys);
    const l2_entry = &root[l2_idx];

    // Allocate the L3 table on first touch.
    if (!l2_entry.valid) {
        const l3_pa = allocTablePage() orelse return error.OutOfMemory;
        l2_entry.* = .{
            .valid = true,
            .is_table_or_page = true, // table descriptor at level 2
            // MemAttr/S2AP/SH/AF/XN fields on a *table* descriptor are
            // RES0 / ignored per ARM ARM D5.3.3 Table D5-15. The HW walker
            // only consults them on leaf descriptors.
        };
        l2_entry.setPAddr(l3_pa);
    }

    const l3_va = VAddr.fromPAddr(l2_entry.getPAddr(), null).addr;
    const l3: *[STAGE2_ENTRIES_PER_TABLE]Stage2Entry = @ptrFromInt(l3_va);
    const l3_idx = stage2L3Idx(guest_phys);

    const can_read = (rights & 0x1) != 0;
    const can_write = (rights & 0x2) != 0;
    const can_exec = (rights & 0x4) != 0;

    // S2AP encoding (ARM ARM D5.4 Table D5-31):
    //   0b00 = no access, 0b01 = RO, 0b10 = WO (rarely used), 0b11 = RW.
    // Our rights bits allow R, W, X independently; we map any non-read
    // mapping with write set to RW rather than WO, which matches what
    // x86 EPT would do.
    const s2ap: u2 = if (can_write) 0b11 else if (can_read) 0b01 else 0b00;

    // MemAttr per caller selection. ARM ARM D5.5.5 Table D5-37:
    //   0b1111 = Normal Inner WB, Outer WB, non-transient (guest RAM)
    //   0b0000 = Device-nGnRnE (MMIO, strongly-ordered, no gathering)
    const mem_attr: u4 = @intFromEnum(memattr);

    l3[l3_idx] = .{
        .valid = true,
        .is_table_or_page = true, // level-3 leaf uses bits [1:0] = 0b11
        .mem_attr = mem_attr,
        .s2ap = s2ap,
        .sh = 0b11, // Inner Shareable
        .af = true,
        .xn = !can_exec,
    };
    l3[l3_idx].setPAddr(host_phys);

    stage2InvalidateIpa(guest_phys);
}

/// Remove a 4 KiB stage-2 mapping. Leaves the owning L3 table in place;
/// the L3 table is freed in bulk by `vmFreeStructures`.
pub fn unmapGuestPage(vm_structures: PAddr, guest_phys: u64) void {
    if (guest_phys >= (1 << 30)) return;

    const root_va = VAddr.fromPAddr(vm_structures, null).addr;
    const root: *[STAGE2_ENTRIES_PER_TABLE]Stage2Entry = @ptrFromInt(root_va);

    const l2_entry = &root[stage2L2Idx(guest_phys)];
    if (!l2_entry.valid) return;

    const l3_va = VAddr.fromPAddr(l2_entry.getPAddr(), null).addr;
    const l3: *[STAGE2_ENTRIES_PER_TABLE]Stage2Entry = @ptrFromInt(l3_va);
    l3[stage2L3Idx(guest_phys)] = .{};

    stage2InvalidateIpa(guest_phys);
}

/// Invalidate any cached stage-2 translation for `guest_phys` (byte
/// address, page-aligned) in the current VM's VMID.
///
/// `TLBI IPAS2E1IS, <ipa>>>12` is the architectural instruction for
/// stage-2 invalidation (ARM ARM K.a D7.7 "TLB maintenance
/// instructions"), but it is EL2-only: executing it from EL1 is
/// UNDEFINED and would trap. The Zag kernel runs at EL1, so we route
/// through the `hvc_tlbi_ipa` hyp stub (HypCallId.tlbi_ipa) which
/// executes the full
///     dsb ishst ; tlbi ipas2e1is ; dsb ish ; tlbi vmalle1is ; dsb ish ; isb
/// sequence at EL2 against the currently-loaded VTTBR_EL2. Called
/// from every stage-2 mutation site (`mapGuestPage`, `unmapGuestPage`,
/// and any future attribute-change path) so speculative walks can
/// never observe a stale descriptor once this function returns.
///
/// Range invalidations (block descriptors, VMID rollover) should keep
/// using `vmalls12e1is` — see the world-switch entry path in
/// `hvc_vcpu_run` in `hyp.zig`, which already issues that for VMID
/// rollover.
///
/// Callers must pass a page-aligned byte IPA; `hvc_tlbi_ipa` shifts
/// right by 12 internally before issuing the TLBI, per the register
/// format in ARM ARM D7.7.7.
pub fn invalidateStage2Ipa(guest_phys: u64) void {
    std.debug.assert(std.mem.isAligned(guest_phys, paging.PAGE4K));
    _ = vm.hypCall(.tlbi_ipa, guest_phys);
}

fn stage2InvalidateIpa(guest_phys: u64) void {
    invalidateStage2Ipa(guest_phys);
}

// ===========================================================================
// Sysreg passthrough
// ===========================================================================

/// Decoded (op0,op1,crn,crm,op2) sysreg key used by
/// `sysregPassthrough`. The packed `sysreg_id` layout comes from
/// the `vm_sysreg_passthrough` syscall and matches
/// `kvm.vm.isSecurityCriticalSysreg`:
///
///   bits [15:14] Op0
///   bits [13:11] Op1
///   bits [10:7]  CRn
///   bits [6:3]   CRm
///   bits [2:0]   Op2
pub const SysregKey = packed struct {
    op0: u8,
    op1: u8,
    crn: u8,
    crm: u8,
    op2: u8,

    pub fn decode(encoded: u32) SysregKey {
        return .{
            .op0 = @intCast((encoded >> 14) & 0x3),
            .op1 = @intCast((encoded >> 11) & 0x7),
            .crn = @intCast((encoded >> 7) & 0xF),
            .crm = @intCast((encoded >> 3) & 0xF),
            .op2 = @intCast(encoded & 0x7),
        };
    }
};

/// HCR_EL2 trap group a particular sysreg belongs to. Only the groups that
/// `HCR_EL2_LINUX_GUEST` forces on are meaningful here — allowing
/// passthrough of a sysreg outside one of these groups is a no-op because
/// the baseline already lets it through. See `HCR_EL2_LINUX_GUEST` above
/// for the full rationale table.
const HcrTrapGroup = enum {
    /// No HCR bit governs this sysreg — passthrough request is vacuous.
    none,
    /// ACTLR_EL1 (impl-defined auxiliary control) — HCR_EL2.TACR.
    /// ARM ARM D13.2.46 TACR; sysreg encoding op0=3 op1=0 crn=1 crm=0 op2=1.
    tacr,
    /// Impl-defined EL1 sysregs — HCR_EL2.TIDCP.
    /// ARM ARM D13.2.46 TIDCP covers CRn ∈ {9, 10, 11, 15} with the
    /// implementation-defined flag. We match CRn in {11, 15} (the two most
    /// commonly used by platform-specific errata knobs on the CPUs this
    /// port targets — Cortex-A76 uses CRn=11 for CPUACTLR, CRn=15 for
    /// CPUECTLR/L2CTLR).
    tidcp,
    /// Stage-1 "VM" sysreg family — HCR_EL2.TVM (writes) / HCR_EL2.TRVM
    /// (reads). ARM ARM D13.2.46 TVM enumerates:
    ///   SCTLR_EL1, TTBR0_EL1, TTBR1_EL1, TCR_EL1, ESR_EL1, FAR_EL1,
    ///   AFSR0_EL1, AFSR1_EL1, MAIR_EL1, AMAIR_EL1, CONTEXTIDR_EL1.
    tvm,
};

/// Classify a sysreg key into the HCR_EL2 trap group that governs its
/// EL1 access, or `.none` if no bit in `HCR_EL2_LINUX_GUEST` covers it.
///
/// Sysreg encodings cross-referenced against ARM ARM C5.3 "System register
/// encoding". All entries are op0=3, op1=0 (the EL1-accessible half).
fn classifySysreg(key: SysregKey) HcrTrapGroup {
    if (key.op0 != 3 or key.op1 != 0) return .none;

    // ACTLR_EL1 — op0=3 op1=0 CRn=1 CRm=0 op2=1 (ARM ARM D13.2.9).
    if (key.crn == 1 and key.crm == 0 and key.op2 == 1) return .tacr;

    // TVM-governed stage-1 VM sysregs. Each entry is (CRn, CRm, op2).
    //   SCTLR_EL1       (1, 0, 0)    D13.2.119
    //   TTBR0_EL1       (2, 0, 0)    D13.2.137
    //   TTBR1_EL1       (2, 0, 1)    D13.2.139
    //   TCR_EL1         (2, 0, 2)    D13.2.131
    //   AFSR0_EL1       (5, 1, 0)    D13.2.23
    //   AFSR1_EL1       (5, 1, 1)    D13.2.24
    //   ESR_EL1         (5, 2, 0)    D13.2.39
    //   FAR_EL1         (6, 0, 0)    D13.2.41
    //   MAIR_EL1        (10, 2, 0)   D13.2.93
    //   AMAIR_EL1       (10, 3, 0)   D13.2.25
    //   CONTEXTIDR_EL1  (13, 0, 1)   D13.2.31
    switch (key.crn) {
        1 => if (key.crm == 0 and key.op2 == 0) return .tvm,
        2 => if (key.crm == 0 and key.op2 <= 2) return .tvm,
        5 => {
            if (key.crm == 1 and key.op2 <= 1) return .tvm;
            if (key.crm == 2 and key.op2 == 0) return .tvm;
        },
        6 => if (key.crm == 0 and key.op2 == 0) return .tvm,
        10 => {
            if (key.crm == 2 and key.op2 == 0) return .tvm;
            if (key.crm == 3 and key.op2 == 0) return .tvm;
        },
        13 => if (key.crm == 0 and key.op2 == 1) return .tvm,
        else => {},
    }

    // Impl-defined groups governed by TIDCP.
    if (key.crn == 11 or key.crn == 15) return .tidcp;

    return .none;
}

/// Update a VM's HCR_EL2 override-set/override-clear pair based on a
/// passthrough request. Baseline `HCR_EL2_LINUX_GUEST` has every relevant
/// trap bit *set* (deny-by-default), so "allow passthrough" means dropping
/// the matching bit into `override_clear`; "deny passthrough" removes it
/// from `override_clear` (returning to the baseline's trap-on state).
///
/// The TVM/TRVM group is split read/write: `allow_write` gates TVM and
/// `allow_read` gates TRVM. For TACR and TIDCP the baseline does not
/// distinguish direction, so either flag being set opens the group.
///
/// Rejects sysregs the guest must never own — EL2/EL3 encodings and the ID
/// registers the VmPolicy depends on — with `error.SecurityCritical` before
/// touching any state. The check is the function's own invariant so a
/// forgetful caller can't smuggle a dangerous encoding through.
///
/// Sysregs that pass the security check but do not map to a HCR_EL2 bit
/// managed by the baseline are silently ignored.
///
/// Dispatch-level signature — matches `x64.vm.sysregPassthrough(vm_structures,
/// sysreg_id, allow_read, allow_write)` 1:1. The HCR override pair lives in
/// the per-VM control block at `vm_structures + PAGE4K`, so a `PAddr` handle
/// is sufficient and no caller-owned pointer pair is threaded through.
pub const SysregPassthroughError = error{SecurityCritical};

pub fn sysregPassthrough(
    vm_structures: PAddr,
    sysreg_id: u32,
    allow_read: bool,
    allow_write: bool,
) SysregPassthroughError!void {
    if (isSecurityCriticalSysreg(sysreg_id)) return error.SecurityCritical;

    const cb = controlBlock(vm_structures);
    const key = SysregKey.decode(sysreg_id);
    const group = classifySysreg(key);
    const any = allow_read or allow_write;
    switch (group) {
        .none => {},
        .tacr => cb.setHcrOverride(vm.HCR_EL2_TACR, any),
        .tidcp => cb.setHcrOverride(vm.HCR_EL2_TIDCP, any),
        .tvm => {
            // TVM is *write*-side, TRVM is *read*-side. Only drop a bit
            // once every sysreg in the group has been opened — but the
            // current API is per-sysreg. For now treat any allow_write in
            // the group as "clear TVM" and any allow_read as "clear
            // TRVM". This is correct for the common case (VMM opens the
            // whole family at once to let the guest own its stage-1
            // state) and coarser than necessary otherwise. TODO: track a
            // per-sysreg allow mask and only clear TVM/TRVM when every
            // member of the group is allowed.
            cb.setHcrOverride(vm.HCR_EL2_TVM, allow_write);
            cb.setHcrOverride(vm.HCR_EL2_TRVM, allow_read);
        },
    }
}

/// Reject sysregs the guest must never own: anything addressing EL2 or EL3
/// (op1 ∈ {4,5,6,7} per ARM ARM C5.3), plus the ID registers (op0=3,op1=0,
/// CRn=0,CRm ∈ 0..7) that the VmPolicy decisions depend on. The encoding
/// layout matches the doc comment above `sysregPassthrough`: bits [15:14]
/// Op0, [13:11] Op1, [10:7] CRn, [6:3] CRm, [2:0] Op2.
pub fn isSecurityCriticalSysreg(encoded: u32) bool {
    const op0: u8 = @intCast((encoded >> 14) & 0x3);
    const op1: u8 = @intCast((encoded >> 11) & 0x7);
    if (op1 >= 4) return true;
    const crn: u8 = @intCast((encoded >> 7) & 0xF);
    const crm: u8 = @intCast((encoded >> 3) & 0xF);
    if (op0 == 3 and op1 == 0 and crn == 0 and crm <= 7) return true;
    return false;
}
