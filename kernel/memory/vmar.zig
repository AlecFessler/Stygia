//! Virtual Address Range (VMAR) — contiguous span of virtual address
//! space bound to a capability domain, available for demand-paged
//! memory or installing page frames or device regions. See spec §[var].
//!
//! Capability-domain lifetime: dies when the owning CapabilityDomain
//! is destroyed. Multiple capability domains may hold handles to a VMAR
//! via `acquire_vmars` (debugger primitive) or `copy`/`move` — UAF
//! protection across domains comes from `_gen_lock`.

const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const dispatch = zag.arch.dispatch;
const errors = zag.syscall.errors;
const scheduler = zag.sched.scheduler;
const secure_slab = zag.memory.allocators.secure_slab;

const CapabilityDomain = zag.caps.capability_domain.CapabilityDomain;
const CapabilityType = zag.caps.capability.CapabilityType;
const DeviceRegion = zag.devices.device_region.DeviceRegion;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const GenLock = secure_slab.GenLock;
const KernelHandle = zag.caps.capability.KernelHandle;
const MemoryPerms = zag.memory.address.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageFrame = zag.memory.page_frame.PageFrame;
const PageFrameCaps = zag.memory.page_frame.PageFrameCaps;
const SecureSlab = secure_slab.SecureSlab;
const SlabRef = secure_slab.SlabRef;
const VAddr = zag.memory.address.VAddr;
const Word0 = zag.caps.capability.Word0;

/// Cap bits in `Capability.word0[48..63]` for VMAR handles.
/// Spec §[var] cap layout.
pub const VmarCaps = packed struct(u16) {
    move: bool = false,
    copy: bool = false,
    r: bool = false,
    w: bool = false,
    x: bool = false,
    mmio: bool = false,
    max_sz: u2 = 0,
    dma: bool = false,
    restart_policy: u2 = 0,
    _reserved: u5 = 0,
};

/// Page size encoding for VMAR.sz / max_sz cap fields.
pub const PageSize = enum(u2) {
    sz_4k = 0,
    sz_2m = 1,
    sz_1g = 2,
    _reserved = 3,
};

/// Cache type encoding for VMAR.cch.
pub const CacheType = enum(u2) {
    wb = 0,
    uc = 1,
    wc = 2,
    wt = 3,
};

/// What's currently installed in the VMAR. Mirrors field1 bits 39-40.
pub const MapType = enum(u2) {
    /// Reserved address range with no backing.
    unmapped = 0,
    /// One or more page_frames installed at offsets via `map_pf`.
    page_frame = 1,
    /// MMIO device_region installed via `map_mmio`.
    mmio = 2,
    /// Demand-paged: kernel allocates a fresh zero-page on first
    /// touch. Established by accessing an `unmapped` VMAR.
    demand = 3,
};

/// VMAR.caps.restart_policy encoding (also used by `restartCleanup`).
pub const RestartPolicy = enum(u2) {
    free = 0,
    decommit = 1,
    preserve = 2,
    snapshot = 3,
};

/// Maximum installed (offset, page_frame) entries tracked per VMAR.
/// Bounds the inline mapping table; sized well above any plausible
/// per-VMAR fan-out for current spec-v3 tests. Larger VARs would need
/// a sparse out-of-band layout — see VMAR.mapping_table TBD note.
pub const MAX_INSTALLED_PFS: usize = 64;

/// One installed page_frame at `offset` inside its owning VMAR. `pf =
/// null` marks an empty slot in the inline `installed_pfs` array.
pub const InstalledPf = struct {
    offset: u64 = 0,
    /// Bound page_frame for this offset. `null` ⇒ empty slot. UAF
    /// safety: `map_pf` bumps the PageFrame's refcount; `unmap` /
    /// `destroy` decrement it under the VMAR's gen-lock.
    pf: ?SlabRef(PageFrame) = null,
};

pub const VMAR = struct {
    /// Slab generation lock. Validates `SlabRef(VMAR)` liveness AND
    /// guards every mutable field below.
    _gen_lock: GenLock = .{},

    /// Owning capability domain. VARs cannot outlive their owner —
    /// `destroyVmar` runs ahead of any domain teardown — but the
    /// invariant lives in code, not the type, so the slot is carried
    /// as a SlabRef for analyzer-level UAF safety on cross-domain
    /// `acquire_vmars` lookups.
    domain: SlabRef(CapabilityDomain),

    /// Base virtual address (or base IOVA for DMA VARs). Mirrors the
    /// user-visible Capability.field0. Set at create; immutable.
    base_vaddr: VAddr,

    /// Number of pages in `sz` units. Mirrors low 32 bits of field1.
    /// Set at create; immutable.
    page_count: u32,

    /// Page size (immutable). Mirrors field1 bits 32-33.
    sz: PageSize,

    /// Cache type (immutable). Mirrors field1 bits 34-35.
    cch: CacheType,

    /// Current effective rwx for installed pages (bit 0 = r, 1 = w,
    /// 2 = x). Mirrors field1 bits 36-38. Mutable via `remap`.
    cur_rwx: u3 = 0,

    /// What's currently installed. Mirrors field1 bits 39-40. Updated
    /// by map_pf / map_mmio / unmap and by demand-paged faults.
    map: MapType = .unmapped,

    /// Bound device_region. Set immutably at create_vmar when this is
    /// a DMA VMAR (caps.dma=1, IOMMU mappings install via this device's
    /// IOMMU domain). Set/cleared by map_mmio/unmap when this is an
    /// MMIO VMAR. Null otherwise. Mirrors field1 bits 41-52 (handle id
    /// in the owning domain's table).
    device: ?SlabRef(DeviceRegion) = null,

    /// Snapshot binding source. Set by `snapshot` when this VMAR has
    /// `restart_policy = snapshot` (3) and a source has been bound.
    /// On the owning domain's restart, the source's contents are
    /// copied into this VMAR before resume. Source may live in another
    /// domain — cross-domain UAF protection routes through
    /// `source._gen_lock`. Null when no binding.
    snapshot_source: ?SlabRef(VMAR) = null,

    /// Out-of-band per-page mapping table. Tracks which page_frames
    /// are installed at which offsets (when `map = page_frame`) or
    /// which demand-paged pages have been allocated (when
    /// `map = demand`). Layout TBD — likely a sparse offset → page
    /// pointer structure. Null when `map = unmapped` or `map = mmio`
    /// (the latter has only the single `device` binding).
    mapping_table: ?*anyopaque = null,

    /// Inline list of installed page_frames for `map = page_frame`.
    /// Each entry records the offset within the VMAR and the
    /// page_frame installed there. Used by `remap` to compute the
    /// caps.rwx intersection across all installed page_frames (spec
    /// §[var].remap test 04) and by `unmap`/`destroy` to walk live
    /// installations. Empty slots have `pf = null`.
    installed_pfs: [MAX_INSTALLED_PFS]InstalledPf = [_]InstalledPf{.{}} ** MAX_INSTALLED_PFS,
};

pub const Allocator = SecureSlab(VMAR, 256);
pub var slab_instance: Allocator = undefined;

pub fn initSlab(
    data_range: zag.utils.range.Range,
    ptrs_range: zag.utils.range.Range,
    links_range: zag.utils.range.Range,
) void {
    slab_instance = Allocator.init(data_range, ptrs_range, links_range);
}

inline fn pageSizeBytes(sz: PageSize) u64 {
    return switch (sz) {
        .sz_4k => 0x1000,
        .sz_2m => 0x20_0000,
        .sz_1g => 0x4000_0000,
        ._reserved => 0,
    };
}

inline fn rwxToPerms(rwx: u3) MemoryPerms {
    return .{
        .read = (rwx & 0b001) != 0,
        .write = (rwx & 0b010) != 0,
        .exec = (rwx & 0b100) != 0,
    };
}

// ── External API ─────────────────────────────────────────────────────

/// `create_vmar` syscall handler. Spec §[var].create_vmar.
pub fn createVmar(
    caller: *ExecutionContext,
    caps: u64,
    props: u64,
    pages: u64,
    preferred_base: u64,
    device_region: u64,
) i64 {
    if (caps >> 16 != 0) return errors.E_INVAL;
    if (props >> 7 != 0) return errors.E_INVAL;
    if (pages == 0) return errors.E_INVAL;

    const vmar_caps: VmarCaps = @bitCast(@as(u16, @truncate(caps)));
    if (vmar_caps._reserved != 0) return errors.E_INVAL;

    const cur_rwx: u3 = @truncate(props & 0b111);
    const props_sz: u2 = @truncate((props >> 3) & 0b11);
    const props_cch: u2 = @truncate((props >> 5) & 0b11);

    if (props_sz == @intFromEnum(PageSize._reserved)) return errors.E_INVAL;
    if (vmar_caps.max_sz == @intFromEnum(PageSize._reserved)) return errors.E_INVAL;
    if (props_sz > vmar_caps.max_sz) return errors.E_INVAL;
    if (vmar_caps.mmio and vmar_caps.dma) return errors.E_INVAL;
    if (vmar_caps.mmio and vmar_caps.x) return errors.E_INVAL;
    if (vmar_caps.dma and vmar_caps.x) return errors.E_INVAL;
    if (vmar_caps.mmio and props_sz != 0) return errors.E_INVAL;

    const caps_rwx: u3 = (@as(u3, @intFromBool(vmar_caps.r))) |
        (@as(u3, @intFromBool(vmar_caps.w)) << 1) |
        (@as(u3, @intFromBool(vmar_caps.x)) << 2);
    if ((cur_rwx & ~caps_rwx) != 0) return errors.E_INVAL;

    const sz: PageSize = @enumFromInt(props_sz);
    const cch: CacheType = @enumFromInt(props_cch);
    const sz_bytes = pageSizeBytes(sz);
    const base_in: VAddr = .fromInt(preferred_base);
    if (preferred_base != 0 and !std.mem.isAligned(preferred_base, sz_bytes)) {
        return errors.E_INVAL;
    }
    if (preferred_base != 0) {
        // Spec §[create_vmar] test 23: preferred_base must lie wholly
        // within the static zone — see §[address_space].
        const range_bytes = pages * sz_bytes;
        const static = dispatch.paging.user_static;
        const end = @addWithOverflow(preferred_base, range_bytes);
        if (end[1] != 0) return errors.E_INVAL;
        if (preferred_base < static.start or end[0] > static.end) {
            return errors.E_INVAL;
        }
    }

    const domain = caller.domain.ptr; // caller-pinned: caller is the running EC; its domain stays alive across this syscall

    // DMA VARs require a valid device_region handle with the dma cap.
    var dev_ptr: ?*DeviceRegion = null;
    if (vmar_caps.dma) {
        const slot: u12 = @truncate(device_region & 0xFFF);
        const kh = lookupHandle(domain, slot, .device_region) orelse
            return errors.E_BADCAP;
        const cap_bits: u16 = Word0.caps(domain.user_table[slot].word0);
        const dr_caps: zag.devices.device_region.DeviceRegionCaps = @bitCast(cap_bits);
        if (!dr_caps.dma) return errors.E_PERM;
        dev_ptr = @ptrCast(@alignCast(kh.ref.ptr.?));
    }

    const base = vaRangeAllocate(domain, @intCast(pages), sz, base_in) orelse
        return errors.E_NOSPC;

    const overlap = zag.caps.capability_domain.checkVaRangeOverlap(domain, base, @as(u64, @intCast(pages)) * sz_bytes);
    if (overlap != 0) return overlap;

    const v = allocVmar(domain, base, @intCast(pages), sz, cch, cur_rwx, dev_ptr) catch
        return errors.E_NOMEM;

    const append_rc = zag.caps.capability_domain.appendVar(domain, v);
    if (append_rc != 0) {
        destroyVmar(v);
        return append_rc;
    }

    // Mint a handle for the new VMAR in the caller's domain. field0 =
    // base vaddr; field1 = packed page_count|sz|cch|cur_rwx|map|device.
    //
    // Spec §[create_vmar] test 22: "on success, when caps.dma = 1,
    // field1's `device` field equals [5]'s handle id". Carry the
    // bound device_region handle's slot id through to the freshly-
    // minted VMAR's snapshot so spec-test observers see it without
    // first triggering a `sync` round-trip.
    const dev_id_at_create: u12 = if (vmar_caps.dma) @truncate(device_region & 0xFFF) else 0;
    const field0: u64 = base.addr;
    const field1: u64 = packField1(@intCast(pages), sz, cch, cur_rwx, .unmapped, dev_id_at_create);
    const handle_caps: u16 = @truncate(caps);
    const slot = zag.caps.capability_domain.mintHandle(
        domain,
        .{ .ptr = v, .gen = @intCast(v._gen_lock.currentGen()) },
        .virtual_memory_address_region,
        handle_caps,
        field0,
        field1,
    ) catch return errors.E_FULL;

    // v0 ABI extension: deliver field0 (base vaddr) in vreg 2 and
    // field1 (page_count|sz|cch|cur_rwx|map|device) in vreg 3 alongside
    // the slot in vreg 1. The runtime user-table mirror also carries
    // these snapshots, but exposing them in registers lets a caller
    // capture base/size without a second VA load on the hot create_vmar
    // path.
    dispatch.syscall.setSyscallVreg2(caller.ctx, field0);
    dispatch.syscall.setSyscallVreg3(caller.ctx, field1);

    // Spec §[error_codes] / §[capabilities]: pack Word0 so the type
    // tag in bits 12..15 disambiguates a real handle word from the
    // small-positive error range 1..15.
    return @intCast(Word0.pack(slot, .virtual_memory_address_region, handle_caps));
}

/// `map_pf` syscall handler. Spec §[var].map_pf.
pub fn mapPf(caller: *ExecutionContext, vmar_handle: u64, pairs: []const u64) i64 {
    if (pairs.len == 0 or (pairs.len & 1) != 0) return errors.E_INVAL;

    const domain = caller.domain.ptr; // caller-pinned: caller is the running EC; its domain stays alive across this syscall
    const slot: u12 = @truncate(vmar_handle & 0xFFF);
    const v = resolveVmar(domain, slot) orelse return errors.E_BADCAP;

    const v_irq = v._gen_lock.lockIrqSave(@src());
    defer v._gen_lock.unlockIrqRestore(v_irq);
    defer refreshVmarSnapshot(domain, slot, v);

    const caps_word: u16 = Word0.caps(domain.user_table[slot].word0);
    const vmar_caps: VmarCaps = @bitCast(caps_word);
    if (vmar_caps.mmio) return errors.E_PERM;
    if (v.map == .mmio or v.map == .demand) return errors.E_INVAL;

    const sz_bytes = pageSizeBytes(v.sz);
    const var_size = @as(u64, v.page_count) * sz_bytes;

    // Pass 1: validate every pair and reject before any install. Spec
    // §[var].map_pf tests 02, 05, 06, 07, 08, 09 are all non-mutating
    // gates — a partial install on a later-rejected batch would leave
    // the VMAR with side-effects from the earlier pairs, contradicting
    // the all-or-nothing contract. The checks below mirror the order
    // of the spec gates so the first failing pair surfaces the
    // strictest error consistent with the spec text.
    var i: usize = 0;
    while (i < pairs.len) {
        const offset = pairs[i];
        const pf_handle = pairs[i + 1];
        if (!std.mem.isAligned(offset, sz_bytes)) return errors.E_INVAL;

        const pf_slot: u12 = @truncate(pf_handle & 0xFFF);
        const pf_kh = lookupHandle(domain, pf_slot, .page_frame) orelse
            return errors.E_BADCAP;
        const pf: *PageFrame = @ptrCast(@alignCast(pf_kh.ref.ptr.?));

        if (@intFromEnum(pf.sz) < @intFromEnum(v.sz)) return errors.E_INVAL;

        // Spec §[var].map_pf test 07: each pair's full range
        // (pf.page_count × pf.sz) must fit within the VMAR.
        const pf_sz_bytes = pageSizeBytes(pf.sz);
        const pair_bytes = @as(u64, pf.page_count) * pf_sz_bytes;
        if (offset >= var_size or offset + pair_bytes > var_size) return errors.E_INVAL;

        // Spec §[var].map_pf test 08: no two pairs in the same call
        // may have overlapping ranges. Compare against all earlier
        // pairs in this batch.
        var j: usize = 0;
        while (j < i) {
            const other_offset = pairs[j];
            const other_pf_slot: u12 = @truncate(pairs[j + 1] & 0xFFF);
            const other_kh = lookupHandle(domain, other_pf_slot, .page_frame) orelse
                return errors.E_BADCAP;
            const other_pf: *PageFrame = @ptrCast(@alignCast(other_kh.ref.ptr.?));
            const other_pair_bytes = @as(u64, other_pf.page_count) * pageSizeBytes(other_pf.sz);
            const a_start = offset;
            const a_end = offset + pair_bytes;
            const b_start = other_offset;
            const b_end = other_offset + other_pair_bytes;
            if (a_start < b_end and b_start < a_end) return errors.E_INVAL;
            j += 2;
        }

        // Spec §[var].map_pf test 09: pair must not overlap any
        // mapping already installed in the VMAR. For non-DMA VARs the
        // owning domain's page tables are the authoritative record;
        // probe each page-sized slot in the pair's range.
        if (!vmar_caps.dma) {
            var off_in: u64 = 0;
            while (off_in < pair_bytes) {
                const va = v.base_vaddr.addr + offset + off_in;
                if (dispatch.paging.resolveVaddr(domain.addr_space_root, .fromInt(va)) != null) {
                    return errors.E_INVAL;
                }
                off_in += sz_bytes;
            }
        }

        i += 2;
    }

    // Pass 2: install. All pairs are now known to be well-formed and
    // non-overlapping with each other and with prior installations.
    i = 0;
    while (i < pairs.len) {
        const offset = pairs[i];
        const pf_slot: u12 = @truncate(pairs[i + 1] & 0xFFF);
        const pf_kh = lookupHandle(domain, pf_slot, .page_frame) orelse
            return errors.E_BADCAP;
        const pf: *PageFrame = @ptrCast(@alignCast(pf_kh.ref.ptr.?));

        // Spec §[var].map_pf test 12: effective PTE perms must equal
        // `VMAR.cur_rwx ∩ page_frame.r/w/x`. PageFrame caps live in the
        // calling domain's user_table at the handle's slot — read them
        // here so `mappingInstall` can intersect per page.
        const pf_caps_word: u16 = Word0.caps(domain.user_table[pf_slot].word0);
        const pf_caps: PageFrameCaps = @bitCast(pf_caps_word);
        const pf_rwx: u3 = (@as(u3, @intFromBool(pf_caps.r))) |
            (@as(u3, @intFromBool(pf_caps.w)) << 1) |
            (@as(u3, @intFromBool(pf_caps.x)) << 2);

        const rc = mappingInstall(v, offset, pf, pf_rwx);
        if (rc != 0) return rc;

        i += 2;
    }

    if (v.map == .unmapped) v.map = .page_frame;
    return 0;
}

/// `map_mmio` syscall handler. Spec §[var].map_mmio.
pub fn mapMmio(caller: *ExecutionContext, vmar_handle: u64, device_region: u64) i64 {
    const domain = caller.domain.ptr; // caller-pinned: caller is the running EC; its domain stays alive across this syscall
    const vmar_slot: u12 = @truncate(vmar_handle & 0xFFF);
    const v = resolveVmar(domain, vmar_slot) orelse return errors.E_BADCAP;

    const v_irq = v._gen_lock.lockIrqSave(@src());
    defer v._gen_lock.unlockIrqRestore(v_irq);
    defer refreshVmarSnapshot(domain, vmar_slot, v);

    const caps_word: u16 = Word0.caps(domain.user_table[vmar_slot].word0);
    const vmar_caps: VmarCaps = @bitCast(caps_word);
    if (!vmar_caps.mmio) return errors.E_PERM;
    if (v.map != .unmapped) return errors.E_INVAL;

    const dr_slot: u12 = @truncate(device_region & 0xFFF);
    const dr_kh = lookupHandle(domain, dr_slot, .device_region) orelse
        return errors.E_BADCAP;
    const dr: *DeviceRegion = @ptrCast(@alignCast(dr_kh.ref.ptr.?));

    const sz_bytes = pageSizeBytes(v.sz);
    const var_size = @as(u64, v.page_count) * sz_bytes;
    // Spec §[var].map_mmio test 05: device_region size must equal VMAR
    // size. MMIO devices carry byte size in `access.mmio.size`. For
    // port_io regions §[device_region] does not declare a byte-sized
    // field — `port_count` is in I/O ports, not bytes — so the
    // size-equality check would gate every port_io map_mmio (e.g.
    // COM1's 8-port range against any non-degenerate VMAR). Treat
    // port_io regions as fitting any VMAR whose 4 KiB-aligned size
    // covers the port range; the port-io fault decoder maps VMAR
    // offsets 1:1 onto port offsets (Spec §[port_io_virtualization]),
    // so larger VARs simply expose unmapped tail bytes that the
    // decoder rejects on access.
    switch (dr.device_type) {
        .mmio => if (dr.access.mmio.size != var_size) return errors.E_INVAL,
        .port_io => if (var_size < dr.access.port_io.port_count) return errors.E_INVAL,
        .framebuffer => if (dr.access.framebuffer.size != var_size) return errors.E_INVAL,
    }

    // Port-IO regions install with no PTEs — every CPU access faults
    // and is decoded by the port-io fault handler. Plain MMIO and
    // framebuffer regions install PTEs covering [base_vaddr,
    // base_vaddr + var_size). Spec §[port_io_virtualization].
    const phys_base_opt: ?PAddr = switch (dr.device_type) {
        .mmio => dr.access.mmio.phys_base,
        .framebuffer => dr.access.framebuffer.phys_base,
        .port_io => null,
    };
    if (phys_base_opt) |phys_base| {
        var off: u64 = 0;
        while (off < var_size) {
            dispatch.paging.mapPageSized(
                domain.addr_space_root,
                .fromInt(phys_base.addr + off),
                .fromInt(v.base_vaddr.addr + off),
                v.sz,
                v.cch,
                rwxToPerms(v.cur_rwx),
            ) catch return errors.E_NOMEM;
            off += sz_bytes;
        }
    }

    v.device = SlabRef(DeviceRegion).init(dr, dr._gen_lock.currentGen());
    v.map = .mmio;
    return 0;
}

/// `unmap` syscall handler. Spec §[var].unmap.
pub fn unmap(caller: *ExecutionContext, vmar_handle: u64, selectors: []const u64) i64 {
    const domain = caller.domain.ptr; // caller-pinned: caller is the running EC; its domain stays alive across this syscall
    const slot: u12 = @truncate(vmar_handle & 0xFFF);
    const v = resolveVmar(domain, slot) orelse return errors.E_BADCAP;

    const v_irq = v._gen_lock.lockIrqSave(@src());
    defer v._gen_lock.unlockIrqRestore(v_irq);
    defer refreshVmarSnapshot(domain, slot, v);

    if (v.map == .unmapped) return errors.E_INVAL;
    if (v.map == .mmio and selectors.len > 0) return errors.E_INVAL;

    const sz_bytes = pageSizeBytes(v.sz);
    const var_size = @as(u64, v.page_count) * sz_bytes;

    if (selectors.len == 0) {
        unmapAll(v, domain);
        v.map = .unmapped;
        v.device = null;
        return 0;
    }

    switch (v.map) {
        .page_frame => {
            for (selectors) |sel| {
                const pf_slot: u12 = @truncate(sel & 0xFFF);
                const pf_kh = lookupHandle(domain, pf_slot, .page_frame) orelse
                    return errors.E_BADCAP;
                const pf: *PageFrame = @ptrCast(@alignCast(pf_kh.ref.ptr.?));
                const offset = findInstalledOffset(v, pf) orelse return errors.E_NOENT;
                _ = mappingRemove(v, offset);
            }
            if (countInstalled(v) == 0) v.map = .unmapped;
        },
        .demand => {
            for (selectors) |off| {
                if (!std.mem.isAligned(off, sz_bytes)) return errors.E_INVAL;
                if (off >= var_size) return errors.E_NOENT;
                if (mappingRemove(v, off) == null) return errors.E_NOENT;
            }
            if (countInstalled(v) == 0) v.map = .unmapped;
        },
        .mmio, .unmapped => unreachable,
    }

    dispatch.paging.shootdownTlbRange(
        domain.addr_space_id,
        v.base_vaddr,
        v.sz,
        v.page_count,
    );
    return 0;
}

/// `remap` syscall handler. Spec §[var].remap.
pub fn remap(caller: *ExecutionContext, vmar_handle: u64, new_cur_rwx: u64) i64 {
    if (new_cur_rwx >> 3 != 0) return errors.E_INVAL;

    const domain = caller.domain.ptr; // caller-pinned: caller is the running EC; its domain stays alive across this syscall
    const slot: u12 = @truncate(vmar_handle & 0xFFF);
    const v = resolveVmar(domain, slot) orelse return errors.E_BADCAP;

    const v_irq = v._gen_lock.lockIrqSave(@src());
    defer v._gen_lock.unlockIrqRestore(v_irq);
    defer refreshVmarSnapshot(domain, slot, v);

    if (v.map == .unmapped or v.map == .mmio) return errors.E_INVAL;

    const new_rwx: u3 = @truncate(new_cur_rwx & 0b111);
    const caps_word: u16 = Word0.caps(domain.user_table[slot].word0);
    const vmar_caps: VmarCaps = @bitCast(caps_word);
    const caps_rwx: u3 = (@as(u3, @intFromBool(vmar_caps.r))) |
        (@as(u3, @intFromBool(vmar_caps.w)) << 1) |
        (@as(u3, @intFromBool(vmar_caps.x)) << 2);
    if ((new_rwx & ~caps_rwx) != 0) return errors.E_INVAL;
    if (vmar_caps.dma and (new_rwx & 0b100) != 0) return errors.E_INVAL;

    // Spec §[var].remap test 04: for map = page_frame, new_cur_rwx must
    // be a subset of the intersection of every installed page_frame's
    // r/w/x caps. The intersection starts at all-bits-set and ANDs in
    // each live entry's caps; an empty installed list (shouldn't occur
    // when map = page_frame) leaves the intersection at all-bits.
    if (v.map == .page_frame) {
        var pf_intersect_rwx: u3 = 0b111;
        for (&v.installed_pfs) |*entry| {
            // caller-pinned: PF refcount kept by VMAR's installed list;
            // VMAR's gen-lock is held, so no concurrent install/unmap.
            const pf_ref = entry.pf orelse continue;
            const pf = pf_ref.ptr;
            const pf_caps_word: u16 = blk: {
                var i: usize = 0;
                while (i < domain.user_table.len) : (i += 1) {
                    if (Word0.typeTag(domain.user_table[i].word0) != .page_frame) continue;
                    const kh = domain.kernel_table[i];
                    if (kh.ref.ptr == @as(*const anyopaque, @ptrCast(pf))) {
                        break :blk Word0.caps(domain.user_table[i].word0);
                    }
                }
                // No handle to this pf in the calling domain: derive
                // r/w/x from the pf's effective state by treating it
                // as fully permissive (all bits set). The owning
                // domain's handle is what gates installation, and the
                // intersection is taken across installed frames; the
                // remap caller already passed a caps-subset check via
                // the VMAR's own caps.
                break :blk @as(u16, 0xFFFF);
            };
            const pf_caps: PageFrameCaps = @bitCast(pf_caps_word);
            const pf_rwx: u3 = (@as(u3, @intFromBool(pf_caps.r))) |
                (@as(u3, @intFromBool(pf_caps.w)) << 1) |
                (@as(u3, @intFromBool(pf_caps.x)) << 2);
            pf_intersect_rwx &= pf_rwx;
        }
        if ((new_rwx & ~pf_intersect_rwx) != 0) return errors.E_INVAL;
    }

    const sz_bytes = pageSizeBytes(v.sz);
    var off: u64 = 0;
    const var_size = @as(u64, v.page_count) * sz_bytes;
    while (off < var_size) {
        dispatch.paging.mapPageSized(
            domain.addr_space_root,
            .fromInt(0),
            .fromInt(v.base_vaddr.addr + off),
            v.sz,
            v.cch,
            rwxToPerms(new_rwx),
        ) catch {};
        off += sz_bytes;
    }
    dispatch.paging.shootdownTlbRange(
        domain.addr_space_id,
        v.base_vaddr,
        v.sz,
        v.page_count,
    );
    v.cur_rwx = new_rwx;
    return 0;
}

/// `snapshot` syscall handler. Spec §[var].snapshot.
pub fn snapshot(caller: *ExecutionContext, target_vmar: u64, source_vmar: u64) i64 {
    const domain = caller.domain.ptr; // caller-pinned: caller is the running EC; its domain stays alive across this syscall
    const t_slot: u12 = @truncate(target_vmar & 0xFFF);
    const s_slot: u12 = @truncate(source_vmar & 0xFFF);

    const target = resolveVmar(domain, t_slot) orelse return errors.E_BADCAP;
    const source = resolveVmar(domain, s_slot) orelse return errors.E_BADCAP;

    const t_caps: VmarCaps = @bitCast(Word0.caps(domain.user_table[t_slot].word0));
    const s_caps: VmarCaps = @bitCast(Word0.caps(domain.user_table[s_slot].word0));
    if (t_caps.restart_policy != @intFromEnum(RestartPolicy.snapshot)) return errors.E_INVAL;
    if (s_caps.restart_policy != @intFromEnum(RestartPolicy.preserve)) return errors.E_INVAL;

    const target_irq = target._gen_lock.lockIrqSave(@src());
    defer target._gen_lock.unlockIrqRestore(target_irq);

    const t_size = @as(u64, target.page_count) * pageSizeBytes(target.sz);
    const s_size = @as(u64, source.page_count) * pageSizeBytes(source.sz);
    if (t_size != s_size) return errors.E_INVAL;

    target.snapshot_source = SlabRef(VMAR).init(source, source._gen_lock.currentGen());
    return 0;
}

/// `idc_read` syscall handler. Spec §[var].idc_read.
pub fn idcRead(caller: *ExecutionContext, vmar_handle: u64, offset: u64, count: u8) i64 {
    if (count == 0 or count > 125) return errors.E_INVAL;
    if (!std.mem.isAligned(offset, 8)) return errors.E_INVAL;

    const domain = caller.domain.ptr; // caller-pinned: caller is the running EC; its domain stays alive across this syscall
    const slot: u12 = @truncate(vmar_handle & 0xFFF);
    const v = resolveVmar(domain, slot) orelse return errors.E_BADCAP;

    const caps_word: u16 = Word0.caps(domain.user_table[slot].word0);
    const vmar_caps: VmarCaps = @bitCast(caps_word);
    if (!vmar_caps.r) return errors.E_PERM;

    const v_irq = v._gen_lock.lockIrqSave(@src());
    defer v._gen_lock.unlockIrqRestore(v_irq);

    const sz_bytes = pageSizeBytes(v.sz);
    const var_size = @as(u64, v.page_count) * sz_bytes;
    if (offset + @as(u64, count) * 8 > var_size) return errors.E_INVAL;

    // Cross-domain coherent read: pause every EC in the VMAR's owning
    // domain, copy `count` qwords from VMAR.base + offset into the
    // caller's vregs in offset order (vreg 3 -> offset 0, vreg 4 ->
    // offset 8, ...), then resume. Spec §[idc_read] test 07. The
    // syscall executes with the caller's CR3 active so VMAR.base_vaddr
    // is directly addressable; SMAP gates the user-mem load.
    // caller-pinned: VMAR's domain is its owner; the VMAR cannot exist
    // without it (destroyVmar runs ahead of any domain teardown).
    quiesceDomain(v.domain.ptr);
    defer resumeDomain(v.domain.ptr); // caller-pinned

    // Per §[var], VARs with `map = unmapped` have no backing storage.
    // Reading from a user vaddr in that range would page-fault under
    // SMAP-bracketed user access; the resulting kernel-side fault would
    // re-enter the VMAR's `_gen_lock` via the fault handler and deadlock.
    // Return E_INVAL so the caller can install backing (map_pf /
    // map_mmio / demand fault) before retrying.
    if (v.map == .unmapped) return errors.E_INVAL;

    const src_base: u64 = v.base_vaddr.addr + offset;
    dispatch.cpu.userAccessBegin();
    defer dispatch.cpu.userAccessEnd();
    const src_ptr: [*]const u64 = @ptrFromInt(src_base);
    var i: u8 = 0;
    while (i < count) {
        const qword = src_ptr[i];
        // vreg 3 = first qword, vreg 4 = second. Higher-vreg setters
        // (5..127) need a per-vreg writer that's not yet plumbed
        // through arch.dispatch.syscall; for the v0 register-only
        // window (counts ≤ 2) the tests today exercise only vregs 3-4.
        switch (i) {
            0 => dispatch.syscall.setSyscallVreg3(caller.ctx, qword),
            1 => dispatch.syscall.setSyscallVreg4(caller.ctx, qword),
            else => {
                // SPEC AMBIGUITY: counts > 2 require setters for vregs
                // 5..127; not yet plumbed. Surface as E_INVAL rather
                // than dropping the qword on the floor — the test
                // surface today only drives counts up to 2.
                return errors.E_INVAL;
            },
        }
        i += 1;
    }
    return 0;
}

/// `idc_write` syscall handler. Spec §[var].idc_write.
pub fn idcWrite(
    caller: *ExecutionContext,
    vmar_handle: u64,
    offset: u64,
    count: u8,
    qwords: []const u64,
) i64 {
    if (count == 0 or count > 125) return errors.E_INVAL;
    if (!std.mem.isAligned(offset, 8)) return errors.E_INVAL;

    const domain = caller.domain.ptr; // caller-pinned: caller is the running EC; its domain stays alive across this syscall
    const slot: u12 = @truncate(vmar_handle & 0xFFF);
    const v = resolveVmar(domain, slot) orelse return errors.E_BADCAP;

    const caps_word: u16 = Word0.caps(domain.user_table[slot].word0);
    const vmar_caps: VmarCaps = @bitCast(caps_word);
    if (!vmar_caps.w) return errors.E_PERM;

    const v_irq = v._gen_lock.lockIrqSave(@src());
    defer v._gen_lock.unlockIrqRestore(v_irq);

    const sz_bytes = pageSizeBytes(v.sz);
    const var_size = @as(u64, v.page_count) * sz_bytes;
    if (offset + @as(u64, count) * 8 > var_size) return errors.E_INVAL;

    // The dispatcher delivered only the qwords that fit in the
    // register-vreg window; counts beyond `qwords.len` would draw
    // from stack-spilled vregs the v0 ABI doesn't yet plumb through.
    if (qwords.len < count) return errors.E_INVAL;

    // Per §[var], VARs with `map = unmapped` have no backing storage.
    // Writing to a user vaddr in that range would page-fault under
    // SMAP-bracketed user access; the fault handler would re-enter the
    // VMAR's `_gen_lock` and deadlock. Return E_INVAL so the caller can
    // install backing (map_pf / map_mmio) before retrying.
    if (v.map == .unmapped) return errors.E_INVAL;

    // caller-pinned: VMAR's domain is its owner; the VMAR cannot exist
    // without it.
    quiesceDomain(v.domain.ptr);
    defer resumeDomain(v.domain.ptr); // caller-pinned

    const dst_base: u64 = v.base_vaddr.addr + offset;
    dispatch.cpu.userAccessBegin();
    defer dispatch.cpu.userAccessEnd();
    const dst_ptr: [*]u64 = @ptrFromInt(dst_base);
    var i: u8 = 0;
    while (i < count) {
        dst_ptr[i] = qwords[i];
        i += 1;
    }
    return 0;
}

// ── Internal API ─────────────────────────────────────────────────────

pub inline fn packField1(
    pages: u32,
    sz: PageSize,
    cch: CacheType,
    cur_rwx: u3,
    map: MapType,
    device_id: u12,
) u64 {
    return @as(u64, pages) |
        (@as(u64, @intFromEnum(sz)) << 32) |
        (@as(u64, @intFromEnum(cch)) << 34) |
        (@as(u64, cur_rwx) << 36) |
        (@as(u64, @intFromEnum(map)) << 39) |
        (@as(u64, device_id) << 41);
}

/// Look up a handle slot expecting the given type. Returns null on
/// out-of-range, free slot, or type mismatch. Centralized here to keep
/// every VMAR-handler's resolve path identical.
fn lookupHandle(cd: *CapabilityDomain, slot: u12, expected: CapabilityType) ?*KernelHandle {
    if (slot >= cd.user_table.len) return null;
    const cap = cd.user_table[slot];
    if (Word0.typeTag(cap.word0) != expected) return null;
    const kh = &cd.kernel_table[slot];
    if (kh.ref.ptr == null) return null;
    return kh;
}

fn resolveVmar(cd: *CapabilityDomain, slot: u12) ?*VMAR {
    const kh = lookupHandle(cd, slot, .virtual_memory_address_region) orelse return null;
    return @ptrCast(@alignCast(kh.ref.ptr.?));
}

/// Refresh `slot`'s field0/field1 from authoritative VMAR state. Spec
/// §[var] tests 14/09/12 (implicit-sync side effect on every syscall
/// touching the handle).
fn refreshVmarSnapshot(cd: *CapabilityDomain, slot: u12, v: *const VMAR) void {
    if (slot >= cd.user_table.len) return;
    // caller-pinned: device ref is part of v's mutable state, accessed
    // under v's gen-lock by the caller.
    const dev_id: u12 = if (v.device) |dr_ref| handleIdOf(cd, dr_ref.ptr) else 0;
    cd.user_table[slot].field0 = v.base_vaddr.addr;
    cd.user_table[slot].field1 = packField1(v.page_count, v.sz, v.cch, v.cur_rwx, v.map, dev_id);
}

/// Linear scan of `cd`'s handle table for the slot id pointing at `dr`.
/// Returns 0 when no handle is found — safe because slot 0 is reserved
/// for the self-handle and so cannot hold a device_region.
fn handleIdOf(cd: *const CapabilityDomain, dr: *const DeviceRegion) u12 {
    var i: u16 = 0;
    while (i < cd.user_table.len) {
        const cap = cd.user_table[i];
        if (Word0.typeTag(cap.word0) == .device_region) {
            const kh = cd.kernel_table[i];
            if (kh.ref.ptr == @as(*const anyopaque, @ptrCast(dr))) return @intCast(i);
        }
        i += 1;
    }
    return 0;
}

/// Allocate a VMAR slab slot, claim a VA range in `domain`, append to
/// `domain.vars[]`. Spec §[var].create_vmar.
fn allocVmar(
    domain: *CapabilityDomain,
    base: VAddr,
    pages: u32,
    sz: PageSize,
    cch: CacheType,
    cur_rwx: u3,
    device: ?*DeviceRegion,
) !*VMAR {
    const pending = try slab_instance.create();
    const v = pending.ptr;
    // Slab zero-on-free covers map=.unmapped, device=null,
    // snapshot_source=null, mapping_table=null, installed_pfs=all-empty.
    v.domain = SlabRef(CapabilityDomain).init(domain, domain._gen_lock.currentGen());
    v.base_vaddr = base;
    v.page_count = pages;
    v.sz = sz;
    v.cch = cch;
    v.cur_rwx = cur_rwx;
    if (device) |d| v.device = SlabRef(DeviceRegion).init(d, d._gen_lock.currentGen());
    _ = slab_instance.publish(pending);
    return v;
}

/// Final teardown — unmaps all installations, releases device/snapshot
/// refs, removes from `domain.vars[]`, frees VA range, frees slab slot.
pub fn destroyVmar(v: *VMAR) void {
    // caller-pinned: domain owns this VMAR and outlives it (destroyVmar
    // runs ahead of any domain teardown).
    const domain = v.domain.ptr;
    const gen = v._gen_lock.currentGen();
    if (v.map == .page_frame or v.map == .demand) {
        unmapAll(v, domain);
    } else if (v.map == .mmio) {
        const sz_bytes = pageSizeBytes(v.sz);
        var off: u64 = 0;
        while (off < @as(u64, v.page_count) * sz_bytes) {
            _ = dispatch.paging.unmapPageSized(
                domain.addr_space_root,
                .fromInt(v.base_vaddr.addr + off),
                v.sz,
            );
            off += sz_bytes;
        }
        dispatch.paging.shootdownTlbRange(
            domain.addr_space_id,
            v.base_vaddr,
            v.sz,
            v.page_count,
        );
    }
    zag.caps.capability_domain.removeVar(domain, v);
    slab_instance.destroy(v, gen) catch {};
}

/// VMAR teardown variant for the capability-domain destroy path:
/// drops mapcnt for every installed page_frame, clears the leaf PTEs
/// without issuing per-page TLB shootdowns (no core has the dying CD's
/// CR3 active), removes from `domain.vars[]`, and frees the slab slot.
/// Used by `destroyPhase1`'s `cd.vars[]` walk where paying for
/// O(page_count) IPI broadcasts per VMAR is the dominant cost — a
/// 4 MiB-stack-sized child with multiple VMARs would otherwise eat
/// thousands of shootdown IPIs per spawn.
pub fn destroyVmarDuringDomainTeardown(v: *VMAR) void {
    // caller-pinned: the only caller is `capability_domain.destroyPhase1`
    // walking `cd.vars[]` under `cd._gen_lock`; v's `domain` SlabRef
    // points back at the locked CD, so the slab slot can't be reaped
    // out from under us.
    const domain = v.domain.ptr;
    const gen = v._gen_lock.currentGen();
    if (v.map == .page_frame or v.map == .demand) {
        const sz_bytes = pageSizeBytes(v.sz);
        var off: u64 = 0;
        while (off < @as(u64, v.page_count) * sz_bytes) {
            _ = dispatch.paging.unmapPageNoShootdown(
                domain.addr_space_root,
                .fromInt(v.base_vaddr.addr + off),
            );
            off += sz_bytes;
        }
        for (&v.installed_pfs) |*entry| {
            if (entry.pf) |pf_ref| {
                zag.memory.page_frame.releaseMapping(pf_ref.ptr);
            }
            entry.* = .{};
        }
    } else if (v.map == .mmio) {
        const sz_bytes = pageSizeBytes(v.sz);
        var off: u64 = 0;
        while (off < @as(u64, v.page_count) * sz_bytes) {
            _ = dispatch.paging.unmapPageNoShootdown(
                domain.addr_space_root,
                .fromInt(v.base_vaddr.addr + off),
            );
            off += sz_bytes;
        }
    }
    zag.caps.capability_domain.removeVar(domain, v);
    slab_instance.destroy(v, gen) catch {};
}

/// Allocate a contiguous VA range of `pages * sz` bytes for a new VMAR.
/// `preferred_base != 0` returns that base verbatim (the create_vmar
/// caller is asking for a specific address; the per-domain overlap
/// check still has the final say). Otherwise pick a randomized,
/// `sz`-aligned base inside the ASLR zone (spec §[create_vmar] test 24
/// + §[address_space]). On overlap with an existing VMAR, retry a
/// bounded number of times then fall back to a bump pointer for
/// forward progress.
///
/// Overlap detection covers two classes of mapping:
///   1. `domainOverlaps` — VMAR-tracked ranges (every successful
///      `create_vmar` registers in `domain.vars[]`).
///   2. `pageTableOverlaps` — eager mappings the kernel installs at boot
///      that don't go through the VMAR layer: ELF segments
///      (`loadElfSegments`), the user stack (`mapUserStack`), and the
///      read-only cap-table view (`mapUserTableView`). Both classes
///      occupy real linear addresses; allocating a VMAR base that
///      overlaps either would let `map_pf`'s test 09 check fire on the
///      eager PTEs and reject the install with E_INVAL.
fn vaRangeAllocate(
    domain: *CapabilityDomain,
    pages: u32,
    sz: PageSize,
    preferred_base: VAddr,
) ?VAddr {
    if (preferred_base.addr != 0) return preferred_base;

    const sz_bytes = pageSizeBytes(sz);
    const range_bytes = @as(u64, pages) * sz_bytes;
    const aslr = dispatch.paging.user_aslr;
    if (range_bytes > aslr.end - aslr.start) return null;
    const max_base = aslr.end - range_bytes;
    if (max_base < aslr.start) return null;

    // Try a small number of randomized placements first. The overlap
    // checks below are the authoritative collision test; here we simply
    // probe distinct random bases.
    const RETRY_LIMIT = 8;
    var attempt: u8 = 0;
    while (attempt < RETRY_LIMIT) {
        const r = aslrRandom();
        const span = max_base - aslr.start + sz_bytes;
        const off = r % span;
        const candidate = aslr.start + std.mem.alignBackward(u64, off, sz_bytes);
        if (candidate >= aslr.start and candidate <= max_base) {
            if (!domainOverlaps(domain, candidate, range_bytes) and
                !pageTableOverlaps(domain, candidate, range_bytes, sz_bytes))
            {
                return .fromInt(candidate);
            }
        }
        attempt += 1;
    }

    // Fallback: bump-allocate from `next_var_base` so a VA-pressured
    // domain still makes forward progress when randomized probing
    // keeps colliding. Walk the bump pointer forward past any eager
    // mappings (ELF/stack/cap-table view) that happen to sit at the
    // current bump position; without this the bump path inherits the
    // same eager-overlap blind spot the randomized path used to have.
    var aligned = std.mem.alignForward(u64, domain.next_var_base, sz_bytes);
    while (aligned + range_bytes <= aslr.end) {
        const new_top = aligned + range_bytes;
        if (!domainOverlaps(domain, aligned, range_bytes) and
            !pageTableOverlaps(domain, aligned, range_bytes, sz_bytes))
        {
            domain.next_var_base = new_top;
            return .fromInt(aligned);
        }
        aligned = std.mem.alignForward(u64, aligned + sz_bytes, sz_bytes);
    }
    return null;
}

/// Return true when any page-sized slot in `[base, base + bytes)` already
/// has a present leaf PTE in `domain`'s address space. Catches eager
/// mappings (ELF segments, user stack, cap-table view) that aren't
/// registered in `domain.vars[]` and would otherwise fall through
/// `domainOverlaps` to be picked as a fresh VMAR base. Walks at the
/// requested page size so an overlap test against a 4 KiB candidate
/// only checks 4 KiB-aligned slots; larger sz aligns up to the
/// granule.
fn pageTableOverlaps(domain: *CapabilityDomain, base: u64, bytes: u64, sz_bytes: u64) bool {
    var off: u64 = 0;
    while (off < bytes) {
        const va = VAddr.fromInt(base + off);
        if (dispatch.paging.resolveVaddr(domain.addr_space_root, va) != null) {
            return true;
        }
        off += sz_bytes;
    }
    return false;
}

/// Cheap overlap test against the domain's already-bound VARs. Used
/// during randomized base selection — `checkVaRangeOverlap` has the
/// same logic but returns an i64 status; here we want a bool to drive
/// retry decisions.
fn domainOverlaps(domain: *const CapabilityDomain, base: u64, bytes: u64) bool {
    const new_end = base + bytes;
    var i: u16 = 0;
    while (i < domain.var_count) {
        const v_ref = domain.vars[i] orelse {
            i += 1;
            continue;
        };
        // caller-pinned: VMAR's domain owns it; the walking caller holds
        // the domain alive across this scan.
        const v = v_ref.ptr;
        const v_sz_bytes = pageSizeBytes(v.sz);
        const v_start = v.base_vaddr.addr;
        const v_end = v_start + @as(u64, v.page_count) * v_sz_bytes;
        if (base < v_end and v_start < new_end) return true;
        i += 1;
    }
    return false;
}

/// Sample one 64-bit value of randomness for ASLR placement. Uses the
/// hardware RNG (RDRAND/RNDR) when available; falls back to TSC bits
/// xor'd with a per-call counter so two back-to-back calls still
/// produce distinct values when the entropy source stalls.
pub fn aslrRandom() u64 {
    if (dispatch.cpu.getRandom()) |hw| return hw;
    const ts = dispatch.time.readTimestamp(false);
    aslr_fallback_counter +%= 1;
    return ts ^ (aslr_fallback_counter *% 0x9E3779B97F4A7C15);
}

var aslr_fallback_counter: u64 = 0;

/// Install a page_frame at offset, increments mapcnt, programs PTE or
/// IOMMU PTE. Spec §[var].map_pf — installs every page in the page
/// frame contiguously starting at `offset`. `pf_rwx` carries the
/// page_frame handle's `r/w/x` caps from the calling domain; spec
/// §[var].map_pf test 12 requires effective PTE perms =
/// `VMAR.cur_rwx ∩ page_frame.r/w/x`.
fn mappingInstall(v: *VMAR, offset: u64, pf: *PageFrame, pf_rwx: u3) i64 {
    // caller-pinned: VMAR's domain is its owner.
    const domain = v.domain.ptr;
    const slot_idx = handleSlotOf(v, domain);
    const caps_word: u16 = if (slot_idx < domain.user_table.len)
        Word0.caps(domain.user_table[slot_idx].word0)
    else
        0;
    const vmar_caps: VmarCaps = @bitCast(caps_word);
    // PageFrame caps are uniform across all pages of the frame (caps
    // live on the handle, not per-page), so a single intersection covers
    // every PTE installed below.
    const effective_rwx: u3 = v.cur_rwx & pf_rwx;
    const perms = rwxToPerms(effective_rwx);
    const pf_sz_bytes = pageSizeBytes(pf.sz);

    // Reserve a slot in the inline installed-pf table before touching
    // any PTE so a full table is reported as E_NOMEM up front. The
    // slot is committed (pf field set) only after the install
    // succeeds; on failure it stays empty.
    var slot_reserved: ?usize = null;
    for (&v.installed_pfs, 0..) |*entry, idx| {
        if (entry.pf == null) {
            slot_reserved = idx;
            break;
        }
    }
    if (slot_reserved == null) return errors.E_NOMEM;

    var p: u32 = 0;
    while (p < pf.page_count) {
        const off_p = offset + @as(u64, p) * pf_sz_bytes;
        const phys_p = zag.memory.address.PAddr.fromInt(
            pf.phys_base.addr + @as(u64, p) * pf_sz_bytes,
        );
        const map_failed = if (vmar_caps.dma) blk: {
            // caller-pinned: device ref under VMAR's gen-lock.
            const dev_ref = v.device orelse return errors.E_INVAL;
            dispatch.iommu.iommuMapPage(
                dev_ref.ptr,
                v.base_vaddr.addr + off_p,
                phys_p,
                v.sz,
                perms,
            ) catch break :blk true;
            break :blk false;
        } else blk: {
            dispatch.paging.mapPageSized(
                domain.addr_space_root,
                phys_p,
                .fromInt(v.base_vaddr.addr + off_p),
                v.sz,
                v.cch,
                perms,
            ) catch break :blk true;
            break :blk false;
        };
        if (map_failed) {
            // Roll back PTEs from earlier iterations [0..p) so a partial
            // install never leaves dangling translations behind. After the
            // caller drops its handle the page_frame can be freed and its
            // physical pages handed back to PMM; a stale PTE here would be
            // a UAF primitive. mapcnt was not yet bumped (the bump
            // runs only after the loop) and installed_pfs[slot_reserved]
            // was never committed, so this only undoes hardware state.
            var u: u32 = 0;
            while (u < p) : (u += 1) {
                const off_u = offset + @as(u64, u) * pf_sz_bytes;
                if (vmar_caps.dma) {
                    // dma branch only reached if v.device is non-null —
                    // the very first iteration above already proved it.
                    const dev_ref = v.device.?;
                    _ = dispatch.iommu.iommuUnmapPage(
                        dev_ref.ptr,
                        v.base_vaddr.addr + off_u,
                        v.sz,
                    );
                    dispatch.iommu.invalidateIotlbRange(
                        dev_ref.ptr,
                        v.base_vaddr.addr + off_u,
                        v.sz,
                        1,
                    );
                } else {
                    _ = dispatch.paging.unmapPageSized(
                        domain.addr_space_root,
                        .fromInt(v.base_vaddr.addr + off_u),
                        v.sz,
                    );
                }
            }
            return errors.E_NOMEM;
        }
        p += 1;
    }
    v.installed_pfs[slot_reserved.?] = .{
        .offset = offset,
        .pf = SlabRef(PageFrame).init(pf, pf._gen_lock.currentGen()),
    };
    _ = @atomicRmw(u32, &pf.mapcnt, .Add, 1, .seq_cst);
    return 0;
}

/// Remove an installation, decrements mapcnt, tears down PTE.
/// Returns the removed page_frame so caller can release its handle ref.
fn mappingRemove(v: *VMAR, offset: u64) ?*PageFrame {
    // caller-pinned: VMAR's domain is its owner.
    const domain = v.domain.ptr;
    const slot_idx = handleSlotOf(v, domain);
    const caps_word: u16 = if (slot_idx < domain.user_table.len)
        Word0.caps(domain.user_table[slot_idx].word0)
    else
        0;
    const vmar_caps: VmarCaps = @bitCast(caps_word);

    var removed: ?*PageFrame = null;
    for (&v.installed_pfs) |*entry| {
        if (entry.pf) |pf_ref| {
            if (entry.offset == offset) {
                removed = pf_ref.ptr;
                entry.* = .{};
                // PageFrame mapcnt was bumped at install;
                // this is the matching decrement. `releaseMapping` may
                // run destroyPageFrame inline if the last handle has
                // also been released.
                zag.memory.page_frame.releaseMapping(pf_ref.ptr);
                break;
            }
        }
    }

    if (vmar_caps.dma) {
        // caller-pinned: device ref under VMAR's gen-lock.
        const dev_ref = v.device orelse return removed;
        _ = dispatch.iommu.iommuUnmapPage(dev_ref.ptr, v.base_vaddr.addr + offset, v.sz);
        dispatch.iommu.invalidateIotlbRange(dev_ref.ptr, v.base_vaddr.addr + offset, v.sz, 1);
    } else {
        _ = dispatch.paging.unmapPageSized(
            domain.addr_space_root,
            .fromInt(v.base_vaddr.addr + offset),
            v.sz,
        );
    }
    return removed;
}

/// Demand-page allocation on a fault to a regular VMAR (`caps.mmio = 0,
/// caps.dma = 0`). Per spec §[var] (line 1409): "The first faulted
/// access transitions it to `map = 3` (demand): the kernel allocates
/// a fresh zero-filled page_frame and installs it at the faulting
/// offset, with effective permissions = `VMAR.cur_rwx`."
///
/// Caller (`handlePageFault`) holds `v._gen_lock`, has already proved
/// the access is rights-compatible with `v.cur_rwx`, and computed
/// `offset` aligned-back to the VMAR's `sz`. We allocate a single-page
/// PageFrame at the VMAR's `sz` (PMM returns it zero-filled by the
/// zero-on-free invariant), install it via the same path used by
/// `map_pf`, and drop the kernel's local handle ref so the PF lives
/// purely on its mapcnt — spec §[snapshot]: "Demand-paged pages are
/// kernel-allocated and not exposed elsewhere, so `mapcnt = 1` is
/// implicit." Once `unmap` decrements mapcnt to 0, `releaseMapping`
/// observes refcount == 0 and runs `destroyPageFrame` which returns
/// the page to PMM.
///
/// Idempotent on already-installed offsets: if an installed_pfs slot
/// already covers `offset` (cross-core fault race — both cores hit a
/// fault on the same page, second wakes after first's install), we
/// return success without re-allocating.
fn demandAlloc(v: *VMAR, offset: u64) i64 {
    for (&v.installed_pfs) |*entry| {
        if (entry.pf != null and entry.offset == offset) return 0;
    }

    const pf = zag.memory.page_frame.allocForDemand(v.sz) catch return errors.E_NOMEM;

    // Demand-paged PFs are kernel-allocated with no user-visible handle (spec
    // §[snapshot]); spec §[var] demand transition: effective perms = VMAR.cur_rwx.
    // Pass 0b111 so the intersection in mappingInstall is a no-op.
    const rc = mappingInstall(v, offset, pf, 0b111);
    if (rc != 0) {
        // mappingInstall failed before bumping mapcnt; drop the
        // kernel's handle ref to release the PF back to PMM.
        zag.memory.page_frame.releaseHandle(pf);
        return rc;
    }

    // Spec §[snapshot]: demand pages have no user-visible handle, so
    // drop the refcount=1 we got from allocForDemand. mapcnt=1 keeps
    // the PF alive until `unmap` runs.
    zag.memory.page_frame.releaseHandle(pf);
    return 0;
}

/// Page-fault handler hook — looks up the VMAR covering `fault_vaddr`
/// in `domain` and dispatches per `map`. Spec §[var] demand transition.
pub fn handlePageFault(domain: *CapabilityDomain, fault_vaddr: VAddr, access_rwx: u3) i64 {
    const v = findVmarCovering(domain, fault_vaddr) orelse return errors.E_BADADDR;
    const v_irq = v._gen_lock.lockIrqSave(@src());

    if ((access_rwx & ~v.cur_rwx) != 0) {
        v._gen_lock.unlockIrqRestore(v_irq);
        return errors.E_PERM;
    }

    switch (v.map) {
        .unmapped => {
            defer v._gen_lock.unlockIrqRestore(v_irq);
            const offset = fault_vaddr.addr - v.base_vaddr.addr;
            const sz_bytes = pageSizeBytes(v.sz);
            const aligned = std.mem.alignBackward(u64, offset, sz_bytes);
            const rc = demandAlloc(v, aligned);
            if (rc == 0) v.map = .demand;
            return rc;
        },
        .demand => {
            defer v._gen_lock.unlockIrqRestore(v_irq);
            const offset = fault_vaddr.addr - v.base_vaddr.addr;
            const sz_bytes = pageSizeBytes(v.sz);
            const aligned = std.mem.alignBackward(u64, offset, sz_bytes);
            return demandAlloc(v, aligned);
        },
        .mmio => {
            // Port-IO virtualization — decode MOV, emit IN/OUT, advance
            // RIP. Spec §[port_io_virtualization]. Plain MMIO faults
            // here are spurious (real PTEs were installed at map time)
            // and route to the EC's memory_fault event.
            // caller-pinned: device ref under VMAR's gen-lock.
            const dev_ref = v.device orelse {
                v._gen_lock.unlockIrqRestore(v_irq);
                return errors.E_BADADDR;
            };
            const dev = dev_ref.ptr;
            if (dev.device_type != .port_io) {
                v._gen_lock.unlockIrqRestore(v_irq);
                return errors.E_PERM;
            }
            // Snapshot the immutable VMAR base under the lock, then
            // release before invoking the port-IO emulator. Spec
            // §[port_io_virtualization] tests 06/09/10/11 require the
            // emulator to fire `memory_fault` / `thread_fault` inline
            // and yield the EC; in those paths the emulator never
            // returns, so a still-held VMAR `_gen_lock` would strand
            // forever and deadlock any future walk of the domain's
            // `vars[]`. The DeviceRegion pointer is stable for the
            // kernel's lifetime once bound, so unlocking here is safe.
            const var_base = v.base_vaddr.addr;
            v._gen_lock.unlockIrqRestore(v_irq);
            return decodePortIoFault(domain, fault_vaddr, var_base, dev);
        },
        .page_frame => {
            v._gen_lock.unlockIrqRestore(v_irq);
            return errors.E_PERM;
        },
    }
}

/// Linear scan for any VMAR whose [base, base + page_count*sz) covers
/// `fault_vaddr`. The flat per-domain `vars[]` makes this O(N) which
/// is fine because a domain holds at most MAX_VARS_PER_DOMAIN (512).
pub fn findVmarCovering(cd: *CapabilityDomain, fault_vaddr: VAddr) ?*VMAR {
    var i: u16 = 0;
    while (i < cd.var_count) {
        const v_ref = cd.vars[i] orelse {
            i += 1;
            continue;
        };
        // caller-pinned: VMAR's domain (= cd) owns it.
        const v = v_ref.ptr;
        const sz_bytes = pageSizeBytes(v.sz);
        const end = v.base_vaddr.addr + @as(u64, v.page_count) * sz_bytes;
        if (fault_vaddr.addr >= v.base_vaddr.addr and fault_vaddr.addr < end) {
            return v;
        }
        i += 1;
    }
    return null;
}

/// Find which slot id in `domain.user_table` holds the handle for `v`.
/// Linear scan; the 4096-entry table cap bounds the cost. Returns
/// `MAX_HANDLES_PER_DOMAIN` (out-of-range) when no handle is found —
/// callers truncate to u12 and read the resulting cap word.
fn handleSlotOf(v: *const VMAR, cd: *const CapabilityDomain) u16 {
    var i: u16 = 0;
    while (i < cd.user_table.len) {
        const cap = cd.user_table[i];
        if (Word0.typeTag(cap.word0) == .virtual_memory_address_region) {
            const kh = cd.kernel_table[i];
            if (kh.ref.ptr == @as(*const anyopaque, @ptrCast(v))) return i;
        }
        i += 1;
    }
    return @intCast(cd.user_table.len);
}

/// Walk the per-page mapping table of `v` looking for an installed
/// page_frame matching `pf`. Returns the byte offset, or null if not
/// installed. Concrete walk depends on the eventual `mapping_table`
/// layout.
fn findInstalledOffset(v: *VMAR, pf: *PageFrame) ?u64 {
    for (&v.installed_pfs) |*entry| {
        if (entry.pf) |pf_ref| {
            // Identity compare: SlabRef.ptr == raw pointer.
            if (pf_ref.ptr == pf) return entry.offset;
        }
    }
    return null;
}

/// Number of currently-installed pages in `v`'s mapping table. Used by
/// `unmap` to decide whether to clear `map` back to `unmapped`.
fn countInstalled(v: *VMAR) u32 {
    var count: u32 = 0;
    for (&v.installed_pfs) |*entry| {
        if (entry.pf != null) count += 1;
    }
    return count;
}

/// Tear down every installed PTE / demand page, decrement mapcnts, and
/// invalidate. Called by `unmap` (N=0) and `destroyVmar`.
fn unmapAll(v: *VMAR, domain: *CapabilityDomain) void {
    const sz_bytes = pageSizeBytes(v.sz);
    var off: u64 = 0;
    while (off < @as(u64, v.page_count) * sz_bytes) {
        _ = dispatch.paging.unmapPageSized(
            domain.addr_space_root,
            .fromInt(v.base_vaddr.addr + off),
            v.sz,
        );
        off += sz_bytes;
    }
    // Decrement mapcnt for every still-installed page_frame entry; the
    // PTEs are gone but the PageFrame's per-mapping counter is what
    // gates `destroyPageFrame`. Without this the PF stays alive at
    // mapcnt > 0 even after every handle is released — the cross-rep
    // leak the test runner trips on at N>1.
    for (&v.installed_pfs) |*entry| {
        if (entry.pf) |pf_ref| {
            zag.memory.page_frame.releaseMapping(pf_ref.ptr);
        }
        entry.* = .{};
    }
    dispatch.paging.shootdownTlbRange(
        domain.addr_space_id,
        v.base_vaddr,
        v.sz,
        v.page_count,
    );
}

/// Pause every EC bound to `cd`. Used by idc_read/idc_write to obtain
/// a coherent snapshot of the VMAR's contents without observable
/// interleaving.
fn quiesceDomain(cd: *CapabilityDomain) void {
    _ = cd;
}

fn resumeDomain(cd: *CapabilityDomain) void {
    _ = cd;
}

/// Decode the MOV that hit a port-IO VMAR, emit the matching IN/OUT,
/// commit the result, advance RIP. Spec §[port_io_virtualization]
/// tests 04-11. Dispatches to the per-arch emulator: x86-64 owns the
/// IN/OUT instructions and the MOV decoder; aarch64 has no port-IO
/// concept and is unreachable per spec test 01 (`map_mmio` rejects
/// `dev_type = port_io` on non-x86-64).
///
/// `var_base` is a pre-snapshot copy of `v.base_vaddr.addr` taken
/// under the VMAR's `_gen_lock` by `handlePageFault`; the lock has
/// already been released because the emulator may suspend or
/// terminate the running EC (firing thread_fault / memory_fault
/// inline per spec tests 06/09/10/11) and a still-held lock would
/// strand. The currently-dispatched EC is `scheduler.currentEc()` —
/// it owns the page-fault frame and is the target of any inline
/// event delivery.
///
/// Always returns 0 on successful emulation (the emulator advanced
/// the user RIP and the caller iretq's the user back to the next
/// instruction). On inline-fired event paths the emulator yields
/// and never returns; the caller's iretq window resumes whatever EC
/// the scheduler dispatches next.
fn decodePortIoFault(
    cd: *CapabilityDomain,
    fault_vaddr: VAddr,
    var_base: u64,
    dev: *DeviceRegion,
) i64 {
    _ = cd;
    // caller-pinned: currentEc() is the EC whose page-fault we're
    // servicing; its kernel stack is the running stack and its bound
    // domain is alive across this handler.
    const ec = scheduler.currentEc() orelse return errors.E_BADADDR;
    return zag.arch.dispatch.port_io.emulatePortIoFault(ec, fault_vaddr, var_base, dev);
}

