//! Page Frame — reference to a contiguous physical memory region.
//! Installing it into virtual address ranges bound to multiple
//! capability domains creates shared memory. See spec §[page_frame].
//!
//! Refcount lifetime — total handles across all capability domains
//! plus VMAR installations keep the underlying physical pages alive.
//! When the last handle drops the physical memory returns to the free
//! pool.

const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const capability = zag.caps.capability;
const capability_domain = zag.caps.capability_domain;
const errors = zag.syscall.errors;
const pmm = zag.memory.pmm;
const vmar = zag.memory.vmar;

const CapabilityDomain = capability_domain.CapabilityDomain;
const CapabilityType = capability.CapabilityType;
const ErasedSlabRef = capability.ErasedSlabRef;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const GenLock = zag.memory.allocators.secure_slab.GenLock;
const PAddr = zag.memory.address.PAddr;
const SecureSlab = zag.memory.allocators.secure_slab.SecureSlab;
const VAddr = zag.memory.address.VAddr;

/// Page size encoding (immutable per page frame). Same enum used by
/// VMAR — re-exported for convenience.
pub const PageSize = vmar.PageSize;

/// Cap bits in `Capability.word0[48..63]` for page_frame handles.
/// Spec §[page_frame] cap layout.
pub const PageFrameCaps = packed struct(u16) {
    move: bool = false,
    copy: bool = false,
    r: bool = false,
    w: bool = false,
    x: bool = false,
    max_sz: u2 = 0,
    restart_policy: u1 = 0,
    _reserved: u8 = 0,
};

pub const PageFrame = struct {
    /// Slab generation lock + per-instance mutex.
    _gen_lock: GenLock = .{},

    /// Total user-visible handles across all capability domains. Plain
    /// u32 mutated under `_gen_lock`; the decrementer that brings
    /// this to 0 owns teardown (returns physical pages to PMM).
    refcount: u32 = 0,

    /// Total active installations across all VARs and IOMMU domains.
    /// Mirrors user-visible field1 bits 0-31 (`mapcnt`). Mutated by
    /// `map_pf` / `unmap` and IOMMU bind/unbind paths under
    /// `_gen_lock`. snapshot binding stability check requires this
    /// to be exactly 1.
    mapcnt: u32 = 0,

    /// Physical base address of the backing memory. Set at create;
    /// immutable.
    phys_base: PAddr,

    /// Number of pages in `sz` units. Mirrors field0 bits 0-31. Set
    /// at create; immutable.
    page_count: u32,

    /// Page size (immutable). Mirrors field0 bits 32-33.
    sz: PageSize,
};

pub const Allocator = SecureSlab(PageFrame, 256);
pub var slab_instance: Allocator = undefined;

pub fn initSlab(
    data_range: zag.utils.range.Range,
    ptrs_range: zag.utils.range.Range,
    links_range: zag.utils.range.Range,
) void {
    slab_instance = Allocator.init(data_range, ptrs_range, links_range);
}

// ── External API ─────────────────────────────────────────────────────

/// `create_page_frame` syscall handler. Spec §[page_frame].
pub fn createPageFrame(caller: *anyopaque, caps: u64, props: u64, pages: u64) i64 {
    // Reserved-bit validation (test 08): caps' upper 48 bits must be
    // zero; props' upper 62 bits must be zero. Fail fast before any
    // expensive lookup or allocation.
    if (caps >> 16 != 0) return errors.E_INVAL;
    if (props >> 2 != 0) return errors.E_INVAL;

    if (pages == 0) return errors.E_INVAL;

    const caps_bits: PageFrameCaps = @bitCast(@as(u16, @truncate(caps)));
    const sz_raw: u2 = @truncate(props);

    // Reserved page-size encodings (test 05, test 06).
    if (caps_bits.max_sz == @intFromEnum(PageSize._reserved)) return errors.E_INVAL;
    if (sz_raw == @intFromEnum(PageSize._reserved)) return errors.E_INVAL;

    // sz must not exceed max_sz (test 07).
    if (sz_raw > caps_bits.max_sz) return errors.E_INVAL;

    const sz: PageSize = @enumFromInt(sz_raw);

    // u32 page_count fits the field0 layout.
    if (pages > std.math.maxInt(u32)) return errors.E_INVAL;
    const page_count: u32 = @intCast(pages);

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));

    if (selfHandleLacksCrpf(ec)) return errors.E_PERM;
    if (!rwxIsSubsetOfCeiling(ec, caps_bits)) return errors.E_PERM;
    if (!maxSzWithinCeiling(ec, caps_bits)) return errors.E_PERM;

    const pf = allocPageFrame(sz, page_count) catch return errors.E_NOMEM;

    // Mint the user-visible handle into the caller's table. The kernel
    // table entry holds the `SlabRef(PageFrame)` (gen-validated); the
    // user table mirrors caps + field0/field1 snapshot.
    const cd = callerDomain(ec);
    const erased: ErasedSlabRef = .{
        .ptr = @ptrCast(pf),
        .gen = @intCast(pf._gen_lock.currentGen()),
    };
    const field0: u64 = packField0(page_count, sz);
    const field1: u64 = 0;
    const handle_caps: u16 = @bitCast(caps_bits);
    const slot = capability_domain.mintHandle(
        cd,
        erased,
        CapabilityType.page_frame,
        handle_caps,
        field0,
        field1,
    ) catch {
        // Handle table full: drop the lone refcount we minted; mapcnt
        // was 0, so this triggers full teardown back to PMM.
        decHandleRef(pf);
        return errors.E_FULL;
    };

    // Spec §[error_codes] / §[capabilities]: success returns the
    // packed Word0 so the type tag in bits 12..15 always disambiguates
    // a real handle word from the error range 1..15.
    return @intCast(capability.Word0.pack(slot, .page_frame, handle_caps));
}

// ── Internal API ─────────────────────────────────────────────────────

/// Allocate a PageFrame slot + `page_count` pages of `sz` from PMM,
/// refcount=1, mapcnt=0. Spec §[page_frame] create.
fn allocPageFrame(sz: PageSize, page_count: u32) !*PageFrame {
    const total_bytes: u64 = buddyAllocBytes(sz, page_count);

    const pmm_mgr = &(pmm.global_pmm orelse return error.OutOfMemory);
    const block = pmm_mgr.allocBlock(total_bytes) orelse return error.OutOfMemory;
    errdefer pmm_mgr.freeBlock(block[0..total_bytes]);

    const ref = slab_instance.create() catch return error.OutOfMemory;

    // SecureSlab.create returns a zeroed slot with gen flipped to live.
    // Caller is the sole observer until the handle is published, so
    // direct field writes are safe (no lock/unlock bracketing needed).
    const pf = ref.ptr;
    pf.refcount = 1;
    pf.mapcnt = 0;
    // PMM allocBlock returns a physmap virtual pointer (the buddy
    // allocator is initialized over the physmap window — see
    // memory/init.zig). Convert to PA here so PTE installs and
    // IOMMU mappings see the real frame number rather than a
    // canonical-form VA that overflows the 52-bit PA field.
    pf.phys_base = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(block)), null);
    pf.page_count = page_count;
    pf.sz = sz;

    return pf;
}

/// Final teardown — caller has observed refcount==0 AND mapcnt==0 under
/// `_gen_lock`. Returns physical pages to PMM and frees the slab slot.
fn destroyPageFrame(pf: *PageFrame) void {
    // Snapshot what we need before the slab destroy invalidates `pf`.
    // PMM freeBlock expects a physmap virtual pointer (matches what
    // allocBlock returned); convert from the stored physical address.
    const phys_base = pf.phys_base;
    const total_bytes = buddyAllocBytes(pf.sz, pf.page_count);
    const expected_gen: u63 = @intCast(pf._gen_lock.currentGen());

    // Caller holds the gen-lock at expected_gen (per the inc/dec
    // contract that observed both counters at zero); destroyLocked
    // clears the slot and bumps the gen as part of releasing the lock.
    slab_instance.destroyLocked(pf, expected_gen);

    // PMM freeBlock zero-fills before returning pages to the buddy, so
    // the next allocator sees a clean region.
    if (pmm.global_pmm) |*pmm_mgr| {
        const virt = VAddr.fromPAddr(phys_base, null);
        const ptr: [*]u8 = @ptrFromInt(virt.addr);
        pmm_mgr.freeBlock(ptr[0..total_bytes]);
    }
}

/// Handle delete: decrement refcount under `_gen_lock`; if both
/// refcount and mapcnt are zero, calls `destroyPageFrame`.
fn decHandleRef(pf: *PageFrame) void {
    const irq = pf._gen_lock.lockIrqSave(@src());
    if (pf.refcount > 0) pf.refcount -= 1;
    const reached_zero = pf.refcount == 0 and pf.mapcnt == 0;
    if (!reached_zero) {
        pf._gen_lock.unlockIrqRestore(irq);
        return;
    }
    // Lock stays held — destroyPageFrame routes through
    // SecureSlab.destroyLocked which expects the gen-lock held and
    // releases it as part of the gen bump. The teardown bumps gen via
    // setGenRelease without restoring IRQ state; do it manually here.
    destroyPageFrame(pf);
    arch.cpu.restoreInterrupts(irq);
}

/// Public release-handle entry point invoked from the cross-cutting
/// `caps.capability.delete` path. Wraps `decHandleRef` for callers
/// that don't have access to the module-private helper.
pub fn releaseHandle(pf: *PageFrame) void {
    decHandleRef(pf);
}

// ── Helpers ──────────────────────────────────────────────────────────

inline fn pageSizeBytes(sz: PageSize) u64 {
    return switch (sz) {
        .sz_4k => 0x1000,
        .sz_2m => 0x200000,
        .sz_1g => 0x40000000,
        ._reserved => unreachable,
    };
}

/// Bytes the buddy allocator must reserve to cover `page_count` pages
/// of `sz`. Buddy.allocBlock requires a power-of-two page count, so
/// any non-power-of-two request is rounded up to the next power of two.
/// Both alloc and free paths route through this helper so accounting
/// stays consistent.
inline fn buddyAllocBytes(sz: PageSize, page_count: u32) u64 {
    const pages_pow2: u64 = std.math.ceilPowerOfTwoAssert(u64, page_count);
    return pageSizeBytes(sz) * pages_pow2;
}

inline fn packField0(page_count: u32, sz: PageSize) u64 {
    return @as(u64, page_count) | (@as(u64, @intFromEnum(sz)) << 32);
}

/// Resolve the caller's owning capability domain. The syscall ABI
/// dispatches via `*anyopaque`; the concrete type is `*ExecutionContext`
/// whose `domain` SlabRef names the owner.
fn callerDomain(ec: *ExecutionContext) *CapabilityDomain {
    return ec.domain.ptr; // self-alive: ec is the running EC; its domain stays alive across this syscall
}

/// Spec §[create_page_frame] test 01: returns E_PERM if the caller's
/// self-handle lacks `crpf`. The self-handle's caps live in the
/// capability domain's user_table[0].word0 caps field.
fn selfHandleLacksCrpf(ec: *ExecutionContext) bool {
    const cd = callerDomain(ec);
    const self_caps_word: u16 = capability.Word0.caps(cd.user_table[0].word0);
    const self_caps: capability_domain.CapabilityDomainCaps = @bitCast(self_caps_word);
    return !self_caps.crpf;
}

/// Spec §[create_page_frame] test 02: returns E_PERM if caps' r/w/x
/// bits are not a subset of the caller's `pf_ceiling.max_rwx`. Per
/// §[capability_domain] Self handle — pf_ceiling lives at field0 bits
/// 40..47 with `max_rwx` at bits 40..42 and `max_sz` at bits 43..44.
/// (Self-handle field0 differs from [2] ceilings_inner: it inserts
/// idc_rx at bits 32..39, shifting pf/vm/port ceilings up by 8.)
fn rwxIsSubsetOfCeiling(ec: *ExecutionContext, caps_bits: PageFrameCaps) bool {
    const cd = callerDomain(ec);
    const self_field0 = cd.user_table[0].field0;
    const max_rwx: u3 = @truncate((self_field0 >> 40) & 0b111);
    const requested_rwx: u3 = (@as(u3, @intFromBool(caps_bits.r))) |
        (@as(u3, @intFromBool(caps_bits.w)) << 1) |
        (@as(u3, @intFromBool(caps_bits.x)) << 2);
    return (requested_rwx & ~max_rwx) == 0;
}

/// Spec §[create_page_frame] test 03: returns E_PERM if `caps.max_sz`
/// exceeds the caller's `pf_ceiling.max_sz`. Stored in self-handle
/// field0 bits 43..44 per §[capability_domain] layout (shifted by 8
/// vs the [2] ceilings_inner layout to make room for idc_rx).
fn maxSzWithinCeiling(ec: *ExecutionContext, caps_bits: PageFrameCaps) bool {
    const cd = callerDomain(ec);
    const self_field0 = cd.user_table[0].field0;
    const ceiling_max_sz: u2 = @truncate((self_field0 >> 43) & 0b11);
    return caps_bits.max_sz <= ceiling_max_sz;
}
