const std = @import("std");
const zag = @import("zag");

const apic = zag.arch.x64.apic;
const cpu = zag.arch.x64.cpu;
const interrupts = zag.arch.x64.interrupts;
const kprof = zag.kprof.trace_id;
const paging = zag.memory.paging;
const physmap = zag.memory.address.AddrSpacePartition.physmap;
const pmm = zag.memory.pmm;

const MappingKind = zag.memory.address.MappingKind;
const MemoryPerms = zag.memory.address.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageSize = zag.memory.paging.PageSize;
const SpinLock = zag.utils.sync.SpinLock;
const VAddr = zag.memory.address.VAddr;
const VmarCacheType = zag.memory.vmar.CacheType;
const VmarPageSize = zag.memory.vmar.PageSize;

/// First user-mappable virtual address. The NULL guard `[0, 0x1000)` is
/// reserved by spec §[address_space] so that NULL dereferences always
/// fault; this is the upper bound of that guard. Mirrors the value in
/// `arch.dispatch.paging.user_null_guard.end` — repeated locally so the
/// arch backend doesn't reach upward through the dispatch boundary.
const FIRST_USER_PAGE: u64 = 0x1000;

/// Per-MappingKind page-attribute derivation. cache/global/user fields
/// are owned by the arch backend (Intel SDM Vol 3A §5.10, §11.11).
const KindAttrs = struct {
    user_accessible: bool,
    global: bool,
    not_cacheable: bool,
    write_through: bool,
    write_combining: bool,
};

fn kindAttrs(kind: MappingKind) KindAttrs {
    return switch (kind) {
        .kernel_data => .{
            .user_accessible = false,
            .global = true,
            .not_cacheable = false,
            .write_through = false,
            .write_combining = false,
        },
        .kernel_mmio => .{
            .user_accessible = false,
            .global = false,
            .not_cacheable = true,
            .write_through = false,
            .write_combining = false,
        },
        .user_data => .{
            .user_accessible = true,
            .global = false,
            .not_cacheable = false,
            .write_through = false,
            .write_combining = false,
        },
        .user_mmio => .{
            .user_accessible = true,
            .global = false,
            .not_cacheable = true,
            .write_through = false,
            .write_combining = false,
        },
    };
}

/// TLB shootdown: cross-core invalidation broadcast.
///
/// Intel SDM Vol 3A, Section 5.10.5 "Propagation of Paging-Structure Changes
/// to Multiple Processors" requires software to broadcast invalidations to
/// every logical processor that may have cached the old translation.
///
/// Two shootdown modes co-exist on top of the same lock + descriptor:
///
///   1. **Synchronous** (`flushRemotePcid`, `shootdownTlbRange`): the
///      initiator holds `shootdown_lock`, publishes the request
///      descriptor (kind/addr/pcid), bumps `sync_arm_gen` to a fresh
///      value, fans out IPIs, then spins until every remote core's
///      `core_acked_gen[i] >= sync_arm_gen` before releasing the lock
///      or publishing the next descriptor. The remote IPI handler
///      performs the requested invalidation and stores the current
///      `sync_arm_gen` into its own `core_acked_gen[my_core]` slot.
///      This is the Linux-style "send-then-wait" pattern — without
///      it, a per-page loop that overwrites the shared descriptor
///      between IPIs leaves remote cores executing INVPCID against
///      the *next* descriptor instead of the one they were summoned
///      for, leaking stale TLB entries (cross-core UAF on unmap+free
///      races). Both syscall-side teardown paths run with interrupts
///      enabled, so the wait is safe.
///
///   2. **Fire-and-forget** (`flushRemoteTlb`, single-page): the
///      initiator holds the lock, publishes a `.invlpg_no_ack`
///      descriptor (does NOT bump `sync_arm_gen`), fans out IPIs,
///      releases the lock. The handler INVLPGs and updates its
///      `core_acked_gen` slot to whatever `sync_arm_gen` it observes;
///      because the no-ack path never bumps the gen, that store is
///      idempotent against the most recent sync arm and cannot
///      satisfy a *future* sync arm's wait. This mode is used by
///      `unmapPage`'s kernel-stack teardown, which is reachable from
///      `finalizeDestroyMarkedDead` inside the IRQ-disabled scheduler
///      critical section (`yieldTo`, `parkAndAwaitIRQ`). A synchronous
///      wait there would be a hard deadlock — two cores both calling
///      `unmapPage` with IRQs off would each spin on `shootdown_lock`
///      waiting for the other's ack while neither can process the
///      other's IPI. The pre-existing UAF window described in
///      `unmapPage`'s body remains for this single-page kernel-side
///      path.
///
/// ## Why per-core gen tracking instead of a shared decrement counter
///
/// The earlier design used `shootdown_acks_remaining: u32` which the
/// handler decremented exactly once per IPI. That design was wrong
/// when the no-ack and sync paths interleaved: the handler reads
/// `shootdown_kind` at *service time*, not at IPI dispatch time. A
/// stale fire-and-forget IPI pending in a remote core's IRR (because
/// the remote had IRQs masked at dispatch) might be serviced AFTER a
/// subsequent sync arm has rewritten `shootdown_kind` from
/// `invlpg_no_ack` to `invlpg` / `invpcid_addr`. The handler then sees
/// the new kind, decrements the counter — but that counter belongs to
/// the *new* arm, not the one the IPI was sent for. Each affected
/// remote contributed one extra decrement per arm, underflowing
/// `acks_remaining` past zero (observed: `0xFFFFFFFE` in gdb under
/// `vmar.unmapAll`, which interleaves both modes within a single
/// syscall window — `flushRemoteTlb` per page in `unmapPage`, then
/// `shootdownTlbRange` over the whole range). The sync initiator's
/// `!= 0` spin on the underflowed counter never terminated, hanging
/// CPU0 in `waitForShootdownAcks` while every other core was halted
/// in `parkAndAwaitIRQ` (the `pending_zombies=1` / RDY-EC-not-stolen
/// dump pattern from t5r).
///
/// The fix is to make ack tracking idempotent and per-core: each sync
/// arm advances `sync_arm_gen` (a monotonic u64), and the handler
/// stores that gen into its own slot. A duplicate or stale handler
/// run just re-stores the same value (or a stale lower one — masked
/// by max-store semantics in the wait loop). Underflow is impossible
/// because we never decrement; double-acking is harmless because the
/// store is idempotent within an arm.
var shootdown_lock: SpinLock = .{ .class = "paging.shootdown_lock" };
var shootdown_addr: u64 = 0;
/// Shootdown request kind. Selects which invalidation primitive the
/// handler runs (INVLPG vs INVPCID type 0/1). Note the kind no longer
/// drives the ack-vs-no-ack decision — that's controlled by whether
/// the initiator bumped `sync_arm_gen`.
///   - .invlpg          → INVLPG `shootdown_addr` (flushes every PCID +
///                        globals at this VA on the remote core). Used
///                        by `shootdownTlbRange` when PCID is disabled.
///   - .invpcid_single  → INVPCID type 1 against `shootdown_pcid`
///                        (every linear address, single PCID). Used by
///                        `flushRemotePcid`.
///   - .invpcid_addr    → INVPCID type 0 against `(shootdown_pcid,
///                        shootdown_addr)` (one VA, one PCID — used by
///                        the range walk so remote cores only pay for
///                        the address space being torn down).
///   - .invlpg_no_ack   → INVLPG (kernel-side fire-and-forget). The
///                        kind no longer affects the handler's ack
///                        path — the per-core gen store is
///                        unconditional. Retained as a distinct enum
///                        value so callers and tooling can still see
///                        the publication intent in a debugger.
const ShootdownKind = enum(u8) {
    invlpg = 0,
    invpcid_single = 1,
    invpcid_addr = 2,
    invlpg_no_ack = 3,
};
var shootdown_kind: u8 = @intFromEnum(ShootdownKind.invlpg);
var shootdown_pcid: u16 = 0;

/// MAX_CORES on x86_64. Mirrors `gdt.MAX_CORES`, `acpi.MAX_CORES`, and
/// `intel.vmx.MAX_CORES`; kept local so the shootdown ack-tracking
/// arrays don't reach across files for a constant.
const MAX_CORES: usize = 64;

/// Monotonic generation counter for synchronous shootdown arms. Bumped
/// by `flushRemotePcid` and each iteration of `shootdownTlbRange` while
/// `shootdown_lock` is held. Sync initiators wait for every remote
/// core's `core_acked_gen[i]` to catch up to the value they observed
/// post-bump; remote handlers store the current `sync_arm_gen` into
/// their own slot after performing the invalidation, regardless of
/// kind. `flushRemoteTlb` (no-ack mode) deliberately does NOT bump
/// this — its IPIs cannot satisfy a future sync arm's wait because
/// the gen they'd store is `<=` whatever a future sync arm publishes.
var sync_arm_gen: u64 = 0;
/// Per-core last-acked sync_arm_gen. Each remote core stores its own
/// slot from inside `tlbShootdownHandler` after the invalidation
/// completes; sync initiators spin until every remote slot reaches
/// the gen they bumped to. Idempotent — stale handler runs just
/// re-store the same (or smaller) value, and the wait loop checks
/// `>= expected_gen`.
var core_acked_gen: [MAX_CORES]u64 = [_]u64{0} ** MAX_CORES;

/// IPI handler for TLB shootdown. Dispatches on `shootdown_kind`,
/// performs the requested invalidation, then signals completion by
/// storing the current `sync_arm_gen` into this core's
/// `core_acked_gen` slot. The store is unconditional: a fire-and-
/// forget IPI from `flushRemoteTlb` is harmless because that path
/// never bumps `sync_arm_gen`, so the value stored here will be
/// `<=` whatever any future sync arm publishes (and a sync waiter
/// only completes when every remote's slot is `>=` the new gen).
///
/// Intel SDM Vol 3A §5.10.4.1 (INVLPG); Vol 2A INVPCID (types 0 and 1).
pub fn tlbShootdownHandler(_: *cpu.Context) void {
    kprof.point(.tlb_shootdown, 0);
    const kind = @atomicLoad(u8, &shootdown_kind, .acquire);
    switch (kind) {
        @intFromEnum(ShootdownKind.invpcid_single) => {
            const pcid: u16 = @atomicLoad(u16, &shootdown_pcid, .acquire);
            if (cpu.pcid_enabled) {
                const desc: [2]u64 align(16) = .{ @as(u64, pcid) & 0xFFF, 0 };
                asm volatile ("invpcid (%[desc]), %[type]"
                    :
                    : [desc] "r" (&desc),
                      [type] "r" (@as(u64, 1)),
                    : .{ .memory = true });
            }
        },
        @intFromEnum(ShootdownKind.invpcid_addr) => {
            const pcid: u16 = @atomicLoad(u16, &shootdown_pcid, .acquire);
            const va: u64 = @atomicLoad(u64, &shootdown_addr, .acquire);
            if (cpu.pcid_enabled) {
                const desc: [2]u64 align(16) = .{ @as(u64, pcid) & 0xFFF, va };
                asm volatile ("invpcid (%[desc]), %[type]"
                    :
                    : [desc] "r" (&desc),
                      [type] "r" (@as(u64, 0)),
                    : .{ .memory = true });
            } else {
                cpu.invlpg(va);
            }
        },
        else => {
            // .invlpg or .invlpg_no_ack — both perform the same
            // INVLPG. The kind no longer changes the ack path; that's
            // unified into the unconditional `core_acked_gen` store
            // below.
            cpu.invlpg(@atomicLoad(u64, &shootdown_addr, .acquire));
        },
    }
    // Acknowledge the most recently published sync arm. Done
    // unconditionally — see the design note at the top of the file.
    // Acquire-load of `sync_arm_gen` pairs with the release-store in
    // `bumpSyncArmGen`, so we observe the descriptor that triggered
    // this IPI (or a later one — both are safe).
    const gen = @atomicLoad(u64, &sync_arm_gen, .acquire);
    const my_core = apic.coreID();
    @atomicStore(u64, &core_acked_gen[my_core], gen, .release);
}

/// Bump `sync_arm_gen` and return the new value. Called by sync
/// initiators while holding `shootdown_lock` and after publishing the
/// descriptor (`shootdown_kind`/`shootdown_addr`/`shootdown_pcid`) so
/// the release-store ordering pins the descriptor publication ahead
/// of the IPIs that observe the new gen. The returned value is the
/// gen the wait loop expects every remote core to reach.
inline fn bumpSyncArmGen() u64 {
    return @atomicRmw(u64, &sync_arm_gen, .Add, 1, .release) + 1;
}

/// Wait until every remote core has acked the sync arm at
/// `expected_gen` by storing it into its `core_acked_gen` slot.
/// Caller must hold `shootdown_lock`.
///
/// While spinning we explicitly keep interrupts in the caller's
/// pre-call state — we deliberately do NOT toggle them on/off here,
/// because callers from inside `switchTo`-style critical sections
/// rely on the outer IRQ-off invariant being preserved across our
/// call. The IPI handler runs CPU-side with auto-cli (Intel SDM Vol
/// 3A §6.8.1) and only touches `core_acked_gen[my_core]` plus the
/// local TLB, so it is safe even when nested inside other kernel
/// critical sections on the *remote* cores.
inline fn waitForShootdownAcks(expected_gen: u64, self_id: u64, core_count: u64) void {
    var i: u64 = 0;
    while (i < core_count) : (i += 1) {
        if (i == self_id) continue;
        while (@atomicLoad(u64, &core_acked_gen[i], .acquire) < expected_gen) {
            asm volatile ("pause" ::: .{ .memory = true });
        }
    }
}

/// Send the shootdown IPI to every remote core. Caller must hold
/// `shootdown_lock`; for sync arms the caller has also bumped
/// `sync_arm_gen` (via `bumpSyncArmGen`) to the value the wait loop
/// will expect every remote's `core_acked_gen[i]` to reach.
inline fn fanoutShootdownIpis(self_id: u64) void {
    const vec = @intFromEnum(interrupts.IntVecs.tlb_shootdown);
    for (apic.lapics.?, 0..) |la, i| {
        if (i == self_id) continue;
        apic.sendIpi(@intCast(la.apic_id), vec);
    }
}

/// Flush a virtual address from all cores' TLBs (every PCID).
///
/// Used on unmap paths where the affected address space is unknown to
/// the caller (kernel-stack teardown in `thread_kill`, where the dying
/// thread last ran on some other core).
///
/// Fire-and-forget — does NOT wait for remote acks. The synchronous
/// `flushRemotePcid` / `shootdownTlbRange` paths are reachable via
/// scheduler-internal callers (`finalizeDestroyMarkedDead` in the
/// `yieldTo` / `parkAndAwaitIRQ` IRQ-disabled critical section), and a
/// synchronous wait there is a hard SMP=4 deadlock vector: two cores
/// both reaching `unmapPage` with IRQs off would each spin on
/// `shootdown_lock` waiting for the other's ack while neither can
/// process the other's IPI. The original UAF window described below
/// remains for this single-page kernel-side unmap; cross-domain user
/// mappings shoot down through `shootdownTlbRange`, which IS waited
/// (see that function for why the IRQ-context concern doesn't
/// apply).
///
/// Intel SDM Vol 3A §5.10.4.1 (INVLPG), §5.10.5 (multiprocessor
/// invalidation propagation).
fn flushRemoteTlb(virt_addr: u64) void {
    const core_count = apic.coreCount();
    if (core_count <= 1) return;

    const self_id = apic.coreID();

    shootdown_lock.lock(@src());
    defer shootdown_lock.unlock();

    // Fire-and-forget: publish the descriptor and fan out, but do NOT
    // bump `sync_arm_gen` and do NOT wait. A handler running for this
    // IPI will store whatever `sync_arm_gen` it currently observes
    // into its `core_acked_gen` slot — that store is `<=` the value
    // any future sync arm will publish, so it cannot prematurely
    // satisfy that arm's wait. The `.invlpg_no_ack` kind selects the
    // INVLPG path in the handler dispatch (same as `.invlpg`); the
    // distinct enum value is preserved as a publication-intent marker
    // visible in a debugger.
    @atomicStore(u8, &shootdown_kind, @intFromEnum(ShootdownKind.invlpg_no_ack), .release);
    @atomicStore(u64, &shootdown_addr, virt_addr, .release);

    fanoutShootdownIpis(self_id);
}

/// Broadcast a per-PCID TLB invalidation to every remote core. Used by
/// `pcid.free` so a recycled PCID does not inherit stale TLB entries on
/// cores that previously ran the dying domain. Without this, a CD whose
/// PCID gets reused by a new domain may resolve user-half VAs to the
/// freed (and possibly already-reallocated) physical pages of the prior
/// owner — visible as random user faults / corruption mid-rep on
/// SMP > 1 once the test runner starts recycling PCIDs.
///
/// Intel SDM Vol 2A INVPCID, Vol 3A §5.10.1: type 1 (single-context
/// invalidation) flushes every TLB entry tagged with the descriptor's
/// PCID at all linear addresses; retains entries tagged with other
/// PCIDs and global entries (kernel mappings).
pub fn flushRemotePcid(pcid: u16) void {
    const core_count = apic.coreCount();
    if (core_count <= 1) return;

    const self_id = apic.coreID();

    shootdown_lock.lock(@src());
    defer shootdown_lock.unlock();

    @atomicStore(u16, &shootdown_pcid, pcid, .release);
    @atomicStore(u8, &shootdown_kind, @intFromEnum(ShootdownKind.invpcid_single), .release);
    // Publish a fresh sync-arm gen AFTER the descriptor so handlers
    // observing the new gen also observe the descriptor that
    // triggered them.
    const expected_gen = bumpSyncArmGen();

    fanoutShootdownIpis(self_id);
    waitForShootdownAcks(expected_gen, self_id, core_count);
}

/// Page-table entry for 4-level paging.
///
/// Intel SDM Vol 3A, Table 5-20 "Format of a Page-Table Entry that Maps a
/// 4-KByte Page". The same layout is used for non-leaf entries that reference
/// the next paging structure (Tables 5-15, 5-17, 5-19) with minor field
/// reinterpretation (e.g. bit 7 is PS instead of PAT in directory entries).
pub const PageEntry = packed struct(u64) {
    /// Bit 0 (P) -- Intel SDM Vol 3A, Table 5-20: must be 1 to map a page.
    present: bool = false,
    /// Bit 1 (R/W) -- Intel SDM Vol 3A, Table 5-20: if 0, writes are not allowed.
    writable: bool = false,
    /// Bit 2 (U/S) -- Intel SDM Vol 3A, Table 5-20: if 0, user-mode accesses are not allowed.
    user_accessible: bool = false,
    /// Bit 3 (PWT) -- Intel SDM Vol 3A, Table 5-20: page-level write-through.
    write_through: bool = false,
    /// Bit 4 (PCD) -- Intel SDM Vol 3A, Table 5-20: page-level cache disable.
    not_cacheable: bool = false,
    /// Bit 5 (A) -- Intel SDM Vol 3A, Table 5-20: set by hardware on access.
    accessed: bool = false,
    /// Bit 6 (D) -- Intel SDM Vol 3A, Table 5-20: set by hardware on write.
    dirty: bool = false,
    /// Bit 7 -- Intel SDM Vol 3A, Table 5-20: PAT bit for 4-KByte PTEs;
    /// Table 5-18: PS (page size) for PDEs that map 2-MByte pages.
    /// In leaf L1 entries this kernel uses it as the PAT index bit to select
    /// write-combining memory type (Section 5.9.2).
    huge_page: bool = false,
    /// Bit 8 (G) -- Intel SDM Vol 3A, Table 5-20: global; if CR4.PGE = 1,
    /// the translation is not invalidated on MOV to CR3 (Section 5.10).
    global: bool = false,
    /// Bits 10:9 -- ignored by hardware.
    ignored: u3 = 0,
    /// Bits M-1:12 -- Intel SDM Vol 3A, Table 5-20: physical address of the
    /// 4-KByte page (or next paging structure for non-leaf entries).
    addr: u40 = 0,
    _res: u11 = 0,
    /// Bit 63 (XD) -- Intel SDM Vol 3A, Table 5-20: execute-disable when
    /// IA32_EFER.NXE = 1; instruction fetches are not allowed from the page.
    not_executable: bool = false,

    pub fn setPAddr(self: *PageEntry, paddr: PAddr) void {
        std.debug.assert(std.mem.isAligned(paddr.addr, paging.PAGE4K));
        self.addr = @intCast(paddr.addr >> l1sh);
    }

    pub fn getPAddr(self: *const PageEntry) PAddr {
        const addr = @as(u64, self.addr) << l1sh;
        return PAddr.fromInt(addr);
    }
};

const default_page_entry = PageEntry{};

const page_entry_table_size = 512;

/// Level shift constants for 4-level paging linear-address translation.
///
/// Intel SDM Vol 3A, Figure 5-8 "Linear-Address Translation to a 4-KByte
/// Page Using 4-Level Paging":
///   - Bits 47:39 index the PML4 table  (l4sh = 39)
///   - Bits 38:30 index the PDPT         (l3sh = 30)
///   - Bits 29:21 index the page directory (l2sh = 21)
///   - Bits 20:12 index the page table    (l1sh = 12)
///   - Bits 11:0  are the page offset
const l4sh: u6 = 39;
const l3sh: u6 = 30;
const l2sh: u6 = 21;
const l1sh: u6 = 12;

fn l4Idx(virt: VAddr) u9 {
    return @truncate(virt.addr >> l4sh);
}

fn l3Idx(virt: VAddr) u9 {
    return @truncate(virt.addr >> l3sh);
}

fn l2Idx(virt: VAddr) u9 {
    return @truncate(virt.addr >> l2sh);
}

fn l1Idx(virt: VAddr) u9 {
    return @truncate(virt.addr >> l1sh);
}

/// Return the physical address of the current PML4 table from CR3.
///
/// Intel SDM Vol 3A, Table 5-12 "Use of CR3 with 4-Level Paging and
/// 5-Level Paging and CR4.PCIDE = 0": bits M-1:12 hold the physical
/// address of the 4-KByte aligned PML4 table.
pub fn getAddrSpaceRoot() PAddr {
    const cr3 = cpu.readCr3();
    const mask: u64 = 0xFFF;
    return PAddr.fromInt(cr3 & ~mask);
}

/// Boot-time CR3 write used by the bootloader to install the kernel
/// page-table root before CR4.PCIDE has been enabled. With PCIDE=0 the
/// CR3 source operand's PCID/no-flush bits are reserved and must be
/// clear — `swapAddrSpace` cannot be used here. Always flushes the TLB.
pub fn setKernelAddrSpace(root: PAddr) void {
    cpu.writeCr3(root.addr);
}

/// Load a new PML4 table address into CR3, switching the active address space.
///
/// With CR4.PCIDE=1, CR3 carries the per-process PCID in bits[11:0] and a
/// "preserve TLB" hint in bit 63. Setting bit 63 tells the CPU not to
/// invalidate TLB entries on this CR3 write — entries from other PCIDs
/// stay cached and are simply ignored on lookup mismatch (Intel SDM Vol 3A
/// §5.10.4.1). Combined with CR4.PGE for global kernel pages, an
/// address-space switch costs effectively zero TLB work.
pub fn swapAddrSpace(root: PAddr, id: u16) void {
    if (!cpu.pcid_enabled) {
        cpu.writeCr3(root.addr);
        return;
    }
    const pcid: u64 = @as(u64, id) & 0xFFF;
    const no_flush: u64 = @as(u64, 1) << 63;
    cpu.writeCr3((root.addr & ~@as(u64, 0xFFF)) | pcid | no_flush);
}

/// Copy the upper-half (kernel) PML4 entries from the current address space
/// into a new PML4 table. Entries 256..511 cover the kernel's virtual
/// address range (bits 47:39 >= 256, i.e. canonical high-half addresses).
///
/// Intel SDM Vol 3A, Section 5.5.4, Figure 5-8 -- bits 47:39 of the linear
/// address select the PML4 entry; the upper 256 entries map the kernel half.
pub fn copyKernelMappings(root: VAddr) void {
    const src_root_phys = getAddrSpaceRoot();
    const src_root_virt = VAddr.fromPAddr(src_root_phys, null);
    const src = src_root_virt.getPtr([*]PageEntry);
    const dst = root.getPtr([*]PageEntry);

    for (256..page_entry_table_size) |i| {
        dst[i] = src[i];
    }
}

/// Clear the lower-half (user/identity) PML4 entries and flush the TLB
/// by reloading CR3.
///
/// Intel SDM Vol 3A, Section 5.10.4.1 -- MOV to CR3 invalidates all
/// non-global TLB entries for the current PCID.
pub fn dropIdentityMapping() void {
    const root_phys = getAddrSpaceRoot();
    const root_virt = VAddr.fromPAddr(root_phys, null);
    const root = root_virt.getPtr([*]PageEntry);

    for (0..256) |i| {
        root[i] = default_page_entry;
    }

    cpu.writeCr3(root_phys.addr);
}

/// Map a 4-KByte physical page at the given virtual address.
///
/// Intel SDM Vol 3A, Section 5.5.4 "Linear-Address Translation with 4-Level
/// Paging and 5-Level Paging" -- walks PML4 -> PDPT -> PD -> PT, allocating
/// intermediate tables as needed, then writes the leaf PTE (Table 5-20).
pub fn mapPage(
    addr_space_root: PAddr,
    phys: PAddr,
    virt: VAddr,
    perms: MemoryPerms,
    kind: MappingKind,
) !void {
    kprof.point(.map_page, virt.addr);
    std.debug.assert(std.mem.isAligned(phys.addr, paging.PAGE4K));
    std.debug.assert(std.mem.isAligned(virt.addr, paging.PAGE4K));

    const pmm_mgr = &pmm.global_pmm.?;

    const attrs = kindAttrs(kind);
    if (attrs.user_accessible and virt.addr < FIRST_USER_PAGE) {
        // Spec §[address_space]: NULL guard `[0, 0x1000)` must always
        // fault. No mapping path may install a leaf into the first page,
        // even in release builds — checked unconditionally so a buggy
        // caller cannot silently install a leaf there.
        @panic("paging.mapPage: user mapping into NULL guard");
    }
    const writable = perms.write;
    const not_executable = !perms.exec;

    const parent_entry = PageEntry{
        .present = true,
        .writable = true,
        .user_accessible = attrs.user_accessible,
    };

    // For L1 leaf entries, bit 7 (huge_page) is the PAT index bit
    const leaf_entry = PageEntry{
        .present = true,
        .writable = writable,
        .user_accessible = attrs.user_accessible,
        .write_through = attrs.write_through or attrs.write_combining,
        .not_cacheable = attrs.not_cacheable,
        .huge_page = attrs.write_combining,
        .global = attrs.global,
        .not_executable = not_executable,
    };

    const root_virt = VAddr.fromPAddr(addr_space_root, null);
    var table: *[page_entry_table_size]PageEntry = @ptrFromInt(root_virt.addr);

    const walk_indices = [_]u9{ l4Idx(virt), l3Idx(virt), l2Idx(virt) };
    for (walk_indices) |idx| {
        const entry = &table[idx];
        if (!entry.present) {
            const new_page = try pmm_mgr.create(paging.PageMem(.page4k));
            const new_virt = VAddr.fromInt(@intFromPtr(new_page));
            const new_phys = PAddr.fromVAddr(new_virt, null);
            entry.* = parent_entry;
            entry.setPAddr(new_phys);
        }
        const next_virt = VAddr.fromPAddr(entry.getPAddr(), null);
        table = @ptrFromInt(next_virt.addr);
    }

    const l1_entry = &table[l1Idx(virt)];
    l1_entry.* = leaf_entry;
    l1_entry.setPAddr(phys);
}

/// Boot-time page mapping supporting 4-KByte, 2-MByte, and 1-GByte pages.
///
/// Intel SDM Vol 3A, Section 5.5.4 -- walks the paging hierarchy, with
/// early termination for huge pages (Table 5-16 for 1-GByte PDPTE with
/// PS=1, Table 5-18 for 2-MByte PDE with PS=1).
pub fn mapPageBoot(
    addr_space_root: VAddr,
    phys: PAddr,
    virt: VAddr,
    size: PageSize,
    perms: MemoryPerms,
    kind: MappingKind,
    allocator: std.mem.Allocator,
) !void {
    std.debug.assert(std.mem.isAligned(phys.addr, paging.pageAlign(size).toByteUnits()));
    std.debug.assert(std.mem.isAligned(virt.addr, paging.pageAlign(size).toByteUnits()));

    const attrs = kindAttrs(kind);
    const writable = perms.write;
    const not_executable = !perms.exec;

    const parent_entry = PageEntry{
        .present = true,
        .writable = true,
        .user_accessible = attrs.user_accessible,
    };

    // For L1 leaf entries, bit 7 (huge_page) is the PAT index bit
    const leaf_entry = PageEntry{
        .present = true,
        .writable = writable,
        .user_accessible = attrs.user_accessible,
        .write_through = attrs.write_through or attrs.write_combining,
        .not_cacheable = attrs.not_cacheable,
        .huge_page = attrs.write_combining,
        .global = attrs.global,
        .not_executable = not_executable,
    };

    const l4_idx = l4Idx(virt);
    const l3_idx = l3Idx(virt);
    const l2_idx = l2Idx(virt);
    const l1_idx = l1Idx(virt);

    var table: *[page_entry_table_size]PageEntry = @ptrFromInt(addr_space_root.addr);
    var entry = &table[l4_idx];
    var level_entry_size: PageSize = .page1g;
    const use_physmap = physmap.contains(addr_space_root.addr);

    for (0..3) |i| {
        if (!entry.present) {
            const new_entry: []align(paging.PAGE4K) PageEntry = try allocator.alignedAlloc(
                PageEntry,
                paging.pageAlign(.page4k),
                page_entry_table_size,
            );
            @memset(new_entry, default_page_entry);
            entry.* = parent_entry;

            const new_entry_virt = VAddr.fromInt(@intFromPtr(new_entry.ptr));
            var new_entry_phys: PAddr = undefined;
            if (use_physmap) {
                new_entry_phys = PAddr.fromVAddr(new_entry_virt, null);
            } else {
                new_entry_phys = PAddr.fromVAddr(new_entry_virt, 0);
            }
            entry.setPAddr(new_entry_phys);
        }

        var entry_virt: VAddr = undefined;
        if (use_physmap) {
            entry_virt = VAddr.fromPAddr(entry.getPAddr(), null);
            std.debug.assert(physmap.contains(entry_virt.addr));
        } else {
            entry_virt = VAddr.fromPAddr(entry.getPAddr(), 0);
            std.debug.assert(!physmap.contains(entry_virt.addr));
        }

        table = @ptrFromInt(entry_virt.addr);
        const idx = switch (i) {
            0 => l3_idx,
            1 => l2_idx,
            2 => l1_idx,
            else => unreachable,
        };
        entry = &table[idx];

        if (size == level_entry_size) {
            entry.* = leaf_entry;
            if (level_entry_size != .page4k) entry.huge_page = true;
            entry.setPAddr(phys);
            return;
        }

        if (i == 0) {
            level_entry_size = .page2m;
        } else if (i == 1) {
            level_entry_size = .page4k;
        }
    }
}

/// Unmap a 4-KByte page and return its physical address, or null if not mapped.
///
/// Intel SDM Vol 3A, Section 5.5.4 -- walks PML4 -> PDPT -> PD -> PT to find
/// the leaf PTE, clears it, then invalidates the local TLB with INVLPG
/// (Section 5.10.4.1) and broadcasts a shootdown IPI to remote cores
/// (Section 5.10.5).
pub fn unmapPage(
    addr_space_root: PAddr,
    virt: VAddr,
) ?PAddr {
    kprof.point(.unmap_page, virt.addr);
    const root_virt = VAddr.fromPAddr(addr_space_root, null);
    var table: *[page_entry_table_size]PageEntry = @ptrFromInt(root_virt.addr);

    const walk_indices = [_]u9{ l4Idx(virt), l3Idx(virt), l2Idx(virt) };
    for (walk_indices) |idx| {
        const entry = &table[idx];
        if (!entry.present) return null;
        if (entry.huge_page) return null;
        const next_virt = VAddr.fromPAddr(entry.getPAddr(), null);
        table = @ptrFromInt(next_virt.addr);
    }

    const l1_entry = &table[l1Idx(virt)];
    if (!l1_entry.present) return null;
    const phys = l1_entry.getPAddr();
    l1_entry.* = default_page_entry;
    cpu.invlpg(virt.addr);

    // Shoot down remote TLBs on every unmap, user-space AND kernel-space.
    //
    // The earlier version only shot down for user addresses, on the
    // assumption that kernel mappings were identical across cores and
    // therefore couldn't go stale. That assumption is wrong: when
    // `thread_kill` tears down a kernel thread (`stack.destroyKernel`),
    // it unmaps the dying thread's kernel-stack pages from the killer
    // core and frees the physical pages back to the PMM. The physical
    // pages are immediately reusable — a subsequent allocation can
    // hand them out to a completely unrelated kernel data structure.
    // Meanwhile, any OTHER core that had those old kernel-stack VAs
    // cached in its TLB (because the dying thread last ran there)
    // still translates the old VA to the now-reused physical page. If
    // that remote core touches anything in that old VA range before
    // its TLB happens to evict the entry, it reads/writes a completely
    // unrelated kernel object — silent cross-core memory corruption.
    //
    // This is the root cause of the long-standing `s2_4_9` flake. The
    // test pins a spinning worker to core 1 via `set_affinity`,
    // suspends it (cross-core IPI), then `thread_kill`s it from core 0.
    // `thread_kill` runs `deinit -> destroyKernel -> unmapPage` on
    // core 0; the worker's kernel stack pages are unmapped locally on
    // core 0 but core 1's TLB still maps them. The freed pages land
    // wherever PMM's next allocation sends them, and the resulting
    // corruption manifests as a hang on the subsequent `serial.write`
    // path in ~60% of multi-core runs.
    //
    // Paying for a remote-TLB shootdown on every unmap is fine because
    // the kernel rarely unmaps pages outside of process teardown and
    // stack destruction — both are already slow-path operations.
    flushRemoteTlb(virt.addr);

    return phys;
}

/// Variant of `unmapPage` for the capability-domain destroy path: clears
/// the leaf PTE but skips the local INVLPG and the remote-core
/// shootdown IPI. Safe because no core has the dying CD's CR3 active —
/// the calling core's own switchAddrSpace runs on its way out of
/// `scheduler.run`'s next dispatch, and other cores never used it. The
/// leaf clear lets the subsequent `freeUserAddrSpace` walk distinguish
/// PF-backed leaves (already cleared here) from singleton PMM leaves
/// (still present, freePage'd by the walk).
pub fn unmapPageNoShootdown(addr_space_root: PAddr, virt: VAddr) ?PAddr {
    const root_virt = VAddr.fromPAddr(addr_space_root, null);
    var table: *[page_entry_table_size]PageEntry = @ptrFromInt(root_virt.addr);

    const walk_indices = [_]u9{ l4Idx(virt), l3Idx(virt), l2Idx(virt) };
    for (walk_indices) |idx| {
        const entry = &table[idx];
        if (!entry.present) return null;
        if (entry.huge_page) return null;
        const next_virt = VAddr.fromPAddr(entry.getPAddr(), null);
        table = @ptrFromInt(next_virt.addr);
    }

    const l1_entry = &table[l1Idx(virt)];
    if (!l1_entry.present) return null;
    const phys = l1_entry.getPAddr();
    l1_entry.* = default_page_entry;
    return phys;
}

/// Recursively walk the 4-level paging hierarchy for the user half of the
/// address space (PML4 indices 0–255) and free all leaf pages and table pages.
/// Intel SDM Vol 3A, §4.5 "4-Level Paging and 5-Level Paging" — the hierarchy
/// is PML4 → PDPT → PD → PT; each table is a 4-KB page of 512 eight-byte
/// entries. Only PML4 entries 0–255 cover user space (canonical low half).
/// Walk the 4-level paging hierarchy and return the page-base physical
/// address mapped at the given virtual address, or null if not mapped.
///
/// Decodes huge-page leaves at L3 (1 GiB, PDPTE.PS=1) and L2 (2 MiB,
/// PDE.PS=1) so callers (e.g. `pageTableOverlaps` in vmar) don't miss
/// user-half block mappings produced by `mapPageBoot`. Returned PAddr
/// is page-base (4 KiB aligned for 4 KiB leaves; the 2 MiB / 1 GiB
/// block bases ORed with the within-block page index).
///
/// Intel SDM Vol 3A, Section 5.5.4 -- performs a software page-table walk
/// through PML4 -> PDPT -> PD -> PT (Tables 5-15, 5-17, 5-19, 5-20).
pub fn resolveVaddr(
    addr_space_root: PAddr,
    virt: VAddr,
) ?PAddr {
    const root_virt = VAddr.fromPAddr(addr_space_root, null);
    var table: *[page_entry_table_size]PageEntry = @ptrFromInt(root_virt.addr);

    // L4 (PML4): no huge-page form (1 PML4E covers 512 GiB; HW does not
    // support 512 GiB pages on current x86_64). PML4E.PS is reserved.
    const l4_entry = &table[l4Idx(virt)];
    if (!l4_entry.present) return null;
    table = @ptrFromInt(VAddr.fromPAddr(l4_entry.getPAddr(), null).addr);

    // L3 (PDPT): PS=1 → 1 GiB block leaf (Intel SDM Vol 3A, Table 5-16).
    const l3_entry = &table[l3Idx(virt)];
    if (!l3_entry.present) return null;
    if (l3_entry.huge_page) {
        const base = l3_entry.getPAddr().addr & ~@as(u64, (1 << 30) - 1);
        const within = virt.addr & ((1 << 30) - 1) & ~@as(u64, 0xFFF);
        return PAddr.fromInt(base | within);
    }
    table = @ptrFromInt(VAddr.fromPAddr(l3_entry.getPAddr(), null).addr);

    // L2 (PD): PS=1 → 2 MiB block leaf (Intel SDM Vol 3A, Table 5-18).
    const l2_entry = &table[l2Idx(virt)];
    if (!l2_entry.present) return null;
    if (l2_entry.huge_page) {
        const base = l2_entry.getPAddr().addr & ~@as(u64, (1 << 21) - 1);
        const within = virt.addr & ((1 << 21) - 1) & ~@as(u64, 0xFFF);
        return PAddr.fromInt(base | within);
    }
    table = @ptrFromInt(VAddr.fromPAddr(l2_entry.getPAddr(), null).addr);

    // L1 (PT): bit 7 is the PAT bit, NOT a PS bit — there is no L1
    // huge-page leaf (Intel SDM Vol 3A, Table 5-20).
    const l1_entry = &table[l1Idx(virt)];
    if (!l1_entry.present) return null;
    return l1_entry.getPAddr();
}

/// Map a single user 4 KiB page with cache attributes drawn from the
/// VMAR's `cch` field. Spec §[var] line 1444: 0=wb, 1=uc, 2=wc, 3=wt.
///
/// Cache attribute selection on x86_64 uses the per-PTE PAT index
/// formed by `{PAT, PCD, PWT}` (Intel SDM Vol 3A §11.12, Table 11-10);
/// in a 4 KiB leaf entry bit 7 is the PAT bit (`huge_page` field here
/// — see Table 5-20). The boot-time IA32_PAT layout
/// (`arch.x64.cpu.initPat`) is `PAT0=WB, PAT1=WT, PAT2=UC-, PAT3=UC,
/// PAT4=WB, PAT5=WC, PAT6=UC-, PAT7=UC`, so:
///   wb → {PAT,PCD,PWT}=000 → PAT0 (WB)
///   uc → {PAT,PCD,PWT}=011 → PAT3 (UC, strong-uncacheable)
///   wc → {PAT,PCD,PWT}=101 → PAT5 (WC)
///   wt → {PAT,PCD,PWT}=001 → PAT1 (WT)
pub fn mapPageSized(
    addr_space_root: PAddr,
    phys: PAddr,
    virt: VAddr,
    sz: VmarPageSize,
    cch: VmarCacheType,
    perms: MemoryPerms,
) !void {
    // v0: only 4 KiB pages supported through the VMAR-side map path.
    // 2 MiB / 1 GiB landings go through `mapPageBoot` for the kernel
    // address space; userspace VARs are spec'd over 4 KiB throughout
    // the test runner so the simple fallback covers what the runner
    // exercises.
    std.debug.assert(sz == .sz_4k);

    kprof.point(.map_page, virt.addr);
    std.debug.assert(std.mem.isAligned(phys.addr, paging.PAGE4K));
    std.debug.assert(std.mem.isAligned(virt.addr, paging.PAGE4K));

    // Spec §[address_space]: NULL guard `[0, 0x1000)` must always fault.
    // Runtime check (active in all build modes) so a buggy caller cannot
    // silently install a leaf into the first page.
    if (virt.addr < FIRST_USER_PAGE) @panic("paging.mapPageSized: NULL guard");

    const writable = perms.write;
    const not_executable = !perms.exec;

    // {PAT_bit, PCD, PWT} encoding for each cch enum value.
    const pat_bits: struct { pat: bool, pcd: bool, pwt: bool } = switch (cch) {
        .wb => .{ .pat = false, .pcd = false, .pwt = false },
        .uc => .{ .pat = false, .pcd = true, .pwt = true },
        .wc => .{ .pat = true, .pcd = false, .pwt = true },
        .wt => .{ .pat = false, .pcd = false, .pwt = true },
    };

    const parent_entry = PageEntry{
        .present = true,
        .writable = true,
        .user_accessible = true,
    };

    const leaf_entry = PageEntry{
        .present = true,
        .writable = writable,
        .user_accessible = true,
        .write_through = pat_bits.pwt,
        .not_cacheable = pat_bits.pcd,
        .huge_page = pat_bits.pat, // bit 7 = PAT in 4 KiB leaf
        .global = false,
        .not_executable = not_executable,
    };

    const pmm_mgr = &pmm.global_pmm.?;
    const root_virt = VAddr.fromPAddr(addr_space_root, null);
    var table: *[page_entry_table_size]PageEntry = @ptrFromInt(root_virt.addr);

    const walk_indices = [_]u9{ l4Idx(virt), l3Idx(virt), l2Idx(virt) };
    for (walk_indices) |idx| {
        const entry = &table[idx];
        if (!entry.present) {
            const new_page = try pmm_mgr.create(paging.PageMem(.page4k));
            const new_virt = VAddr.fromInt(@intFromPtr(new_page));
            const new_phys = PAddr.fromVAddr(new_virt, null);
            entry.* = parent_entry;
            entry.setPAddr(new_phys);
        }
        const next_virt = VAddr.fromPAddr(entry.getPAddr(), null);
        table = @ptrFromInt(next_virt.addr);
    }

    const l1_entry = &table[l1Idx(virt)];
    l1_entry.* = leaf_entry;
    l1_entry.setPAddr(phys);
}

pub fn unmapPageSized(
    addr_space_root: PAddr,
    virt: VAddr,
    sz: VmarPageSize,
) ?PAddr {
    std.debug.assert(sz == .sz_4k);
    return unmapPage(addr_space_root, virt);
}

/// Allocate a fresh PML4 table for a new capability domain. Kernel
/// mappings (entries 256..511) are copied from the current address
/// space so kernel addresses translate identically; user-half entries
/// (0..255) come up empty for the caller to populate.
///
/// Intel SDM Vol 3A, Section 5.5.4: PML4 = 4 KiB-aligned table of 512
/// PageEntry slots. Section 5.10.4: kernel-shared mappings rely on
/// CR4.PGE = 1 and PageEntry.global = 1, but the PML4 entries themselves
/// (the table pointers) must be replicated into every address-space
/// root because the L4 walk indexes them by linear address bits 47:39.
pub fn allocAddrSpaceRoot() !PAddr {
    const pmm_mgr = if (pmm.global_pmm) |*p| p else return error.OutOfMemory;
    const new_table = try pmm_mgr.create(paging.PageMem(.page4k));
    const new_virt = VAddr.fromInt(@intFromPtr(new_table));
    copyKernelMappings(new_virt);
    return PAddr.fromVAddr(new_virt, null);
}

/// Tear down the user-half of an address space root and return every
/// page reachable through PML4[0..255] to PMM:
///   - intermediate table pages (PDPT, PD, PT) — always single-page
///     PMM allocations made by `mapPage`'s on-demand walk
///   - leaf 4 KiB pages whose physical address is NOT in the
///     [skip_phys_start, skip_phys_start + skip_phys_bytes) skip range
///     (used by the caller to keep page-aliased buddy blocks alive — the
///     `mapUserTableView` path aliases the cap-domain's `user_buf` block
///     into user space, and that block is freed wholesale via
///     `pmm.freeBlock` rather than per-page)
///   - the PML4 itself
///
/// Leaves backed by VMAR-installed page_frames must already be cleared
/// (PTE.present = 0) by the caller — `destroyVmar`'s `unmapAll` does
/// this and decrements PageFrame mapcnt for each entry. Any present
/// leaves remaining at this point came from boot-side eager mappings:
///   - `mapUserStack` — 1024 pages × 4 KiB per child
///   - `loadElfSegments` — N × 4 KiB per child for ELF text/data/rodata
///   - `mapUserTableView` — aliases `user_buf` (skipped via skip range)
///
/// PML4 indices 256..511 are kernel-shared (per `copyKernelMappings`)
/// and are NEVER touched by this walk — the kernel half lives until
/// shutdown.
///
/// Intel SDM Vol 3A §5.5.4: each table is 512 PageEntry slots; entries
/// 0–255 cover the canonical low half (user). PT entries are leaf
/// PTEs; PDPT/PD entries are non-leaf when `huge_page == 0`. Huge-page
/// leaves at L3/L2 are not produced by the user-side mapping path
/// (mapPage hard-codes 4 KiB walks) but defensive checks below keep
/// the recursion correct if a future patch lands one.
pub fn freeUserAddrSpace(
    root: PAddr,
    skip1_start: u64,
    skip1_bytes: u64,
    skip2_start: u64,
    skip2_bytes: u64,
) void {
    const pmm_mgr = if (pmm.global_pmm) |*p| p else return;
    const root_virt = VAddr.fromPAddr(root, null);
    const pml4: *[page_entry_table_size]PageEntry = @ptrFromInt(root_virt.addr);

    var i: usize = 0;
    while (i < 256) : (i += 1) {
        const entry = &pml4[i];
        if (!entry.present) continue;
        if (entry.huge_page) {
            // 1 GiB leaf at PML4 — not produced today, but if it ever
            // is, treat as a leaf and free per skip-range.
            const phys = entry.getPAddr().addr;
            entry.* = default_page_entry;
            if (!leafSkipped(phys, skip1_start, skip1_bytes, skip2_start, skip2_bytes)) {
                pmm_mgr.freePage(physToPagePtr(phys));
            }
            continue;
        }
        freePdpt(pmm_mgr, entry.getPAddr(), skip1_start, skip1_bytes, skip2_start, skip2_bytes);
        entry.* = default_page_entry;
    }

    // Deliberately do NOT free the PML4 root here — it is still the
    // active CR3 on the calling core until the next dispatch swaps
    // address space. Freeing it inline would let PMM hand the page
    // out to another allocator, whose write would corrupt the live
    // page-table walk on this core. The kernel-half (entries 256..511)
    // remains intact for kernel-mode references; the user-half is now
    // empty so no future user TLB miss can walk into freed pages. The
    // 4 KiB leak is reaped at the next reuse of the addr_space_id /
    // PCID (which currently never happens — see allocAddrSpaceRoot
    // doc) — addressable later by deferring the free until after a
    // CR3 swap, e.g. via a per-core "pending PML4 free" slot drained
    // by `loadEcContextAndReturn`.
}

fn freePdpt(pmm_mgr: *pmm.PhysicalMemoryManager, pdpt_phys: PAddr, skip1_start: u64, skip1_bytes: u64, skip2_start: u64, skip2_bytes: u64) void {
    const pdpt_virt = VAddr.fromPAddr(pdpt_phys, null);
    const pdpt: *[page_entry_table_size]PageEntry = @ptrFromInt(pdpt_virt.addr);
    var i: usize = 0;
    while (i < page_entry_table_size) : (i += 1) {
        const entry = &pdpt[i];
        if (!entry.present) continue;
        if (entry.huge_page) {
            const phys = entry.getPAddr().addr;
            entry.* = default_page_entry;
            if (!leafSkipped(phys, skip1_start, skip1_bytes, skip2_start, skip2_bytes)) {
                pmm_mgr.freePage(physToPagePtr(phys));
            }
            continue;
        }
        freePd(pmm_mgr, entry.getPAddr(), skip1_start, skip1_bytes, skip2_start, skip2_bytes);
        entry.* = default_page_entry;
    }
    pmm_mgr.freePage(@as([*]u8, @ptrFromInt(pdpt_virt.addr)));
}

fn freePd(pmm_mgr: *pmm.PhysicalMemoryManager, pd_phys: PAddr, skip1_start: u64, skip1_bytes: u64, skip2_start: u64, skip2_bytes: u64) void {
    const pd_virt = VAddr.fromPAddr(pd_phys, null);
    const pd: *[page_entry_table_size]PageEntry = @ptrFromInt(pd_virt.addr);
    var i: usize = 0;
    while (i < page_entry_table_size) : (i += 1) {
        const entry = &pd[i];
        if (!entry.present) continue;
        if (entry.huge_page) {
            // 2 MiB leaf at L2.
            const phys = entry.getPAddr().addr;
            entry.* = default_page_entry;
            if (!leafSkipped(phys, skip1_start, skip1_bytes, skip2_start, skip2_bytes)) {
                pmm_mgr.freePage(physToPagePtr(phys));
            }
            continue;
        }
        freePt(pmm_mgr, entry.getPAddr(), skip1_start, skip1_bytes, skip2_start, skip2_bytes);
        entry.* = default_page_entry;
    }
    pmm_mgr.freePage(@as([*]u8, @ptrFromInt(pd_virt.addr)));
}

fn freePt(pmm_mgr: *pmm.PhysicalMemoryManager, pt_phys: PAddr, skip1_start: u64, skip1_bytes: u64, skip2_start: u64, skip2_bytes: u64) void {
    const pt_virt = VAddr.fromPAddr(pt_phys, null);
    const pt: *[page_entry_table_size]PageEntry = @ptrFromInt(pt_virt.addr);
    var i: usize = 0;
    while (i < page_entry_table_size) : (i += 1) {
        const entry = &pt[i];
        if (!entry.present) continue;
        const phys = entry.getPAddr().addr;
        entry.* = default_page_entry;
        if (!leafSkipped(phys, skip1_start, skip1_bytes, skip2_start, skip2_bytes)) {
            pmm_mgr.freePage(physToPagePtr(phys));
        }
    }
    pmm_mgr.freePage(@as([*]u8, @ptrFromInt(pt_virt.addr)));
}

inline fn leafSkipped(phys: u64, s1: u64, n1: u64, s2: u64, n2: u64) bool {
    if (n1 != 0 and phys >= s1 and phys < s1 + n1) return true;
    if (n2 != 0 and phys >= s2 and phys < s2 + n2) return true;
    return false;
}

inline fn physToPagePtr(phys: u64) [*]u8 {
    return @ptrFromInt(VAddr.fromPAddr(.{ .addr = phys }, null).addr);
}

/// Per-PCID, per-VA shootdown over a contiguous range. Each iteration
/// publishes a fresh `(pcid, va)` request, fans out IPIs to every remote
/// core, and waits for every remote to ack before publishing the next
/// request. Without the wait, a fire-and-forget loop overwrites the
/// shared descriptor while remote cores are still mid-handler against
/// the prior descriptor — the second IPI may even coalesce in the LAPIC
/// IRR (one pending interrupt for the remote vector at a time), so only
/// the *last* descriptor in the loop is observed by remote cores. That
/// is the cross-core UAF window on unmap+free races.
///
/// `addr_space_id` is threaded through so remote cores execute INVPCID
/// type 0 (single-PCID, single-address) when PCIDs are enabled — without
/// the PCID, a remote core that later reloads CR3 with the dying AS's
/// PCID would walk into stale TLB entries, since INVLPG only flushes
/// the *current* CR3's translations.
///
/// Intel SDM Vol 3A §5.10.4.1 (INVLPG), Vol 2A INVPCID, §5.10.5
/// (multiprocessor invalidation).
pub fn shootdownTlbRange(
    addr_space_id: u16,
    virt: VAddr,
    sz: VmarPageSize,
    page_count: u32,
) void {
    std.debug.assert(sz == .sz_4k);
    if (page_count == 0) return;

    const core_count = apic.coreCount();
    const remote_count: u32 = if (core_count > 1) @intCast(core_count - 1) else 0;
    const self_id = if (remote_count != 0) apic.coreID() else 0;

    // Local invalidation always runs (the calling core may itself hold
    // a stale TLB entry). Remote shootdown only when there is more than
    // one core online.
    var i: u32 = 0;
    while (i < page_count) : (i += 1) {
        cpu.invlpg(virt.addr + @as(u64, i) * paging.PAGE4K);
    }
    if (remote_count == 0) return;

    shootdown_lock.lock(@src());
    defer shootdown_lock.unlock();

    const kind: ShootdownKind = if (cpu.pcid_enabled) .invpcid_addr else .invlpg;
    @atomicStore(u16, &shootdown_pcid, addr_space_id, .release);

    var j: u32 = 0;
    while (j < page_count) : (j += 1) {
        const va = virt.addr + @as(u64, j) * paging.PAGE4K;
        @atomicStore(u64, &shootdown_addr, va, .release);
        @atomicStore(u8, &shootdown_kind, @intFromEnum(kind), .release);
        // Bump the sync-arm gen AFTER publishing the descriptor so a
        // handler observing the new gen also observes (va, kind).
        const expected_gen = bumpSyncArmGen();

        fanoutShootdownIpis(self_id);
        waitForShootdownAcks(expected_gen, self_id, core_count);
    }
}

