const std = @import("std");
const stygia = @import("stygia");

const apic = stygia.arch.x64.apic;
const cpu = stygia.arch.x64.cpu;
const interrupts = stygia.arch.x64.interrupts;
const kprof = stygia.kprof.trace_id;
const paging = stygia.memory.paging;
const physmap = stygia.memory.address.AddrSpacePartition.physmap;
const pmm = stygia.memory.pmm;

const MappingKind = stygia.memory.address.MappingKind;
const MemoryPerms = stygia.memory.address.MemoryPerms;
const PAddr = stygia.memory.address.PAddr;
const PageSize = stygia.memory.paging.PageSize;
const SpinLock = stygia.utils.sync.SpinLock;
const VAddr = stygia.memory.address.VAddr;
const VmarCacheType = stygia.memory.vmar.CacheType;
const VmarPageSize = stygia.memory.vmar.PageSize;

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
/// Three shootdown modes co-exist on top of `shootdown_lock`:
///
///   1. **Synchronous descriptor** (`shootdownTlbRange`): the initiator
///      holds `shootdown_lock`, publishes the request descriptor
///      (kind/addr/pcid), bumps `sync_arm_gen` to a fresh value, fans
///      out IPIs, then spins until every remote core's
///      `core_acked_gen[i] >= sync_arm_gen` before releasing the lock
///      or publishing the next descriptor. The remote IPI handler
///      performs the requested invalidation and stores the current
///      `sync_arm_gen` into its own `core_acked_gen[my_core]` slot.
///      This is the Linux-style "send-then-wait" pattern — without
///      it, a per-page loop that overwrites the shared descriptor
///      between IPIs leaves remote cores executing INVPCID against
///      the *next* descriptor instead of the one they were summoned
///      for, leaking stale TLB entries (cross-core UAF on unmap+free
///      races). The syscall-side range-teardown path runs with
///      interrupts enabled, so the wait is safe.
///
///   2. **Fire-and-forget descriptor** (`flushRemoteTlb`, single-page):
///      the initiator holds the lock, publishes a `.invlpg_no_ack`
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
///   3. **Fire-and-forget per-PCID queue** (`flushRemotePcid`): same
///      IRQ-off-deadlock concern as mode (2), but PCID free has the
///      additional Invariant 3 constraint (a recycled PCID must not
///      inherit stale TLB entries on any core), so the descriptor's
///      "stale handler reads new descriptor" hazard from
///      back-to-back arms cannot just be tolerated as a wasted INVLPG.
///      Instead the protocol uses a per-(core, pcid) bitmap that
///      survives across descriptor multiplexing (a stale IPI from arm
///      A drains arm A's bit on this core regardless of what arm B has
///      published since), with the allocator's bitmap-clear gated on
///      every remote ack landing. See the `Fire-and-forget per-PCID
///      shootdown queue` block further down.
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
    /// Whole-TLB invalidation INCLUDING global pages. The only kind
    /// that reaches kernel mappings, which are installed global
    /// (`kindAttrs(.kernel_data)`). Carries no address — one arm
    /// covers an arbitrary kernel range, which is what the kernel-stack
    /// teardown needs (see `publishKernelUnmapEpoch`).
    flush_all_global = 4,
};
var shootdown_kind: u8 = @intFromEnum(ShootdownKind.invlpg);
var shootdown_pcid: u16 = 0;

/// False until every AP has signalled online. Gates the ONLY shootdown
/// path that both waits for acks and is reachable during bring-up
/// (`publishKernelUnmapEpoch`, via `stack.destroyKernel` on a failed AP
/// stack mapping). `apic.coreCount()` counts discovered LAPICs, so an
/// ack-wait armed before `smpInit` returns would block on cores that
/// have not been started yet.
var remote_shootdown_armed: bool = false;

/// Called by `smpInit` once every AP has signalled online.
pub fn armRemoteShootdown() void {
    @atomicStore(bool, &remote_shootdown_armed, true, .release);
}

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

// ── Fire-and-forget per-PCID shootdown queue ────────────────────────────
//
// `flushRemotePcid` cannot use the descriptor-and-wait pattern of the
// other sync paths above. It is reachable from `pcid.free` →
// `freeAddrSpaceId` → `caps.destroyPhase2`, which masks IRQs across the
// entire phase-2 body so the dying domain's frame cannot be preempted
// and abandoned. With smp ≥ 2 and a destroy storm, two cores can be
// inside `destroyPhase2` simultaneously; each spinning in
// `waitForShootdownAcks` cannot deliver the other's INVPCID IPI — hard
// SMP deadlock (bd-vzdh, 2026-05-10). Same hazard class as the
// `flushRemoteTlb` comment above, but PCID-free has the extra constraint
// of Invariant 3 (a recycled PCID must not inherit stale TLB entries on
// any core), so we cannot simply fire-and-forget and call it done.
//
// The fix replaces the synchronous wait with a deferred-ack protocol:
//
//   1. `flushRemotePcid` marks the freed PCID's bit in each remote core's
//      `per_core_pcid_pending` row, sets `pcid_acks_remaining[pcid]` to
//      a one-bit-per-remote-core mask, sets the pcid's bit in
//      `pcid_pending_free_mask`, then fans out IPIs without waiting.
//   2. The IPI handler (after its existing descriptor dispatch)
//      atomically swaps its row of `per_core_pcid_pending` to zero,
//      issues INVPCID type 1 for each set bit, and clears its core's
//      bit in `pcid_acks_remaining[pcid]`.
//   3. The PCID-bitmap allocator (`pcid.allocate`) drains the pending-
//      free list before each allocation: any pcid with
//      `pcid_acks_remaining == 0` has been flushed on every remote core
//      and may safely be returned to the bitmap.
//
// The pending bitmap is keyed per-(core, pcid) rather than the existing
// shared descriptor because two free()s back-to-back would otherwise
// race on the descriptor — the second's publish would overwrite the
// first's pcid before stale handlers (on cores that were IRQ-off during
// the first fanout) had a chance to read it. A shared descriptor only
// works when the protocol holds the lock through the wait, which is
// exactly what destroyPhase2's IRQ-off window forbids.
//
// Sizing: 4096 PCIDs / 64 = 64 u64s per core; 64 cores → 32 KiB BSS for
// `per_core_pcid_pending`. `pcid_acks_remaining` is 4096 × 8 = 32 KiB.
// `pcid_pending_free_mask` is 64 × 8 = 512 B. ~64 KiB total.

/// Number of u64 words to cover all 4096 possible PCIDs as a bitmap.
/// Mirrors the `pcid_count` / `word_bits` arithmetic in `pcid.zig`; the
/// constants must agree (the bitmap key is a raw PCID id with no remap).
const PCID_PENDING_WORDS: usize = 4096 / 64;

/// Per-(core, pcid) pending-INVPCID bitmap. Producer: `flushRemotePcid`
/// (sets bits while holding `shootdown_lock`). Consumer: the IPI handler
/// on the remote core atomic-swaps its row to zero and INVPCIDs every
/// bit observed.
var per_core_pcid_pending: [MAX_CORES][PCID_PENDING_WORDS]u64 =
    [_][PCID_PENDING_WORDS]u64{[_]u64{0} ** PCID_PENDING_WORDS} ** MAX_CORES;

/// Per-pcid mask of remote cores whose `per_core_pcid_pending` bit for
/// this pcid has not yet been cleared by a handler. Bit `i` set ⇒ core
/// `i` still owes an INVPCID ack. Set by `flushRemotePcid` to the
/// running-cores mask (excluding self); cleared bit-by-bit by the
/// handler. When this reaches zero the pcid is fully drained on every
/// remote core; the allocator's drain pass then clears the bitmap bit.
var pcid_acks_remaining: [4096]u64 = [_]u64{0} ** 4096;

/// Bitmap of pcids that are pending-free (awaiting drain). Set by
/// `flushRemotePcid`, cleared by the allocator's drain pass once
/// `pcid_acks_remaining[id]` has dropped to zero. Distinguishes
/// "currently allocated by a live domain" from "pending-free, drainable"
/// — the allocator's bitmap bit alone cannot tell them apart.
var pcid_pending_free_mask: [PCID_PENDING_WORDS]u64 =
    [_]u64{0} ** PCID_PENDING_WORDS;

/// Drain this core's pending-INVPCID row. Called from the IPI handler
/// after the descriptor-dispatched invalidation. Atomically swaps the
/// row to zero so we observe a stable snapshot, then INVPCIDs each set
/// bit and clears our core's bit in the per-pcid acks-remaining mask.
/// Producers that set new bits between our swap and the per-pcid mask
/// clear will be picked up by the next IPI delivery (every
/// `flushRemotePcid` arm sends a fresh IPI before releasing the
/// shootdown lock).
fn drainLocalPendingPcid(my_core: u64) void {
    const my_bit: u64 = @as(u64, 1) << @intCast(my_core);
    var w: usize = 0;
    while (w < PCID_PENDING_WORDS) : (w += 1) {
        const word = @atomicRmw(u64, &per_core_pcid_pending[my_core][w], .Xchg, 0, .acq_rel);
        if (word == 0) continue;
        var bits = word;
        while (bits != 0) {
            const b: u6 = @intCast(@ctz(bits));
            const id: u16 = @intCast(w * 64 + @as(usize, b));
            if (cpu.pcid_enabled) {
                // Sequential field stores avoid any aggregate movups
                // codegen (the kernel build has SSE disabled —
                // `+soft_float-sse-sse2`).
                var desc: [2]u64 align(16) = undefined;
                desc[0] = @as(u64, id) & 0xFFF;
                desc[1] = 0;
                asm volatile ("invpcid (%[desc]), %[type]"
                    :
                    : [desc] "r" (&desc),
                      [type] "r" (@as(u64, 1)),
                    : .{ .memory = true });
            }
            _ = @atomicRmw(u64, &pcid_acks_remaining[id], .And, ~my_bit, .release);
            bits &= ~(@as(u64, 1) << b);
        }
    }
}

/// Read a word of `pcid_pending_free_mask` for the allocator's drain
/// pass. `pcid.allocate` iterates all words and looks for set bits whose
/// `pcid_acks_remaining` has reached zero.
pub fn pcidPendingFreeMaskWord(w_idx: u16) u64 {
    return @atomicLoad(u64, &pcid_pending_free_mask[w_idx], .acquire);
}

/// Read `pcid_acks_remaining[id]`. Zero ⇒ every remote core has flushed
/// its TLB entries tagged with `id` since the last `flushRemotePcid(id)`,
/// so the id may safely be returned to the allocator's bitmap.
pub fn pcidAcksRemaining(id: u16) u64 {
    return @atomicLoad(u64, &pcid_acks_remaining[id], .acquire);
}

/// Atomically clear `id`'s bit in `pcid_pending_free_mask`. Called by
/// the allocator's drain pass once a pending-free pcid has had every
/// remote ack land.
pub fn clearPcidPendingFreeBit(id: u16) void {
    const w_idx: usize = @as(usize, id) / 64;
    const b: u6 = @intCast(@as(usize, id) % 64);
    _ = @atomicRmw(u64, &pcid_pending_free_mask[w_idx], .And, ~(@as(u64, 1) << b), .release);
}

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
    const my_core = apic.coreID();
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
        @intFromEnum(ShootdownKind.flush_all_global) => {
            cpu.flushTlbIncludingGlobal();
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
    // Drain any pending fire-and-forget per-PCID INVPCIDs queued by
    // `flushRemotePcid`. Decoupled from `shootdown_kind` because PCID
    // free is reachable from IRQ-off destroy critical sections, where
    // the descriptor-and-wait protocol would deadlock; the per-(core,
    // pcid) bitmap lets the producer fire-and-forget without losing
    // shootdowns to descriptor multiplexing across back-to-back arms.
    drainLocalPendingPcid(my_core);
    // Acknowledge the most recently published sync arm. Done
    // unconditionally — see the design note at the top of the file.
    // Acquire-load of `sync_arm_gen` pairs with the release-store in
    // `bumpSyncArmGen`, so we observe the descriptor that triggered
    // this IPI (or a later one — both are safe).
    const gen = @atomicLoad(u64, &sync_arm_gen, .acquire);
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

/// Service any pending sync arm from OUTSIDE the lock, using a
/// conservative whole-TLB flush. The descriptor
/// (`shootdown_kind`/`addr`/`pcid`) is only stable under
/// `shootdown_lock`, so a spinning contender cannot decode it — but
/// over-flushing is always safe, and the ack contract requires that
/// this core's TLB holds no stale entry for ANY descriptor at or
/// below the acked gen. Also drains the fire-and-forget per-PCID
/// queue, mirroring `tlbShootdownHandler`.
///
/// The flush MUST include global pages. This used INVPCID type 3
/// ("all-context, EXCLUDING globals") / a CR3 reload (which also
/// preserves globals under CR4.PGE), which is a superset of every
/// *user* descriptor but reaches no kernel mapping at all — and kernel
/// mappings are exactly what `kindAttrs(.kernel_data)` installs global.
/// A `flush_all_global` arm (kernel-stack teardown) acked that way
/// would be acknowledged without the stale kernel translation ever
/// being dropped, which is precisely the lie the ack protocol exists to
/// prevent.
fn ackPendingSyncArmConservative(my_core: u64) void {
    const armed = @atomicLoad(u64, &sync_arm_gen, .acquire);
    if (@atomicLoad(u64, &core_acked_gen[my_core], .monotonic) >= armed) {
        drainLocalPendingPcid(my_core);
        return;
    }
    cpu.flushTlbIncludingGlobal();
    drainLocalPendingPcid(my_core);
    @atomicStore(u64, &core_acked_gen[my_core], armed, .release);
}

/// Public spin-loop service hook: acknowledge any pending sync TLB
/// arm with a conservative full non-global flush. Called from the
/// generic lock spin loops (SpinLock / GenLock) between acquisition
/// attempts, because the shootdown-ack deadlock is NOT specific to
/// `shootdown_lock` contention: ANY IRQs-masked spin on ANY lock
/// whose holder is (transitively) inside `waitForShootdownAcks`
/// wedges the machine — captured live (stygia-rs6 mechanism 9) as a
/// #PF handler spinning IRQs-off on a CapabilityDomain gen-lock
/// while the lock's holder ran `capability.delete` → `destroyVmar`
/// → `unmapAll` → sync shootdown, waiting for the spinner's ack.
/// Cheap when idle: one shared-cacheline load and compare.
pub fn serviceTlbArmsWhileSpinning() void {
    ackPendingSyncArmConservative(apic.coreID());
}

/// Acquire `shootdown_lock` while staying responsive to concurrent
/// sync arms. The blind `shootdown_lock.lock()` deadlocks: a core
/// spinning here with IRQs masked (destroyPhase2's `freeAddrSpaceId`
/// → `flushRemotePcid`) cannot take the shootdown IPI, while the
/// current holder sits in `waitForShootdownAcks` waiting for exactly
/// this core's ack (stygia-rs6, captured live: core 0 IRQs-off in
/// this spin, core 1 holding the lock waiting on core 0, both RDY
/// test ECs stranded behind them). Servicing arms between attempts
/// is the standard IPI-vs-spinlock discipline; it is correct for
/// IRQs-on contenders too (the IPI handler acking concurrently is
/// idempotent — both store the latest gen).
fn lockShootdownServicingArms(src: std.builtin.SourceLocation) void {
    const my_core = apic.coreID();
    while (!shootdown_lock.tryLock(src)) {
        ackPendingSyncArmConservative(my_core);
        std.atomic.spinLoopHint();
    }
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
            stygia.utils.spin_diag.note(.shootdown_ack, i);
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

    lockShootdownServicingArms(@src());
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

/// Queue a per-PCID TLB invalidation for every remote core. Used by
/// `pcid.free` so a recycled PCID does not inherit stale TLB entries on
/// cores that previously ran the dying domain. Without this, a CD whose
/// PCID gets reused by a new domain may resolve user-half VAs to the
/// freed (and possibly already-reallocated) physical pages of the prior
/// owner — visible as random user faults / corruption mid-rep on
/// SMP > 1 once the test runner starts recycling PCIDs.
///
/// Fire-and-forget: marks `pcid` pending on every remote core's
/// `per_core_pcid_pending` row, sets `pcid_acks_remaining[pcid]` to the
/// running-cores mask (excluding self), sets the pending-free bit, and
/// fans out IPIs without spinning. Reachable from `pcid.free` →
/// `freeAddrSpaceId` → `caps.destroyPhase2`'s IRQ-off window, where a
/// synchronous wait deadlocks under smp ≥ 2 destroy storms (bd-vzdh).
/// The PCID does not return to `pcid.allocate`'s bitmap until every
/// remote core has serviced its queued INVPCID and cleared its bit in
/// `pcid_acks_remaining[pcid]` — the allocator's drain pass enforces
/// that gate, preserving Invariant 3 (PCID free order vs. recycled-id
/// stale-TLB UAF).
///
/// Intel SDM Vol 2A INVPCID, Vol 3A §5.10.1: type 1 (single-context
/// invalidation) flushes every TLB entry tagged with the descriptor's
/// PCID at all linear addresses; retains entries tagged with other
/// PCIDs and global entries (kernel mappings).
pub fn flushRemotePcid(pcid: u16) void {
    const w_idx: usize = @as(usize, pcid) / 64;
    const bit_pos: u6 = @intCast(@as(usize, pcid) % 64);
    const bit_mask: u64 = @as(u64, 1) << bit_pos;

    const core_count = apic.coreCount();
    if (core_count <= 1) {
        // No remotes ⇒ no IPI to send. Mark pending-free with zero
        // outstanding acks so `pcid.free`'s fast path / `pcid.allocate`'s
        // drain can finalize the bitmap clear uniformly across smp=1
        // and smp>1.
        _ = @atomicRmw(u64, &pcid_pending_free_mask[w_idx], .Or, bit_mask, .release);
        return;
    }

    const self_id = apic.coreID();

    // Build the running-remote-cores mask. `apic.lapics.?` enumerates
    // every booted core including self; exclude self.
    var remote_mask: u64 = 0;
    for (apic.lapics.?, 0..) |_, i| {
        if (i == self_id) continue;
        remote_mask |= @as(u64, 1) << @intCast(i);
    }
    if (remote_mask == 0) {
        _ = @atomicRmw(u64, &pcid_pending_free_mask[w_idx], .Or, bit_mask, .release);
        return;
    }

    lockShootdownServicingArms(@src());
    defer shootdown_lock.unlock();

    // Order matters under concurrent handler runs (a stale IPI from a
    // prior arm racing with this publish):
    //   (1) acks_remaining first — establishes the per-pcid mask before
    //       any handler can observe and clear its bit.
    //   (2) per-core pending bits — once visible, a handler running
    //       (for our or any other IPI) may drain and clear acks.
    //   (3) pending_free bit — the allocator-drain gate. Must follow
    //       acks_remaining so a concurrent drain reading
    //       pending_free=set then loading acks_remaining sees the
    //       non-zero mask (release/acquire across handlers' atomicAnd).
    //   (4) IPI fanout — wakes remote handlers; subsequent handler runs
    //       will service whatever is in their pending row.
    @atomicStore(u64, &pcid_acks_remaining[pcid], remote_mask, .release);
    for (apic.lapics.?, 0..) |_, i| {
        if (i == self_id) continue;
        _ = @atomicRmw(u64, &per_core_pcid_pending[i][w_idx], .Or, bit_mask, .release);
    }
    _ = @atomicRmw(u64, &pcid_pending_free_mask[w_idx], .Or, bit_mask, .release);

    fanoutShootdownIpis(self_id);
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

    // The bit-field declarations below are part of the architectural
    // x86-64 4-level paging PTE layout (Intel SDM Vol 3A, Table 5-20)
    // and MUST remain in this `packed struct(u64)` to preserve binary-
    // correct encoding of every other field. They are unused at the
    // source level today (the kernel does not consume the hardware-set
    // dirty bit, never writes the architectural ignored bits 11:9, and
    // emits no descriptors with the upper reserved range non-zero), so
    // the dead-code analyzer would otherwise flag them. Reference them
    // in a comptime no-op so the analyzer's `.<ident>` token heuristic
    // keeps them alive without affecting codegen.
    comptime {
        _ = PageEntry{
            .dirty = false,
            .ignored = 0,
            ._res = 0,
        };
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
        // Intermediate-entry install must be atomic. Two cores mapping
        // DIFFERENT VAs that happen to share a parent table both see the
        // slot empty, both allocate, and — with a plain check-then-store
        // — both publish. The loser then keeps walking into the table IT
        // allocated, which is no longer referenced by the tree, installs
        // its leaf there and returns success. The mapping silently does
        // not exist; it resurfaces arbitrarily later as a wild address,
        // and the orphaned table page leaks.
        //
        // Invisible until the suite actually ran on more than one core:
        // `affinity = 0` put every test EC on the runner's core, so no
        // two mappers ever overlapped. `-Dspread_cores` is what exposed
        // it. `mapPageBoot` is deliberately left alone — single-core by
        // construction.
        //
        // An absent entry is all-zero — every clear site writes
        // `default_page_entry` (= `PageEntry{}`), and `PageEntry` is a
        // `packed struct(u64)` whose fields all default to false/0 — so
        // 0 is the correct compare value.
        const slot: *u64 = @ptrCast(@alignCast(entry));
        var cur = @atomicLoad(u64, slot, .acquire);
        if (cur == 0) {
            const new_page = try pmm_mgr.create(paging.PageMem(.page4k));
            const new_virt = VAddr.fromInt(@intFromPtr(new_page));
            const new_phys = PAddr.fromVAddr(new_virt, null);
            // Compose the full descriptor BEFORE the single 8-byte
            // store. The previous two-store sequence (install entry,
            // then setPAddr) left a transient PRESENT table entry
            // pointing at phys 0; hardware page walks are asynchronous
            // and the paging-structure caches may capture the bogus
            // intermediate, after which every sibling VA under this
            // table persistently faults against a stale cached walk
            // even though memory holds the corrected entry
            // (stygia-rs6 mechanism 8 — the aarch64 twin of this
            // pattern was implicated in eternal translation-fault
            // loops on a Pi 5 / KVM-6.6 host). The cmpxchg keeps that
            // single-store publication intact.
            var filled_parent = parent_entry;
            filled_parent.setPAddr(new_phys);
            const want: u64 = @bitCast(filled_parent);
            if (@cmpxchgStrong(u64, slot, 0, want, .release, .acquire)) |winner| {
                // Lost the race. Hand the orphan back and follow the
                // winner's table — the walk is correct either way.
                pmm_mgr.destroy(new_page);
                cur = winner;
            } else {
                cur = want;
            }
        }
        // Whatever we ended up with — ours or the winner's — must be a
        // live table pointer. Asserting keeps the "absent ⟺ zero"
        // invariant honest instead of silently walking into garbage if
        // some future clear site starts leaving stale bits behind.
        const cur_entry: PageEntry = @bitCast(cur);
        std.debug.assert(cur_entry.present);
        const next_virt = VAddr.fromPAddr(cur_entry.getPAddr(), null);
        table = @ptrFromInt(next_virt.addr);
    }

    const l1_entry = &table[l1Idx(virt)];
    // Single-store leaf install — same transient-phys-0 hazard as the
    // parent-entry sites above.
    var filled_leaf = leaf_entry;
    filled_leaf.setPAddr(phys);
    l1_entry.* = filled_leaf;
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

            const new_entry_virt = VAddr.fromInt(@intFromPtr(new_entry.ptr));
            var new_entry_phys: PAddr = undefined;
            if (use_physmap) {
                new_entry_phys = PAddr.fromVAddr(new_entry_virt, null);
            } else {
                new_entry_phys = PAddr.fromVAddr(new_entry_virt, 0);
            }
            // Single-store descriptor install (stygia-rs6 mechanism 8):
            // the old two-store sequence left a WIDE transient window
            // (address computed between the stores) with a PRESENT
            // table entry pointing at phys 0 — poisonable by the
            // paging-structure caches when this runs with paging live
            // (AP bring-up). See the aarch64 mapPageBoot twin.
            var filled_parent = parent_entry;
            filled_parent.setPAddr(new_entry_phys);
            entry.* = filled_parent;
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
            // Single-store leaf install — see the parent-entry comment
            // above (stygia-rs6 mechanism 8).
            var filled_leaf = leaf_entry;
            if (level_entry_size != .page4k) filled_leaf.huge_page = true;
            filled_leaf.setPAddr(phys);
            entry.* = filled_leaf;
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
        // Intermediate-entry install must be atomic. Two cores mapping
        // DIFFERENT VAs that happen to share a parent table both see the
        // slot empty, both allocate, and — with a plain check-then-store
        // — both publish. The loser then keeps walking into the table IT
        // allocated, which is no longer referenced by the tree, installs
        // its leaf there and returns success. The mapping silently does
        // not exist; it resurfaces arbitrarily later as a wild address,
        // and the orphaned table page leaks.
        //
        // Invisible until the suite actually ran on more than one core:
        // `affinity = 0` put every test EC on the runner's core, so no
        // two mappers ever overlapped. `-Dspread_cores` is what exposed
        // it. `mapPageBoot` is deliberately left alone — single-core by
        // construction.
        //
        // An absent entry is all-zero — every clear site writes
        // `default_page_entry` (= `PageEntry{}`), and `PageEntry` is a
        // `packed struct(u64)` whose fields all default to false/0 — so
        // 0 is the correct compare value.
        const slot: *u64 = @ptrCast(@alignCast(entry));
        var cur = @atomicLoad(u64, slot, .acquire);
        if (cur == 0) {
            const new_page = try pmm_mgr.create(paging.PageMem(.page4k));
            const new_virt = VAddr.fromInt(@intFromPtr(new_page));
            const new_phys = PAddr.fromVAddr(new_virt, null);
            // Compose the full descriptor BEFORE the single 8-byte
            // store. The previous two-store sequence (install entry,
            // then setPAddr) left a transient PRESENT table entry
            // pointing at phys 0; hardware page walks are asynchronous
            // and the paging-structure caches may capture the bogus
            // intermediate, after which every sibling VA under this
            // table persistently faults against a stale cached walk
            // even though memory holds the corrected entry
            // (stygia-rs6 mechanism 8 — the aarch64 twin of this
            // pattern was implicated in eternal translation-fault
            // loops on a Pi 5 / KVM-6.6 host). The cmpxchg keeps that
            // single-store publication intact.
            var filled_parent = parent_entry;
            filled_parent.setPAddr(new_phys);
            const want: u64 = @bitCast(filled_parent);
            if (@cmpxchgStrong(u64, slot, 0, want, .release, .acquire)) |winner| {
                // Lost the race. Hand the orphan back and follow the
                // winner's table — the walk is correct either way.
                pmm_mgr.destroy(new_page);
                cur = winner;
            } else {
                cur = want;
            }
        }
        // Whatever we ended up with — ours or the winner's — must be a
        // live table pointer. Asserting keeps the "absent ⟺ zero"
        // invariant honest instead of silently walking into garbage if
        // some future clear site starts leaving stale bits behind.
        const cur_entry: PageEntry = @bitCast(cur);
        std.debug.assert(cur_entry.present);
        const next_virt = VAddr.fromPAddr(cur_entry.getPAddr(), null);
        table = @ptrFromInt(next_virt.addr);
    }

    const l1_entry = &table[l1Idx(virt)];
    // Single-store leaf install — same transient-phys-0 hazard as the
    // parent-entry sites above.
    var filled_leaf = leaf_entry;
    filled_leaf.setPAddr(phys);
    l1_entry.* = filled_leaf;
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

    lockShootdownServicingArms(@src());
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

/// Publish a globals-inclusive whole-TLB invalidation to every remote
/// core and return the sync-arm generation it was published at, WITHOUT
/// waiting for anyone. Pair with `kernelUnmapEpochRetired`, which
/// reports when every core has honoured it. Call after clearing leaf
/// PTEs for a KERNEL virtual range; the backing physical frames may
/// only be recycled once the returned epoch has retired.
///
/// `flushRemoteTlb` — what `unmapPage` uses — cannot serve that purpose:
/// it is fire-and-forget AND per-VA. It publishes a single address into
/// the shared descriptor, fans out IPIs and returns, so back-to-back
/// arms overwrite each other's descriptor, and same-vector IPIs coalesce
/// in the LAPIC IRR (one pending interrupt per vector). A caller
/// unmapping N pages in a loop therefore leaves remote cores having
/// invalidated, at best, the last VA of the run. The design note on
/// `shootdownTlbRange` above documents exactly that hazard.
///
/// For kernel ranges the per-VA form is the wrong instrument twice over:
/// kernel mappings are GLOBAL, and neither INVPCID type 0 (with PCIDs
/// on) nor the conservative acker's flush used to touch a global
/// translation. One whole-TLB, globals-inclusive arm carries no address,
/// so descriptor overwrite and IPI coalescing are both harmless: any
/// core that services ANY of these IPIs drops every stale kernel
/// translation it holds.
///
/// Publish-and-poll rather than publish-and-wait, deliberately. This is
/// reachable from `stack.destroyKernel` on paths that hold object
/// gen-locks (`destroyExecutionContextLocked` runs under the dying
/// domain's lock) and run with IRQs masked. Blocking for acks there
/// closes a cycle against the IPC fast path, whose gen-lock CAS spins
/// are hand-written assembly that runs IRQs-off and services no arms:
/// the waiter cannot progress until a core acks, and that core cannot
/// ack until the waiter releases the lock it is spinning on. Nothing in
/// this function ever waits for another core.
pub fn publishKernelUnmapEpoch() u64 {
    // Local half: our own stale global entries have to go regardless of
    // how many cores are online.
    cpu.flushTlbIncludingGlobal();
    const core_count = apic.coreCount();
    if (core_count <= 1) return 0;
    // `apic.coreCount()` counts DISCOVERED LAPICs, not running cores.
    // Before `smpInit` finishes, an epoch could never retire: the cores
    // it names have not been SIPI'd yet. The AP bring-up path itself
    // calls `stack.destroyKernel` on a failed-mapping stack, and no
    // remote core can hold a translation for a kernel VA the BSP mapped
    // and tore down while that core was still parked in the trampoline —
    // so the local flush above is the whole story until then.
    if (!@atomicLoad(bool, &remote_shootdown_armed, .acquire)) return 0;

    const self_id = apic.coreID();
    lockShootdownServicingArms(@src());
    defer shootdown_lock.unlock();

    @atomicStore(u8, &shootdown_kind, @intFromEnum(ShootdownKind.flush_all_global), .release);
    const gen = bumpSyncArmGen();
    // We just performed the flush this arm asks for, so record our own
    // ack directly. `kernelUnmapEpochRetired` can then require EVERY
    // core to be caught up without knowing which core published.
    @atomicStore(u64, &core_acked_gen[self_id], gen, .release);
    fanoutShootdownIpis(self_id);
    return gen;
}

/// Has every core honoured the invalidation published at `epoch`?
/// `epoch == 0` means "nothing remote was published" (uniprocessor, or
/// pre-SMP) and is always retired.
pub fn kernelUnmapEpochRetired(epoch: u64) bool {
    if (epoch == 0) return true;
    const core_count = apic.coreCount();
    var i: u64 = 0;
    while (i < core_count) : (i += 1) {
        if (@atomicLoad(u64, &core_acked_gen[i], .acquire) < epoch) return false;
    }
    return true;
}

