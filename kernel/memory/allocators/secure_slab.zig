const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const bump = zag.memory.allocators.bump;
const debug = zag.utils.sync.debug;
const spin_diag = zag.utils.sync.spin_diag;

const Range = zag.utils.range.Range;
const SpinLock = zag.utils.sync.SpinLock;
const SrcLoc = debug.SrcLoc;

const INVALID_INDEX: u32 = std.math.maxInt(u32);
const DEFAULT_WALK_BOUND: u32 = 256;

pub const AllocError = error{
    SlabFull,
};

pub const AccessError = error{
    StaleHandle,
};

/// Per-object gen+lock word. First field of every slab-backed T. Encodes:
///   word = (gen << 1) | lock_bit
///   gen even  → slot is freed
///   gen odd   → slot is live
///   lock_bit  → 1 while a critical section is in progress
///
/// Replaces the object-level `SpinLock` that slab-backed types used to
/// carry as a separate field: same mutual-exclusion semantics, plus
/// structural UAF detection on every acquire (stale expected_gen → the
/// slot was freed since the handle was issued).
///
/// Callers that have a handle and a snapshotted `expected_gen` use
/// `lockWithGen` to verify + lock in one atomic instruction. Callers
/// holding a *T from a live internal reference chain use the plain
/// `lock()` which acquires whatever gen is current.
pub const GenLock = extern struct {
    word: std.atomic.Value(u64) align(8) = .{ .raw = 0 },
    class: [*:0]const u8 = "@unclassified",

    /// Plain spin-acquire of the lock bit, regardless of generation.
    /// Used by internal kernel paths that already have a live *T from a
    /// pinned reference chain (no handle, no staleness concern).
    pub fn lock(self: *GenLock, src: SrcLoc) void {
        self.lockOrdered(0, src);
    }

    /// `lock` variant that tags the lockdep entry with a non-zero
    /// `ordered_group`. The tag opts out of two checks: same-class
    /// overlap (lockdep treats every instance in the same group as
    /// disjoint for the duration of the held window) and pair-edge
    /// insertion against any other held lock (lockdep skips the
    /// (held, acquiring) pair-registry entry when either side is
    /// ordered, so cross-class cycle detection treats the ordered
    /// acquisition as exempt). Mirrors `SpinLock.lockIrqSaveOrdered`
    /// in spin_lock.zig and the futex `FUTEX_BUCKET_GROUP` site in
    /// kernel/proc/futex.zig. Caller must enforce a fixed acquisition
    /// order across every instance sharing this group; otherwise the
    /// escape hides real AB-BA deadlocks.
    pub fn lockOrdered(self: *GenLock, ordered_group: u32, src: SrcLoc) void {
        debug.acquire(self, self.class, ordered_group, src);
        var spin_count: u64 = 0;
        while (true) {
            const cur = self.word.load(.monotonic);
            if (cur & 1 == 0) {
                if (self.word.cmpxchgWeak(cur, cur | 1, .acquire, .monotonic) == null) return;
            }
            std.atomic.spinLoopHint();
            spin_diag.tick(&spin_count, src, "GenLock");
        }
    }

    /// Release a lock acquired via `lock` or `lockWithGen`. Clears the
    /// lock bit without touching the generation counter.
    ///
    /// Pairing rule: callers MUST match `lock`/`lockWithGen` to `unlock`,
    /// and `lockIrqSave*`/`lockWithGenIrqSave*` to `unlockIrqRestore`.
    /// Mixing produces broken IRQ state (an `unlock` paired with an
    /// `lockIrqSave` leaves IRQs disabled forever; `unlockIrqRestore`
    /// paired with a plain `lock` reads an undefined IRQ state) and is
    /// flagged by the gen-lock analyzer.
    pub fn unlock(self: *GenLock) void {
        debug.release(self);
        const prev = self.word.fetchAnd(~@as(u64, 1), .release);
        std.debug.assert(prev & 1 == 1);
    }

    /// IRQ-saving counterpart of `lock`. Disables IRQs on the current
    /// core, then spin-acquires the lock bit. The returned `u64` carries
    /// the prior IRQ state — callers MUST pass it back to
    /// `unlockIrqRestore` to release.
    ///
    /// Required at every acquire site of an IRQ-acquired lock class
    /// (one some IRQ/NMI handler can transitively reach an acquire of)
    /// — see `tools/check_gen_lock` for the static enforcement.
    /// Without IRQ masking across the held window, a timer/IPI/etc.
    /// firing mid-hold runs the ISR on top of the held lock; if the
    /// ISR acquires any other lock M, lockdep records L→M against the
    /// destroy-side M→L = AB-BA cycle.
    pub fn lockIrqSave(self: *GenLock, src: SrcLoc) u64 {
        return self.lockIrqSaveOrdered(0, src);
    }

    /// `lockIrqSave` variant that tags the lockdep entry with a
    /// non-zero `ordered_group`. See `lockOrdered` for the ordered-group
    /// semantics; this just adds the IRQ-mask discipline on top.
    pub fn lockIrqSaveOrdered(self: *GenLock, ordered_group: u32, src: SrcLoc) u64 {
        const state = arch.cpu.saveAndDisableInterrupts();
        self.lockOrdered(ordered_group, src);
        return state;
    }

    /// IRQ-saving counterpart of `lockWithGen`. Disables IRQs first,
    /// then spin-CAS-acquires + verifies gen. On `StaleHandle` the IRQ
    /// state is restored before returning the error so callers don't
    /// have to special-case; on success the caller MUST pass the
    /// returned `u64` to `unlockIrqRestore`.
    pub fn lockWithGenIrqSave(self: *GenLock, expected_gen: u63, src: SrcLoc) AccessError!u64 {
        return self.lockWithGenIrqSaveOrdered(expected_gen, 0, src);
    }

    /// `lockWithGenIrqSave` variant that tags the lockdep entry with a
    /// non-zero `ordered_group`.
    pub fn lockWithGenIrqSaveOrdered(
        self: *GenLock,
        expected_gen: u63,
        ordered_group: u32,
        src: SrcLoc,
    ) AccessError!u64 {
        const state = arch.cpu.saveAndDisableInterrupts();
        self.lockWithGenOrdered(expected_gen, ordered_group, src) catch |err| {
            arch.cpu.restoreInterrupts(state);
            return err;
        };
        return state;
    }

    /// Release a lock acquired via `lockIrqSave*` / `lockWithGenIrqSave*`.
    /// Clears the lock bit and restores the IRQ state captured at
    /// acquire time. MUST NOT be paired with a plain `lock`/`lockWithGen`
    /// acquire — see the pairing note on `unlock`.
    pub fn unlockIrqRestore(self: *GenLock, state: u64) void {
        debug.release(self);
        const prev = self.word.fetchAnd(~@as(u64, 1), .release);
        std.debug.assert(prev & 1 == 1);
        arch.cpu.restoreInterrupts(state);
    }

    /// Spin-CAS-acquire the lock bit while atomically verifying the
    /// caller's `expected_gen` snapshot matches the slot's current gen.
    /// Returns `StaleHandle` if the slot has been freed (and possibly
    /// reallocated) since the handle was issued.
    pub fn lockWithGen(self: *GenLock, expected_gen: u63, src: SrcLoc) AccessError!void {
        return self.lockWithGenOrdered(expected_gen, 0, src);
    }

    /// `lockWithGen` variant that tags the lockdep entry with a
    /// non-zero `ordered_group`. Same semantics as `GenLock.lockOrdered`
    /// — opts out of both same-class overlap and cross-class
    /// pair-edge cycle detection for this acquisition. Mirrors
    /// `SpinLock.lockIrqSaveOrdered`. Caller must enforce a fixed
    /// acquisition order across every instance sharing this group;
    /// otherwise the escape hides real AB-BA deadlocks.
    pub fn lockWithGenOrdered(
        self: *GenLock,
        expected_gen: u63,
        ordered_group: u32,
        src: SrcLoc,
    ) AccessError!void {
        // Parity invariant: a live-handle gen is always odd. An even
        // expected_gen means the caller is holding a reference to a
        // freed slot — a bug at the issuance site, not a stale handle.
        std.debug.assert(expected_gen % 2 == 1);
        debug.acquire(self, self.class, ordered_group, src);
        const unlocked: u64 = (@as(u64, expected_gen) << 1) | 0;
        const locked: u64 = (@as(u64, expected_gen) << 1) | 1;
        var spin_count: u64 = 0;
        while (true) {
            if (self.word.cmpxchgWeak(unlocked, locked, .acquire, .monotonic) == null) return;
            const cur = self.word.load(.monotonic);
            if ((cur >> 1) != expected_gen) {
                debug.release(self);
                return error.StaleHandle;
            }
            std.atomic.spinLoopHint();
            spin_diag.tick(&spin_count, src, "GenLock-withgen");
        }
    }

    /// Read the current generation. Callers issuing a handle snapshot
    /// this alongside the *T; callers on refcount-zero destroy paths
    /// read it to hand back to `SecureSlab.destroy`.
    pub fn currentGen(self: *const GenLock) u63 {
        return @intCast(self.word.load(.monotonic) >> 1);
    }

    /// Replace the word with `(new_gen << 1) | 0` — clears the lock bit
    /// and installs a new gen in one release store. Used by the slab
    /// allocator on alloc (freed→live) and destroy (live→freed).
    pub fn setGenRelease(self: *GenLock, new_gen: u63) void {
        const new_word: u64 = (@as(u64, new_gen) << 1) | 0;
        self.word.store(new_word, .release);
    }
};

/// Fat pointer to a slab-backed object. Pairs the pointer with the
/// generation captured at issuance; every access goes through `lock` /
/// `unlock`, which internally calls `GenLock.lockWithGen(self.gen)`.
///
/// This is the ONLY sanctioned form for kernel storage of a pointer to
/// a slab-backed object. Bare `*T` for slab-backed T is banned at the
/// type-system level (enforced by the static analyzer — see
/// `tools/check_gen_lock/`). Wherever such a pointer would be stored
/// — struct field, array element, function parameter, local variable —
/// the slot is `SlabRef(T)` instead.
///
/// Semantics:
///  * `init(ptr, gen)` — construct a fat pointer; gen is the snapshot
///    taken when the reference was minted (perm-table insertion,
///    fresh-alloc return, etc.).
///  * `lock()` returns a guarded pointer to T on success, or
///    `StaleHandle` if the slot has been freed since the ref was
///    minted. Caller must pair with `unlock()`.
///  * `unlock()` releases the lock bit. The gen carried by the ref is
///    untouched — the ref remains valid for subsequent locks until the
///    slot is actually freed.
///  * `eql(other)` — identity compare. Fat refs to the same slot with
///    the same gen are the same reference.
pub fn SlabRef(comptime T: type) type {
    // NOTE: `validateT` is intentionally deferred to the method bodies
    // below (via `ptr._gen_lock` field syntax) rather than called at
    // the outer `fn SlabRef` scope. Otherwise embedding `SlabRef(T)` in
    // a struct field of T itself (e.g. `KernelObject.process:
    // SlabRef(Process)` inside `Process.perm_table`) creates a
    // self-referential comptime cycle — Zig's `@hasField` requires the
    // struct to be fully resolved, which cannot happen while T is
    // still being declared. Field-syntax access inside `lock`/`unlock`
    // still produces the same `@hasField("_gen_lock")` guarantee, just
    // at method-call time instead of at type-instantiation time.
    return extern struct {
        const Self = @This();

        ptr: *T,
        gen: u32,
        _pad: u32 = 0,

        pub fn init(ptr: *T, gen: u63) Self {
            std.debug.assert(gen % 2 == 1);
            return .{ .ptr = ptr, .gen = @intCast(gen) };
        }

        /// Verify-and-acquire. On success the caller has exclusive
        /// access to `self.ptr` until `unlock()`. On `StaleHandle` the
        /// slot was freed since this ref was minted — the caller must
        /// NOT touch `self.ptr`.
        pub fn lock(self: Self, src: SrcLoc) AccessError!*T {
            try self.ptr._gen_lock.lockWithGen(@intCast(self.gen), src);
            return self.ptr;
        }

        /// `lock` variant that tags the lockdep entry with a non-zero
        /// `ordered_group`. Same semantics as `GenLock.lockOrdered` —
        /// opts out of both same-class overlap and cross-class
        /// pair-edge cycle detection for this acquisition. Mirrors
        /// `SpinLock.lockIrqSaveOrdered`. Caller must enforce a
        /// fixed acquisition order across every instance sharing this
        /// group; otherwise the escape hides real AB-BA deadlocks.
        pub fn lockOrdered(self: Self, ordered_group: u32, src: SrcLoc) AccessError!*T {
            try self.ptr._gen_lock.lockWithGenOrdered(@intCast(self.gen), ordered_group, src);
            return self.ptr;
        }

        pub fn unlock(self: Self) void {
            self.ptr._gen_lock.unlock();
        }

        /// IRQ-saving counterpart of `lock`. Required at acquire sites
        /// of IRQ-acquired classes (any class an IRQ/NMI handler can
        /// reach an acquire of) — see `GenLock.lockIrqSave` for the
        /// rationale. Returns the prior IRQ state, which the caller
        /// MUST pass to `unlockIrqRestore`. On `StaleHandle` the IRQ
        /// state is restored internally before the error returns.
        pub fn lockIrqSave(self: Self, src: SrcLoc) AccessError!struct { ptr: *T, irq_state: u64 } {
            const state = try self.ptr._gen_lock.lockWithGenIrqSave(@intCast(self.gen), src);
            return .{ .ptr = self.ptr, .irq_state = state };
        }

        /// `lockIrqSave` variant that tags the lockdep entry with a
        /// non-zero `ordered_group`.
        pub fn lockOrderedIrqSave(self: Self, ordered_group: u32, src: SrcLoc) AccessError!struct { ptr: *T, irq_state: u64 } {
            const state = try self.ptr._gen_lock.lockWithGenIrqSaveOrdered(@intCast(self.gen), ordered_group, src);
            return .{ .ptr = self.ptr, .irq_state = state };
        }

        /// Release a lock acquired via `lockIrqSave` / `lockOrderedIrqSave`.
        /// MUST NOT be paired with a plain `lock` acquire.
        pub fn unlockIrqRestore(self: Self, irq_state: u64) void {
            self.ptr._gen_lock.unlockIrqRestore(irq_state);
        }

        pub fn eql(self: Self, other: Self) bool {
            return self.ptr == other.ptr and self.gen == other.gen;
        }
    };
}

/// Out-of-band doubly-linked list entry. Sits in its own vaddr region
/// separate from the slot pointers so a single OOB write from a T instance
/// cannot corrupt both the address table and the freelist topology.
pub const LinkPair = extern struct {
    prev: u32,
    next: u32,
};

/// Secure slab allocator.
///
/// Memory model: three comptime-reserved kernel vaddr regions per class,
/// each demand-paged via the kernel page-fault handler. Regions:
///   data  — dense array of T slots (T embeds its own GenLock at offset 0)
///   ptrs  — parallel array of `*T` (one per slot index)
///   links — parallel array of `LinkPair` (prev/next indices into the free list)
///
/// Freelist: circular doubly-linked by u32 index. Two cursors (pop_cursor,
/// push_cursor) each walk by a hardware-random `[-N, N]` modulo free-list
/// size, every alloc *and* free. Intent: break deterministic heap grooming
/// so an attacker cannot pin which slot their next free-then-alloc will
/// reclaim.
///
/// Per-object gen+lock word: T declares `_gen_lock: GenLock` as its first
/// field. Capability handles store the expected gen alongside *T; deref
/// goes through `GenLock.lockWithGen` which CAS-verifies gen + acquires
/// the lock bit in one instruction.
pub fn SecureSlab(
    comptime T: type,
    comptime walk_bound: u32,
) type {
    comptime validateT(T);

    return struct {
        const Self = @This();

        const slot_align: u64 = @alignOf(T);
        const slot_stride: u64 = std.mem.alignForward(u64, @sizeOf(T), slot_align);

        data_bump: bump.BumpAllocator,
        ptrs_bump: bump.BumpAllocator,
        links_bump: bump.BumpAllocator,

        data_base: u64,
        ptrs_base: u64,
        links_base: u64,

        pop_cursor: u32,
        push_cursor: u32,
        count_free: u32,
        count_total: u32,
        max_slots: u32,

        rng_state: u64,

        /// Allocator-internal lock guarding the freelist / cursors /
        /// bump pointers. Orthogonal to per-slot GenLocks.
        lock: SpinLock = .{ .class = "SecureSlab(" ++ @typeName(T) ++ ").lock" },

        pub const Ref = SlabRef(T);

        /// Pending allocation handed back by `create`. The slot has been
        /// removed from the freelist but is still at an even (freed)
        /// gen — bare-pointer cross-core readers cannot `lockWithGen`
        /// on it, and `forEachAlive` skips it. Caller writes T's
        /// fields, then calls `publish` to flip the gen to odd and
        /// receive the live `Ref`. This two-phase split closes the
        /// publishing race that an "publish-then-init" sequence opens
        /// for any reader holding a stale `*T` from a prior life of
        /// the slot.
        pub const Pending = struct {
            ptr: *T,
            pending_gen: u63,
        };

        pub fn init(
            data_range: Range,
            ptrs_range: Range,
            links_range: Range,
        ) Self {
            std.debug.assert(data_range.start < data_range.end);
            std.debug.assert(ptrs_range.start < ptrs_range.end);
            std.debug.assert(links_range.start < links_range.end);
            std.debug.assert(!data_range.overlapsWith(ptrs_range));
            std.debug.assert(!data_range.overlapsWith(links_range));
            std.debug.assert(!ptrs_range.overlapsWith(links_range));

            const max_by_data: u64 = (data_range.end - data_range.start) / slot_stride;
            const max_by_ptrs: u64 = (ptrs_range.end - ptrs_range.start) / @sizeOf(*T);
            const max_by_links: u64 = (links_range.end - links_range.start) / @sizeOf(LinkPair);
            const max_index_space: u64 = INVALID_INDEX;
            const max_slots: u32 = @intCast(@min(
                @min(max_by_data, max_by_ptrs),
                @min(max_by_links, max_index_space),
            ));

            // Mix a timestamp into the seed even when RDRAND / RNDR is
            // available, and use it as sole entropy if hardware RNG is not.
            // Prevents a deterministic cursor walk in the narrow window
            // before any hardware RNG has been observed.
            const ts = arch.time.readTimestamp(false);
            const hw = arch.cpu.getRandom() orelse 0x9E3779B97F4A7C15;
            const seed: u64 = hw ^ ts;

            return .{
                .data_bump = bump.BumpAllocator.init(data_range.start, data_range.end),
                .ptrs_bump = bump.BumpAllocator.init(ptrs_range.start, ptrs_range.end),
                .links_bump = bump.BumpAllocator.init(links_range.start, links_range.end),
                .data_base = data_range.start,
                .ptrs_base = ptrs_range.start,
                .links_base = links_range.start,
                .pop_cursor = INVALID_INDEX,
                .push_cursor = INVALID_INDEX,
                .count_free = 0,
                .count_total = 0,
                .max_slots = max_slots,
                .rng_state = seed,
            };
        }

        /// Pop a freed slot off the freelist. The slot is returned
        /// at its post-destroy (even) gen — NOT yet live. Caller must
        /// write every T field it cares about, then call `publish`
        /// to flip the gen to its new odd value and receive the
        /// matching `Ref`. Splitting alloc this way closes the
        /// publish-before-init race a stale bare-pointer reader could
        /// otherwise drive: while gen is even, `lockWithGen` rejects
        /// the slot and `forEachAlive` skips it.
        pub fn create(self: *Self) AllocError!Pending {
            self.lock.lock(@src());
            defer self.lock.unlock();

            if (self.count_free == 0) {
                try self.growOne();
            }

            const draw_pop = self.randStep();
            const draw_push = self.randStep();
            self.pop_cursor = self.walkCursorLocked(self.pop_cursor, draw_pop);

            const popped = self.pop_cursor;
            const link = self.linkAt(popped);
            const next_after_pop = link.next;

            self.unlinkLocked(popped);
            self.pop_cursor = if (self.count_free == 0) INVALID_INDEX else next_after_pop;
            self.push_cursor = self.walkCursorLocked(self.push_cursor, draw_push);

            const slot_ptr = self.ptrAt(popped);
            const prev_gen = slot_ptr._gen_lock.currentGen();
            std.debug.assert(prev_gen % 2 == 0); // was freed (gen even)
            return .{
                .ptr = slot_ptr,
                .pending_gen = prev_gen + 1,
            };
        }

        /// Companion of `create`: caller has finished initializing T's
        /// fields; flip the slot's gen to its new odd value (live,
        /// unlocked) and return the matching `Ref`. After this call
        /// the slot is observable by any cross-core reader holding a
        /// `*T` from a prior life — they will now see the fully-
        /// initialized fields the caller just wrote.
        pub fn publish(_: *Self, pending: Pending) Ref {
            pending.ptr._gen_lock.setGenRelease(pending.pending_gen);
            return Ref.init(pending.ptr, pending.pending_gen);
        }

        /// Atomically verify the caller's carried gen, acquire the
        /// lock, bump gen to the next even (freed) value, and re-link
        /// the slot. Returns `StaleHandle` if the gen no longer matches
        /// — a concurrent destroy already ran (or the ref predates a
        /// reallocation and is a bug). A racing double-free is rejected
        /// cleanly rather than panicking.
        ///
        /// For call sites that already hold the slot's gen-lock (they
        /// locked, did work, and are ready to free) prefer
        /// `destroyLocked(ptr, expected_gen)` — it avoids the awkward
        /// unlock/destroy-relock dance and cannot fail.
        pub fn destroy(
            self: *Self,
            ptr: *T,
            expected_gen: u63,
        ) AccessError!void {
            // Parity invariant: expected_gen must be odd (live slot).
            // lockWithGen asserts this too; stating it here makes the
            // destroy-side contract explicit for readers.
            std.debug.assert(expected_gen % 2 == 1);
            try ptr._gen_lock.lockWithGen(expected_gen, @src());
            self.destroyLockedInner(ptr, expected_gen);
        }

        /// Destroy a slot whose gen-lock the caller already holds at
        /// `expected_gen`. Releases the lock as part of the gen bump
        /// (same `setGenRelease(expected_gen + 1)` that `destroy` does).
        /// Cannot fail: gen was verified when the caller took the lock,
        /// and the lock bit prevents anyone else from mutating the slot.
        pub fn destroyLocked(self: *Self, ptr: *T, expected_gen: u63) void {
            std.debug.assert(expected_gen % 2 == 1);
            // Debug-only: caller must actually hold the lock at expected_gen.
            if (std.debug.runtime_safety) {
                const word = ptr._gen_lock.word.load(.monotonic);
                std.debug.assert(word == ((@as(u64, expected_gen) << 1) | 1));
            }
            self.destroyLockedInner(ptr, expected_gen);
        }

        /// Bump the gen-lock from a held `expected_gen` to `expected_gen + 1`
        /// (even = freed) without zeroing the slot or returning it to the
        /// freelist. Used by deferred-destroy paths (cross-core terminate
        /// of a still-running EC) that need handle resolution to start
        /// failing immediately while leaving the slot's bytes intact for
        /// the running core to keep dereferencing until its next dispatch.
        ///
        /// Caller must hold the slot's gen-lock at `expected_gen`. Pair
        /// with `destroyAlreadyMarked(ptr)` from the running core's reap
        /// path once the slot is safe to recycle.
        pub fn bumpDeadGenLocked(self: *Self, ptr: *T, expected_gen: u63) void {
            _ = self;
            std.debug.assert(expected_gen % 2 == 1);
            if (std.debug.runtime_safety) {
                const word = ptr._gen_lock.word.load(.monotonic);
                std.debug.assert(word == ((@as(u64, expected_gen) << 1) | 1));
            }
            // Same release-store the normal destroy path uses; matches
            // `debug.release` so lockdep's per-core held stack stays
            // balanced.
            debug.release(&ptr._gen_lock);
            ptr._gen_lock.setGenRelease(expected_gen + 1);
        }

        /// Finish the destroy of a slot previously rotated to its
        /// freed-gen via `bumpDeadGenLocked`. Verifies the slot is at an
        /// even gen (no concurrent re-allocation snuck in), zeros every
        /// byte except `_gen_lock`, and pushes the slot back onto the
        /// freelist. Pair with `bumpDeadGenLocked` only.
        ///
        /// Zero on free, not on alloc: matches `destroyLockedInner`'s
        /// policy and removes the entire class of "stale-bits look like
        /// a valid live field" races. The slot's gen has been even
        /// (freed) since `bumpDeadGenLocked` ran; bare-pointer holders
        /// must gate any field read on `lockWithGen`, which fails
        /// against an even gen. Allocators in turn don't need to write
        /// every default-zero field — the slot is guaranteed all-zero
        /// when `create` pops it.
        pub fn destroyAlreadyMarked(self: *Self, ptr: *T) void {
            const word = ptr._gen_lock.word.load(.acquire);
            std.debug.assert(word & 1 == 0);
            std.debug.assert((word >> 1) % 2 == 0);

            zeroExceptGenLock(ptr);

            self.lock.lock(@src());
            defer self.lock.unlock();

            const idx = self.indexOf(ptr);
            const draw_push = self.randStep();
            const draw_pop = self.randStep();
            self.linkInLocked(idx);
            self.push_cursor = self.walkCursorLocked(self.push_cursor, draw_push);
            self.pop_cursor = self.walkCursorLocked(self.pop_cursor, draw_pop);
        }

        /// Visit every currently-allocated slot. The visitor receives a
        /// `*T` and a `u63` gen for the live slot, then returns whether
        /// to continue iterating. Slots whose gen-lock parity is even
        /// (freed) or zero (never allocated) are skipped.
        ///
        /// No lock is held across the visitor — callers must take the
        /// per-slot gen-lock themselves if they need exclusive access
        /// to T's fields. Liveness across the visitor is best-effort:
        /// a slot can be destroyed concurrently. The `gen` returned
        /// alongside the pointer is the snapshot the visitor would use
        /// to construct a `SlabRef(T)` for verify-and-acquire.
        ///
        /// Used by cross-domain object-holder lookups (e.g. timer
        /// fire propagation walks every CapabilityDomain to find handles
        /// pointing at a given Timer) where no inverse index exists.
        pub fn forEachAlive(self: *Self, ctx: anytype, comptime visit: fn (@TypeOf(ctx), *T, u63) bool) void {
            // Snapshot count_total once. New slots minted concurrently
            // will sit at indices >= the snapshot; visiting them is
            // optional and could be racy with their initialization.
            const total = @atomicLoad(u32, &self.count_total, .acquire);
            var i: u32 = 0;
            while (i < total) {
                const ptr = self.ptrAt(i);
                const gen = ptr._gen_lock.currentGen();
                if (gen != 0 and (gen % 2) == 1) {
                    if (!visit(ctx, ptr, gen)) return;
                }
                i += 1;
            }
        }

        /// Shared tail of `destroy` / `destroyLocked`. Caller has already
        /// established the slot's gen-lock is held at `expected_gen`.
        fn destroyLockedInner(self: *Self, ptr: *T, expected_gen: u63) void {
            self.lock.lock(@src());
            defer self.lock.unlock();

            // Defense-in-depth: clear every byte of T *except* `_gen_lock`
            // before releasing the slot. Stale capability data, keys, or
            // IPC payloads can't leak across a free→realloc cycle, and the
            // zero'd representation gives the next allocator the same
            // "clean-zero" state it'd get from a freshly-grown slot.
            // Uses `@offsetOf(T, "_gen_lock")` so T is free to place the
            // lock word wherever Zig's auto-layout prefers.
            zeroExceptGenLock(ptr);

            // Gen-lock currently held. Bump to (expected_gen+1)<<1 | 0 and
            // release in one store: the new gen is even (freed) and the
            // lock bit is clear. The atomic store releases the in-memory
            // lock bit, but lockdep tracks acquires/releases on its own
            // per-core held stack — the matching `debug.release` keeps that
            // stack in sync, otherwise the entry stays held until the slot
            // gets re-acquired and same-class / cycle false positives fire
            // on the next sibling-slot destroy under the same critical
            // section (e.g. `vmm.deinit` walking and freeing every node).
            debug.release(&ptr._gen_lock);
            ptr._gen_lock.setGenRelease(expected_gen + 1);

            const idx = self.indexOf(ptr);

            const draw_push = self.randStep();
            const draw_pop = self.randStep();

            self.linkInLocked(idx);
            self.push_cursor = self.walkCursorLocked(self.push_cursor, draw_push);
            self.pop_cursor = self.walkCursorLocked(self.pop_cursor, draw_pop);
        }

        // ---- internals ----

        fn growOne(self: *Self) AllocError!void {
            if (self.count_total >= self.max_slots) return error.SlabFull;

            const slot_base = bumpBytes(&self.data_bump, slot_stride, slot_align) orelse
                return error.SlabFull;
            // Freshly demand-paged memory is already zero (fault handler
            // zeroes new pages); be explicit under second-touch reuse.
            @memset(slot_base[0..slot_stride], 0);
            const slot_ptr: *T = @ptrCast(@alignCast(slot_base));
            // The whole-slot @memset above clobbers `_gen_lock.class`. The
            // GenLock struct-default `"@unclassified"` only fills in for
            // instances built via `.{}` literals; the slab's raw-bytes init
            // path bypasses it entirely. Without this restore the class
            // pointer stays NULL for the slot's lifetime — `zeroExceptGenLock`
            // on subsequent destroys preserves whatever's already there.
            // A NULL `class` page-faults the lockdep panic-printer (fixed
            // alongside this) and, more importantly, makes every two slab-
            // backed `_gen_lock` acquires falsely register as a same-class
            // overlap (NULL == NULL), turning every nested slab access into
            // a lockdep panic. Naming each slab's GenLock-class by T's
            // typename keeps distinct slabs distinct in the detector.
            slot_ptr._gen_lock.class = "SecureSlab(" ++ @typeName(T) ++ ")._gen_lock";

            const ptr_cell = bumpOne(&self.ptrs_bump, *T) orelse return error.SlabFull;
            ptr_cell.* = slot_ptr;

            const link_cell = bumpOne(&self.links_bump, LinkPair) orelse return error.SlabFull;
            link_cell.* = .{ .prev = INVALID_INDEX, .next = INVALID_INDEX };

            const new_idx: u32 = self.count_total;
            self.count_total += 1;

            self.linkInLocked(new_idx);
        }

        fn randStep(self: *Self) i32 {
            const r = self.nextRandom();
            const span: u64 = 2 * @as(u64, walk_bound) + 1;
            const unsigned_step: u32 = @intCast(r % span);
            return @as(i32, @intCast(unsigned_step)) - @as(i32, walk_bound);
        }

        fn nextRandom(self: *Self) u64 {
            if (arch.cpu.getRandom()) |r| {
                self.rng_state ^= r;
                return r;
            }
            var s = self.rng_state;
            if (s == 0) s = 0x9E3779B97F4A7C15;
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            self.rng_state = s;
            return s *% 0x2545F4914F6CDD1D;
        }

        fn walkCursorLocked(self: *Self, start: u32, raw_steps: i32) u32 {
            if (self.count_free == 0) return INVALID_INDEX;

            const size_i: i32 = @intCast(self.count_free);
            const effective: u32 = @intCast(@mod(raw_steps, size_i));

            var cursor = if (start == INVALID_INDEX) self.anyFreeSlotLocked() else start;
            var i: u32 = 0;
            while (i < effective) {
                cursor = self.linkAt(cursor).next;
                i += 1;
            }
            return cursor;
        }

        fn anyFreeSlotLocked(self: *Self) u32 {
            if (self.push_cursor != INVALID_INDEX) return self.push_cursor;
            if (self.pop_cursor != INVALID_INDEX) return self.pop_cursor;
            @panic("anyFreeSlotLocked called on empty list");
        }

        fn linkInLocked(self: *Self, idx: u32) void {
            // Parity invariant: slots on the freelist have even gen.
            // linkIn is called from growOne (slot fresh at gen=0) and
            // from destroy (slot just bumped to the next even gen).
            std.debug.assert(self.ptrAt(idx)._gen_lock.currentGen() % 2 == 0);
            const link = self.linkAt(idx);
            if (self.count_free == 0) {
                link.* = .{ .prev = idx, .next = idx };
                self.pop_cursor = idx;
                self.push_cursor = idx;
            } else {
                const anchor = if (self.push_cursor == INVALID_INDEX)
                    self.anyFreeSlotLocked()
                else
                    self.push_cursor;
                const anchor_link = self.linkAt(anchor);
                const after = anchor_link.next;
                link.* = .{ .prev = anchor, .next = after };
                anchor_link.next = idx;
                self.linkAt(after).prev = idx;
            }
            self.count_free += 1;
        }

        fn unlinkLocked(self: *Self, idx: u32) void {
            std.debug.assert(self.count_free > 0);
            // Parity invariant: slots on the freelist have even gen.
            // unlink is called from create() before the gen is bumped
            // to odd, so the slot must still be even here.
            std.debug.assert(self.ptrAt(idx)._gen_lock.currentGen() % 2 == 0);
            const link = self.linkAt(idx);
            const saved_prev = link.prev;
            if (self.count_free == 1) {
                std.debug.assert(link.prev == idx and link.next == idx);
            } else {
                self.linkAt(link.prev).next = link.next;
                self.linkAt(link.next).prev = link.prev;
            }
            link.* = .{ .prev = INVALID_INDEX, .next = INVALID_INDEX };
            self.count_free -= 1;

            if (self.push_cursor == idx) {
                self.push_cursor = if (self.count_free == 0) INVALID_INDEX else saved_prev;
            }
        }

        fn linkAt(self: *Self, idx: u32) *LinkPair {
            std.debug.assert(idx < self.count_total);
            const addr = self.links_base + @as(u64, idx) * @sizeOf(LinkPair);
            return @ptrFromInt(addr);
        }

        pub fn ptrAt(self: *Self, idx: u32) *T {
            std.debug.assert(idx < self.count_total);
            const addr = self.ptrs_base + @as(u64, idx) * @sizeOf(*T);
            const cell: *const *T = @ptrFromInt(addr);
            return cell.*;
        }

        fn zeroExceptGenLock(ptr: *T) void {
            const byte_ptr: [*]u8 = @ptrCast(ptr);
            const gen_off = comptime @offsetOf(T, "_gen_lock");
            const gen_end = comptime gen_off + @sizeOf(GenLock);
            const total = comptime @sizeOf(T);
            if (comptime gen_off > 0) {
                @memset(byte_ptr[0..gen_off], 0);
            }
            if (comptime gen_end < total) {
                @memset(byte_ptr[gen_end..total], 0);
            }
        }

        pub fn indexOf(self: *Self, ptr: *T) u32 {
            // Slots are laid out at `data_base + i * slot_stride` by
            // growOne; the pointer's offset from data_base divides by
            // stride to give its index. O(1), no ptrs-array walk.
            const addr = @intFromPtr(ptr);
            std.debug.assert(addr >= self.data_base);
            const offset = addr - self.data_base;
            std.debug.assert(offset % slot_stride == 0);
            const idx: u32 = @intCast(offset / slot_stride);
            std.debug.assert(idx < self.count_total);
            // Defensive: ptrs-array must still agree. This is a
            // debug-only cross-check that catches corruption of the
            // ptrs region independent of the stride math.
            std.debug.assert(self.ptrAt(idx) == ptr);
            return idx;
        }
    };
}

// ---- shared helpers ----

fn validateT(comptime T: type) void {
    const info = @typeInfo(T);

    // ---- shape: T must be a struct ----
    if (info != .@"struct") {
        @compileError("SecureSlab requires a struct T; got " ++ @typeName(T));
    }

    // ---- identity: T must carry a `_gen_lock: GenLock` field ----
    if (!@hasField(T, "_gen_lock")) {
        @compileError(@typeName(T) ++ " must declare a `_gen_lock: GenLock` field");
    }
    if (@FieldType(T, "_gen_lock") != GenLock) {
        @compileError(
            @typeName(T) ++ "._gen_lock must be `GenLock`, got `" ++
                @typeName(@FieldType(T, "_gen_lock")) ++ "`",
        );
    }

    // ---- alignment: T must be at least 8-byte-aligned for the atomic word ----
    if (@alignOf(T) < @alignOf(GenLock)) {
        @compileError(
            @typeName(T) ++ " must be at least " ++
                std.fmt.comptimePrint("{d}", .{@alignOf(GenLock)}) ++
                "-byte aligned (GenLock's atomic u64 requires it); got " ++
                std.fmt.comptimePrint("{d}", .{@alignOf(T)}),
        );
    }

    // ---- size / stride stability: @sizeOf divides @alignOf cleanly ----
    // slot_stride = alignForward(@sizeOf(T), @alignOf(T)) in SecureSlab;
    // if @sizeOf isn't already a multiple of @alignOf, alignForward pads
    // and the in-between bytes become reusable scratch across free→alloc
    // (they're not part of T's storage, so the slab allocator's zeroing
    // protections don't cover them). Ban this shape — every slab T
    // should be sized to its own alignment.
    if (@sizeOf(T) % @alignOf(T) != 0) {
        @compileError(
            @typeName(T) ++ " @sizeOf (" ++
                std.fmt.comptimePrint("{d}", .{@sizeOf(T)}) ++
                ") must be a multiple of @alignOf (" ++
                std.fmt.comptimePrint("{d}", .{@alignOf(T)}) ++
                ") for stable array stride",
        );
    }

    // ---- layout: `_gen_lock`'s offset is whatever Zig picked ----
    // `_gen_lock` persists across free→alloc cycles (the whole gen-parity
    // invariant depends on it), but its *offset within T* is not load-
    // bearing — `zeroExceptGenLock` below uses `@offsetOf(T, "_gen_lock")`
    // at comptime to skip it when clearing the slot. This lets T stay a
    // plain `struct` and keeps Zig free to reorder for packing, avoiding
    // the extern-cascade churn (tagged unions, nested optionals, …) that
    // would otherwise ripple through Process/Thread/Vm/VCpu.
}

fn bumpOne(ba: *bump.BumpAllocator, comptime R: type) ?*R {
    const aligned = std.mem.alignForward(u64, ba.free_addr, @alignOf(R));
    const next_free = aligned + @sizeOf(R);
    if (next_free > ba.end_addr) return null;
    ba.free_addr = next_free;
    return @ptrFromInt(aligned);
}

fn bumpBytes(ba: *bump.BumpAllocator, size: u64, alignment: u64) ?[*]u8 {
    const aligned = std.mem.alignForward(u64, ba.free_addr, alignment);
    const next_free = aligned + size;
    if (next_free > ba.end_addr) return null;
    ba.free_addr = next_free;
    return @ptrFromInt(aligned);
}

// ---- tests ----

const testing = std.testing;

const TestT = extern struct {
    _gen_lock: GenLock = .{},
    value: u64 = 0,
};

test "validateT accepts well-formed extern struct" {
    _ = SecureSlab(TestT, DEFAULT_WALK_BOUND);
}

test "randStep stays in [-N, N]" {
    const S = SecureSlab(TestT, 16);
    var dummy: S = undefined;
    dummy.rng_state = 0xDEADBEEFCAFEBABE;
    var i: usize = 0;
    while (i < 1000) {
        const step = dummy.randStep();
        try testing.expect(step >= -16 and step <= 16);
        i += 1;
    }
}

test "genlock lock/unlock sequencing" {
    var gl: GenLock = .{};
    gl.setGenRelease(5); // pretend we just allocated gen=5
    gl.lock(@src());
    try testing.expect(gl.word.load(.monotonic) & 1 == 1);
    gl.unlock();
    try testing.expect(gl.word.load(.monotonic) & 1 == 0);
    try testing.expectEqual(@as(u63, 5), gl.currentGen());
}

test "genlock lockWithGen rejects stale" {
    var gl: GenLock = .{};
    gl.setGenRelease(5);
    // Stale gen must still be odd — an even expected_gen would trip
    // the parity assert, not return StaleHandle (that's a caller bug,
    // not an ordinary stale-handle miss).
    try testing.expectError(error.StaleHandle, gl.lockWithGen(3, @src()));
}

test "SlabRef lock / unlock round-trip on live slot" {
    var t: TestT = .{};
    t._gen_lock.setGenRelease(3); // pretend live at gen=3
    const ref = SlabRef(TestT).init(&t, 3);
    const got = try ref.lock(@src());
    try testing.expectEqual(&t, got);
    try testing.expect(t._gen_lock.word.load(.monotonic) & 1 == 1);
    ref.unlock();
    try testing.expect(t._gen_lock.word.load(.monotonic) & 1 == 0);
}

test "SlabRef.lock rejects a stale ref" {
    var t: TestT = .{};
    t._gen_lock.setGenRelease(5); // slot has advanced to 5
    const stale = SlabRef(TestT).init(&t, 3); // caller captured gen=3
    try testing.expectError(error.StaleHandle, stale.lock(@src()));
}
