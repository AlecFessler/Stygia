//! Generic capability envelope. See docs/kernel/specv3.md §[capabilities].
//!
//! A capability is an unforgeable reference to a kernel object, paired
//! with type-dependent caps and metadata. The system holds two parallel
//! tables per capability domain, indexed by the same 12-bit handle id:
//!
//!   - User table — array of `Capability` (24 bytes each). Mapped
//!     read-only into the holding domain so userspace can inspect cap
//!     bits, type, and the kernel-mutable field0/field1 snapshots
//!     directly without a syscall.
//!
//!   - Kernel table — array of `KernelHandle`. Carries the actual
//!     `*Object` (type-erased) and slab gen for UAF validation. Not
//!     mapped to userspace.
//!
//! Slot N in the user table mirrors slot N in the kernel table. A read
//! of `Capability.word0` bits 12-15 names which kernel object type the
//! parallel `KernelHandle.obj` points at.
//!
//! The kernel writes field0/field1 directly on the user table pages
//! (via the kernel-side R/W view of the same physical pages) when an
//! object's kernel-mutable snapshot changes (e.g. EC priority).

const zag = @import("zag");

const arch = zag.arch.dispatch;
const capability_domain = zag.caps.capability_domain;
const derivation = zag.caps.derivation;
const device_region = zag.devices.device_region;
const errors = zag.syscall.errors;
const execution_context = zag.sched.execution_context;
const page_frame = zag.memory.page_frame;
const port = zag.sched.port;
const secure_slab = zag.memory.allocators.secure_slab;
const timer = zag.sched.timer;
const vmar = zag.memory.vmar;
const virtual_machine = zag.hv.virtual_machine;

const CapabilityDomain = capability_domain.CapabilityDomain;
const DeviceRegion = device_region.DeviceRegion;
const ExecutionContext = execution_context.ExecutionContext;
const PageFrame = page_frame.PageFrame;
const Port = port.Port;
const Timer = timer.Timer;
const VMAR = vmar.VMAR;
const VirtualMachine = virtual_machine.VirtualMachine;

/// Maximum handles per capability domain. Spec: 12-bit handle id.
pub const MAX_HANDLES_PER_DOMAIN: u16 = 4096;

/// Sentinel marking the tail of the free-slot list.
pub const FREE_LIST_TAIL: u16 = 0xFFFF;

/// Type tag carried in `Capability.word0` bits 12-15. Names which kind
/// of kernel object the corresponding `KernelHandle.obj` points at.
/// 4-bit field allows up to 16 distinct types.
pub const CapabilityType = enum(u4) {
    /// Slot 0 in every domain. References the domain itself (its
    /// self-handle, with the full ceiling-bearing cap word).
    capability_domain_self = 0,
    /// IDC handle to another (or this) capability domain.
    capability_domain = 1,
    execution_context = 2,
    page_frame = 3,
    virtual_memory_address_region = 4,
    device_region = 5,
    port = 6,
    reply = 7,
    virtual_machine = 8,
    timer = 9,
    _,
};

/// User-visible capability entry. 24 bytes, three little-endian u64s.
/// One of these per slot in the domain's user-mapped table.
pub const Capability = extern struct {
    /// Word 0 — universal envelope:
    /// ```
    /// 63            48 47                          16 15   12 11         0
    /// ┌────────────────┬──────────────────────────────┬───────┬────────────┐
    /// │   cap (16)     │       _reserved (32)         │type(4)│   id(12)   │
    /// └────────────────┴──────────────────────────────┴───────┴────────────┘
    /// ```
    /// - bits 0-11  : `id`   — slot index, equals this entry's position
    /// - bits 12-15 : `type` — `CapabilityType`
    /// - bits 16-47 : reserved, must be zero
    /// - bits 48-63 : `cap`  — type-dependent cap bitfield (see each
    ///                         object's spec section for layout)
    word0: u64,

    /// Word 1 — type-dependent metadata. Layout per object type. Some
    /// fields are kernel-mutable snapshots refreshed on syscalls
    /// touching the handle.
    field0: u64,

    /// Word 2 — type-dependent metadata. Same.
    field1: u64,
};

comptime {
    if (@sizeOf(Capability) != 24) @compileError("Capability must be 24 bytes");
}

/// Bit-packing helpers for `Capability.word0`.
pub const Word0 = struct {
    pub inline fn id(word0: u64) u12 {
        return @truncate(word0 & 0xFFF);
    }
    pub inline fn typeTag(word0: u64) CapabilityType {
        return @enumFromInt(@as(u4, @truncate((word0 >> 12) & 0xF)));
    }
    pub inline fn caps(word0: u64) u16 {
        return @truncate(word0 >> 48);
    }
    pub inline fn pack(handle_id: u12, t: CapabilityType, c: u16) u64 {
        return @as(u64, handle_id) |
            (@as(u64, @intFromEnum(t)) << 12) |
            (@as(u64, c) << 48);
    }
};

/// Mask of the syscall-handle argument bits the caller is allowed to
/// set. Spec: a handle argument is bits 0-11; upper bits are reserved
/// and must be zero. `restrict`/`delete`/`revoke`/`sync` all return
/// E_INVAL if bits 12-63 are non-zero.
pub const HANDLE_ARG_MASK: u64 = 0xFFF;

/// Mask of the caps-argument bits the caller is allowed to set in
/// `restrict`. Spec packs new caps into bits 0-15; bits 16-63 are
/// reserved.
pub const RESTRICT_CAPS_MASK: u64 = 0xFFFF;

/// Type-erased SlabRef. Same on-wire layout as `SlabRef(T)` for any T —
/// `{ ptr, gen, _pad }`, 16 bytes — but with `?*anyopaque` for the ptr
/// so the free-slot state can be encoded as `ptr = null` without a
/// separate discriminator. Bit-cast to/from `SlabRef(T)` once the user
/// table's type tag names the concrete T.
pub const ErasedSlabRef = extern struct {
    ptr: ?*anyopaque = null,
    gen: u32 = 0,
    _pad: u32 = 0,

    /// Reconstitute a typed `SlabRef(T)` from the erased fat pointer
    /// and acquire its gen-lock with a non-zero `ordered_group` tag,
    /// IRQs masked. Returns `StaleHandle` if the slot has been freed
    /// since this reference was minted.
    ///
    /// The `ordered_group` tag opts out of same-class overlap
    /// detection (lockdep treats every instance in the same group as
    /// disjoint for the duration of the held window) so callers that
    /// legitimately hold multiple `SlabRef(T)` locks of the same T at
    /// once — e.g. the cross-domain copy-derivation tree walk in
    /// `caps/derivation.zig` holds two `*CapabilityDomain` gen-locks
    /// under `tree_mutex` — don't trip the lockdep guard. Caller is
    /// responsible for ensuring an outer serializer (here, `tree_mutex`)
    /// makes the same-class overlap structurally safe. Caller pairs
    /// with `unlockTypedIrqRestore` and threads the returned IRQ state
    /// back.
    ///
    /// The plain (`ordered_group=0`) variant intentionally is not
    /// exposed here — every CD-lock acquire on the tree-mutation paths
    /// goes through `TREE_DOMAIN_GROUP`. Adding a non-ordered variant
    /// would risk callers mixing plain and ordered acquires on the
    /// same class, which lockdep rejects via `acquireOn`'s
    /// `held.ordered_group != ordered_group` clause.
    pub fn lockTypedIrqSaveOrdered(
        self: ErasedSlabRef,
        comptime T: type,
        ordered_group: u32,
    ) secure_slab.AccessError!struct { ptr: *T, irq_state: u64 } {
        const raw = self.ptr orelse return error.StaleHandle;
        const ref = secure_slab.SlabRef(T){
            .ptr = @ptrCast(@alignCast(raw)),
            .gen = self.gen,
            ._pad = self._pad,
        };
        const lr = try ref.lockOrderedIrqSave(ordered_group, @src());
        return .{ .ptr = lr.ptr, .irq_state = lr.irq_state };
    }

    /// Release the lock acquired via `lockTypedIrqSaveOrdered`.
    /// Restores the captured IRQ state. Pairs with the lock-side
    /// regardless of which `ordered_group` was passed there — release
    /// looks the held entry up by lock_ptr, not by group tag.
    pub fn unlockTypedIrqRestore(self: ErasedSlabRef, comptime T: type, irq_state: u64) void {
        const raw = self.ptr orelse return;
        const ref = secure_slab.SlabRef(T){
            .ptr = @ptrCast(@alignCast(raw)),
            .gen = self.gen,
            ._pad = self._pad,
        };
        ref.unlockIrqRestore(irq_state);
    }
};

comptime {
    const SlabRef = secure_slab.SlabRef;
    const Concrete = SlabRef(u8);
    if (@sizeOf(ErasedSlabRef) != @sizeOf(Concrete)) {
        @compileError("ErasedSlabRef size must match SlabRef");
    }
    if (@offsetOf(ErasedSlabRef, "ptr") != @offsetOf(Concrete, "ptr")) {
        @compileError("ErasedSlabRef.ptr offset must match SlabRef.ptr");
    }
    if (@offsetOf(ErasedSlabRef, "gen") != @offsetOf(Concrete, "gen")) {
        @compileError("ErasedSlabRef.gen offset must match SlabRef.gen");
    }
    if (@offsetOf(ErasedSlabRef, "_pad") != @offsetOf(Concrete, "_pad")) {
        @compileError("ErasedSlabRef._pad offset must match SlabRef._pad");
    }
    if (@alignOf(ErasedSlabRef) != @alignOf(Concrete)) {
        @compileError("ErasedSlabRef alignment must match SlabRef");
    }
}

/// Cross-domain link to a `KernelHandle` in another (or this) capability
/// domain. Used for revoke-ancestry tree links — parent, first_child,
/// next_sibling — embedded in `KernelHandle`.
///
/// Carries the holder domain as an `ErasedSlabRef` so each traversal step
/// goes through `SlabRef.lock` for gen validation: if the target domain
/// has been freed since the link was installed, the lock raises
/// `StaleHandle` and the descendant is treated as already gone.
///
/// `slot` is the 12-bit handle id within `domain`'s `kernel_table`. The
/// remaining bits in the trailing word are reserved.
///
/// Two-state encoding mirrors `ErasedSlabRef` itself:
///   - Linked  : `domain.ptr != null`. `slot` is the linked slot id.
///   - Unlinked: `domain.ptr == null`. `slot` is meaningful only on the
///               `parent` link of a free slot, where it carries the
///               next-free-slot index (see `KernelHandle` doc).
pub const HandleLink = extern struct {
    domain: ErasedSlabRef = .{},
    slot: u16 = 0,
    _reserved: [6]u8 = .{ 0, 0, 0, 0, 0, 0 },
};

comptime {
    if (@sizeOf(HandleLink) != 24) @compileError("HandleLink must be 24 bytes");
    if (@offsetOf(HandleLink, "domain") != 0) @compileError("HandleLink.domain must be at offset 0");
}

/// Kernel-side mirror entry. One per slot in the domain's handle table,
/// indexed identically to the user-visible `Capability` table. Lives in
/// kernel-only memory.
///
/// Two states distinguished by `ref.ptr`:
///   - **Used** (`ref.ptr != null`): the embedded `SlabRef` references
///     the kernel object. Combine with the user table's type tag to
///     reconstruct a typed `SlabRef(T)` via `typedRef`. The three link
///     fields (`parent`, `first_child`, `next_sibling`) describe this
///     handle's position in the cross-domain copy-derivation tree used
///     by `revoke` (Spec §[capabilities].revoke). A null `parent.domain`
///     in the used state means the handle was minted as a tree root
///     (e.g. via `create_*`) and has no copy ancestor.
///   - **Free** (`ref.ptr == null`): the parent link doubles as the
///     free-slot list link — `parent.slot` low 16 bits hold the next
///     free slot index (`FREE_LIST_TAIL` = end of list). The
///     `first_child` and `next_sibling` fields are zeroed. The two
///     states are unambiguous because a free slot has no copy ancestor
///     and no descendants.
pub const KernelHandle = extern struct {
    ref: ErasedSlabRef = .{},
    parent: HandleLink = .{},
    first_child: HandleLink = .{},
    next_sibling: HandleLink = .{},
    /// Per-handle entry on the parent device_region's IRQ-propagation
    /// list. Only populated when `Word0.typeTag(user_table[slot].word0)
    /// == .device_region`; stays zeroed and unlinked for every other
    /// slot type (and for free slots). Wired by `writeHandleSlot` on
    /// mint and unlinked by the `.device_region` arm of `releaseHandle`
    /// / destroyPhase2 before the handle table memory is freed. See
    /// `device_region.HandleListNode`.
    dr_node: device_region.HandleListNode = .{},
};

comptime {
    if (@sizeOf(KernelHandle) != 104) @compileError("KernelHandle must be 104 bytes");
    if (@offsetOf(KernelHandle, "ref") != 0) @compileError("KernelHandle.ref must be at offset 0");
    if (@offsetOf(KernelHandle, "parent") != 16) @compileError("KernelHandle.parent must be at offset 16");
    if (@offsetOf(KernelHandle, "dr_node") != 88) @compileError("KernelHandle.dr_node must be at offset 88");
}

/// Reconstruct a typed `SlabRef(T)` from a kernel entry. Returns `null`
/// if the slot is free. Caller is responsible for matching `T` to the
/// type tag in the parallel user `Capability.word0`.
///
/// Explicit field reconstruction rather than `@bitCast` — Zig disallows
/// bit-casting between `?*anyopaque` and a non-null `*T`, even when
/// the comptime layout assertion above proves the bit representation
/// is identical. The compiler treats them as different types at the
/// optional level. Field-by-field copy sidesteps that.
pub fn typedRef(comptime T: type, entry: KernelHandle) ?SlabRefOf(T) {
    const raw = entry.ref.ptr orelse return null;
    return SlabRefOf(T){
        .ptr = @ptrCast(@alignCast(raw)),
        .gen = entry.ref.gen,
        ._pad = entry.ref._pad,
    };
}

// Forward reference — the real `SlabRef(T)` lives in
// `memory.allocators.secure_slab`. Aliased here to avoid a circular
// import while we're still stubbing.
fn SlabRefOf(comptime T: type) type {
    return secure_slab.SlabRef(T);
}

// ── Free-list helpers ─────────────────────────────────────────────────

/// Compose the free-list cell stored in a free entry's `parent` link.
/// In the free state `parent.domain` is null and `parent.slot` carries
/// the next free slot index (`FREE_LIST_TAIL` for end of list).
pub inline fn encodeFreeNext(next: u16) HandleLink {
    return .{ .domain = .{}, .slot = next };
}

/// Read the next free slot index from a free entry's `parent` link.
pub inline fn decodeFreeNext(link: HandleLink) u16 {
    return link.slot;
}

// ── External API (cross-cutting capability operations) ───────────────

/// `restrict` syscall handler. Spec §[capabilities].restrict.
pub fn restrict(caller: *anyopaque, handle: u64, caps_arg: u64) i64 {
    if (handle & ~HANDLE_ARG_MASK != 0) return errors.E_INVAL;
    if (caps_arg & ~RESTRICT_CAPS_MASK != 0) return errors.E_INVAL;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const cd_ref = ec.domain;
    const cd_lr = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = cd_lr.ptr;
    defer cd_ref.unlockIrqRestore(cd_lr.irq_state);

    const slot: u12 = @truncate(handle);
    const entry = resolveHandleOnDomain(cd, slot, null) orelse return errors.E_BADCAP;
    const user_entry = &cd.user_table[slot];

    const type_tag = Word0.typeTag(user_entry.word0);
    const current_caps = Word0.caps(user_entry.word0);
    const requested_caps: u16 = @truncate(caps_arg);

    if (!capsAreSubset(current_caps, requested_caps, type_tag)) return errors.E_PERM;
    if (!restartPolicyMonotone(current_caps, requested_caps, type_tag)) return errors.E_PERM;

    user_entry.word0 = Word0.pack(slot, type_tag, requested_caps);

    // Spec §[capabilities].restrict (proposal §2.8): clearing a cap
    // bit that contributes to a refcount-bearing object's lifetime
    // must run the matching dec as if `delete` had been performed
    // for that bit. Today only `.port` encodes lifetime authority in
    // its caps (suspend / bind / recv); page_frame / device_region /
    // timer use slot-keyed lifetime which is unaffected by restrict.
    const cleared: u16 = current_caps & ~requested_caps;
    if (cleared != 0 and type_tag == .port) {
        const ref = typedRef(Port, entry.*) orelse return 0;
        const old_caps: port.PortCaps = @bitCast(current_caps);
        const new_caps: port.PortCaps = @bitCast(requested_caps);
        const port_lr = ref.lockIrqSave(@src()) catch return 0;
        const p = port_lr.ptr;
        // Bind-side dec never destroys; recv-side dec is the slab
        // teardown owner. Run the bind dec first so a handle holding
        // both `bind` and `recv` doesn't have its bind dec operate on
        // a freed slab if recv-side teardown beats it.
        if (old_caps.bind and !new_caps.bind) {
            port.decBindRef(p);
        }
        var dec_result: port.DecResult = .{ .destroyed = false, .pending_vcpus = null };
        if (old_caps.recv and !new_caps.recv) {
            dec_result = port.decRecvRef(p);
        }
        if (!dec_result.destroyed) {
            ref.unlockIrqRestore(port_lr.irq_state);
        } else {
            arch.cpu.restoreInterrupts(port_lr.irq_state);
        }
        port.finalizePendingVcpus(dec_result.pending_vcpus);
    }

    refreshSnapshot(cd, slot, entry);
    return 0;
}

/// `delete` syscall handler. Spec §[capabilities].delete.
///
/// Detaches the handle from the copy-derivation tree (reparenting any
/// children to the deleted handle's parent so a subsequent revoke on
/// an ancestor still reaches them — Spec §[capabilities].revoke
/// test 04), then runs the per-type release and clears the slot.
///
/// Lock order: `tree_mutex` → caller's domain gen-lock. Matches the
/// order taken by `derivation.revoke`/`derivation.derive`.
pub fn delete(caller: *anyopaque, handle: u64) i64 {
    if (handle & ~HANDLE_ARG_MASK != 0) return errors.E_INVAL;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const caller_dom_ref: ErasedSlabRef = @bitCast(ec.domain);

    const slot: u12 = @truncate(handle);
    return derivation.deleteAndDetach(caller_dom_ref, slot);
}

/// `revoke` syscall handler. Spec §[capabilities].revoke.
///
/// Walks the copy-derivation subtree under `handle` and releases every
/// transitive descendant; `handle` itself is left in place. See
/// `caps.derivation.revoke`.
pub fn revoke(caller: *anyopaque, handle: u64) i64 {
    if (handle & ~HANDLE_ARG_MASK != 0) return errors.E_INVAL;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const caller_dom_ref: ErasedSlabRef = @bitCast(ec.domain);
    return derivation.revoke(caller_dom_ref, handle);
}

/// `sync` syscall handler. Spec §[capabilities].sync.
pub fn sync(caller: *anyopaque, handle: u64) i64 {
    if (handle & ~HANDLE_ARG_MASK != 0) return errors.E_INVAL;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const cd_ref = ec.domain;
    const cd_lr = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = cd_lr.ptr;
    defer cd_ref.unlockIrqRestore(cd_lr.irq_state);

    const slot: u12 = @truncate(handle);
    const entry = resolveHandleOnDomain(cd, slot, null) orelse return errors.E_BADCAP;

    refreshSnapshot(cd, slot, entry);
    return 0;
}

// ── Internal helpers (used by every per-object syscall handler) ──────

/// Resolve a 12-bit handle id from the caller's table to the parallel
/// (Capability, KernelHandle) entries, validating reserved bits, that
/// the slot is in-use, and that the type tag matches `expected`.
///
/// `expected == null` skips the type-tag check (used by
/// `restrict`/`delete`/`revoke`/`sync` which all accept any type).
pub fn resolveHandleOnDomain(
    cd: *CapabilityDomain,
    slot: u12,
    expected: ?CapabilityType,
) ?*KernelHandle {
    if (@as(u16, slot) >= MAX_HANDLES_PER_DOMAIN) return null;

    const entry = &cd.kernel_table[slot];
    // Free slots are flagged by `ref.ptr == null` (see KernelHandle
    // doc comment for the two-state encoding). The free-list link
    // lives in `parent`; an in-use entry has `ref.ptr` set to the
    // underlying kernel object.
    if (entry.ref.ptr == null) return null;

    if (expected) |t| {
        const user_word0 = cd.user_table[slot].word0;
        if (Word0.typeTag(user_word0) != t) return null;
    }
    return entry;
}

/// Per-type delete dispatch — switch on `entry`'s type tag (read from
/// the parallel user `Capability`) and apply the type-specific delete
/// behavior. Refcount-lifetime types (Port, PageFrame, DeviceRegion,
/// Timer) call their `decHandleRef` to release their per-handle
/// increment; capability-domain-lifetime types (EC, VMAR, VM) and
/// system-lifetime IDC handles do not — those die only with the
/// owning domain. Spec §[capabilities].delete table.
pub fn releaseHandle(holder: *CapabilityDomain, slot: u12, entry: *KernelHandle) void {
    const user_entry = &holder.user_table[slot];
    const type_tag = Word0.typeTag(user_entry.word0);
    const caps_word = Word0.caps(user_entry.word0);

    switch (type_tag) {
        .capability_domain_self => {
            // SLOT_SELF tear-down is driven directly from
            // `caps.derivation.deleteAndDetach`'s slot==0 branch so it
            // can release `tree_mutex` and the CD `_gen_lock` between
            // the destroy's phase 1 and phase 2. Reaching this arm
            // means a caller routed a self-handle through `releaseHandle`
            // bypassing that path — surface it loudly rather than
            // silently leaking the domain.
            @panic("releaseHandle on capability_domain_self: route via deleteAndDetach SLOT_SELF instead");
        },
        .capability_domain => {
            // System-lifetime: dropping an IDC handle does not destroy
            // the referenced domain. No per-handle refcount.
        },
        .execution_context => {
            // Capability-domain lifetime: ECs die with their domain,
            // not with the last handle drop.
        },
        .page_frame => {
            // releaseHandle takes its own _gen_lock internally; pass
            // the bare *T pulled out of the SlabRef rather than holding
            // the lock at this layer.
            const ref = typedRef(PageFrame, entry.*) orelse return;
            page_frame.releaseHandle(ref.ptr);
        },
        .virtual_memory_address_region => {
            // Spec §[capabilities].delete (virtual_memory_address_region row):
            // "Delete unmaps everything installed, frees the address
            // range, releases the handle." VMAR holds exactly one handle
            // by construction (non-transferable), so the per-handle
            // delete is the same teardown that fires when the owning
            // capability domain dies — `destroyVmar` unmaps every
            // installed page, removes the VMAR from `domain.vars[]` so
            // the address range is reusable, and frees the slab slot.
            const ref = typedRef(VMAR, entry.*) orelse return;
            vmar.destroyVmar(ref.ptr);
        },
        .device_region => {
            const ref = typedRef(DeviceRegion, entry.*) orelse return;
            // Unlink this slot's IRQ-propagation node before dropping
            // the per-handle refcount. If we win the dec-to-zero the
            // dr slab slot is destroyed and reusing memory could
            // re-publish a fresh DeviceRegion whose `handle_list_head`
            // happens to match a stale node — clear the link first.
            // `decHandleRef` expects `dr._gen_lock` held; the same
            // lock guards both the list mutation and the dec.
            const dr_irq = ref.ptr._gen_lock.lockIrqSave(@src());
            device_region.removeHandleListNodeLocked(ref.ptr, &entry.dr_node);
            device_region.releaseHandleLocked(ref.ptr, dr_irq);
        },
        .port => {
            const ref = typedRef(Port, entry.*) orelse return;
            port.releaseHandle(ref.ptr, caps_word);
        },
        .reply => {
            // The reply slot holds a back-pointer to a suspended
            // sender EC; the entry's ref.ptr is that EC. Resume them
            // with E_ABANDONED if still parked. The reply is not a
            // separate slab object — clearing the slot below severs
            // the back-pointer. Spec §[capabilities] line 176: "If
            // the suspended sender is still waiting, resume them
            // with E_ABANDONED. Release handle."
            const ref = typedRef(ExecutionContext, entry.*) orelse return;
            const sender_lr = ref.lockIrqSave(@src()) catch return;
            const sender = sender_lr.ptr;
            defer ref.unlockIrqRestore(sender_lr.irq_state);
            port.resumeWithAbandoned(sender);
        },
        .virtual_machine => {
            const ref = typedRef(VirtualMachine, entry.*) orelse return;
            virtual_machine.releaseHandle(ref.ptr);
        },
        .timer => {
            const ref = typedRef(Timer, entry.*) orelse return;
            timer.decHandleRef(ref.ptr);
        },
        _ => {},
    }
}

/// Zero out both halves of `slot` in `holder`'s tables and push it
/// back onto the free list. Pure handle-table bookkeeping — caller has
/// already applied any object-side release semantics via `releaseHandle`
/// and unlinked the handle from any copy-derivation tree it participated
/// in (see `caps.derivation`).
pub fn clearAndFreeSlot(holder: *CapabilityDomain, slot: u12, entry: *KernelHandle) void {
    holder.user_table[slot] = .{ .word0 = 0, .field0 = 0, .field1 = 0 };
    entry.ref = .{};
    entry.parent = encodeFreeNext(holder.free_head);
    entry.first_child = .{};
    entry.next_sibling = .{};
    // device_region IRQ-propagation node (only ever populated for
    // `.device_region` slots): the per-type `releaseHandle` arm above
    // already unlinked it under `dr._gen_lock`. Zero the embedded
    // record so the slot starts clean for its next mint.
    entry.dr_node = .{};
    holder.free_head = @as(u16, slot);
    holder.free_count += 1;
}

/// Bit-subset cap check for `restrict` (and `copy` cap-mint paths).
/// `restart_policy` is handled separately via `restartPolicyMonotone`
/// because it's a numeric-monotone field, not bitwise subset.
fn capsAreSubset(current: u16, requested: u16, type_tag: CapabilityType) bool {
    const mask = restartPolicyMask(type_tag);
    const masked_current = current & ~mask;
    const masked_requested = requested & ~mask;
    // Bitwise subset: every bit set in requested must be set in current.
    return (masked_requested & ~masked_current) == 0;
}

/// Numeric-monotone reduction check for `restart_policy` cap field.
/// Per spec, "reducing" means new ≤ current along the privilege
/// ordering, not bitwise subset. Spec §[restart_semantics].
fn restartPolicyMonotone(current: u16, requested: u16, type_tag: CapabilityType) bool {
    const mask = restartPolicyMask(type_tag);
    if (mask == 0) return true;
    const shift: u4 = @intCast(@ctz(mask));
    const cur_val = (current & mask) >> shift;
    const req_val = (requested & mask) >> shift;
    return req_val <= cur_val;
}

/// Bit mask of the `restart_policy` field within a handle's caps word
/// for the given type, or 0 if the type carries no restart_policy.
/// Tracks the per-type cap layouts in §[execution_context], §[var],
/// §[port], §[page_frame], §[device_region], §[timer], §[capability_domain].
fn restartPolicyMask(type_tag: CapabilityType) u16 {
    return switch (type_tag) {
        .execution_context => 0b11 << 8, // EcCaps bits 8-9
        .virtual_memory_address_region => 0b11 << 9, // VmarCaps bits 9-10
        .port => 0b1 << 5, // PortCaps bit 5
        .page_frame => 0b1 << 7, // PageFrameCaps bit 7
        .device_region => 0b1 << 4, // DeviceRegionCaps bit 4
        .timer => 0b1 << 4, // TimerCaps bit 4
        .virtual_machine => 0b1 << 1, // VmCaps bit 1
        .capability_domain => 0b1 << 5, // IdcCaps bit 5
        else => 0,
    };
}

/// Refresh `entry`'s parallel user `Capability.field0`/`field1` from
/// authoritative kernel state (per-type snapshot). No-op for types
/// whose snapshot doesn't drift. Spec §[capabilities].sync.
///
/// The user table is mapped read-only into the holding domain but
/// kernel writes go through the kernel-side R/W view of the same
/// physical pages — see `CapabilityDomain.user_table` doc comment.
pub fn refreshSnapshot(holder: *CapabilityDomain, slot: u12, entry: *KernelHandle) void {
    const user_entry = &holder.user_table[slot];
    const type_tag = Word0.typeTag(user_entry.word0);
    switch (type_tag) {
        .execution_context => {
            const ref = typedRef(ExecutionContext, entry.*) orelse return;
            const lr = ref.lockIrqSave(@src()) catch return;
            defer ref.unlockIrqRestore(lr.irq_state);
            const ec = lr.ptr;
            // field0 bits 0-1 = priority (Spec §[execution_context])
            user_entry.field0 = @intFromEnum(ec.priority);
            // field1 bits 0-63 = affinity mask
            user_entry.field1 = ec.affinity;
        },
        .virtual_memory_address_region => {
            const ref = typedRef(VMAR, entry.*) orelse return;
            const lr = ref.lockIrqSave(@src()) catch return;
            defer ref.unlockIrqRestore(lr.irq_state);
            const v = lr.ptr;
            // VMAR field0 = base vaddr (immutable; refresh is harmless).
            user_entry.field0 = v.base_vaddr.addr;
            // VMAR field1: page_count[0..31], sz[32..33], cch[34..35],
            // cur_rwx[36..38], map[39..40], device[41..52]. cur_rwx,
            // map, and device are the kernel-mutable subset. The device
            // sub-field is the device's handle id in `holder`; resolve
            // it via a linear scan of the user table for the slot that
            // points at `v.device`. Mirrors the per-syscall fast path
            // in `kernel/memory/vmar.zig refreshVmarSnapshot`.
            var dev_id: u12 = 0;
            if (v.device) |dr_ref| {
                const dr_ptr: *const anyopaque = @ptrCast(dr_ref.ptr);
                var i: u16 = 0;
                while (i < holder.user_table.len) : (i += 1) {
                    const cap = holder.user_table[i];
                    if (Word0.typeTag(cap.word0) != .device_region) continue;
                    if (holder.kernel_table[i].ref.ptr == dr_ptr) {
                        dev_id = @intCast(i);
                        break;
                    }
                }
            }
            const new_field1 = (@as(u64, v.page_count)) |
                (@as(u64, @intFromEnum(v.sz)) << 32) |
                (@as(u64, @intFromEnum(v.cch)) << 34) |
                (@as(u64, v.cur_rwx) << 36) |
                (@as(u64, @intFromEnum(v.map)) << 39) |
                (@as(u64, dev_id) << 41);
            user_entry.field1 = new_field1;
        },
        .device_region => {
            const ref = typedRef(DeviceRegion, entry.*) orelse return;
            const lr = ref.lockIrqSave(@src()) catch return;
            defer ref.unlockIrqRestore(lr.irq_state);
            const dr = lr.ptr;
            // Spec §[device_region] handle ABI: field0 packs immutable
            // dev_type (bits 0-3) plus the type-specific addressing
            // fields — port_io: base_port (4-19), port_count (20-35);
            // mmio: base_paddr>>12 (4-51), size_pages (52-63). field1
            // = irq_count, owned by the IRQ handler — it propagates
            // increments directly to each copy's `field1` paddr via
            // `device_region.onIrq`. Refresh must NOT clobber it (would
            // race with concurrent IRQs and erase coalesced counts not
            // yet ack'd by userspace).
            var field0: u64 = @intFromEnum(dr.device_type);
            switch (dr.device_type) {
                .mmio => {
                    const m = dr.access.mmio;
                    field0 |= ((m.phys_base.addr >> 12) << 4) |
                        ((m.size >> 12) << 52);
                },
                .port_io => {
                    const pio = dr.access.port_io;
                    field0 |= (@as(u64, pio.base_port) << 4) |
                        (@as(u64, pio.port_count) << 20);
                },
                .framebuffer => {
                    const fb = dr.access.framebuffer;
                    field0 |= ((fb.phys_base.addr >> 12) << 4) |
                        ((fb.size >> 12) << 52);
                    // Framebuffers carry no IRQ, so the IRQ handler
                    // never touches field1 — stamp the geometry here
                    // and let it ride. Layout: width(16) | height(16)
                    // | stride(16) | pixel_format(8) | reserved(8).
                    user_entry.field1 =
                        @as(u64, fb.width) |
                        (@as(u64, fb.height) << 16) |
                        (@as(u64, fb.stride) << 32) |
                        (@as(u64, @intFromEnum(fb.pixel_format)) << 48);
                },
            }
            user_entry.field0 = field0;
        },
        .timer => {
            const ref = typedRef(Timer, entry.*) orelse return;
            const lr = ref.lockIrqSave(@src()) catch return;
            defer ref.unlockIrqRestore(lr.irq_state);
            const t = lr.ptr;
            // field0 = counter; field1 bit0 = armed, bit1 = periodic.
            user_entry.field0 = t.counter;
            user_entry.field1 = (@as(u64, @intFromBool(t.armed))) |
                (@as(u64, @intFromBool(t.periodic)) << 1);
        },
        .page_frame => {
            const ref = typedRef(PageFrame, entry.*) orelse return;
            const lr = ref.lockIrqSave(@src()) catch return;
            defer ref.unlockIrqRestore(lr.irq_state);
            const pf = lr.ptr;
            // §[page_frame] field0 layout: page_count[0..31] | sz[32..33].
            // page_count and sz are immutable, but refresh re-stamps
            // them so a kernel-side rewrite of the snapshot (e.g. a
            // future field0 layout extension) stays consistent.
            user_entry.field0 = (@as(u64, @intFromEnum(pf.sz)) << 32) |
                @as(u64, pf.page_count);
            // §[page_frame] field1 layout: mapcnt[0..31] | _reserved[32..63].
            // mapcnt is mutated by every map_pf / unmap / map_guest /
            // unmap_guest. Spec line 2017: "sync-refreshed on any
            // syscall touching the handle". Read it as an atomic load
            // because vmar.mappingInstall raises it via @atomicRmw
            // outside `_gen_lock`.
            const mapcnt = @atomicLoad(u32, &pf.mapcnt, .acquire);
            user_entry.field1 = @as(u64, mapcnt);
        },
        // Types whose snapshots don't drift. For these, no-op.
        .capability_domain_self,
        .capability_domain,
        .port,
        .reply,
        .virtual_machine,
        => {},
        _ => {},
    }
}

// Per-object release entry points live in each object's own file.
// They wrap the type-specific refcount/teardown machinery; this file
// invokes them through the per-module `releaseHandle` symbol so the
// switch in `releaseHandle` below stays purely dispatch.
