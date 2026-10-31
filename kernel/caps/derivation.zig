//! Capability derivation tree. See docs/kernel/specv3.md §[capabilities].
//!
//! Every used `KernelHandle` slot carries three cross-domain links —
//! `parent`, `first_child`, `next_sibling` — that together form the copy
//! ancestry tree the `revoke` syscall walks.
//!
//! Tree shape:
//!   - The handle minted by a `create_*` syscall is a tree root: its
//!     `parent` link is null in the used state.
//!   - The handle minted as a copy via `derive` (driven by the
//!     handle-attachment paths in suspend/recv/reply_transfer) is hung
//!     under the source as the new head of `source.first_child`. Older
//!     siblings shift down via `next_sibling`.
//!   - `revoke(target)` releases every transitive descendant of
//!     `target` (DFS over `first_child`/`next_sibling`); the target
//!     itself is NOT released — Spec test 05.
//!   - `delete(target)` reparents `target`'s children to `target.parent`
//!     before clearing `target`'s slot, so a later `revoke` on any
//!     ancestor still reaches the descendant subtree (Spec test 04 —
//!     a moved descendant is still on the chain).
//!
//! Cross-domain locking: the tree spans capability domains, so naive
//! per-domain locking risks AB-BA when two domains hold cross-derived
//! handles. We take a single global `tree_mutex` for the whole tree
//! mutation and walk all participating domains with that single lock
//! held — gen validation on each domain reference still catches
//! freed-domain races. TODO: scope this lock per-tree (e.g. partition
//! by root) once profiling shows contention.
//!
//! NOTE: We intentionally do not store `prev_sibling`. The in-kernel
//! `delete` of a single handle therefore costs O(siblings) — scan from
//! `parent.first_child` until finding the predecessor and patching its
//! `next_sibling`. We can add `prev_sibling` (4 pointers per handle, +8B)
//! for O(1) splice if profiling shows that fanout per source is large
//! enough to matter. Most use cases have small fanout (a server hands a
//! port to a handful of clients), so for now we accept the linear cost.

const std = @import("std");
const stygia = @import("stygia");

const capability = stygia.caps.capability;
const capability_domain = stygia.caps.capability_domain;
const errors = stygia.syscall.errors;

const CapabilityDomain = capability_domain.CapabilityDomain;
const CapabilityType = capability.CapabilityType;
const ErasedSlabRef = capability.ErasedSlabRef;
const Thread = stygia.sched.thread.Thread;
const HandleLink = capability.HandleLink;
const KernelHandle = capability.KernelHandle;
const SlabRef = stygia.memory.allocators.secure_slab.SlabRef;
const SpinLock = stygia.utils.sync.SpinLock;

/// Defensive bound on tree-walk depth. Caps both the max depth a single
/// tree can reach and the sibling-chain length we will scan before
/// asserting corruption. Per-domain handle count is 4096; that bounds
/// single-domain depth, but a tree spanning N domains can reach
/// `N * 4096`. A flat 1<<20 ceiling is generous in practice.
const MAX_DEPTH: u32 = 1 << 20;
/// Single global mutex serializing every tree mutation. See module-
/// level note. Acquired by `derive` and `revoke` for the full duration
/// of their work. Each per-domain access still goes through that
/// domain's `_gen_lock` for staleness validation; the tree mutex only
/// orders concurrent tree mutations against each other.
///
/// Acquired with `lockIrqSaveOrdered(TREE_MUTEX_GROUP)` everywhere it is
/// taken.
///
/// KERNEL-WIDE ORDER: `tree_mutex` BEFORE any CapabilityDomain gen-lock,
/// with NO exceptions. The tree walks (`revoke`, `deleteAndDetach`,
/// `detachDyingDomainFromTree`) hold `tree_mutex` while blocking-
/// acquiring arbitrary third-party CD gen-locks via `lockEntrySkip`, so
/// ANY path that holds a CD gen-lock while acquiring `tree_mutex` forms
/// a real AB-BA with them. The old code let mint sites (suspend/recv/
/// reply pair transfers) call `derive`
/// with a CD lock held and waved the inversion off in this very comment
/// ("since tree_mutex is a single global mutex, AB-BA on tree_mutex
/// itself is impossible") — but the cycle was never tree-vs-tree, it
/// was tree-vs-CD, and it deadlocked live: `replyTransfer` on one core
/// holding the sender's CD and spinning on `tree_mutex`,
/// `detachDyingDomainFromTree` on another holding `tree_mutex` and
/// spinning on that same CD, both IRQ-masked, READY Threads (including the
/// test runner) stranded in a deaf core's run queue. Mint sites now
/// defer their `derive` calls until after their CD locks drop; the
/// ordered tag remains only to keep the tree-walk's structured
/// multi-CD acquires out of lockdep's pair-edge detection.
pub var tree_mutex: SpinLock = .{ .class = "caps.derivation.tree_mutex" };

/// Lockdep group tag for `tree_mutex`. Non-zero opts every acquisition
/// out of pair-edge cycle detection (see `SpinLock.lockIrqSaveOrdered`).
/// The tree_mutex is a single global lock; serialization is sufficient.
///
/// Exported so external callers that hold `tree_mutex` across calls into
/// `destroyPhase1` (e.g. `cleanupPartiallyCreatedCd`) can match this
/// group; mismatched ordered-group tags on the same lock would still
/// register a phantom edge in the cycle-detection registry.
pub const TREE_MUTEX_GROUP: u32 = 0x7245_5645; // "TREVE" — derivation tree mutex

/// Lockdep group tag for the per-CapabilityDomain gen-locks taken inside
/// `lockEntrySkip`. The cross-domain tree walk legitimately holds
/// multiple `*CapabilityDomain` gen-locks at once (a parent in domain A,
/// a child in domain B) — same lockdep class, two instances. The
/// `tree_mutex` outer serializer makes the same-class overlap structurally
/// safe: only one tree mutator runs at a time. The ordered tag opts
/// these CD acquires out of lockdep's same-class overlap check.
///
/// Exported so call sites that take the *first* CD gen-lock of a tree
/// mutation (revoke / delete / cleanupPartiallyCreatedCd / fault-path
/// SLOT_SELF teardown) can tag it with the same group. Without that, the
/// inner cross-domain CD acquire inside `lockEntrySkip` (this group) and
/// an outer un-grouped CD acquire (`ordered_group=0`) form a same-class
/// pair the lockdep checker rejects via `acquireOn`'s
/// `held.ordered_group != ordered_group` clause — both sides of the
/// pair must agree on the group for the opt-out to apply.
pub const TREE_DOMAIN_GROUP: u32 = 0x5452_4544; // "TRED" — tree-walk CD lock

// ── External API ─────────────────────────────────────────────────────

/// Release `handle`'s subtree in the copy-derivation tree.
/// Spec §[capabilities].revoke.
///
/// Walks every transitive descendant of the calling-domain handle DFS
/// over `first_child`/`next_sibling`, applies per-type release on each,
/// and clears its slot. Does NOT release `handle` itself (Spec test 05)
/// and does NOT touch any handle on the copy-ancestor side (Spec test
/// 06). After return, `handle.first_child` is null.
pub fn revoke(caller_domain: ErasedSlabRef, handle: u64) i64 {
    if (handle & ~capability.HANDLE_ARG_MASK != 0) return errors.E_INVAL;

    const slot: u12 = @truncate(handle);

    const tree_irq = tree_mutex.lockIrqSaveOrdered(@src(), TREE_MUTEX_GROUP);
    defer tree_mutex.unlockIrqRestore(tree_irq);

    // Tag the caller-domain acquire with `TREE_DOMAIN_GROUP` so the
    // sibling-chain walk's cross-domain CD acquires (also `TREE_DOMAIN_GROUP`)
    // don't trip lockdep's same-class overlap check. See
    // `TREE_DOMAIN_GROUP` doc comment for why both sides must agree.
    const cd_lr = caller_domain.lockTypedIrqSaveOrdered(CapabilityDomain, TREE_DOMAIN_GROUP) catch
        return errors.E_BADCAP;
    const cd = cd_lr.ptr;
    defer caller_domain.unlockTypedIrqRestore(CapabilityDomain, cd_lr.irq_state);

    const entry = capability.resolveHandleOnDomain(cd, slot, null) orelse
        return errors.E_BADCAP;
    assertInTree(entry);

    // Detach the entire `first_child` list and walk it. The target
    // itself remains in place, with `first_child` cleared.
    const head = entry.first_child;
    entry.first_child = .{};

    releaseSiblingChain(head, cd);
    return 0;
}

/// Splice a freshly-minted child handle into the copy-derivation tree
/// under an existing parent handle. Spec §[capabilities].revoke /
/// §[capabilities].Lifetimes.
///
/// The child slot was already published in `child_dom`'s kernel_table by
/// `mintHandle*`, with all three tree links zeroed. This function fixes
/// up:
///   - `child.parent           = (parent_dom, parent_slot)`
///   - `child.next_sibling     = parent.first_child` (push as new head)
///   - `parent.first_child     = (child_dom, child_slot)`
///
/// LOCK CONTRACT — the caller must hold NO CapabilityDomain gen-lock.
/// `derive` takes `tree_mutex` and then re-acquires both domains'
/// gen-locks itself, keeping the kernel-wide `tree_mutex → CD` order
/// intact. The old `held_dom` parameter let callers keep a CD lock
/// across this call, which established the inverse `CD → tree_mutex`
/// edge — autopsied live as a two-core AB-BA deadlock: one core in
/// `replyTransfer` holding the sender's CD and spinning on
/// `tree_mutex`, the other in `detachDyingDomainFromTree` holding
/// `tree_mutex` and spinning on that exact CD gen-lock. Both spun with
/// IRQs masked; the machine wedged with READY Threads (including the test
/// runner) stranded in a deaf core's run queue. Mint-then-derive
/// callers now run their derive loops AFTER dropping their CD locks.
///
/// Cycle prevention: walks the parent's ancestor chain and refuses to
/// install the link if `child` already appears as an ancestor of
/// `parent`. Spec doesn't pin this but a corrupt or buggy mint path
/// could otherwise create a cyclic chain that would loop revoke/delete
/// forever. Returns `false` on cycle (link not installed; child remains
/// a tree root), stale source (treated as no-op — the source is gone
/// so the alias has no live ancestor anyway), or a child slot whose
/// links are already populated (the deferred-derive window lets a
/// concurrent copy/delete touch the fresh slot first; linking over it
/// would corrupt the tree, dropping the link only costs revoke
/// reachability for a handle the racer already owns).
pub fn derive(
    parent_dom_ref: ErasedSlabRef,
    parent_slot: u12,
    child_dom_ref: ErasedSlabRef,
    child_slot: u12,
) bool {
    return deriveInternal(parent_dom_ref, parent_slot, null, child_dom_ref, child_slot);
}

pub fn deriveExpected(
    parent_dom_ref: ErasedSlabRef,
    parent_slot: u12,
    expected_parent_ref: ErasedSlabRef,
    expected_parent_type: CapabilityType,
    expected_parent_caps: u16,
    expected_parent_instance: u64,
    child_dom_ref: ErasedSlabRef,
    child_slot: u12,
) bool {
    _ = expected_parent_caps;
    return deriveInternal(parent_dom_ref, parent_slot, .{
        .ref = expected_parent_ref,
        .type_tag = expected_parent_type,
        .instance = expected_parent_instance,
    }, child_dom_ref, child_slot);
}

const ExpectedHandle = struct {
    ref: ErasedSlabRef,
    type_tag: CapabilityType,
    instance: u64,
};

pub const ExpectedDelete = struct {
    slot: u12,
    ref: ErasedSlabRef,
    type_tag: CapabilityType,
    caps: u16,
    instance: u64,
};

fn deriveInternal(
    parent_dom_ref: ErasedSlabRef,
    parent_slot: u12,
    expected_parent: ?ExpectedHandle,
    child_dom_ref: ErasedSlabRef,
    child_slot: u12,
) bool {
    const parent_link: HandleLink = .{ .domain = parent_dom_ref, .slot = parent_slot };
    const child_link: HandleLink = .{ .domain = child_dom_ref, .slot = child_slot };

    const tree_irq = tree_mutex.lockIrqSaveOrdered(@src(), TREE_MUTEX_GROUP);
    defer tree_mutex.unlockIrqRestore(tree_irq);

    const parent_le = lockEntrySkip(parent_link, .{}) orelse return false;
    defer unlockEntrySkip(parent_le, .{});
    if (expected_parent) |expected| {
        if (parent_le.entry.instance != expected.instance) return false;
        if (!erasedRefMatches(parent_le.entry.ref, expected.ref)) return false;
        const parent_dom: *CapabilityDomain = @ptrCast(@alignCast(parent_le.dom_ref.ptr.?));
        const parent_word0 = parent_dom.user_table[parent_slot].word0;
        if (capability.Word0.typeTag(parent_word0) != expected.type_tag) return false;
    }

    // Every further entry acquire in this call (the ancestor hops, the
    // child) must skip the domain whose gen-lock the parent acquire
    // just took — the same-CD shape (self-IDC capability derivation,
    // single-domain pair transfers) has parent and child in ONE domain,
    // and a second blocking acquire of the same gen-lock is a
    // self-deadlock (caught by lockdep as a recursive acquire). This is
    // the intra-call role the old `held_dom` parameter played; it now
    // derives from the parent lock itself rather than from a
    // caller-held lock.
    // caller-pinned: identity-only token. `self_held` is never
    // dereferenced — it is compared by address inside `lockEntrySkip` /
    // `ancestorChainContains` to decide which domain's gen-lock this
    // call already holds and must not re-acquire. The parent acquire
    // above holds that very gen-lock for the whole scope, so the slot
    // cannot be recycled underneath the comparison.
    const self_held: ?*CapabilityDomain = if (parent_link.domain.ptr) |p|
        @ptrCast(@alignCast(p))
    else
        null;

    // Cycle check: walk parent.parent.parent... — if any ancestor names
    // (child_dom, child_slot), refuse the link.
    if (ancestorChainContains(parent_le.entry, child_link, HeldDomains.one(self_held))) return false;

    const child_le = lockEntrySkip(child_link, HeldDomains.one(self_held)) orelse return false;
    defer unlockEntrySkip(child_le, HeldDomains.one(self_held));

    // The child slot is normally the caller's fresh mint with all three
    // tree links zeroed. Under the deferred-derive discipline the mint
    // and this link run in separate critical sections, so a concurrent
    // path may have already linked (or freed and re-minted) the slot —
    // bail rather than stomp the existing links.
    if (child_le.entry.parent.domain.ptr != null or
        child_le.entry.first_child.domain.ptr != null or
        child_le.entry.next_sibling.domain.ptr != null)
    {
        return false;
    }

    child_le.entry.parent = parent_link;
    child_le.entry.next_sibling = parent_le.entry.first_child;
    parent_le.entry.first_child = child_link;
    return true;
}

/// Like `deleteAndDetach`, but only consumes the slot if it still names
/// the object captured by the transfer validator. This keeps delayed
/// move cleanup from deleting an unrelated handle after source
/// delete/reuse in the original domain.
pub fn deleteAndDetachExpected(
    caller_domain: ErasedSlabRef,
    slot: u12,
    expected_ref: ErasedSlabRef,
    expected_type: CapabilityType,
    expected_caps: u16,
    expected_instance: u64,
) i64 {
    _ = expected_caps;
    if (slot == 0) return errors.E_BADCAP;

    const tree_irq = tree_mutex.lockIrqSaveOrdered(@src(), TREE_MUTEX_GROUP);
    defer tree_mutex.unlockIrqRestore(tree_irq);

    const cd_lr = caller_domain.lockTypedIrqSaveOrdered(CapabilityDomain, TREE_DOMAIN_GROUP) catch
        return errors.E_BADCAP;
    const cd = cd_lr.ptr;
    defer caller_domain.unlockTypedIrqRestore(CapabilityDomain, cd_lr.irq_state);

    const entry = capability.resolveHandleOnDomain(cd, slot, null) orelse
        return errors.E_BADCAP;
    if (entry.instance != expected_instance) return errors.E_BADCAP;
    if (!erasedRefMatches(entry.ref, expected_ref)) return errors.E_BADCAP;
    const word0 = cd.user_table[slot].word0;
    if (capability.Word0.typeTag(word0) != expected_type) return errors.E_BADCAP;

    detachForDelete(cd, slot, entry);
    capability.releaseHandle(cd, slot, entry);
    capability.clearAndFreeSlot(cd, slot, entry);
    return 0;
}

/// Atomically consume a batch of move sources from one caller domain.
///
/// Every source is validated while holding `tree_mutex` and the caller CD
/// gen-lock; deletion starts only after the full batch still names the
/// expected handle instances. This gives transfer-style callers an
/// all-or-nothing failure surface for moved source handles: stale input
/// discovered here reports E_BADCAP without consuming any earlier source.
pub fn deleteAndDetachExpectedBatch(
    caller_domain: ErasedSlabRef,
    expected: []const ExpectedDelete,
) i64 {
    const tree_irq = tree_mutex.lockIrqSaveOrdered(@src(), TREE_MUTEX_GROUP);
    defer tree_mutex.unlockIrqRestore(tree_irq);

    const cd_lr = caller_domain.lockTypedIrqSaveOrdered(CapabilityDomain, TREE_DOMAIN_GROUP) catch
        return errors.E_BADCAP;
    const cd = cd_lr.ptr;
    defer caller_domain.unlockTypedIrqRestore(CapabilityDomain, cd_lr.irq_state);

    for (expected) |item| {
        _ = item.caps;
        if (item.slot == 0) return errors.E_BADCAP;

        const entry = capability.resolveHandleOnDomain(cd, item.slot, null) orelse
            return errors.E_BADCAP;
        if (entry.instance != item.instance) return errors.E_BADCAP;
        if (!erasedRefMatches(entry.ref, item.ref)) return errors.E_BADCAP;
        const word0 = cd.user_table[item.slot].word0;
        if (capability.Word0.typeTag(word0) != item.type_tag) return errors.E_BADCAP;
    }

    for (expected) |item| {
        const entry = capability.resolveHandleOnDomain(cd, item.slot, null) orelse unreachable;
        detachForDelete(cd, item.slot, entry);
        capability.releaseHandle(cd, item.slot, entry);
        capability.clearAndFreeSlot(cd, item.slot, entry);
    }

    return 0;
}

/// Walk `start.parent.parent...` looking for a link that names `target`.
/// Returns true if `target` is an ancestor of (or equal to) `start`.
/// Used by `derive` to reject cycles: refusing to install
/// `parent → child` when `child` is already an ancestor of `parent`
/// short-circuits any subsequent revoke/delete walks that would
/// otherwise loop forever.
fn ancestorChainContains(
    start: *KernelHandle,
    target: HandleLink,
    held: HeldDomains,
) bool {
    var cur: HandleLink = start.parent;
    var depth: u32 = 0;
    while (cur.domain.ptr != null) {
        std.debug.assert(depth < MAX_DEPTH);
        if (linkMatchesLink(cur, target)) return true;
        const cur_le = lockEntrySkip(cur, held) orelse return false;
        const next = cur_le.entry.parent;
        unlockEntrySkip(cur_le, held);
        cur = next;
        depth += 1;
    }
    return false;
}

inline fn linkMatchesLink(a: HandleLink, b: HandleLink) bool {
    return a.domain.ptr == b.domain.ptr and a.slot == b.slot;
}

inline fn erasedRefMatches(a: ErasedSlabRef, b: ErasedSlabRef) bool {
    return a.ptr == b.ptr and a.gen == b.gen;
}

/// `delete` syscall driver. Spec §[capabilities].delete.
///
/// Takes `tree_mutex` then the caller's domain gen-lock (matching the
/// order in `derive`/`revoke`), detaches the handle from the
/// copy-derivation tree, runs the per-type release, and clears the
/// slot.
pub fn deleteAndDetach(caller_domain: ErasedSlabRef, slot: u12) i64 {
    // SLOT_SELF (CD self-destruct) takes neither `tree_mutex` nor the
    // CD lock across phase 2 of the destroy. Phase 1 still runs under
    // both locks (the CD gen-lock is the destroy gate); the locks are
    // dropped before the thread and VM tear-downs lock their own slab classes.
    // Otherwise the (CD._gen_lock → thread._gen_lock) and
    // (tree_mutex → thread._gen_lock)
    // edges registered by the in-line destroys close an AB-BA cycle
    // against any concurrent `port.recv` (CD → ...) or other delete /
    // revoke path that takes `tree_mutex` after touching an thread.
    if (slot == 0) {
        const tree_irq = tree_mutex.lockIrqSaveOrdered(@src(), TREE_MUTEX_GROUP);

        // Tag the CD acquire with `TREE_DOMAIN_GROUP` so the
        // `destroyPhase1`-driven `detachDyingDomainFromTree` walk (which
        // re-locks cross-domain CDs under the same group inside
        // `lockEntrySkip`) does not trip lockdep's same-class overlap
        // check.
        const cd_lr = caller_domain.lockTypedIrqSaveOrdered(CapabilityDomain, TREE_DOMAIN_GROUP) catch {
            tree_mutex.unlockIrqRestore(tree_irq);
            return errors.E_BADCAP;
        };
        const cd = cd_lr.ptr;

        const cd_ref = SlabRef(CapabilityDomain).init(cd, cd._gen_lock.currentGen());
        const caller_thread = stygia.sched.scheduler.currentThread();
        caller_domain.unlockTypedIrqRestore(CapabilityDomain, cd_lr.irq_state);
        tree_mutex.unlockIrqRestore(tree_irq);

        stygia.sched.thread.printPreReportTerminal(caller_thread, cd, "delete_slot_self");

        stygia.sched.scheduler.queueCurrentTeardown(.{
            .kind = .self_delete,
            .cd = cd_ref,
            .caller_thread = if (caller_thread) |thread|
                SlabRef(Thread).init(thread, thread._gen_lock.currentGen())
            else
                null,
        });
        if (caller_thread) |thread| {
            stygia.sched.thread.parkSelfFaulted(thread);
        }
        stygia.sched.scheduler.hopParkRun();
    }

    const tree_irq = tree_mutex.lockIrqSaveOrdered(@src(), TREE_MUTEX_GROUP);
    defer tree_mutex.unlockIrqRestore(tree_irq);

    // Tag the caller-domain acquire with `TREE_DOMAIN_GROUP` so
    // `detachForDelete`'s cross-domain CD acquires (also under that
    // group) don't trip lockdep's same-class overlap check.
    const cd_lr = caller_domain.lockTypedIrqSaveOrdered(CapabilityDomain, TREE_DOMAIN_GROUP) catch
        return errors.E_BADCAP;
    const cd = cd_lr.ptr;
    defer caller_domain.unlockTypedIrqRestore(CapabilityDomain, cd_lr.irq_state);

    const entry = capability.resolveHandleOnDomain(cd, slot, null) orelse
        return errors.E_BADCAP;

    detachForDelete(cd, slot, entry);
    capability.releaseHandle(cd, slot, entry);
    capability.clearAndFreeSlot(cd, slot, entry);
    return 0;
}

/// Sweep every live slot in a dying domain and detach each from the
/// copy-derivation tree before the domain's kernel_table is freed.
/// Used by `capability_domain.destroyPhase1` so cross-domain
/// parent/first_child/next_sibling links spliced into the dying
/// domain's slots are spliced out cleanly: descendants in other
/// domains reparent to the dying-slot's grandparent, ancestors in
/// other domains lose the dying-slot from their child list.
///
/// **Caller holds `tree_mutex`** (acquired with `TREE_MUTEX_GROUP`)
/// AND the dying domain's gen-lock. Both invariants are documented on
/// `destroyPhase1`. The walk's per-link `lockEntrySkip` re-locks
/// cross-domain CDs under `TREE_DOMAIN_GROUP`; the caller's CD lock
/// must therefore also be tagged with `TREE_DOMAIN_GROUP` (see
/// `cleanupPartiallyCreatedCd`, the SLOT_SELF arm of `deleteAndDetach`,
/// and the fault-path SLOT_SELF teardown in `port.fireMemoryFault`).
/// The held CD lock is passed through to `lockEntrySkip` so the walk
/// never re-acquires it on cross-domain links that loop back to the
/// dying domain.
///
/// Note: this only patches the tree links. The dying domain's slots
/// are NOT released here (per-type release happens in `destroyPhase2`'s
/// existing kernel_table walk for refcount-lifetime objects); we just
/// rewrite the cross-domain links so other domains' tree views stay
/// consistent.
pub fn detachDyingDomainFromTree(cd: *CapabilityDomain) void {
    var slot_idx: u16 = 0;
    while (slot_idx < capability.MAX_HANDLES_PER_DOMAIN) : (slot_idx += 1) {
        const entry = &cd.kernel_table[slot_idx];
        if (entry.ref.ptr == null) continue;
        // Slot is live. If it has any tree link (parent / sibling /
        // child) pointing OUT of this domain, the link must be
        // unwoven before the kernel_table memory disappears.
        // detachForDelete handles same-domain links via the
        // `entry_dom` skip rule and resets entry's own links to .{}.
        const has_tree_links =
            entry.parent.domain.ptr != null or
            entry.first_child.domain.ptr != null or
            entry.next_sibling.domain.ptr != null;
        if (!has_tree_links) continue;
        detachForDelete(cd, @intCast(slot_idx), entry);
    }
}

/// Detach `entry` from the copy-derivation tree. Reparents `entry`'s
/// children to its parent so `revoke` on an ancestor still reaches the
/// descendants — Spec §[capabilities].revoke test 04.
///
/// Caller has both `tree_mutex` and `entry_dom`'s gen-lock; this
/// function does NOT take either. Skips the gen-lock acquisition when
/// a traversed link names `entry_dom`.
fn detachForDelete(
    entry_dom: *CapabilityDomain,
    entry_slot: u12,
    entry: *KernelHandle,
) void {
    assertInTree(entry);

    const parent_link = entry.parent;
    const next_sibling = entry.next_sibling;
    const first_child = entry.first_child;

    // Reparent every child to entry.parent. Track the last child so
    // we can splice its next_sibling onto entry.next_sibling after.
    var cur = first_child;
    var last_child_link: ?HandleLink = null;
    var depth: u32 = 0;
    while (cur.domain.ptr != null) {
        std.debug.assert(depth < MAX_DEPTH);
        const c = lockEntrySkip(cur, HeldDomains.one(entry_dom)) orelse break;
        c.entry.parent = parent_link;
        last_child_link = cur;
        const nxt = c.entry.next_sibling;
        unlockEntrySkip(c, HeldDomains.one(entry_dom));
        if (nxt.domain.ptr == null) break;
        cur = nxt;
        depth += 1;
    }

    if (last_child_link) |last_link| {
        if (lockEntrySkip(last_link, HeldDomains.one(entry_dom))) |lc| {
            lc.entry.next_sibling = next_sibling;
            unlockEntrySkip(lc, HeldDomains.one(entry_dom));
        }
    }

    const replacement: HandleLink = if (first_child.domain.ptr != null) first_child else next_sibling;

    if (parent_link.domain.ptr != null) {
        if (lockEntrySkip(parent_link, HeldDomains.one(entry_dom))) |p| {
            // From here until the `unlockEntrySkip` below, this core holds
            // TWO CD gen-locks: `entry_dom` (taken by our caller) and the
            // parent link's domain (just taken above). The child-list walk
            // must skip BOTH. Passing only `entry_dom` — as this did — let
            // a sibling living in the PARENT's domain fail the skip test
            // and get blocking-acquired while this core already held it.
            // See `HeldDomains` for the full failure mode.
            //
            // caller-pinned: identity-only token, never dereferenced —
            // `HeldDomains.contains` compares by address, and the acquire
            // above pins that gen-lock for this whole scope.
            const parent_dom: ?*CapabilityDomain = if (parent_link.domain.ptr) |q|
                @ptrCast(@alignCast(q))
            else
                null;
            replaceLinkInChildList(
                p.entry,
                entry_dom,
                entry_slot,
                replacement,
                .{ .a = entry_dom, .b = parent_dom },
            );
            unlockEntrySkip(p, HeldDomains.one(entry_dom));
        }
    }
    // entry was a root (or parent dead): the children become roots
    // themselves. They've already had their parent links nulled
    // (via parent_link being .{}). There is nothing else to do.

    entry.parent = .{};
    entry.first_child = .{};
    entry.next_sibling = .{};
}

// ── Internal helpers ─────────────────────────────────────────────────

/// Pair of `(*CapabilityDomain, *KernelHandle)` returned by
/// `lockEntry` so callers can unlock symmetrically. `dom_ref` is the
/// erased ref the caller used to acquire the typed lock — kept so
/// `unlockEntrySkip` can release the same lock + apply the same
/// `held` skip rule. The actual `*CapabilityDomain` stays internal to
/// `lockEntrySkip`'s walk; callers reach the entry through `.entry`.
/// `irq_state` carries the IRQ state captured at acquire time when a
/// fresh gen-lock was taken (i.e. `same_held == false`); it is
/// undefined when the held-skip rule applied (the caller already
/// holds an outer lockIrqSave).
const LockedEntry = struct {
    dom_ref: ErasedSlabRef,
    entry: *KernelHandle,
    irq_state: u64 = 0,
    same_held: bool = false,
};

/// The set of CapabilityDomain gen-locks the current call already holds,
/// which `lockEntrySkip` must NOT try to acquire a second time.
///
/// This is a SET, not a single domain, because the tree walk genuinely
/// holds two at once: `detachForDelete` runs with the dying domain's
/// gen-lock held by its caller and then takes the PARENT link's domain
/// gen-lock before fixing up the parent's child list. Passing only the
/// dying domain down into `replaceLinkInChildList` meant a sibling that
/// lived in the parent's domain — the common case, since a child list is
/// usually rooted in one domain — failed the skip test and was
/// blocking-acquired while this very core already held it. That is a
/// recursive acquire of the same gen-lock with IRQs masked and
/// `tree_mutex` held: lockdep catches it as `panic_recursive` in Debug,
/// but `debug.active` is Debug-only, so in ReleaseSafe it is a silent
/// machine-wide wedge of exactly the shape stygia-9yp produced.
///
/// Two slots is sufficient and checked: no tree-walk path holds more
/// than the caller's domain plus one link's domain at a time.
const HeldDomains = struct {
    /// caller-pinned: bare `*T` rather than `SlabRef(T)` on purpose. A
    /// slot is only ever populated with a domain whose gen-lock the
    /// caller ALREADY holds, and it is dropped when that lock is
    /// released, so the slab slot cannot recycle while the field is
    /// non-null — a gen re-check would have nothing to catch. Matching
    /// against a stale generation is also the wrong test here: the set
    /// answers "is this the very lock I am standing on", which is a
    /// question about pointer identity, not liveness.
    a: ?*CapabilityDomain = null,
    /// caller-pinned: second slot, same contract as `a` above.
    b: ?*CapabilityDomain = null,

    inline fn one(d: ?*CapabilityDomain) HeldDomains {
        return .{ .a = d };
    }

    /// Identity comparison only — the domains are never dereferenced
    /// through this set, so a slot cannot go stale underneath it: the
    /// caller holds every gen-lock named here for the whole scope.
    inline fn contains(self: HeldDomains, raw: ?*anyopaque) bool {
        return self.find(raw) != null;
    }

    /// The already-held `*CapabilityDomain` matching `raw`, if any, so a
    /// skipped acquire can still reach the domain it did not re-lock.
    inline fn find(self: HeldDomains, raw: ?*anyopaque) ?*CapabilityDomain {
        const p = raw orelse return null;
        if (self.a) |x| if (@as(*anyopaque, @ptrCast(x)) == p) return x;
        if (self.b) |x| if (@as(*anyopaque, @ptrCast(x)) == p) return x;
        return null;
    }
};

/// Lock the holder domain of a tree link and return a pointer to the
/// referenced kernel-table entry. Returns null on stale domain or bad
/// link (out-of-range slot, free slot). Caller must call `unlockEntrySkip`.
///
/// `held` names a domain whose gen-lock the caller already holds; if
/// the link names `held`, the gen-lock acquisition is skipped (would
/// deadlock against the held lock).
fn lockEntrySkip(link: HandleLink, held: HeldDomains) ?LockedEntry {
    if (link.domain.ptr == null) return null;

    // caller-pinned: `.ptr` read as an identity-only key, never
    // dereferenced through. A lock bracket is impossible by
    // construction here — the whole point of the test is to decide
    // whether acquiring this gen-lock would be a RECURSIVE acquire of a
    // lock this core already holds, so locking to find out would be the
    // deadlock (stygia-wh7). A stale pointer is harmless: it can only
    // fail to match, and a miss takes the normal locking path below.
    const held_match = held.find(link.domain.ptr);
    const same_held = held_match != null;
    var irq_state: u64 = 0;
    const dom: *CapabilityDomain = if (held_match) |m| m else blk: {
        const lr = link.domain.lockTypedIrqSaveOrdered(CapabilityDomain, TREE_DOMAIN_GROUP) catch return null;
        irq_state = lr.irq_state;
        break :blk lr.ptr;
    };

    if (@as(u16, link.slot) >= capability.MAX_HANDLES_PER_DOMAIN) {
        if (!same_held) link.domain.unlockTypedIrqRestore(CapabilityDomain, irq_state);
        return null;
    }
    const entry = &dom.kernel_table[@as(u12, @intCast(link.slot))];
    if (entry.ref.ptr == null) {
        if (!same_held) link.domain.unlockTypedIrqRestore(CapabilityDomain, irq_state);
        return null;
    }
    return .{ .dom_ref = link.domain, .entry = entry, .irq_state = irq_state, .same_held = same_held };
}

fn unlockEntrySkip(le: LockedEntry, held: HeldDomains) void {
    // Must mirror `lockEntrySkip`'s predicate exactly, and callers must
    // pass the SAME set to both — a mismatched set here would either
    // leak the gen-lock or unlock one this call never took.
    if (held.contains(le.dom_ref.ptr)) return;
    le.dom_ref.unlockTypedIrqRestore(CapabilityDomain, le.irq_state);
}

/// Walk a sibling chain rooted at `head`, releasing each subtree DFS.
/// `caller_dom` is the calling domain — kept locked throughout — and
/// is unlocked transiently if a descendant lives in the same domain
/// (so `lockTyped` does not deadlock against the same gen-lock).
fn releaseSiblingChain(initial_head: HandleLink, caller_dom: *CapabilityDomain) void {
    var head = initial_head;
    var depth: u32 = 0;
    while (head.domain.ptr != null) {
        std.debug.assert(depth < MAX_DEPTH);
        const next = popSibling(&head, caller_dom) orelse break;
        releaseSubtree(next, caller_dom);
        depth += 1;
    }
}

/// Pop the head of a sibling chain, returning the popped link. Updates
/// `head` to the next sibling. Returns null if the chain is empty or
/// the popped link is unreachable (stale domain).
///
/// Locks the popped entry's holder domain transiently (skipping when
/// it is the caller's own domain, which is already locked).
fn popSibling(head: *HandleLink, caller_dom: *CapabilityDomain) ?HandleLink {
    const popped = head.*;
    if (popped.domain.ptr == null) return null;

    const same_caller = popped.domain.ptr == @as(*anyopaque, @ptrCast(caller_dom));
    var popped_irq_state: u64 = 0;
    const dom: *CapabilityDomain = if (same_caller) caller_dom else blk: {
        const lr = popped.domain.lockTypedIrqSaveOrdered(CapabilityDomain, TREE_DOMAIN_GROUP) catch {
            head.* = .{};
            return null;
        };
        popped_irq_state = lr.irq_state;
        break :blk lr.ptr;
    };
    defer if (!same_caller) popped.domain.unlockTypedIrqRestore(CapabilityDomain, popped_irq_state);

    if (@as(u16, popped.slot) >= capability.MAX_HANDLES_PER_DOMAIN) {
        head.* = .{};
        return null;
    }
    const entry = &dom.kernel_table[@as(u12, @intCast(popped.slot))];
    if (entry.ref.ptr == null) {
        head.* = .{};
        return null;
    }
    head.* = entry.next_sibling;
    entry.next_sibling = .{};
    entry.parent = .{};
    return popped;
}

/// Release the subtree rooted at `root_link`. DFS — descend into
/// `first_child` first, then process the node. The node is `release`d
/// per type, then `clearAndFreeSlot`d.
///
/// `caller_dom` is the calling domain's `*CapabilityDomain`, kept
/// locked throughout `revoke`. Used to skip a re-lock when a descendant
/// happens to live in the calling domain.
fn releaseSubtree(root: HandleLink, caller_dom: *CapabilityDomain) void {
    if (root.domain.ptr == null) return;

    const same_caller = root.domain.ptr == @as(*anyopaque, @ptrCast(caller_dom));
    var root_irq_state: u64 = 0;
    const dom: *CapabilityDomain = if (same_caller) caller_dom else blk: {
        const lr = root.domain.lockTypedIrqSaveOrdered(CapabilityDomain, TREE_DOMAIN_GROUP) catch return;
        root_irq_state = lr.irq_state;
        break :blk lr.ptr;
    };
    defer if (!same_caller) root.domain.unlockTypedIrqRestore(CapabilityDomain, root_irq_state);

    if (@as(u16, root.slot) >= capability.MAX_HANDLES_PER_DOMAIN) return;
    const slot: u12 = @intCast(root.slot);
    const entry = &dom.kernel_table[slot];
    if (entry.ref.ptr == null) return;

    // Recurse into children first.
    const child_head = entry.first_child;
    entry.first_child = .{};
    releaseSiblingChain(child_head, caller_dom);

    capability.releaseHandle(dom, slot, entry);
    capability.clearAndFreeSlot(dom, slot, entry);
}

/// Replace any link in `parent_entry.first_child` that names
/// `(target_dom, target_slot)` with `replacement`. Walks the
/// sibling chain by snapshotting each link, locking its holder, and
/// patching in place. If `replacement` is empty, the link is dropped
/// (the chain seams shut around it).
///
/// `held` names a domain whose gen-lock the caller already holds; the
/// walk skips re-acquisition for links that name it.
fn replaceLinkInChildList(
    parent_entry: *KernelHandle,
    target_dom: *CapabilityDomain,
    target_slot: u12,
    replacement: HandleLink,
    held: HeldDomains,
) void {
    if (linkMatches(parent_entry.first_child, target_dom, target_slot)) {
        parent_entry.first_child = replacement;
        return;
    }

    var prev_link = parent_entry.first_child;
    var depth: u32 = 0;
    while (prev_link.domain.ptr != null) {
        std.debug.assert(depth < MAX_DEPTH);
        const prev = lockEntrySkip(prev_link, held) orelse return;

        if (linkMatches(prev.entry.next_sibling, target_dom, target_slot)) {
            prev.entry.next_sibling = replacement;
            unlockEntrySkip(prev, held);
            return;
        }

        const next = prev.entry.next_sibling;
        unlockEntrySkip(prev, held);
        prev_link = next;
        depth += 1;
    }
}

/// Identity check: link names `(dom, slot)`.
inline fn linkMatches(link: HandleLink, dom: *CapabilityDomain, slot: u12) bool {
    return link.domain.ptr == @as(*anyopaque, @ptrCast(dom)) and
        @as(u12, @intCast(link.slot)) == slot;
}

/// Cheap structural check — `entry` is well-formed and sits in the
/// used state of the kernel table. Always-on (does not get compiled
/// out). Used as the entry-gate for both `derive` and `revoke`.
fn assertInTree(entry: *const KernelHandle) void {
    std.debug.assert(entry.ref.ptr != null);
    if (entry.parent.domain.ptr != null) {
        std.debug.assert(@as(u16, entry.parent.slot) < capability.MAX_HANDLES_PER_DOMAIN);
    }
    if (entry.first_child.domain.ptr != null) {
        std.debug.assert(@as(u16, entry.first_child.slot) < capability.MAX_HANDLES_PER_DOMAIN);
    }
    if (entry.next_sibling.domain.ptr != null) {
        std.debug.assert(@as(u16, entry.next_sibling.slot) < capability.MAX_HANDLES_PER_DOMAIN);
    }
}
