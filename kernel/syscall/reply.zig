const std = @import("std");
const zag = @import("zag");

const capability = zag.caps.capability;
const cpu = zag.arch.dispatch.cpu;
const device_region = zag.devices.device_region;
const errors = zag.syscall.errors;
const port = zag.sched.port;

const CapabilityDomain = zag.caps.capability_domain.CapabilityDomain;
const DeviceRegion = device_region.DeviceRegion;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const HANDLE_ARG_MASK = capability.HANDLE_ARG_MASK;
const PAddr = zag.memory.address.PAddr;
const ReplyCaps = port.ReplyCaps;
const Word0 = capability.Word0;

/// Pair entry layout — Spec §[handle_attachments].
/// bits 0-11 source handle id, 16-31 caps, 32 move flag. All other bits
/// must be zero.
const PAIR_SOURCE_MASK: u64 = 0xFFF;
const PAIR_CAPS_MASK: u64 = @as(u64, 0xFFFF) << 16;
const PAIR_MOVE_BIT: u64 = @as(u64, 1) << 32;
const PAIR_VALID_MASK: u64 = PAIR_SOURCE_MASK | PAIR_CAPS_MASK | PAIR_MOVE_BIT;

const MIN_PAIR_COUNT: usize = 1;
const MAX_PAIR_COUNT: usize = 63;

/// Stack-allocated upper bound for pair entries read from the user
/// stack. Matches `MAX_PAIR_COUNT`.
const PAIR_BUF_LEN: usize = MAX_PAIR_COUNT;

/// Consumes a reply handle and resumes the suspended EC. State
/// modifications written to the receiver's event-state vregs (per
/// §[event_state] / §[vm_exit_state]) between recv and reply are applied
/// to the suspended EC's state on resume, gated by the `write` cap on the
/// EC handle that originated the binding (the suspending EC handle for
/// explicit suspend, the EC handle used at `bind_event_route` for fault
/// events, the vCPU EC handle for vm_exit).
///
/// ```
/// reply -> void
///   syscall_num = 38
///   syscall word bits  0-11: syscall_num
///   syscall word bits 12-23: reply_handle_id (12 bits)
///   syscall word bits 24-63: _reserved
/// ```
///
/// No self-handle cap required — the reply handle itself authorizes the
/// operation.
///
/// The reply handle id rides in the syscall word rather than vreg 1 so
/// the GPR-backed event-state vregs (1..13 on x86-64) survive intact
/// across the reply syscall. Receivers handling vm_exits can keep
/// modified guest GPRs in registers throughout the handler and on into
/// the syscall, preserving the L4-style IPC fast path.
///
/// [test 01] returns E_BADCAP if `reply_handle_id` is not a valid reply handle.
/// [test 02] returns E_INVAL if any reserved bits are set in the syscall word.
/// [test 03] returns E_TERM if the suspended EC was terminated before reply could deliver; the reply handle is consumed.
/// [test 04] on success, the reply handle is consumed (removed from the caller's table).
/// [test 05] on success when the originating EC handle had the `write` cap, the resumed EC's state reflects modifications written to the receiver's event-state vregs between recv and reply.
/// [test 06] on success when the originating EC handle did not have the `write` cap, the resumed EC's state matches its pre-suspension state, ignoring any modifications made by the receiver.
/// [test 07] on success, the suspended EC is resumed.
pub fn reply(caller: *anyopaque, syscall_word: u64) i64 {
    // Spec §[reply] unified syscall word:
    //   bits  0-11: syscall_num
    //   bits 12-19: pair_count (0..63; 0 = bare reply)
    //   bits 20-31: reply_handle_id
    //   bits 32-43: recv_port_handle_id (0 = no recv mode)
    //   bits 44-63: _reserved (must be 0 — test 02)
    const REPLY_RESERVED_MASK: u64 = ~@as(u64, 0xFFFFFFFFFFF);
    if (syscall_word & REPLY_RESERVED_MASK != 0) return errors.E_INVAL;

    const pair_count: u8 = @truncate((syscall_word >> 12) & 0xFF);
    const reply_handle: u64 = (syscall_word >> 20) & 0xFFF;
    const recv_port: u64 = (syscall_word >> 32) & 0xFFF;
    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));

    // Test 10 — pair_count range. 0 is the bare-reply path.
    if (@as(usize, pair_count) > MAX_PAIR_COUNT) return errors.E_INVAL;

    if (recv_port != 0) {
        const port_slot: u12 = @truncate(recv_port);
        const cd_ref_p = ec.domain;
        const lr_p = cd_ref_p.lockIrqSave(@src()) catch return errors.E_BADCAP;
        const cd_p = lr_p.ptr;
        const entry_p = capability.resolveHandleOnDomain(cd_p, port_slot, .port);
        var has_recv = false;
        if (entry_p != null) {
            const port_caps_word: u16 = @truncate(Word0.caps(cd_p.user_table[port_slot].word0));
            const port_caps: port.PortCaps = @bitCast(port_caps_word);
            has_recv = port_caps.recv;
        }
        cd_ref_p.unlockIrqRestore(lr_p.irq_state);
        if (entry_p == null) return errors.E_BADCAP;
        if (!has_recv) return errors.E_PERM;
    }

    const reply_result = if (pair_count > 0)
        replyTransferInternal(ec, syscall_word, pair_count)
    else blk: {
        const slot: u12 = @truncate(reply_handle);
        const cd_ref = ec.domain;
        const lr = cd_ref.lockIrqSave(@src()) catch break :blk errors.E_BADCAP;
        const cd = lr.ptr;
        const entry_present = capability.resolveHandleOnDomain(cd, slot, .reply) != null;
        cd_ref.unlockIrqRestore(lr.irq_state);
        if (!entry_present) break :blk errors.E_BADCAP;
        break :blk port.reply(ec, reply_handle);
    };

    if (reply_result != errors.OK) return reply_result;

    if (recv_port != 0) {
        // Spec §[reply] tests 24/26: atomic recv-after-reply parks the
        // caller on the named port for the next event. The recv contract's
        // return word + vregs ride out via the iretq epilogue (port.recv
        // stages `pending_event_word` on synchronous match or suspend).
        return port.recv(ec, recv_port, 0);
    }

    return errors.OK;
}

/// Consumes a reply handle, resumes the suspended EC, and attaches N
/// handles to the resumption. The resumed EC's syscall word carries
/// `pair_count = N` and `tstart = S` (slot id of the first attached
/// handle in the resumed EC's domain). State writes are applied per
/// `reply` semantics.
///
/// ```
/// reply_transfer([128-N..127] pair_entries) -> void
///   syscall_num = 39
///   syscall word bits  0-11: syscall_num
///   syscall word bits 12-19: N (1..63)
///   syscall word bits 20-31: reply_handle_id (12 bits)
///   syscall word bits 32-63: _reserved
///
///   [128-N..127]: pair entries packed per §[handle_attachments]
/// ```
///
/// Reply cap required on the reply handle: `xfer`.
///
/// The reply handle id rides in the syscall word rather than vreg 1 for
/// the same reason as `reply` — see the §[reply] note on the L4-style
/// IPC fast path.
///
/// [test 01] returns E_BADCAP if `reply_handle_id` is not a valid reply handle.
/// [test 02] returns E_PERM if the reply handle does not have the `xfer` cap.
/// [test 03] returns E_INVAL if N is 0 or N > 63.
/// [test 04] returns E_INVAL if any reserved bits are set in the syscall word or any pair entry.
/// [test 05] returns E_BADCAP if any pair entry's source handle id is not valid in the caller's domain.
/// [test 06] returns E_PERM if any pair entry's caps are not a subset of the source handle's current caps.
/// [test 07] returns E_PERM if any pair entry with `move = 1` references a source handle that lacks the `move` cap.
/// [test 08] returns E_PERM if any pair entry with `move = 0` references a source handle that lacks the `copy` cap.
/// [test 09] returns E_INVAL if two pair entries reference the same source handle.
/// [test 10] returns E_TERM if the suspended EC was terminated before reply could deliver; the reply handle is consumed and no handle transfer occurs.
/// [test 11] returns E_FULL if the resumed EC's domain handle table cannot accommodate N contiguous slots; the reply handle is NOT consumed and the caller's table is unchanged.
/// [test 12] on success, the reply handle is consumed; the resumed EC's syscall word `pair_count = N` and `tstart = S`; the next N slots [S, S+N) in the resumed EC's domain contain the inserted handles per §[handle_attachments] (caps intersected with `idc_rx` for IDC handles, verbatim otherwise).
/// [test 13] on success, source pair entries with `move = 1` are removed from the caller's table; entries with `move = 0` are not removed.
/// [test 14] on success when the originating EC handle had the `write` cap, the resumed EC's state reflects modifications written to the receiver's event-state vregs between recv and reply_transfer; otherwise modifications are discarded.
/// [test 15] on success, the suspended EC is resumed.
fn replyTransferInternal(caller: *ExecutionContext, syscall_word: u64, n: u8) i64 {
    // Caller (`reply`) already validated the unified-syscall reserved
    // bits (44-63) and N ≤ 63. N == 0 is the bare-reply path and never
    // reaches here.
    std.debug.assert(n > 0 and @as(usize, n) <= MAX_PAIR_COUNT);

    const reply_handle: u64 = (syscall_word >> 20) & 0xFFF;
    const ec: *ExecutionContext = caller;
    const slot: u12 = @truncate(reply_handle);

    // Pre-resolve the reply handle so test 02 (xfer cap) can fire
    // before any pair-entry read — see tests/reply_transfer_02 header
    // ("the kernel rejects on the missing xfer cap before reading any
    // pair-entry vreg") — and so test 01 fires early when the slot is
    // outright empty. Test 04b (per-entry reserved-bit) must fire
    // before test 01 *only when the slot is occupied as a non-reply
    // handle* (per tests/reply_transfer_04 case B which uses
    // SLOT_SELF, an in-domain capability_domain entry).
    const cd_ref = ec.domain;
    const lr_pre = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd_pre = lr_pre.ptr;
    const slot_occupied = capability.resolveHandleOnDomain(cd_pre, slot, null) != null;
    const reply_present = slot_occupied and
        capability.resolveHandleOnDomain(cd_pre, slot, .reply) != null;
    var has_xfer = false;
    if (reply_present) {
        const caps_word = Word0.caps(cd_pre.user_table[slot].word0);
        const reply_caps: ReplyCaps = @bitCast(caps_word);
        has_xfer = reply_caps.xfer;
    }
    cd_ref.unlockIrqRestore(lr_pre.irq_state);

    // Test 01 — fires here iff the slot is unoccupied. An occupied
    // non-reply slot keeps going so test 04b can trip first.
    if (!slot_occupied) return errors.E_BADCAP;
    // Test 02 — xfer-cap check on a confirmed reply handle.
    if (reply_present and !has_xfer) return errors.E_PERM;

    // Read pair entries from the user stack. Spec §[syscall_abi]: vreg
    // M for `firstStackVreg() ≤ M ≤ 127` lives at
    // `[user_sp + (M - firstStackVreg() + 1) * 8]` when the syscall
    // executes. Spec §[handle_attachments] places N entries at vregs
    // `[128-N..127]`. SMAP/PAN gates the load via userAccess{Begin,End}.
    var entries: [PAIR_BUF_LEN]u64 = undefined;
    const len: usize = n;
    const user_rsp = cpu.userStackPointer(ec.ctx);
    const first_stack_vreg = cpu.firstStackVreg();
    const first_vreg: u64 = 128 - @as(u64, n);
    const first_off: u64 = (first_vreg - first_stack_vreg + 1) * 8;

    cpu.userAccessBegin();
    var i: usize = 0;
    while (i < len) {
        const off = first_off + i * 8;
        const ptr: *const u64 = @ptrFromInt(user_rsp + off);
        entries[i] = ptr.*;
        i += 1;
    }
    cpu.userAccessEnd();

    const pair_entries: []const u64 = entries[0..len];

    // Test 04b: per-entry reserved-bit check (fires before test 01 per
    // the reply_transfer_04 ladder).
    if (validatePairEntryBits(pair_entries)) |err| return err;
    // Test 09: intra-batch duplicate source ids.
    if (hasDuplicateSources(pair_entries)) return errors.E_INVAL;

    // Test 01: reply handle resolves as a reply. Deferred to here so
    // test 04b fires first against in-domain non-reply slots.
    if (!reply_present) return errors.E_BADCAP;

    // Spec §[reply].reply_transfer per-entry gates (tests 05/06/07/08).
    // Resolved under the domain lock so the check is atomic against
    // concurrent revoke/delete on the source handles. While the lock is
    // held we also stash decoded entries on the caller's EC for the
    // port-layer install pass — capturing each source's ErasedSlabRef
    // here pins the underlying object across the upcoming reply ops
    // even if the source slot is later cleared on a `move = 1` path.
    const lr2 = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = lr2.ptr;
    if (validatePairEntrySources(cd, ec, pair_entries)) |err| {
        ec.pending_pair_count = 0;
        cd_ref.unlockIrqRestore(lr2.irq_state);
        return err;
    }
    cd_ref.unlockIrqRestore(lr2.irq_state);

    return port.replyTransfer(ec, reply_handle, n);
}

/// Reserved-bit check for every pair entry — Spec §[handle_attachments]
/// test 06.
fn validatePairEntryBits(entries: []const u64) ?i64 {
    for (entries) |entry| {
        if (entry & ~PAIR_VALID_MASK != 0) return errors.E_INVAL;
    }
    return null;
}

/// Per-entry source-id resolution + caps subset + move/copy authority
/// for `reply_transfer`. Spec §[reply].reply_transfer tests 05/06/07/08.
/// Caller holds `cd._gen_lock`. Returns `null` on full pass; otherwise
/// the first failing test's error code. Stashes each decoded entry on
/// `ec.pending_pair_entries` as a side effect — the kernel-side
/// `port.replyTransfer` consumes the stash to install handles in the
/// resumed sender's domain. `ec.pending_pair_count` is published only
/// on full pass to keep partial failure observably equivalent to "no
/// entries stashed" for cleanup / re-entry.
fn validatePairEntrySources(
    cd: *CapabilityDomain,
    ec: *ExecutionContext,
    entries: []const u64,
) ?i64 {
    var idx: usize = 0;
    while (idx < entries.len) : (idx += 1) {
        const entry = entries[idx];
        const slot: u12 = @truncate(entry & PAIR_SOURCE_MASK);
        const entry_caps: u16 = @truncate((entry >> 16) & 0xFFFF);
        const move_flag: bool = (entry & PAIR_MOVE_BIT) != 0;

        // Test 05: source handle must resolve in the caller's domain.
        const src = capability.resolveHandleOnDomain(cd, slot, null) orelse return errors.E_BADCAP;

        const src_caps: u16 = @truncate(Word0.caps(cd.user_table[slot].word0));

        // Test 06: requested caps must be a subset of the source
        // handle's current caps. Bitwise subset is correct for every
        // transferable handle type (none of them carry `restrict`'s
        // restart_policy enum special-case).
        if (entry_caps & ~src_caps != 0) return errors.E_PERM;

        // Tests 07/08: move/copy authority. Bit 0 = `move`, bit 1 =
        // `copy` in the cap layout shared by transferable handle types.
        const has_move = (src_caps & 0x1) != 0;
        const has_copy = (src_caps & 0x2) != 0;
        if (move_flag) {
            if (!has_move) return errors.E_PERM;
        } else {
            if (!has_copy) return errors.E_PERM;
        }

        // Stash the decoded entry. Captures the source object's
        // ErasedSlabRef under `cd._gen_lock` so the gen baked into the
        // ref matches a live object until at least the install phase.
        const obj_type = Word0.typeTag(cd.user_table[slot].word0);
        ec.pending_pair_entries[idx] = .{
            .obj_ref = src.ref,
            .obj_type = obj_type,
            .caps = entry_caps,
            .move = move_flag,
            .src_slot = slot,
        };
    }
    ec.pending_pair_count = @intCast(entries.len);
    return null;
}

/// Intra-batch source-id duplicate check — Spec §[handle_attachments]
/// test 07. O(N²) is fine: N ≤ 63 and the alternative (sort or bitmap)
/// would allocate.
fn hasDuplicateSources(entries: []const u64) bool {
    var i: usize = 0;
    while (i < entries.len) {
        const a: u12 = @truncate(entries[i] & PAIR_SOURCE_MASK);
        var j: usize = i + 1;
        while (j < entries.len) {
            const b: u12 = @truncate(entries[j] & PAIR_SOURCE_MASK);
            if (a == b) return true;
            j += 1;
        }
        i += 1;
    }
    return false;
}

/// Acknowledges a device IRQ counter. Per Spec §[device_region].ack:
/// the kernel atomically reads the caller's `field1.irq_count` back to
/// zero, signals EOI to the interrupt controller, unmasks the line,
/// and returns the prior counter value.
///
/// Spec gap: `ack` lives in §[device_region] only. Other handle types
/// (port, timer, reply, etc.) carry no per-handle ack semantics; ack on
/// them returns E_BADCAP.
///
/// ```
/// ack([1] handle) -> [1] prior_count
///   syscall_num = 26
///
///   [1] handle: device_region handle
/// ```
///
/// [test 01] returns E_BADCAP if [1] is not a valid device_region handle.
/// [test 02] returns E_INVAL if any reserved bits are set in [1].
/// [test 03] on success, [1].field1.irq_count is reset to zero, the
///           interrupt line's EOI is signaled, the line is unmasked, and
///           the return value is the counter value observed before the
///           reset.
pub fn ack(caller: *anyopaque, handle: u64) i64 {
    if (handle & ~HANDLE_ARG_MASK != 0) return errors.E_INVAL;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const slot: u12 = @truncate(handle);

    const cd_ref = ec.domain;
    const lr = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = lr.ptr;
    const cd_irq_state = lr.irq_state;

    const entry = capability.resolveHandleOnDomain(cd, slot, .device_region) orelse {
        cd_ref.unlockIrqRestore(cd_irq_state);
        return errors.E_BADCAP;
    };
    const dr_ref = capability.typedRef(DeviceRegion, entry.*) orelse {
        cd_ref.unlockIrqRestore(cd_irq_state);
        return errors.E_BADCAP;
    };

    // Resolve the physical address of the caller's `field1` slot in its
    // domain's user_table — the futex-watch address Spec §[device_irq]
    // wakes on. The user_table page is identity-mapped via the kernel's
    // direct map, so taking `&` yields a valid kernel-VA the userio
    // helpers can translate.
    const field1_kva: u64 = @intFromPtr(&cd.user_table[slot].field1);
    const field1_paddr = PAddr.fromInt(field1_kva);

    cd_ref.unlockIrqRestore(cd_irq_state);

    const drlr = dr_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const dr = drlr.ptr;
    defer dr_ref.unlockIrqRestore(drlr.irq_state);

    const prior = device_region.ack(dr, field1_paddr);
    return @bitCast(prior);
}
