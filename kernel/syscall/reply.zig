const std = @import("std");
const stygia = @import("stygia");

const capability = stygia.caps.capability;
const device_region = stygia.devices.device_region;
const errors = stygia.syscall.errors;
const port = stygia.sched.port;

const Process = stygia.caps.process.Process;
const DeviceRegion = device_region.DeviceRegion;
const Thread = stygia.sched.thread.Thread;
const HANDLE_ARG_MASK = capability.HANDLE_ARG_MASK;
const PAddr = stygia.memory.address.PAddr;
const ReplyCaps = port.ReplyCaps;
const Word0 = capability.Word0;

/// Pair entry layout — Spec §[handle_attachments].
/// bits 0-11 source handle id, 16-31 caps, 32 move flag. All other bits
/// must be zero.
const PAIR_SOURCE_MASK: u64 = 0xFFF;
const PAIR_CAPS_MASK: u64 = @as(u64, 0xFFFF) << 16;
const PAIR_MOVE_BIT: u64 = @as(u64, 1) << 32;
const PAIR_VALID_MASK: u64 = PAIR_SOURCE_MASK | PAIR_CAPS_MASK | PAIR_MOVE_BIT;

const MAX_PAIR_COUNT: usize = 63;

/// Stack-allocated upper bound for pair entries read from the user
/// stack. Matches `MAX_PAIR_COUNT`.
const PAIR_BUF_LEN: usize = MAX_PAIR_COUNT;

/// Consumes a reply handle and resumes the suspended thread. State
/// modifications written to the receiver's event-state vregs (per
/// §[event_state] / §[vm_exit_state]) between recv and reply are applied
/// to the suspended thread's state on resume, gated by the `write` cap on the
/// thread handle that originated the binding (the suspending thread handle for
/// explicit suspend, the vCPU thread handle for vm_exit).
///
/// ```
/// reply -> void
///   syscall_num = 52
///   syscall word bits  0-11: syscall_num
///   syscall word bits 12-19: pair_count (0 for bare reply)
///   syscall word bits 20-31: reply_handle_id (12 bits)
///   syscall word bits 32-43: recv_port_handle_id (0 for no recv mode)
///   syscall word bits 44-63: _reserved
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
/// [test 03] returns E_TERM if the suspended thread was terminated before reply could deliver; the reply handle is consumed.
/// [test 04] on success, the reply handle is consumed (removed from the caller's table).
/// [test 05] on success when the originating thread handle had the `write` cap, the resumed thread's state reflects modifications written to the receiver's event-state vregs between recv and reply.
/// [test 06] on success when the originating thread handle did not have the `write` cap, the resumed thread's state matches its pre-suspension state, ignoring any modifications made by the receiver.
/// [test 07] on success, the suspended thread is resumed.
pub fn reply(caller: *anyopaque, syscall_word: u64, args: []const u64) i64 {
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
    const thread: *Thread = @ptrCast(@alignCast(caller));

    // Test 10 — pair_count range. 0 is the bare-reply path.
    if (@as(usize, pair_count) > MAX_PAIR_COUNT) return errors.E_INVAL;

    if (recv_port != 0) {
        const port_slot: u12 = @truncate(recv_port);
        const process_ref_p = thread.process;
        const lr_p = process_ref_p.lockIrqSave(@src()) catch return errors.E_BADCAP;
        const process_p = lr_p.ptr;
        const entry_p = capability.resolveHandleOnProcess(process_p, port_slot, .port);
        var has_recv = false;
        if (entry_p != null) {
            const port_caps_word: u16 = @truncate(Word0.caps(process_p.user_table[port_slot].word0));
            const port_caps: port.PortCaps = @bitCast(port_caps_word);
            has_recv = port_caps.recv;
        }
        process_ref_p.unlockIrqRestore(lr_p.irq_state);
        if (entry_p == null) return errors.E_BADCAP;
        if (!has_recv) return errors.E_PERM;
    }

    const reply_result = if (pair_count > 0)
        replyTransferInternal(thread, syscall_word, pair_count, args)
    else blk: {
        const slot: u12 = @truncate(reply_handle);
        const process_ref = thread.process;
        const lr = process_ref.lockIrqSave(@src()) catch break :blk errors.E_BADCAP;
        const process = lr.ptr;
        const entry_present = capability.resolveHandleOnProcess(process, slot, .reply) != null;
        process_ref.unlockIrqRestore(lr.irq_state);
        if (!entry_present) break :blk errors.E_BADCAP;
        break :blk port.reply(thread, reply_handle);
    };

    if (reply_result != errors.OK) return reply_result;

    if (recv_port != 0) {
        // Spec §[reply] tests 24/26: atomic recv-after-reply parks the
        // caller on the named port for the next event. The recv contract's
        // return word + vregs ride out via the iretq epilogue (port.recv
        // stages `pending_event_word` on synchronous match or suspend).
        return port.recv(thread, recv_port, 0);
    }

    return errors.OK;
}

/// Consumes a reply handle, resumes the suspended thread, and attaches N
/// handles to the resumption. The resumed thread's syscall word carries
/// `pair_count = N` and `tstart = S` (slot id of the first attached
/// handle in the resumed thread's process). State writes are applied per
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
/// [test 05] returns E_BADCAP if any pair entry's source handle id is not valid in the caller's process.
/// [test 06] returns E_PERM if any pair entry's caps are not a subset of the source handle's current caps.
/// [test 07] returns E_PERM if any pair entry with `move = 1` references a source handle that lacks the `move` cap.
/// [test 08] returns E_PERM if any pair entry with `move = 0` references a source handle that lacks the `copy` cap.
/// [test 09] returns E_INVAL if two pair entries reference the same source handle.
/// [test 10] returns E_TERM if the suspended thread was terminated before reply could deliver; the reply handle is consumed and no handle transfer occurs.
/// [test 11] returns E_FULL if the resumed thread's process handle table cannot accommodate N contiguous slots; the reply handle is NOT consumed and the caller's table is unchanged.
/// [test 12] on success, the reply handle is consumed; the resumed thread's syscall word `pair_count = N` and `tstart = S`; the next N slots [S, S+N) in the resumed thread's process contain the inserted handles per §[handle_attachments] (caps intersected with `ipc_rx` for IPC handles, verbatim otherwise).
/// [test 13] on success, source pair entries with `move = 1` are removed from the caller's table; entries with `move = 0` are not removed.
/// [test 14] on success when the originating thread handle had the `write` cap, the resumed thread's state reflects modifications written to the receiver's event-state vregs between recv and reply_transfer; otherwise modifications are discarded.
/// [test 15] on success, the suspended thread is resumed.
fn replyTransferInternal(caller: *Thread, syscall_word: u64, n: u8, args: []const u64) i64 {
    // Caller (`reply`) already validated the unified-syscall reserved
    // bits (44-63) and N ≤ 63. N == 0 is the bare-reply path and never
    // reaches here.
    std.debug.assert(n > 0 and @as(usize, n) <= MAX_PAIR_COUNT);

    const reply_handle: u64 = (syscall_word >> 20) & 0xFFF;
    const thread: *Thread = caller;
    const slot: u12 = @truncate(reply_handle);

    // Pre-resolve the reply handle so test 02 (xfer cap) can fire
    // before any pair-entry read — see tests/reply_transfer_02 header
    // ("the kernel rejects on the missing xfer cap before reading any
    // pair-entry vreg") — and so test 01 fires early when the slot is
    // outright empty. Test 04b (per-entry reserved-bit) must fire
    // before test 01 *only when the slot is occupied as a non-reply
    // handle* (per tests/reply_transfer_04 case B which uses
    // SLOT_SELF, an in-process process entry).
    const process_ref = thread.process;
    const lr_pre = process_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const process_pre = lr_pre.ptr;
    const slot_occupied = capability.resolveHandleOnProcess(process_pre, slot, null) != null;
    const reply_present = slot_occupied and
        capability.resolveHandleOnProcess(process_pre, slot, .reply) != null;
    var has_xfer = false;
    if (reply_present) {
        const caps_word = Word0.caps(process_pre.user_table[slot].word0);
        const reply_caps: ReplyCaps = @bitCast(caps_word);
        has_xfer = reply_caps.xfer;
    }
    process_ref.unlockIrqRestore(lr_pre.irq_state);

    // Test 01 — fires here iff the slot is unoccupied. An occupied
    // non-reply slot keeps going so test 04b can trip first.
    if (!slot_occupied) return errors.E_BADCAP;
    // Test 02 — xfer-cap check on a confirmed reply handle.
    if (reply_present and !has_xfer) return errors.E_PERM;

    var entries: [PAIR_BUF_LEN]u64 = undefined;
    const len: usize = n;
    const first_vreg: usize = 128 - @as(usize, n);
    if (args.len < 127) return errors.E_INVAL;
    var i: usize = 0;
    while (i < len) {
        entries[i] = args[first_vreg + i - 1];
        i += 1;
    }

    const pair_entries: []const u64 = entries[0..len];

    // Test 04b: per-entry reserved-bit check (fires before test 01 per
    // the reply_transfer_04 ladder).
    if (validatePairEntryBits(pair_entries)) |err| {
        return err;
    }
    // Test 09: intra-batch duplicate source ids.
    if (hasDuplicateSources(pair_entries)) {
        return errors.E_INVAL;
    }

    // Test 01: reply handle resolves as a reply. Deferred to here so
    // test 04b fires first against in-process non-reply slots.
    if (!reply_present) return errors.E_BADCAP;

    // Spec §[reply].reply_transfer per-entry gates (tests 05/06/07/08).
    // Resolved under the process lock so the check is atomic against
    // concurrent revoke/delete on the source handles. While the lock is
    // held we also stash decoded entries on the caller's thread for the
    // port-layer install pass — capturing each source's ErasedSlabRef
    // here pins the underlying object across the upcoming reply ops
    // even if the source slot is later cleared on a `move = 1` path.
    const lr2 = process_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const process = lr2.ptr;
    if (validatePairEntrySources(process, thread, pair_entries)) |err| {
        port.releasePendingPairEntries(thread);
        process_ref.unlockIrqRestore(lr2.irq_state);
        return err;
    }
    process_ref.unlockIrqRestore(lr2.irq_state);

    return port.replyTransfer(thread, reply_handle, n);
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
/// Caller holds `process._gen_lock`. Returns `null` on full pass; otherwise
/// the first failing test's error code. Stashes each decoded entry on
/// `thread.pending_pair_entries` as a side effect — the kernel-side
/// `port.replyTransfer` consumes the stash to install handles in the
/// resumed sender's process. `thread.pending_pair_count` is published only
/// on full pass to keep partial failure observably equivalent to "no
/// entries stashed" for cleanup / re-entry.
fn validatePairEntrySources(
    process: *Process,
    thread: *Thread,
    entries: []const u64,
) ?i64 {
    const source_process: capability.ErasedSlabRef = .{
        .ptr = process,
        .gen = @intCast(process._gen_lock.currentGen()),
    };
    var idx: usize = 0;
    while (idx < entries.len) : (idx += 1) {
        const entry = entries[idx];
        const slot: u12 = @truncate(entry & PAIR_SOURCE_MASK);
        const entry_caps: u16 = @truncate((entry >> 16) & 0xFFFF);
        const move_flag: bool = (entry & PAIR_MOVE_BIT) != 0;

        // Test 05: source handle must resolve in the caller's process.
        const src = capability.resolveHandleOnProcess(process, slot, null) orelse {
            thread.pending_pair_count = @intCast(idx);
            port.releasePendingPairEntries(thread);
            return errors.E_BADCAP;
        };

        const src_caps: u16 = @truncate(Word0.caps(process.user_table[slot].word0));

        // Test 06: requested caps must be a subset of the source
        // handle's current caps. Bitwise subset is correct for every
        // transferable handle type (none of them carry `restrict`'s
        // restart_policy enum special-case).
        if (entry_caps & ~src_caps != 0) {
            thread.pending_pair_count = @intCast(idx);
            port.releasePendingPairEntries(thread);
            return errors.E_PERM;
        }

        // Tests 07/08: move/copy authority. Bit 0 = `move`, bit 1 =
        // `copy` in the cap layout shared by transferable handle types.
        const has_move = (src_caps & 0x1) != 0;
        const has_copy = (src_caps & 0x2) != 0;
        if (move_flag) {
            if (!has_move) {
                thread.pending_pair_count = @intCast(idx);
                port.releasePendingPairEntries(thread);
                return errors.E_PERM;
            }
        } else {
            if (!has_copy) {
                thread.pending_pair_count = @intCast(idx);
                port.releasePendingPairEntries(thread);
                return errors.E_PERM;
            }
        }

        // Stash the decoded entry. Captures the source object's
        // ErasedSlabRef under `process._gen_lock` so the gen baked into the
        // ref matches a live object until at least the install phase.
        const obj_type = Word0.typeTag(process.user_table[slot].word0);
        thread.pending_pair_entries[idx] = .{
            .obj_ref = src.ref,
            .source_process = source_process,
            .source_instance = src.instance,
            .obj_type = obj_type,
            .source_caps = src_caps,
            .pending_ref_caps = 0,
            .caps = entry_caps,
            .move = move_flag,
            .src_slot = slot,
        };
        thread.pending_pair_entries[idx].pending_ref_caps = port.pendingRefCapsForEntry(thread.pending_pair_entries[idx]);
        port.acquirePendingPairEntryRef(thread.pending_pair_entries[idx]) catch {
            thread.pending_pair_count = @intCast(idx);
            port.releasePendingPairEntries(thread);
            return errors.E_BADCAP;
        };
    }
    thread.pending_pair_count = @intCast(entries.len);
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

    const thread: *Thread = @ptrCast(@alignCast(caller));
    const slot: u12 = @truncate(handle);

    const process_ref = thread.process;
    const lr = process_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const process = lr.ptr;
    const process_irq_state = lr.irq_state;

    const entry = capability.resolveHandleOnProcess(process, slot, .device_region) orelse {
        process_ref.unlockIrqRestore(process_irq_state);
        return errors.E_BADCAP;
    };
    const dr_ref = capability.typedRef(DeviceRegion, entry.*) orelse {
        process_ref.unlockIrqRestore(process_irq_state);
        return errors.E_BADCAP;
    };

    // Spec §[ack] test 02: returns E_PERM if [1] does not have the `irq`
    // cap. The cap word lives in user_table[slot].word0 bits 48-63 and
    // is sourced from the device_region cap layout in §[device_region]
    // (bit 3 = irq).
    const dev_caps_word: u16 = Word0.caps(process.user_table[slot].word0);
    const dev_caps: device_region.DeviceRegionCaps = @bitCast(dev_caps_word);
    if (!dev_caps.irq) {
        process_ref.unlockIrqRestore(process_irq_state);
        return errors.E_PERM;
    }

    // Resolve the physical address of the caller's `field1` slot in its
    // process's user_table — the futex-watch address Spec §[device_irq]
    // wakes on. The user_table page is identity-mapped via the kernel's
    // direct map, so taking `&` yields a valid kernel-VA the userio
    // helpers can translate.
    const field1_kva: u64 = @intFromPtr(&process.user_table[slot].field1);
    const field1_paddr = PAddr.fromInt(field1_kva);

    process_ref.unlockIrqRestore(process_irq_state);

    const drlr = dr_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const dr = drlr.ptr;
    defer dr_ref.unlockIrqRestore(drlr.irq_state);

    // Spec §[ack] test 03: returns E_INVAL if the device_region has no
    // IRQ delivery configured. `irq_source == IRQ_SOURCE_NONE` is the
    // not-configured sentinel (kernel/devices/device_region.zig).
    if (dr.irq_source == device_region.IRQ_SOURCE_NONE) {
        return errors.E_INVAL;
    }

    const prior = device_region.ack(dr, field1_paddr);
    return @bitCast(prior);
}
