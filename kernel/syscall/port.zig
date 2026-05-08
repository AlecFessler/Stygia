const zag = @import("zag");

const cpu = zag.arch.dispatch.cpu;
const capability = zag.caps.capability;
const errors = zag.syscall.errors;
const port_obj = zag.sched.port;

const CapabilityDomainCaps = zag.caps.capability_domain.CapabilityDomainCaps;
const EcCaps = zag.sched.execution_context.EcCaps;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const PortCaps = port_obj.PortCaps;
const Word0 = capability.Word0;

/// §[handle_attachments] pair entry layout — bits 0-11 source handle id,
/// bits 16-31 caps, bit 32 move flag. All other bits must be zero.
const PAIR_SOURCE_MASK: u64 = 0xFFF;
const PAIR_CAPS_MASK: u64 = @as(u64, 0xFFFF) << 16;
const PAIR_MOVE_BIT: u64 = @as(u64, 1) << 32;
const PAIR_VALID_MASK: u64 = PAIR_SOURCE_MASK | PAIR_CAPS_MASK | PAIR_MOVE_BIT;

/// Maximum pair_count per §[handle_attachments]. The syscall word's
/// pair_count field is 8 bits (0..255), but only 0..63 are valid; 64..255
/// are reserved.
const MAX_PAIR_COUNT: usize = 63;

/// Maximum entries we read from the user stack at once. Stack-allocated
/// upper bound matching MAX_PAIR_COUNT.
const PAIR_BUF_LEN: usize = MAX_PAIR_COUNT;

/// Mask of the bits the caller is allowed to set in `create_port`'s
/// caps argument. Spec §[port].create_port packs caps into bits 0-15;
/// bits 16-63 are reserved and trip E_INVAL.
const CREATE_PORT_CAPS_MASK: u64 = 0xFFFF;

/// Allocates a port and returns a handle to it.
///
/// ```
/// create_port([1] caps) -> [1] handle
///   syscall_num = 33
///
///   [1] caps: u64 packed as
///     bits  0-15: caps       — caps on the port handle returned to the caller
///     bits 16-63: _reserved
/// ```
///
/// Self-handle cap required: `crpt`.
///
/// Returns E_NOMEM if insufficient kernel memory; returns E_FULL if the
/// caller's handle table has no free slot.
///
/// [test 01] returns E_PERM if the caller's self-handle lacks `crpt`.
/// [test 02] returns E_PERM if caps is not a subset of the caller's `port_ceiling`.
/// [test 03] returns E_INVAL if any reserved bits are set in [1].
/// [test 04] on success, the caller receives a port handle with caps = `[1].caps`.
pub fn createPort(caller: *anyopaque, caps: u64) i64 {
    if (caps & ~CREATE_PORT_CAPS_MASK != 0) return errors.E_INVAL;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const cd_ref = ec.domain;
    const lr = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = lr.ptr;
    const self_caps_word = Word0.caps(cd.user_table[0].word0);
    cd_ref.unlockIrqRestore(lr.irq_state);

    const self_caps: CapabilityDomainCaps = @bitCast(self_caps_word);
    if (!self_caps.crpt) return errors.E_PERM;

    // Port lifetime is governed by `recv_refcount` (Spec §[recv] tests
    // 04/05): a port stays alive while any handle carries `recv`. A
    // handle without `recv` cannot pin the slab, so a port minted with
    // no `recv` cap on the creator's handle would be unobservable —
    // the slab would never be reachable from any recv path and the
    // create syscall's success would be operationally meaningless.
    const requested_caps: PortCaps = @bitCast(@as(u16, @truncate(caps)));
    if (!requested_caps.recv) return errors.E_PERM;

    return port_obj.createPort(ec, caps);
}

/// Suspends the target execution context and delivers a suspension event
/// to a port. The event exposes the EC's state per §[event_state]; the
/// receiver may modify state and reply through the included reply
/// capability to resume the EC.
///
/// ```
/// suspend([1] target, [2] port) -> void
///   syscall_num = 34
///
///   [1] target: EC handle
///   [2] port: port handle (suspension event delivery target)
/// ```
///
/// EC cap required on [1]: `susp`. Visibility and writability of the
/// target's state in the suspension event are gated by [1]'s `read` and
/// `write` caps.
/// Port cap required on [2]: `suspend`. Additionally `xfer` if any handles
/// are attached in the syscall word's `pair_count`.
///
/// `[1]` may reference the calling EC; the syscall returns after the
/// calling EC is resumed.
///
/// Handle attachments in the suspension event payload follow
/// §[handle_attachments].
///
/// [test 01] returns E_BADCAP if [1] is not a valid EC handle.
/// [test 02] returns E_BADCAP if [2] is not a valid port handle.
/// [test 03] returns E_PERM if [1] does not have the `susp` cap.
/// [test 04] returns E_PERM if [2] does not have the `suspend` cap.
/// [test 05] returns E_INVAL if any reserved bits are set.
/// [test 06] returns E_INVAL if [1] references a vCPU.
/// [test 07] returns E_INVAL if [1] is already suspended.
/// [test 08] on success, the target EC stops executing.
/// [test 09] on success, a suspension event is delivered on [2].
/// [test 10] on success, when [1] has the `read` cap, the suspension event payload exposes the target's EC state per §[event_state]; otherwise the state in the payload is zeroed.
/// [test 11] on success, when [1] has the `write` cap, modifications written to the event payload are applied to the target's EC state on reply; otherwise modifications are discarded.
/// [test 12] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.
pub fn @"suspend"(caller: *anyopaque, target: u64, port: u64, pair_count: u8) i64 {
    if (target & ~capability.HANDLE_ARG_MASK != 0) return errors.E_INVAL;
    if (port & ~capability.HANDLE_ARG_MASK != 0) return errors.E_INVAL;

    // Spec §[handle_attachments]: pair_count occupies the syscall
    // word's bits 12-19 (0..255), but only 1..63 are valid attachment
    // counts. Any value above 63 (or 0 with attached entries) is a
    // structural violation of the attachment ABI.
    if (pair_count > MAX_PAIR_COUNT) return errors.E_INVAL;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const cd_ref = ec.domain;
    const lr = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = lr.ptr;
    const irq_state = lr.irq_state;

    // Spec §[suspend] gate order: [1] target validity (test 01) before
    // [2] port validity (test 02) before per-handle cap checks (tests
    // 03/04). The previous implementation checked port first, so an
    // invalid target with a valid port returned E_PERM (port lacks
    // bind) instead of E_BADCAP.
    const target_slot: u12 = @truncate(target);
    if (capability.resolveHandleOnDomain(cd, target_slot, .execution_context) == null) {
        cd_ref.unlockIrqRestore(irq_state);
        return errors.E_BADCAP;
    }

    const port_slot: u12 = @truncate(port);
    if (capability.resolveHandleOnDomain(cd, port_slot, .port) == null) {
        cd_ref.unlockIrqRestore(irq_state);
        return errors.E_BADCAP;
    }
    const ec_caps: EcCaps = @bitCast(Word0.caps(cd.user_table[target_slot].word0));
    const port_caps: PortCaps = @bitCast(Word0.caps(cd.user_table[port_slot].word0));

    cd_ref.unlockIrqRestore(irq_state);

    if (!ec_caps.susp) return errors.E_PERM;
    if (!port_caps.@"suspend") return errors.E_PERM;

    // Spec §[handle_attachments] test 01: when the suspending EC
    // attaches handles (pair_count > 0), [2] must carry the `xfer`
    // cap. This gate runs after the §[suspend] prelude tests so a
    // failure here is unambiguously the handle-attachment policy
    // rather than a §[suspend] cap miss.
    if (pair_count > 0 and !port_caps.xfer) return errors.E_PERM;

    if (pair_count > 0) {
        if (validatePairEntries(ec, pair_count)) |err| return err;
    }

    return port_obj.suspendEc(ec, target, port);
}

/// Reads `pair_count` pair entries from the suspending EC's user
/// stack at vregs `[128-N..127]` per §[syscall_abi] / §[handle_attachments]
/// and runs the per-entry validation gates: reserved-bit check
/// (test 06), intra-batch source-id duplicate check (test 07),
/// per-entry source-id resolution (test 02), per-entry caps subset
/// (test 03), and per-entry move/copy cap (tests 04/05). Returns
/// `null` when every entry passes; otherwise the error code that fires.
fn validatePairEntries(ec: *ExecutionContext, pair_count: u8) ?i64 {
    var entries: [PAIR_BUF_LEN]u64 = undefined;
    const n: usize = pair_count;

    // Spec §[syscall_abi]: vreg N for `firstStackVreg() ≤ N ≤ 127`
    // lives at `[user_sp + (N - firstStackVreg() + 1) * 8]` when the
    // syscall executes. With pair_count = N, entries occupy vregs
    // `[128-N..127]` per §[handle_attachments]. SMAP/PAN gates the load.
    const user_rsp = cpu.userStackPointer(ec.ctx);
    const first_stack_vreg = cpu.firstStackVreg();
    const first_vreg: u64 = 128 - @as(u64, n);
    const first_off: u64 = (first_vreg - first_stack_vreg + 1) * 8;

    cpu.userAccessBegin();
    var i: usize = 0;
    while (i < n) {
        const off = first_off + i * 8;
        const ptr: *const u64 = @ptrFromInt(user_rsp + off);
        entries[i] = ptr.*;
        i += 1;
    }
    cpu.userAccessEnd();

    // Test 06: any reserved bit set in any entry → E_INVAL.
    i = 0;
    while (i < n) {
        if (entries[i] & ~PAIR_VALID_MASK != 0) return errors.E_INVAL;
        i += 1;
    }

    // Test 07: two entries naming the same source handle → E_INVAL.
    // O(N²) scan — N ≤ 63 so the alternative (sort or bitmap) would
    // dwarf the win.
    i = 0;
    while (i < n) {
        const a: u12 = @truncate(entries[i] & PAIR_SOURCE_MASK);
        var j: usize = i + 1;
        while (j < n) {
            const b: u12 = @truncate(entries[j] & PAIR_SOURCE_MASK);
            if (a == b) return errors.E_INVAL;
            j += 1;
        }
        i += 1;
    }

    // Tests 02, 03, 04, 05: per-entry source-handle resolution under
    // the suspending EC's domain lock. Each entry is checked in turn
    // and the first failure short-circuits — spec does not pin
    // intra-list ordering, only that 02 fires on any invalid id, 03
    // on any cap-subset violation, etc.
    const cd_ref = ec.domain;
    const lr = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = lr.ptr;
    defer cd_ref.unlockIrqRestore(lr.irq_state);

    i = 0;
    while (i < n) {
        const slot: u12 = @truncate(entries[i] & PAIR_SOURCE_MASK);
        const entry_caps: u16 = @truncate((entries[i] >> 16) & 0xFFFF);
        const move_flag: bool = (entries[i] & PAIR_MOVE_BIT) != 0;

        const handle = capability.resolveHandleOnDomain(cd, slot, null) orelse return errors.E_BADCAP;

        const src_caps: u16 = @truncate(Word0.caps(cd.user_table[slot].word0));

        // Test 03: requested caps must be a subset of the source
        // handle's current caps. Bitwise subset suffices for every
        // cap type that ships through pair entries today (port,
        // execution_context, page_frame, var, device_region, timer,
        // capability_domain IDC) — none of them carry the 2-bit
        // restart_policy enum that `restrict` special-cases.
        if (entry_caps & ~src_caps != 0) return errors.E_PERM;

        // Tests 04/05: move/copy authority. Bit 0 = `move`, bit 1 =
        // `copy` in the cap layout shared by transferable handle
        // types. EC handles place those bits at the same indices, so
        // this check is type-agnostic for the handle types that can
        // ride a pair entry.
        const has_move = (src_caps & 0x1) != 0;
        const has_copy = (src_caps & 0x2) != 0;
        if (move_flag) {
            if (!has_move) return errors.E_PERM;
        } else {
            if (!has_copy) return errors.E_PERM;
        }

        // Stash the decoded entry on the suspending EC. The kernel
        // ref captures the source object at its current gen so the
        // recv side can mint a handle with a known-live ref. The
        // sender's source handle keeps the underlying object alive
        // across the suspend → recv rendezvous; the at-recv
        // mintHandleAlwaysNew installs a fresh slot in the receiver
        // domain with the entry's caps verbatim (or intersected with
        // idc_rx for IDC handles, when that path is wired).
        const obj_type = Word0.typeTag(cd.user_table[slot].word0);
        ec.pending_pair_entries[i] = .{
            .obj_ref = handle.ref,
            .obj_type = obj_type,
            .caps = entry_caps,
            .move = move_flag,
            .src_slot = slot,
        };

        i += 1;
    }

    // Publish the count last so a partial validation failure leaves
    // `pending_pair_count == 0` and the recv path doesn't try to
    // install half-decoded entries.
    ec.pending_pair_count = pair_count;

    return null;
}

/// Blocks waiting for an event on a port. On return, the kernel has
/// dequeued one suspended sender, allocated a reply handle for it in the
/// caller's table, allocated slots for any handles the sender attached,
/// written the suspended EC's state to the caller's vregs per
/// §[event_state] (and §[vm_exit_state] for vm_exits), and populated the
/// syscall word with the reply handle id, event_type, pair_count, and
/// tstart.
///
/// ```
/// recv([1] port) -> void
///   syscall_num = 35
///
///   syscall word return layout (per §[event_state]):
///     bits  0-11: _reserved
///     bits 12-19: pair_count           — handles attached by sender (0..63)
///     bits 20-31: tstart               — slot id of first attached handle
///     bits 32-43: reply_handle_id      — slot id of the reply handle
///     bits 44-48: event_type
///     bits 49-63: _reserved
///
///   [1] port: port handle
/// ```
///
/// Port cap required on [1]: `recv`.
///
/// When multiple senders are queued on the port, the kernel selects the
/// highest-priority sender; ties resolve FIFO. The chosen sender remains
/// suspended until the reply handle is consumed: `reply` resumes them,
/// `delete` on the reply handle resolves them with `E_ABANDONED`.
///
/// Returns E_CLOSED if the port has no bind-cap holders, no event_routes
/// targeting it, and no events queued — the call returns immediately
/// rather than blocking. If the port becomes terminally closed while a
/// recv is blocked, the call returns E_CLOSED.
///
/// Returns E_FULL if the caller's handle table cannot accommodate the
/// reply handle plus pair_count attached handles.
///
/// [test 01] returns E_BADCAP if [1] is not a valid port handle.
/// [test 02] returns E_PERM if [1] does not have the `recv` cap.
/// [test 03] returns E_INVAL if any reserved bits are set in [1].
/// [test 04] returns E_CLOSED if the port has no bind-cap holders, no event_routes targeting it, and no queued events.
/// [test 05] returns E_CLOSED when a recv is blocked on a port and the last bind-cap holder releases its handle while no event_routes target the port and no events are queued.
/// [test 06] returns E_FULL if the caller's handle table cannot accommodate the reply handle and pair_count attached handles.
/// [test 07] on success, the syscall word's reply_handle_id is the slot id of a reply handle inserted into the caller's table referencing the dequeued sender.
/// [test 08] on success, the syscall word's event_type equals the event_type that triggered delivery.
/// [test 09] on success when the sender attached N handles, the syscall word's pair_count = N and the next N table slots [tstart, tstart+N) contain the inserted handles per §[handle_attachments].
/// [test 10] on success when the sender attached no handles, pair_count = 0.
/// [test 11] on success when the suspending EC handle had the `read` cap, the receiver's vregs reflect the suspended EC's state per §[event_state] (or §[vm_exit_state] when event_type = vm_exit).
/// [test 12] on success when the suspending EC handle did not have the `read` cap, all event-state vregs are zeroed.
/// [test 13] when multiple senders are queued, the kernel selects the highest-priority sender; ties resolve FIFO.
/// [test 14] on success, until the reply handle is consumed, the dequeued sender remains suspended; deleting the reply handle resolves the sender with E_ABANDONED.
pub fn recv(caller: *anyopaque, port: u64, timeout_ns: u64) i64 {
    if (port & ~capability.HANDLE_ARG_MASK != 0) return errors.E_INVAL;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const cd_ref = ec.domain;
    const lr = cd_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const cd = lr.ptr;
    const irq_state = lr.irq_state;

    const port_slot: u12 = @truncate(port);
    if (capability.resolveHandleOnDomain(cd, port_slot, .port) == null) {
        cd_ref.unlockIrqRestore(irq_state);
        return errors.E_BADCAP;
    }
    const port_caps: PortCaps = @bitCast(Word0.caps(cd.user_table[port_slot].word0));

    cd_ref.unlockIrqRestore(irq_state);

    if (!port_caps.recv) return errors.E_PERM;

    return port_obj.recv(ec, port, timeout_ns);
}
