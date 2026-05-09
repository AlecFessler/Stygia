const stygia = @import("stygia");

const capability = stygia.caps.capability;
const errors = stygia.syscall.errors;
const execution_context = stygia.sched.execution_context;
const port_mod = stygia.sched.port;

const EcCaps = execution_context.EcCaps;
const EventType = execution_context.EventType;
const ExecutionContext = execution_context.ExecutionContext;
const Port = port_mod.Port;
const PortCaps = port_mod.PortCaps;
const Word0 = capability.Word0;

const HANDLE_MASK: u64 = 0xFFF;

/// Installs the kernel-held binding `(target, event_type) → port`. If a
/// binding already exists for `(target, event_type)`, it is replaced
/// atomically — there is no window during which the route falls back to
/// the no-route handling.
///
/// ```
/// bind_event_route([1] target, [2] event_type, [3] port) -> void
///   syscall_num = 36
///
///   [1] target:     EC handle
///   [2] event_type: u64; must be a registerable event type (1, 2, 3, or 6)
///   [3] port:       port handle
/// ```
///
/// EC cap required on [1]: `bind` if no prior route exists for `(target,
/// event_type)`; `rebind` if one does.
/// Port cap required on [3]: `bind`.
///
/// [test 01] returns E_BADCAP if [1] is not a valid EC handle.
/// [test 02] returns E_BADCAP if [3] is not a valid port handle.
/// [test 03] returns E_INVAL if [2] is not a registerable event type (i.e., not in {1, 2, 3, 6}).
/// [test 04] returns E_INVAL if any reserved bits are set in [1], [2], or [3].
/// [test 05] returns E_PERM if [3] does not have the `bind` cap.
/// [test 06] returns E_PERM if no prior route exists for ([1], [2]) and [1] does not have the `bind` cap.
/// [test 07] returns E_PERM if a prior route exists for ([1], [2]) and [1] does not have the `rebind` cap.
/// [test 08] on success, when [2] subsequently fires for [1], the EC is suspended and an event of type [2] is delivered on [3] per §[event_state] with the reply handle id placed in the receiver's syscall word `reply_handle_id` field.
/// [test 09] on success when a prior route existed, the replacement is observable atomically: every subsequent firing of [2] for [1] is delivered to [3], and no firing in the interval is delivered to the prior port or to the no-route fallback.
/// [test 10] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.
pub fn bindEventRoute(caller: *anyopaque, target: u64, event_type: u64, port: u64) i64 {
    if (target & ~HANDLE_MASK != 0) return errors.E_INVAL;
    if (port & ~HANDLE_MASK != 0) return errors.E_INVAL;
    const et: EventType = switch (event_type) {
        1 => .memory_fault,
        2 => .thread_fault,
        3 => .breakpoint,
        6 => .pmu_overflow,
        else => return errors.E_INVAL,
    };
    const slot_idx = execution_context.eventRouteSlot(et) orelse return errors.E_INVAL;

    // The work happens inside a labeled block so the domain/EC/port
    // locks all release via `defer` before we issue the snapshot refresh.
    // `capability.sync` re-acquires the domain lock; doing the refresh
    // inside the lock-holding region would self-deadlock on the GenLock
    // spin-acquire.
    const target_was_valid_handle, const rc = blk: {
        const ec_ptr: *ExecutionContext = @ptrCast(@alignCast(caller));
        const cd_ref = ec_ptr.domain;
        const lr = cd_ref.lockIrqSave(@src()) catch break :blk .{ false, errors.E_BADCAP };
        const cd = lr.ptr;
        defer cd_ref.unlockIrqRestore(lr.irq_state);

        const target_slot: u12 = @truncate(target);
        const ec_entry = capability.resolveHandleOnDomain(cd, target_slot, .execution_context) orelse
            break :blk .{ false, errors.E_BADCAP };

        const target_ec_ref = capability.typedRef(ExecutionContext, ec_entry.*) orelse
            break :blk .{ false, errors.E_BADCAP };
        const target_ec_lr = target_ec_ref.lockIrqSave(@src()) catch
            break :blk .{ false, errors.E_BADCAP };
        const target_ec = target_ec_lr.ptr;
        defer target_ec_ref.unlockIrqRestore(target_ec_lr.irq_state);

        // Past this point, target named a real EC slot — even if a later
        // step errors, spec test 10 still requires the field0/field1
        // refresh as a side effect.
        const port_slot: u12 = @truncate(port);
        const port_entry = capability.resolveHandleOnDomain(cd, port_slot, .port) orelse
            break :blk .{ true, errors.E_BADCAP };

        const port_caps_word: u16 = Word0.caps(cd.user_table[port_slot].word0);
        const port_caps: PortCaps = @bitCast(port_caps_word);
        if (!port_caps.bind) break :blk .{ true, errors.E_PERM };

        const ec_caps_word: u16 = Word0.caps(cd.user_table[target_slot].word0);
        const ec_caps: EcCaps = @bitCast(ec_caps_word);
        const had_prior_route = target_ec.event_routes[slot_idx] != null;
        if (had_prior_route) {
            if (!ec_caps.rebind) break :blk .{ true, errors.E_PERM };
        } else {
            if (!ec_caps.bind) break :blk .{ true, errors.E_PERM };
        }

        const target_port_ref = capability.typedRef(Port, port_entry.*) orelse
            break :blk .{ true, errors.E_BADCAP };
        const target_port_lr = target_port_ref.lockIrqSave(@src()) catch
            break :blk .{ true, errors.E_BADCAP };
        const target_port = target_port_lr.ptr;
        defer target_port_ref.unlockIrqRestore(target_port_lr.irq_state);

        break :blk .{ true, port_mod.installEventRoute(target_ec, target_port, slot_idx) };
    };

    if (target_was_valid_handle) _ = capability.sync(caller, target);
    return rc;
}

/// Removes the binding for `(target, event_type)`. Subsequent firings of
/// that event type for the EC fall back to the no-route handling defined
/// above.
///
/// ```
/// clear_event_route([1] target, [2] event_type) -> void
///   syscall_num = 37
///
///   [1] target:     EC handle
///   [2] event_type: u64; must be a registerable event type
/// ```
///
/// EC cap required on [1]: `unbind`.
///
/// [test 01] returns E_BADCAP if [1] is not a valid EC handle.
/// [test 02] returns E_PERM if [1] does not have the `unbind` cap.
/// [test 03] returns E_INVAL if [2] is not a registerable event type.
/// [test 04] returns E_INVAL if any reserved bits are set in [1] or [2].
/// [test 05] returns E_NOENT if no binding exists for ([1], [2]).
/// [test 06] on success, the binding for ([1], [2]) is removed; subsequent firings of [2] for [1] follow the no-route fallback above.
/// [test 07] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.
pub fn clearEventRoute(caller: *anyopaque, target: u64, event_type: u64) i64 {
    if (target & ~HANDLE_MASK != 0) return errors.E_INVAL;
    const et: EventType = switch (event_type) {
        1 => .memory_fault,
        2 => .thread_fault,
        3 => .breakpoint,
        6 => .pmu_overflow,
        else => return errors.E_INVAL,
    };
    const slot_idx = execution_context.eventRouteSlot(et) orelse return errors.E_INVAL;

    const target_was_valid_handle, const rc = blk: {
        const ec_ptr: *ExecutionContext = @ptrCast(@alignCast(caller));
        const cd_ref = ec_ptr.domain;
        const lr = cd_ref.lockIrqSave(@src()) catch break :blk .{ false, errors.E_BADCAP };
        const cd = lr.ptr;
        defer cd_ref.unlockIrqRestore(lr.irq_state);

        const target_slot: u12 = @truncate(target);
        const ec_entry = capability.resolveHandleOnDomain(cd, target_slot, .execution_context) orelse
            break :blk .{ false, errors.E_BADCAP };

        const target_ec_ref = capability.typedRef(ExecutionContext, ec_entry.*) orelse
            break :blk .{ false, errors.E_BADCAP };
        const target_ec_lr = target_ec_ref.lockIrqSave(@src()) catch
            break :blk .{ false, errors.E_BADCAP };
        const target_ec = target_ec_lr.ptr;
        defer target_ec_ref.unlockIrqRestore(target_ec_lr.irq_state);

        const ec_caps_word: u16 = Word0.caps(cd.user_table[target_slot].word0);
        const ec_caps: EcCaps = @bitCast(ec_caps_word);
        if (!ec_caps.unbind) break :blk .{ true, errors.E_PERM };

        if (target_ec.event_routes[slot_idx] == null) {
            break :blk .{ true, errors.E_NOENT };
        }

        break :blk .{ true, port_mod.removeEventRoute(target_ec, slot_idx) };
    };

    if (target_was_valid_handle) _ = capability.sync(caller, target);
    return rc;
}
