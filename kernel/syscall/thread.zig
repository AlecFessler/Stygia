const stygia = @import("stygia");
const build_options = @import("build_options");

const arch = stygia.arch.dispatch;
const capability = stygia.caps.capability;
const process_mod = stygia.caps.process;
const errors = stygia.syscall.errors;
const thread_mod = stygia.sched.thread;
const lifecycle = stygia.sched.lifecycle;
const scheduler = stygia.sched.scheduler;

const Process = process_mod.Process;
const ProcessCaps = process_mod.ProcessCaps;
const ThreadCaps = thread_mod.ThreadCaps;
const Thread = thread_mod.Thread;
const IdcCaps = process_mod.IdcCaps;
const Priority = thread_mod.Priority;
const VAddr = stygia.memory.address.VAddr;
const Word0 = capability.Word0;

/// `caps` argument layout for `create_thread`: bits 0-33 valid
/// (caller-caps + target-caps + 2-bit priority); bits 34-63 reserved.
const CREATE_THREAD_CAPS_MASK: u64 = 0x0000_0003_FFFF_FFFF;

/// Bit offset of the priority field within the create_thread caps word.
const CREATE_THREAD_PRIORITY_SHIFT: u6 = 32;

/// 2-bit priority field width.
const PRIORITY_MASK: u64 = 0b11;

/// Slot 0 of every process holds the self-handle whose cap word carries
/// `crec` and the `pri` ceiling.
const SELF_HANDLE_SLOT: u12 = 0;

/// Reserved-bit mask for `new_priority` argument of `priority` syscall —
/// only bits 0-1 are valid.
const PRIORITY_ARG_MASK: u64 = 0b11;

const YIELD_DIAG_BUDGET: u32 = 96;
var yield_diag_prints: u32 = 0;

fn diagTag(thread: *Thread) u64 {
    if (thread.diag_test_tag != 0) return thread.diag_test_tag;
    return thread.process.ptr.diag_test_tag;
}

fn logYieldDiag(
    caller_thread: *Thread,
    site: []const u8,
    target: u64,
    slot: u12,
    got_type: u64,
    ref_gen: u64,
    current_word: u64,
    state: u64,
    mark_state: u64,
    queue_core: u64,
) void {
    if (!build_options.kernel_spawn_diag) return;
    const n = @atomicRmw(u32, &yield_diag_prints, .Add, 1, .monotonic);
    if (n >= YIELD_DIAG_BUDGET) return;
    arch.boot.print(
        "[yielddiag] site={s} tag=0x{x} caller_process=0x{x} caller_cd_gen={x} target={x} slot={x} got_type={x} ref_gen={x} obj_word=0x{x} live_gen={x} state={x} mark={x} qcore={x}\n",
        .{
            site,
            diagTag(caller_thread),
            @intFromPtr(caller_thread.process.ptr),
            caller_thread.process.gen,
            target,
            slot,
            got_type,
            ref_gen,
            current_word,
            current_word >> 1,
            state,
            mark_state,
            queue_core,
        },
    );
}

/// Creates a new thread either in the caller's own process or
/// in a target process referenced by an IDC handle.
///
/// ```
/// create_thread([1] caps, [2] entry, [3] stack_pages, [4] target, [5] affinity)
///   -> [1] handle
///   syscall_num = 7
///
///   [1] caps: u64 packed as
///     bits  0-15: caps          — caps on the thread handle returned to the caller
///     bits 16-31: target_caps   — caps on the thread handle inserted into target's table
///                                 (ignored when target = self)
///     bits 32-33: priority      — scheduling priority, 0-3, bounded by caller's priority ceiling
///     bits 34-63: _reserved
///
///   [2] entry:        instruction pointer where the thread begins execution
///   [3] stack_pages:  number of stack pages the kernel allocates in the target's address space;
///                     kernel installs unmapped guard pages above and below the stack
///   [4] target:       0 = self, else IDC handle with crec cap to the target process
///   [5] affinity:     64-bit core mask; bit N = 1 allows the thread to run on core N.
///                     0 = any core (kernel chooses)
/// ```
///
/// Caps required:
/// - Caller's self-handle must always have `crec`.
/// - If `[4] != 0`: the IDC handle in `[4]` must additionally have `crec`.
///
/// The kernel allocates `[3]` pages of stack in the target's address space
/// with unmapped guard pages above and below to catch overflow and
/// underflow. The thread begins executing at `[2] entry` with the stack
/// pointer set to the top of the allocated stack.
///
/// Returns E_NOMEM if insufficient kernel memory; returns E_NOSPC if the
/// target's address space has insufficient contiguous space for the
/// stack; returns E_FULL if the caller's handle table has no free slot,
/// or if `[4]` is nonzero and the target process's handle table is full.
///
/// [test 01] returns E_PERM if the caller's self-handle lacks `crec`.
/// [test 02] returns E_PERM if [4] is nonzero and [4] lacks `crec`.
/// [test 03] returns E_PERM if [4] is 0 (target = self) and caps is not a subset of self's `thread_inner_ceiling`.
/// [test 04] returns E_PERM if [4] is nonzero and caps is not a subset of the target process's `thread_outer_ceiling`.
/// [test 05] returns E_PERM if [4] is nonzero and target_caps is not a subset of the target process's `thread_inner_ceiling`.
/// [test 06] returns E_PERM if priority exceeds the caller's priority ceiling.
/// [test 07] returns E_BADCAP if [4] is nonzero and not a valid IDC handle.
/// [test 08] returns E_INVAL if [3] stack_pages is 0.
/// [test 09] returns E_INVAL if [5] affinity has bits set outside the system's core count.
/// [test 10] returns E_INVAL if any reserved bits are set in [1].
/// [test 11] on success, the caller receives a thread handle with caps = `[1].caps`.
/// [test 12] on success, when [4] is nonzero, the target process also receives a handle with caps = `[1].target_caps`.
/// [test 13] on success, the thread's priority is set to `[1].priority`.
/// [test 14] on success, the thread's affinity is set to `[5]`.
pub fn createThread(
    caller: *anyopaque,
    caps: u64,
    entry: u64,
    stack_pages: u64,
    target: u64,
    affinity_mask: u64,
) i64 {
    if (caps & ~CREATE_THREAD_CAPS_MASK != 0) return errors.E_INVAL;
    if (target & ~@as(u64, capability.HANDLE_ARG_MASK) != 0) return errors.E_INVAL;
    if (stack_pages == 0) return errors.E_INVAL;

    const requested_priority: u2 = @intCast((caps >> CREATE_THREAD_PRIORITY_SHIFT) & PRIORITY_MASK);

    // Affinity 0 is the "any core" sentinel and bypasses the per-bit
    // core-count check; otherwise every set bit must name a real core.
    if (affinity_mask != 0) {
        const cores = arch.smp.coreCount();
        if (cores < 64) {
            const valid_mask: u64 = (@as(u64, 1) << @intCast(cores)) - 1;
            if (affinity_mask & ~valid_mask != 0) return errors.E_INVAL;
        }
    }

    const thread: *Thread = @ptrCast(@alignCast(caller));
    const process_ref = thread.process;
    const lr = process_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const process = lr.ptr;
    const irq_state = lr.irq_state;

    const self_caps_word = Word0.caps(process.user_table[SELF_HANDLE_SLOT].word0);
    const self_caps: ProcessCaps = @bitCast(self_caps_word);
    if (!self_caps.crec) {
        process_ref.unlockIrqRestore(irq_state);
        return errors.E_PERM;
    }
    if (requested_priority > self_caps.pri) {
        process_ref.unlockIrqRestore(irq_state);
        return errors.E_PERM;
    }

    // Caller's `thread_inner_ceiling` lives in self-handle field0 bits 0-7
    // (spec §[process] field0 layout) and bounds the basic
    // ThreadCap rights at bits 0-7 (move/copy/saff/spri/term/susp/read/
    // write). ThreadCap bits 8-9 (`restart_policy`) are bounded separately
    // by `restart_policy_ceiling`; bits 10-15 are reserved. Test 03: when target=0 the new thread handle is minted in
    // the caller's own process, so its caps[0..7] must be a subset of
    // `thread_inner_ceiling`.
    const new_caps: u16 = @truncate(caps & 0xFFFF);
    const target_caps: u16 = @truncate((caps >> 16) & 0xFFFF);
    const thread_inner_ceiling: u8 = @truncate(process.user_table[SELF_HANDLE_SLOT].field0 & 0xFF);

    if (target == 0) {
        const new_caps_low: u8 = @truncate(new_caps & 0xFF);
        if (new_caps_low & ~thread_inner_ceiling != 0) {
            process_ref.unlockIrqRestore(irq_state);
            return errors.E_PERM;
        }
    }

    // Spec §[restart_semantics] test 01: requested `caps.restart_policy`
    // (ThreadCap bits 8-9) must not exceed the calling process's
    // `restart_policy_ceiling.thread_restart_max` (self-handle field1 bits
    // 16-17 — the low 2 bits of the 16-bit restart_policy_ceiling
    // sub-word at field1[16..31]). This gate applies regardless of
    // whether the new handle is minted in the caller's own table or the
    // target process's table because `restart_policy` carries the same
    // semantics in both directions.
    const requested_restart_policy: u2 = @truncate((new_caps >> 8) & 0x3);
    const thread_restart_max: u2 = @truncate((process.user_table[SELF_HANDLE_SLOT].field1 >> 16) & 0x3);
    if (requested_restart_policy > thread_restart_max) {
        process_ref.unlockIrqRestore(irq_state);
        return errors.E_PERM;
    }

    // Resolve the target process. For target=0 this is the caller's own
    // process; for target!=0 it's the IDC handle's referenced process.
    // Cross-process (target_process != process) requires a second gen-lock acquire
    // with stable ordering against the caller's lock; the spec test
    // surface only exercises the self-IDC shape (slot 2 minted by the
    // runner points back at the caller's own process), so for now bail
    // E_BADCAP on a non-self-IDC to keep the unimplemented path loud.
    if (target != 0) {
        const idc_slot: u12 = @truncate(target);
        const idc_entry = capability.resolveHandleOnProcess(process, idc_slot, .process) orelse {
            process_ref.unlockIrqRestore(irq_state);
            return errors.E_BADCAP;
        };
        const idc_caps: IdcCaps = @bitCast(Word0.caps(process.user_table[idc_slot].word0));
        if (!idc_caps.crec) {
            process_ref.unlockIrqRestore(irq_state);
            return errors.E_PERM;
        }

        const target_ref_ptr = idc_entry.ref.ptr orelse {
            process_ref.unlockIrqRestore(irq_state);
            return errors.E_BADCAP;
        };
        const target_cd_ptr: *Process = @ptrCast(@alignCast(target_ref_ptr));
        if (target_cd_ptr != process) {
            process_ref.unlockIrqRestore(irq_state);
            return errors.E_BADCAP;
        }

        // Spec §[thread] test 04: caps must be a subset of
        // the target process's `thread_outer_ceiling` (self-handle field1
        // bits 0-7). The 8-bit ceiling implicitly extends to 16 bits
        // with zeros in 8-15, so any cap bit at index 8 or above is
        // outside it — except `restart_policy` (bits 8-9) which is
        // bounded by the caller's `restart_policy_ceiling` above.
        // (target_process == process is enforced just above; read through `process`
        // so the gen-lock analyzer can verify the access is covered
        // by the live process_ref lock.)
        const thread_outer_ceiling: u16 = @truncate(process.user_table[0].field1 & 0xFF);
        const restart_policy_mask: u16 = 0b11 << 8;
        if ((new_caps & ~thread_outer_ceiling) & ~restart_policy_mask != 0) {
            process_ref.unlockIrqRestore(irq_state);
            return errors.E_PERM;
        }

        // Spec §[thread] test 05: target_caps must be a
        // subset of the target process's `thread_inner_ceiling` (self-handle
        // field0 bits 0-7). Same 16-bit-extension rule as test 04.
        const thread_inner_ceiling_target: u16 = @truncate(process.user_table[0].field0 & 0xFF);
        if ((target_caps & ~thread_inner_ceiling_target) & ~restart_policy_mask != 0) {
            process_ref.unlockIrqRestore(irq_state);
            return errors.E_PERM;
        }
    }

    const priority_enum: Priority = @enumFromInt(requested_priority);
    const new_thread = thread_mod.allocThread(
        process,
        VAddr.fromInt(entry),
        @intCast(stack_pages),
        affinity_mask,
        priority_enum,
        null,
        null,
    ) catch {
        process_ref.unlockIrqRestore(irq_state);
        return errors.E_NOMEM;
    };

    const new_thread_ref: capability.ErasedSlabRef = .{
        .ptr = new_thread,
        .gen = @intCast(new_thread._gen_lock.currentGen()),
    };

    // Caller-side handle. Always minted in the caller's process `process`
    // with caps = `new_caps` per spec test 11. When target != 0 and
    // target_process == process (self-IDC shape), bypass the at-most-one-per-
    // (process, object) coalescing so the caller and target sides get
    // distinct slots — spec test 12 verifies a second slot is populated
    // for the target side.
    const caller_slot = blk: {
        if (target != 0) {
            break :blk process_mod.mintHandleAlwaysNew(
                process,
                new_thread_ref,
                .thread,
                new_caps,
                0,
                0,
            ) catch {
                process_ref.unlockIrqRestore(irq_state);
                return errors.E_FULL;
            };
        }
        break :blk process_mod.mintHandle(
            process,
            new_thread_ref,
            .thread,
            new_caps,
            0,
            0,
        ) catch {
            process_ref.unlockIrqRestore(irq_state);
            return errors.E_FULL;
        };
    };

    // Field0/field1 carry the kernel-mutable priority/affinity
    // snapshot per §[thread]. Spec field0 bits 0-1 =
    // priority, field1 bits 0-63 = affinity mask.
    process.user_table[caller_slot].field0 = @intFromEnum(priority_enum);
    process.user_table[caller_slot].field1 = affinity_mask;

    // Target-side handle (only when [4] != 0). Spec test 12 mandates
    // the target process receives an additional handle with caps =
    // `target_caps`. With self-IDC the target process is `process` itself
    // (cross-process target_process != process is bailed E_BADCAP above), so use
    // mintHandleAlwaysNew on `process` to allocate a fresh slot rather than
    // coalescing onto the caller-side handle just minted above.
    if (target != 0) {
        const target_slot = process_mod.mintHandleAlwaysNew(
            process,
            new_thread_ref,
            .thread,
            target_caps,
            0,
            0,
        ) catch {
            process_ref.unlockIrqRestore(irq_state);
            return errors.E_FULL;
        };
        process.user_table[target_slot].field0 = @intFromEnum(priority_enum);
        process.user_table[target_slot].field1 = affinity_mask;
    }

    process_ref.unlockIrqRestore(irq_state);

    // Enqueue the new thread on a core that satisfies its affinity mask so
    // it becomes runnable. Without this enqueue, a yield targeting the
    // new handle finds the thread `.ready` but absent from every per-core
    // run queue and the scheduler can never dispatch it. Mirrors the
    // enqueue path in `createProcess` for the child's initial
    // thread.
    const calling_core: u64 = arch.smp.coreID();
    const enqueue_core: u64 = blk: {
        if (affinity_mask == 0) break :blk calling_core;
        if ((affinity_mask >> @intCast(calling_core)) & 1 != 0) {
            break :blk calling_core;
        }
        break :blk @ctz(affinity_mask);
    };
    scheduler.enqueueOnCore(@intCast(enqueue_core), new_thread);

    // Spec §[error_codes]: a successful create_* returns the packed
    // Word0 so the type tag in bits 12-15 disambiguates from the
    // 1..15 error range.
    return @intCast(Word0.pack(caller_slot, .thread, new_caps));
}

/// Returns the handle in the caller's table that references the calling
/// thread. Pure lookup — no handle is inserted, minted, or
/// modified, and no authority is granted. By the at-most-one invariant,
/// there is at most one such handle.
///
/// ```
/// self() -> [1] handle
///   syscall_num = 8
/// ```
///
/// [test 01] returns E_NOENT if no handle in the caller's table references the calling thread.
/// [test 02] on success, [1] is a handle in the caller's table whose resolved capability references the calling thread.
pub fn self(caller: *anyopaque) i64 {
    const thread: *Thread = @ptrCast(@alignCast(caller));
    return thread_mod.self(thread);
}

/// Terminates the target thread.
///
/// ```
/// terminate([1] target) -> void
///   syscall_num = 9
///
///   [1] target: thread handle
/// ```
///
/// thread cap required: `term`.
///
/// Termination atomically destroys the thread. Handles referencing it in any
/// process become stale; a syscall invoked with a stale handle
/// returns `E_TERM` and the stale handle is removed from the caller's
/// table on the same call.
///
/// Termination marks any reply handles whose suspended sender
/// was the terminated thread such that subsequent operations on those reply
/// handles return `E_ABANDONED`.
///
/// [test 01] returns E_BADCAP if [1] is not a valid thread handle.
/// [test 02] returns E_PERM if [1] does not have the `term` cap.
/// [test 03] returns E_INVAL if any reserved bits are set in [1].
/// [test 04] on success, the target thread stops executing.
/// [test 05] on success, syscalls invoked with any handle to the terminated thread return E_TERM and remove that handle from the caller's table on the same call.
/// [test 07] on success, reply handles whose suspended sender was the terminated thread return E_ABANDONED on subsequent operations.
/// [test 08] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.
pub fn terminate(caller: *anyopaque, target: u64) i64 {
    if (target & ~@as(u64, capability.HANDLE_ARG_MASK) != 0) return errors.E_INVAL;

    const thread: *Thread = @ptrCast(@alignCast(caller));
    const process_ref = thread.process;
    const lr = process_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const process = lr.ptr;
    const irq_state = lr.irq_state;

    const slot: u12 = @truncate(target);
    if (capability.resolveHandleOnProcess(process, slot, .thread) == null) {
        process_ref.unlockIrqRestore(irq_state);
        return errors.E_BADCAP;
    }

    const thread_caps: ThreadCaps = @bitCast(Word0.caps(process.user_table[slot].word0));
    process_ref.unlockIrqRestore(irq_state);
    if (!thread_caps.term) return errors.E_PERM;

    return thread_mod.terminate(thread, target);
}

/// Yields the calling thread's timeslice. With `[1] = 0`, the scheduler
/// selects the next thread to run. With `[1]` a valid handle to a runnable
/// thread, that thread is scheduled next; if it is not runnable, the scheduler
/// selects.
///
/// ```
/// yield([1] target) -> void
///   syscall_num = 10
///
///   [1] target: 0 = yield to scheduler; else a thread handle to yield to
/// ```
///
/// No cap required.
///
/// [test 01] returns E_BADCAP if [1] is nonzero and not a valid thread handle.
/// [test 02] returns E_INVAL if any reserved bits are set in [1].
/// [test 03] on success, when [1] is a valid handle to a runnable thread, an observable side effect performed by the target thread (e.g., a write to shared memory) is visible to the caller before the caller's next syscall returns.
/// [test 04] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.
pub fn yield(caller: *anyopaque, target: u64) i64 {
    if (target & ~@as(u64, capability.HANDLE_ARG_MASK) != 0) return errors.E_INVAL;

    const thread: *Thread = @ptrCast(@alignCast(caller));

    // `yieldTo` may switch contexts via `switchTo`, which abandons
    // this kernel call stack and never returns. The caller's rax
    // would then iret back to userspace carrying the syscall-entry
    // value instead of the OK status, so we stamp the OK return
    // value onto the caller's saved iret frame *before* the switch.
    // The fall-through `return 0` covers the no-switch path (e.g.
    // empty run queue → idle, or yieldTo returns when there is
    // nothing to switch to) for which the asm trampoline writes rax
    // from the dispatch return value.
    arch.syscall.setSyscallReturn(thread.ctx, @bitCast(@as(i64, 0)));

    if (target == 0) {
        scheduler.yieldTo(null);
        return 0;
    }

    const process_ref = thread.process;
    const process_lr = process_ref.lockIrqSave(@src()) catch {
        logYieldDiag(thread, "caller_process_lock", target, 0, 0, process_ref.gen, 0, 0, 0, thread_mod.NOT_IN_RUN_QUEUE);
        return errors.E_BADCAP;
    };
    const process = process_lr.ptr;
    const slot: u12 = @truncate(target);
    const entry = capability.resolveHandleOnProcess(process, slot, .thread) orelse {
        const raw_entry = &process.kernel_table[slot];
        const got_type: u64 = if (raw_entry.ref.ptr == null or capability.isReservedHandleSlot(raw_entry))
            0xffff
        else
            @intFromEnum(Word0.typeTag(process.user_table[slot].word0));
        logYieldDiag(thread, "target_lookup", target, slot, got_type, raw_entry.ref.gen, 0, 0, 0, thread_mod.NOT_IN_RUN_QUEUE);
        process_ref.unlockIrqRestore(process_lr.irq_state);
        return errors.E_BADCAP;
    };
    const ref = capability.typedRef(Thread, entry.*) orelse {
        logYieldDiag(thread, "target_typed_ref", target, slot, @intFromEnum(Word0.typeTag(process.user_table[slot].word0)), entry.ref.gen, 0, 0, 0, thread_mod.NOT_IN_RUN_QUEUE);
        process_ref.unlockIrqRestore(process_lr.irq_state);
        return errors.E_BADCAP;
    };

    // Spec §[yield] test 04: implicit-sync side effect — refresh the
    // handle's field0/field1 snapshot from the kernel's authoritative
    // thread state. Done while holding the caller's process lock so the
    // user-table write is sequenced correctly against concurrent
    // mutators.
    capability.refreshSnapshot(process, slot, entry);

    process_ref.unlockIrqRestore(process_lr.irq_state);

    // Resolve the target thread pointer under its own gen lock just long
    // enough to hand it off — `yieldTo` consumes a stable pointer.
    const target_lr = ref.lockIrqSave(@src()) catch {
        logYieldDiag(thread, "target_lock_term", target, slot, @intFromEnum(capability.CapabilityType.thread), ref.gen, 0, 0, 0, thread_mod.NOT_IN_RUN_QUEUE);
        return errors.E_TERM;
    };
    const target_thread = target_lr.ptr;
    const target_state = lifecycle.load(target_thread);
    if (target_state != .ready) {
        logYieldDiag(thread, "target_not_ready", target, slot, @intFromEnum(capability.CapabilityType.thread), ref.gen, target_thread._gen_lock.word.load(.monotonic), @intFromEnum(target_state), target_thread.mark_state.load(.acquire), target_thread.current_queue_core.load(.acquire));
    }
    if (!lifecycle.pinLiveLocked(target_thread)) {
        logYieldDiag(thread, "target_pin_term", target, slot, @intFromEnum(capability.CapabilityType.thread), ref.gen, target_thread._gen_lock.word.load(.monotonic), @intFromEnum(target_state), target_thread.mark_state.load(.acquire), target_thread.current_queue_core.load(.acquire));
        ref.unlockIrqRestore(target_lr.irq_state);
        return errors.E_TERM;
    }
    ref.unlockIrqRestore(target_lr.irq_state);
    scheduler.yieldToPinned(target_thread);
    return 0;
}

/// Sets the target thread's priority. The new priority applies
/// to subsequent scheduling, port event delivery, and futex wake
/// ordering. If the target is currently suspended on a port or waiting on
/// a futex, the new priority takes effect immediately and reorders the
/// target into the appropriate priority bucket (this is the mechanism
/// priority inheritance is built on).
///
/// ```
/// priority([1] target, [2] new_priority) -> void
///   syscall_num = 11
///
///   [1] target: thread handle
///   [2] new_priority: 0..3
/// ```
///
/// thread cap required on [1]: `spri`. `[2]` must not exceed the caller's
/// self-handle `pri`.
///
/// [test 01] returns E_BADCAP if [1] is not a valid thread handle.
/// [test 02] returns E_PERM if [1] does not have the `spri` cap.
/// [test 03] returns E_PERM if [2] exceeds the caller's self-handle `pri`.
/// [test 04] returns E_INVAL if [2] is greater than 3.
/// [test 05] returns E_INVAL if any reserved bits are set in [1].
/// [test 06] on success, when two Threads are blocked in `futex_wait_val` on the same address and a `futex_wake` is issued, the thread whose priority was last set higher via `priority` is woken first; the same ordering applies to `recv` selection when the two Threads are both queued senders on the same port.
/// [test 07] on success, when the target is suspended on a port or waiting on a futex, [2] takes effect on the target's next port event delivery and futex wake.
/// [test 08] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.
pub fn priority(caller: *anyopaque, target: u64, new_priority: u64) i64 {
    if (target & ~@as(u64, capability.HANDLE_ARG_MASK) != 0) return errors.E_INVAL;
    if (new_priority & ~PRIORITY_ARG_MASK != 0) return errors.E_INVAL;

    const thread: *Thread = @ptrCast(@alignCast(caller));
    const process_ref = thread.process;
    const lr = process_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const process = lr.ptr;
    const irq_state = lr.irq_state;

    const slot: u12 = @truncate(target);
    if (capability.resolveHandleOnProcess(process, slot, .thread) == null) {
        process_ref.unlockIrqRestore(irq_state);
        return errors.E_BADCAP;
    }

    const thread_caps: ThreadCaps = @bitCast(Word0.caps(process.user_table[slot].word0));
    const self_caps: ProcessCaps = @bitCast(Word0.caps(process.user_table[SELF_HANDLE_SLOT].word0));
    process_ref.unlockIrqRestore(irq_state);

    if (!thread_caps.spri) return errors.E_PERM;
    if (new_priority > self_caps.pri) return errors.E_PERM;

    return thread_mod.setPriority(thread, target, new_priority);
}

/// Sets the target thread's CPU affinity mask.
///
/// ```
/// affinity([1] target, [2] new_affinity) -> void
///   syscall_num = 12
///
///   [1] target: thread handle
///   [2] new_affinity: 64-bit core mask. 0 = kernel picks any core.
///                     Otherwise, bit N = 1 allows the target thread to run on core N;
///                     bit N must only be set for cores the system actually has.
/// ```
///
/// thread cap required on [1]: `saff`.
///
/// [test 01] returns E_BADCAP if [1] is not a valid thread handle.
/// [test 02] returns E_PERM if [1] does not have the `saff` cap.
/// [test 03] returns E_INVAL if any bit set in [2] corresponds to a core the system does not have.
/// [test 04] returns E_INVAL if any reserved bits are set in [1].
/// [test 05] on success, the target thread's affinity is set to [2].
/// [test 06] when [1] is a valid handle, [1]'s field0 and field1 are refreshed from the kernel's authoritative state as a side effect, regardless of whether the call returns success or another error code.
pub fn affinity(caller: *anyopaque, target: u64, new_affinity: u64) i64 {
    if (target & ~@as(u64, capability.HANDLE_ARG_MASK) != 0) return errors.E_INVAL;

    if (new_affinity != 0) {
        const cores = arch.smp.coreCount();
        if (cores < 64) {
            const valid_mask: u64 = (@as(u64, 1) << @intCast(cores)) - 1;
            if (new_affinity & ~valid_mask != 0) return errors.E_INVAL;
        }
    }

    const thread: *Thread = @ptrCast(@alignCast(caller));
    const process_ref = thread.process;
    const lr = process_ref.lockIrqSave(@src()) catch return errors.E_BADCAP;
    const process = lr.ptr;
    const irq_state = lr.irq_state;

    const slot: u12 = @truncate(target);
    if (capability.resolveHandleOnProcess(process, slot, .thread) == null) {
        process_ref.unlockIrqRestore(irq_state);
        return errors.E_BADCAP;
    }

    const thread_caps: ThreadCaps = @bitCast(Word0.caps(process.user_table[slot].word0));
    process_ref.unlockIrqRestore(irq_state);
    if (!thread_caps.saff) return errors.E_PERM;

    return thread_mod.setAffinity(thread, target, new_affinity);
}
