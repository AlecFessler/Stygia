const stygia = @import("stygia");

const errors = stygia.syscall.errors;
const futex = stygia.sched.futex;
const paging = stygia.arch.dispatch.paging;

const Process = stygia.caps.process.Process;
const Thread = stygia.sched.thread.Thread;
const PAddr = stygia.memory.address.PAddr;
const SlabRef = stygia.memory.allocators.secure_slab.SlabRef;
const VAddr = stygia.memory.address.VAddr;

/// Per-call address ceiling. Mirrors
/// `thread.MAX_FUTEX_ADDRS_PER_THREAD` so the per-thread scratch
/// storage that backs decoded pairs can never be overrun.
const MAX_PAIRS: usize = stygia.sched.thread.MAX_FUTEX_ADDRS_PER_THREAD;

/// Resolve `vaddr` in `caller`'s process to a physical address.
/// Returns null when the address is unmapped. Holds the process `_gen_lock`
/// for the duration of the walk so the page tables cannot be torn down by
/// a concurrent process delete mid-translation.
///
/// `paging.resolveVaddr` returns the page-base paddr — re-add the
/// intra-page offset so futex value loads/wakes key on the exact
/// 8-byte field. (Capability slots are 24 bytes and never straddle
/// a page boundary, so a single page walk suffices.)
fn resolveCallerVa(caller: *Thread, vaddr: u64) ?PAddr {
    const lr = caller.process.lockIrqSave(@src()) catch return null;
    const dom = lr.ptr;
    defer caller.process.unlockIrqRestore(lr.irq_state);
    const PAGE_MASK: u64 = 0xFFF;
    const page_base = paging.resolveVaddr(
        dom.addr_space_root,
        VAddr.fromInt(vaddr & ~PAGE_MASK),
    ) orelse return null;
    return .{ .addr = page_base.addr | (vaddr & PAGE_MASK) };
}

/// Read `fut_wait_max` (slot-0 self-handle outer-ceiling, field1 bits
/// 32-37) from the caller's process self-handle. Spec §[process]
/// outer-ceiling encoding.
fn readSelfFutWaitMax(process_ref: SlabRef(Process)) u8 {
    const lr = process_ref.lockIrqSave(@src()) catch return 0;
    const dom = lr.ptr;
    defer process_ref.unlockIrqRestore(lr.irq_state);
    const f1 = dom.user_table[0].field1;
    return @truncate((f1 >> 32) & 0x3F);
}

/// Read the slot-0 self-handle `fut_wake` cap bit. Spec §[process]
/// self-handle cap layout — `fut_wake` at bit 11 of the cap word.
fn readSelfHasFutWake(process_ref: SlabRef(Process)) bool {
    const lr = process_ref.lockIrqSave(@src()) catch return false;
    const dom = lr.ptr;
    defer process_ref.unlockIrqRestore(lr.irq_state);
    const caps_word: u16 = stygia.caps.capability.Word0.caps(dom.user_table[0].word0);
    return (caps_word & (1 << 11)) != 0;
}

/// Blocks while every `(addr, expected)` pair satisfies `*addr ==
/// expected`. Returns when any pair has `*addr != expected` (either at
/// call entry or after a wake), when any watched address is woken via
/// `futex_wake`, or on timeout.
///
/// ```
/// futex_wait_val([1] timeout_ns, [2 + 2i] addr, [2 + 2i + 1] expected) -> [1] addr
///   syscall_num = 57
///
///   syscall word bits 12-19: N (1..63)
///
///   [1] timeout_ns: 0 = non-blocking, u64::MAX = indefinite, otherwise nanoseconds
///   [2 + 2i] addr: 8-byte-aligned user address in the caller's process
///   [2 + 2i + 1] expected: u64 expected value at addr
///
///   for i in 0..N-1.
/// ```
///
/// Self-handle requirement: `fut_wait_max >= 1`. The call's `N` must not
/// exceed `fut_wait_max`.
///
/// [test 01] returns E_PERM if the caller's self-handle has `fut_wait_max = 0`.
/// [test 02] returns E_INVAL if N is 0 or N > 63.
/// [test 03] returns E_INVAL if N exceeds the caller's self-handle `fut_wait_max`.
/// [test 04] returns E_INVAL if any addr is not 8-byte aligned.
/// [test 05] returns E_BADADDR if any addr is not a valid user address in the caller's process.
/// [test 06] returns E_TIMEOUT if the timeout expires before any pair's `addr != expected` condition is met and before any watched address is woken.
/// [test 07] on entry, when any pair's current `*addr != expected`, returns immediately with `[1]` set to that addr.
/// [test 08] when another thread calls `futex_wake` on any watched addr, returns with `[1]` set to that addr (caller re-checks the value to determine whether the condition is actually met or the wake was spurious).
pub fn futexWaitVal(caller: *anyopaque, timeout_ns: u64, pairs: []const u64) i64 {
    const thread: *Thread = @ptrCast(@alignCast(caller));

    if (pairs.len == 0 or (pairs.len & 1) != 0) return errors.E_INVAL;
    const n = pairs.len / 2;
    if (n == 0 or n > MAX_PAIRS) return errors.E_INVAL;

    const fut_wait_max = readSelfFutWaitMax(thread.process);
    if (fut_wait_max == 0) return errors.E_PERM;
    if (n > fut_wait_max) return errors.E_INVAL;

    // The 3 parallel arrays below total ~1.5 KiB. Stored on the thread
    // rather than the syscall stack — only the syscall-issuing thread
    // ever uses them, and they are dead once `futex.waitVal` returns
    // (the futex impl copies anything that must outlive the syscall
    // into its own thread-resident storage).
    const addrs = &thread.futex_syscall_addrs_storage;
    const vaddrs = &thread.futex_syscall_vaddrs_storage;
    const expected = &thread.futex_syscall_values_storage;
    var i: usize = 0;
    while (i < n) {
        const va = pairs[i * 2];
        if ((va & 7) != 0) return errors.E_INVAL;
        addrs[i] = resolveCallerVa(thread, va) orelse return errors.E_BADADDR;
        vaddrs[i] = va;
        expected[i] = pairs[i * 2 + 1];
        i += 1;
    }

    return futex.waitVal(addrs[0..n], vaddrs[0..n], expected[0..n], n, timeout_ns, @ptrCast(thread));
}

/// Blocks while every `(addr, target)` pair satisfies `*addr != target`.
/// Returns when any pair has `*addr == target` (at call entry or after a
/// wake), when any watched address is woken via `futex_wake`, or on
/// timeout.
///
/// ```
/// futex_wait_change([1] timeout_ns, [2 + 2i] addr, [2 + 2i + 1] target) -> [1] addr
///   syscall_num = 58
///
///   syscall word bits 12-19: N (1..63)
///
///   [1] timeout_ns: 0 = non-blocking, u64::MAX = indefinite, otherwise nanoseconds
///   [2 + 2i] addr: 8-byte-aligned user address in the caller's process
///   [2 + 2i + 1] target: u64 target value at addr
///
///   for i in 0..N-1.
/// ```
///
/// Self-handle requirement: `fut_wait_max >= 1`. The call's `N` must not
/// exceed `fut_wait_max`.
///
/// [test 01] returns E_PERM if the caller's self-handle has `fut_wait_max = 0`.
/// [test 02] returns E_INVAL if N is 0 or N > 63.
/// [test 03] returns E_INVAL if N exceeds the caller's self-handle `fut_wait_max`.
/// [test 04] returns E_INVAL if any addr is not 8-byte aligned.
/// [test 05] returns E_BADADDR if any addr is not a valid user address in the caller's process.
/// [test 06] returns E_TIMEOUT if the timeout expires before any pair's `addr == target` condition is met and before any watched address is woken.
/// [test 07] on entry, when any pair's current `*addr == target`, returns immediately with `[1]` set to that addr.
/// [test 08] when another thread calls `futex_wake` on any watched addr, returns with `[1]` set to that addr (caller re-checks the value to determine whether the condition is actually met or the wake was spurious).
pub fn futexWaitChange(caller: *anyopaque, timeout_ns: u64, pairs: []const u64) i64 {
    const thread: *Thread = @ptrCast(@alignCast(caller));

    if (pairs.len == 0 or (pairs.len & 1) != 0) return errors.E_INVAL;
    const n = pairs.len / 2;
    if (n == 0 or n > MAX_PAIRS) return errors.E_INVAL;

    const fut_wait_max = readSelfFutWaitMax(thread.process);
    if (fut_wait_max == 0) return errors.E_PERM;
    if (n > fut_wait_max) return errors.E_INVAL;

    // Same thread-resident-scratch discipline as `futexWaitVal`.
    const addrs = &thread.futex_syscall_addrs_storage;
    const vaddrs = &thread.futex_syscall_vaddrs_storage;
    const targets = &thread.futex_syscall_values_storage;
    var i: usize = 0;
    while (i < n) {
        const va = pairs[i * 2];
        if ((va & 7) != 0) return errors.E_INVAL;
        addrs[i] = resolveCallerVa(thread, va) orelse return errors.E_BADADDR;
        vaddrs[i] = va;
        targets[i] = pairs[i * 2 + 1];
        i += 1;
    }

    return futex.waitChange(addrs[0..n], vaddrs[0..n], targets[0..n], n, timeout_ns, @ptrCast(thread));
}

/// Wakes up to `count` Threads blocked in `futex_wait_val` or
/// `futex_wait_change` on the given address. Wake order is
/// priority-ordered.
///
/// ```
/// futex_wake([1] addr, [2] count) -> [1] woken
///   syscall_num = 59
///
///   [1] addr: 8-byte-aligned user address in the caller's process
///   [2] count: maximum number of Threads to wake
/// ```
///
/// Self-handle cap required: `fut_wake`.
///
/// [test 01] returns E_PERM if the caller's self-handle lacks `fut_wake`.
/// [test 02] returns E_INVAL if [1] addr is not 8-byte aligned.
/// [test 03] returns E_BADADDR if [1] addr is not a valid user address in the caller's process.
/// [test 04] on success, [1] is the number of Threads actually woken (0..count).
pub fn futexWake(caller: *anyopaque, addr: u64, count: u64) i64 {
    const thread: *Thread = @ptrCast(@alignCast(caller));

    if ((addr & 7) != 0) return errors.E_INVAL;
    if (!readSelfHasFutWake(thread.process)) return errors.E_PERM;

    const paddr = resolveCallerVa(thread, addr) orelse return errors.E_BADADDR;
    const woken = futex.wake(paddr, @truncate(count));
    return @intCast(woken);
}
