const build_options = @import("build_options");
const std = @import("std");
const zag = @import("zag");

const apic = zag.arch.x64.apic;
const cpu = zag.arch.x64.cpu;
const ctx_trace = zag.utils.ctx_trace;
const gdt = zag.arch.x64.gdt;
const idt = zag.arch.x64.idt;
const kprof = zag.kprof.trace_id;
const paging = zag.arch.x64.paging;
const scheduler = zag.sched.scheduler;
const sync_debug = zag.utils.sync.debug;

const CapabilityDomain = zag.caps.capability_domain.CapabilityDomain;
const CapabilityType = zag.caps.capability.CapabilityType;
const EcQueue = zag.sched.scheduler.EcQueue;
const EcQueueLevel = @typeInfo(@FieldType(EcQueue, "levels")).array.child;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const InterruptHandler = idt.interruptHandler;
const KernelHandle = zag.caps.capability.KernelHandle;
const Port = zag.sched.port.Port;
const PrivilegeLevel = zag.arch.x64.cpu.PrivilegeLevel;
const ReplyCaps = zag.sched.port.ReplyCaps;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const VAddr = zag.memory.address.VAddr;
const WaiterKind = zag.sched.port.WaiterKind;

pub const ArchCpuContext = cpu.Context;

pub const PageFaultContext = struct {
    faulting_address: u64,
    is_kernel_privilege: bool,
    is_write: bool,
    is_exec: bool,
    rip: u64 = 0,
    /// Pointer to the user iret `cpu.Context` captured by the stub, i.e.
    /// the actual register frame that will be restored by the stub epilogue
    /// iret. Used so `fault_reply(FAULT_RESUME_MODIFIED)` can patch the
    /// real user frame instead of `thread.ctx` (which after yield points at
    /// a kernel-mode context). Null for kernel-mode faults.
    user_ctx: ?*ArchCpuContext = null,
};

pub const IntVecs = enum(u8) {
    pmu = 0xFB,
    kprof_dump = 0xFC,
    tlb_shootdown = 0xFD,
    sched = 0xFE,
    spurious = 0xFF,
    fpu_flush = 0xFA,
};

pub const VectorKind = enum {
    exception,
    external,
};

const VectorEntry = struct {
    handler: ?Handler = null,
    kind: VectorKind = .external,
};

const Handler = *const fn (*cpu.Context) void;

pub const stubs: [256]InterruptHandler = blk: {
    var arr: [256]InterruptHandler = undefined;
    for (0..256) |i| {
        arr[i] = getInterruptStub(i, pushes_err[i]);
    }
    break :blk arr;
};

const pushes_err = blk: {
    var a: [256]bool = .{false} ** 256;
    a[8] = true;
    a[10] = true;
    a[11] = true;
    a[12] = true;
    a[13] = true;
    a[14] = true;
    a[17] = true;
    a[20] = true;
    a[30] = true;
    break :blk a;
};

var vector_table: [256]VectorEntry = .{VectorEntry{}} ** 256;

/// Per-core scratch zone for SYSCALL entry, accessed via `gs:` after
/// `swapgs`. Sized to a full 4 KiB page so other arch fast paths
/// (fault delivery, vm-exit) can grow into the same scratch without
/// changing offsets. Statically allocated in BSS — kernel-mapped at
/// boot, no per-cpu page allocation needed at runtime.
///
/// Offsets are load-bearing — the L4 IPC fast-path asm in
/// `syscallEntry` references them as immediate displacements, not
/// through `@offsetOf`. Reordering fields requires updating that asm.
pub const SyscallScratch = extern struct {
    /// Top of the current EC's kernel stack. Updated by `switchTo`
    /// alongside TSS.RSP0. Read first by entry stub to switch RSP.
    kernel_rsp: u64,
    /// Caller's user RSP at SYSCALL trap. Stashed by entry stub.
    user_rsp: u64,
    /// Caller's user RIP (from RCX, which SYSCALL clobbers). Stashed
    /// so RCX can be reused as scratch.
    user_rip: u64,
    /// Caller's user RFLAGS (from R11, ditto).
    user_rflags: u64,
    /// Pointer to the EC currently dispatched on this core. Updated
    /// by `switchTo`. Read in fast-path entry without further lookup.
    current_ec: u64,
    /// Pointer to that EC's bound CapabilityDomain. Updated alongside
    /// `current_ec` so handle-table walks skip a dereference.
    current_domain: u64,
    /// Cached pointer to `current_domain.user_table` (the
    /// [4096]Capability array base). Populated by `switchTo` alongside
    /// `current_domain` so the fast-path's user-table indexing skips
    /// the CD->user_table chained deref — one direct gs-relative load.
    current_user_table: u64,
    /// Cached pointer to `current_domain.kernel_table`
    /// ([4096]KernelHandle array base). Same rationale as
    /// `current_user_table`.
    current_kernel_table: u64,
    /// General fast-path scratch slots used to spill values across
    /// phases (sender RIP/RFLAGS held until the user-stack write,
    /// `*Port` retained across the spinlock release, etc.).
    /// 8 slots = 64 bytes.
    fast_temp: [8]u64,
    /// Pointer to this core's `scheduler.PerCore` slot. Populated at
    /// init so the fast path can reach `last_fpu_owner` and
    /// `fpu_trap_armed` without a CPUID/APIC read followed by an array
    /// index — both would be MOV-CR0/MSR-class costs we can't afford
    /// inside the L4 path. Single deref, RIP-relative-free.
    per_core_ptr: u64,
    /// Address of this core's TSS.RSP0 field. Populated at init so the
    /// fast-path context-switch step can write the new kernel stack
    /// top without computing core-relative TSS addresses (would need
    /// to call into Zig and clobber regs).
    tss_rsp0_ptr: u64,
    /// Snapshot of `cpu.pcid_enabled` written at init. The fast path
    /// can't reach the global `var` symbol RIP-relative from a naked
    /// fn without operand interpolation, so we cache it here and
    /// branch on the byte.
    pcid_enabled: u8,
    _pcid_pad: [7]u8 align(1),
    timed_recv_waiters_ptr: u64,
    timed_recv_lock_ptr: u64,
    /// Address of this core's `scheduler.core_locks[core_id]` slot.
    /// Populated at init so the L4 reply fast path can take the same
    /// per-core run-queue spinlock the slow path's `enqueueOnCore` uses,
    /// without a Zig call back into the scheduler (which would clobber
    /// the live caller-saved vreg registers we are sysretq'ing zero-copy
    /// to the resumed sender).
    core_lock_ptr: u64,
    /// Snapshot of `current_ec._gen_lock`'s current gen, taken by
    /// `switchTo` alongside `current_ec`. Used by the IPC fast path's
    /// `lockWithGen` acquires on `current_ec` (suspend FP step 9.7,
    /// reply FP step R10.5) — both syscall-class lock-windows where
    /// the EC being acquired is the very EC mid-syscall. Holding the
    /// gen snapshot here lets those acquires bail on a concurrent
    /// `terminate(self)` from another core (which would rotate the
    /// gen between syscall entry and the acquire) instead of locking
    /// a slab slot that has been freed and possibly reallocated to
    /// a different EC. Stored as u64 because the asm reads it with
    /// `movq`; the upper 32 bits are always zero.
    current_ec_gen: u64,
    /// This core's id — populated at `initSyscallScratch` time. Read by
    /// the FP step-14 / R-14 `last_dispatched_core` stamp on the EC being
    /// dispatched. Without it the asm would have to derive the core id
    /// from `per_core_ptr` arithmetic against `core_states` base, which
    /// is awkward without operand interpolation in the naked stub.
    core_id: u8,
    /// Pad out to a full page.
    _pad: [4096 - 185]u8,
};

comptime {
    if (@sizeOf(SyscallScratch) != 4096) {
        @compileError("SyscallScratch must be exactly 4 KiB");
    }
}

/// SyscallScratch displacements pinned for the syscall-entry inline
/// asm. The slow-path prologue references these as immediate `gs:N`
/// memory operands rather than going through operand interpolation in
/// a naked stub, so layout drift on `SyscallScratch` must trip a
/// compile error here rather than silently corrupting the path. The
/// future L4 IPC fast path will share the same scratch layout, hence
/// the slot bookkeeping for `current_ec`, `current_domain`,
/// `per_core_ptr`, and the `fast_temp` band stays parked here for
/// when those slots become live again.
const Offsets = struct {
    const sc_kernel_rsp: usize = 0;
    const sc_user_rsp: usize = 8;
    const sc_user_rip: usize = 16;
    const sc_user_rflags: usize = 24;
    const sc_current_ec: usize = 32;
    const sc_current_domain: usize = 40;
    const sc_current_user_table: usize = 48;
    const sc_current_kernel_table: usize = 56;
    const sc_fast_temp_0: usize = 64;
    const sc_per_core_ptr: usize = 128;
    const sc_tss_rsp0_ptr: usize = 136;
    const sc_pcid_enabled: usize = 144;
    const sc_timed_recv_waiters_ptr: usize = 152;
    const sc_timed_recv_lock_ptr: usize = 160;
    const sc_core_lock_ptr: usize = 168;
    const sc_current_ec_gen: usize = 176;
    const sc_core_id: usize = 184;

    // cpu.Context iret-frame field offsets — referenced by the slow-path
    // Context-build literals (136/152/160).
    const ctx_rip: usize = @offsetOf(cpu.Context, "rip");
    const ctx_rflags: usize = @offsetOf(cpu.Context, "rflags");
    const ctx_rsp: usize = @offsetOf(cpu.Context, "rsp");
};

// Sanity-check the SyscallScratch displacements — extern struct, but
// even an extern layout flips on a Zig version bump if alignment
// rules ever change.
comptime {
    if (@offsetOf(SyscallScratch, "kernel_rsp") != Offsets.sc_kernel_rsp) @compileError("scratch.kernel_rsp drift");
    if (@offsetOf(SyscallScratch, "user_rsp") != Offsets.sc_user_rsp) @compileError("scratch.user_rsp drift");
    if (@offsetOf(SyscallScratch, "user_rip") != Offsets.sc_user_rip) @compileError("scratch.user_rip drift");
    if (@offsetOf(SyscallScratch, "user_rflags") != Offsets.sc_user_rflags) @compileError("scratch.user_rflags drift");
    if (@offsetOf(SyscallScratch, "current_ec") != Offsets.sc_current_ec) @compileError("scratch.current_ec drift");
    if (@offsetOf(SyscallScratch, "current_domain") != Offsets.sc_current_domain) @compileError("scratch.current_domain drift");
    if (@offsetOf(SyscallScratch, "current_user_table") != Offsets.sc_current_user_table) @compileError("scratch.current_user_table drift");
    if (@offsetOf(SyscallScratch, "current_kernel_table") != Offsets.sc_current_kernel_table) @compileError("scratch.current_kernel_table drift");
    if (@offsetOf(SyscallScratch, "fast_temp") != Offsets.sc_fast_temp_0) @compileError("scratch.fast_temp drift");
    if (@offsetOf(SyscallScratch, "per_core_ptr") != Offsets.sc_per_core_ptr) @compileError("scratch.per_core_ptr drift");
    if (@offsetOf(SyscallScratch, "tss_rsp0_ptr") != Offsets.sc_tss_rsp0_ptr) @compileError("scratch.tss_rsp0_ptr drift");
    if (@offsetOf(SyscallScratch, "pcid_enabled") != Offsets.sc_pcid_enabled) @compileError("scratch.pcid_enabled drift");
    if (@offsetOf(SyscallScratch, "timed_recv_waiters_ptr") != Offsets.sc_timed_recv_waiters_ptr) @compileError("scratch.timed_recv_waiters_ptr drift");
    if (@offsetOf(SyscallScratch, "timed_recv_lock_ptr") != Offsets.sc_timed_recv_lock_ptr) @compileError("scratch.timed_recv_lock_ptr drift");
    if (@offsetOf(SyscallScratch, "core_lock_ptr") != Offsets.sc_core_lock_ptr) @compileError("scratch.core_lock_ptr drift");
    if (@offsetOf(SyscallScratch, "current_ec_gen") != Offsets.sc_current_ec_gen) @compileError("scratch.current_ec_gen drift");
    if (@offsetOf(SyscallScratch, "core_id") != Offsets.sc_core_id) @compileError("scratch.core_id drift");
    if (Offsets.ctx_rip != 136) @compileError("cpu.Context.rip not at 136");
    if (Offsets.ctx_rflags != 152) @compileError("cpu.Context.rflags not at 152");
    if (Offsets.ctx_rsp != 160) @compileError("cpu.Context.rsp not at 160");
}

// Layout asserts for the L4 IPC fast-path dequeue. The unrolled walk
// of `port.waiters.levels` in `syscallEntry` hardcodes one
// (movq+testq+jnz, leaq+jmp) pair per priority level. Drift here
// requires updating the asm.
comptime {
    const levels_field = @typeInfo(@FieldType(EcQueue, "levels")).array;
    if (levels_field.len != 4) @compileError("EcQueue.levels.len drift — update fast-path dequeue unroll");
    if (@sizeOf(levels_field.child) != 16) @compileError("EcQueue.Level size drift — update fast-path dequeue offsets");
}

// Optional-SlabRef layout assertion. The fast-path mint-reply chunk
// writes `sender.pending_reply_domain` (a `?SlabRef(CapabilityDomain)`)
// and `sender.suspend_port` (a `?SlabRef(Port)`) by hand: 16-byte
// SlabRef payload at offset 0, 1-byte discriminator at offset 16,
// padded to 24 total. If Zig's optional layout changes, this trips.
comptime {
    if (@sizeOf(?SlabRef(CapabilityDomain)) != 24) {
        @compileError("?SlabRef(CapabilityDomain) layout drift — fast-path mint-reply assumes 16-byte payload + disc at +16");
    }
    if (@sizeOf(?SlabRef(Port)) != 24) {
        @compileError("?SlabRef(Port) layout drift — fast-path sender.suspend_port write assumes 16-byte payload + disc at +16");
    }
}

pub var per_cpu_scratch: [64]SyscallScratch align(4096) =
    [_]SyscallScratch{std.mem.zeroes(SyscallScratch)} ** 64;

/// Set KernelGsBase MSR for this core so SWAPGS can access per-CPU scratch.
/// Must be called on each core during init, after APIC is available and
/// after `cpu.enablePcid` has run (so the cached `pcid_enabled` flag is
/// authoritative for this core's lifetime).
pub fn initSyscallScratch(core_id: u64) void {
    const ia32_kernel_gs_base: u32 = 0xC0000102;
    const scratch = &per_cpu_scratch[core_id];
    scratch.per_core_ptr = @intFromPtr(&scheduler.core_states[core_id]);
    scratch.tss_rsp0_ptr = @intFromPtr(&gdt.coreTss(core_id).rsp0);
    scratch.pcid_enabled = if (cpu.pcid_enabled) 1 else 0;
    scratch.timed_recv_waiters_ptr = @intFromPtr(&zag.sched.port.timed_recv_waiters);
    scratch.timed_recv_lock_ptr = @intFromPtr(&zag.sched.port.timed_recv_lock);
    scratch.core_lock_ptr = @intFromPtr(&scheduler.core_locks[core_id]);
    scratch.core_id = @intCast(core_id);
    cpu.wrmsr(ia32_kernel_gs_base, @intFromPtr(scratch));
}

/// Update per-CPU scratch kernel_rsp. Called from switchTo on every
/// context switch, mirroring the TSS.RSP0 update.
///
/// Pointer-index `per_cpu_scratch[]` to avoid Debug-mode codegen
/// copying the entire [64]SyscallScratch array (256 KiB) onto the
/// kernel stack on every context switch. See the matching note in
/// sched.scheduler on `core_states[]`.
pub fn updateScratchKernelRsp(core_id: u64, kernel_rsp: u64) void {
    (&per_cpu_scratch[core_id]).kernel_rsp = kernel_rsp;
}

/// Syscall dispatch — exported so the SYSCALL asm entry can call it.
/// Wraps the generic syscall.dispatch and writes the i64 return into
/// vreg 1 (rax). Spec §[syscall_abi] ABI:
///   - syscall_word lives at user vreg 0 = `[ctx.rsp + 0]`. SMAP gates
///     the read; STAC/CLAC bracket the user-stack load.
///   - args[0..13] = vregs 1..13, in spec order: rax, rbx, rdx, rbp,
///     rsi, rdi, r8, r9, r10, r12, r13, r14, r15. Stack-spilled vregs
///     14..127 are not collected here — handlers that need them read
///     them from `[ctx.rsp + (N-13)*8]` directly.
///   - return: i64 → ctx.regs.rax (vreg 1).
///
/// L4 IPC fast path lives entirely in the asm classifier
/// (`.Lsyscall_suspend_fast` in `syscallEntry`). When that fires the
/// CPU never reaches `syscallDispatch` — the rendezvous + sysretq are
/// inline. Anything reaching here is the slow-path tail.
export fn syscallDispatch(ctx: *cpu.Context) void {
    const r = &ctx.regs;
    var syscall_word: u64 = undefined;
    cpu.stac();
    syscall_word = @as(*const u64, @ptrFromInt(ctx.rsp)).*;
    cpu.clac();
    const caller = scheduler.currentEc() orelse @panic("syscall with no current EC");
    ctx_trace.mark(caller, .slowpath_save);

    var args: [13]u64 = .{
        r.rax, r.rbx, r.rdx, r.rbp, r.rsi, r.rdi,
        r.r8,  r.r9,  r.r10, r.r12, r.r13, r.r14, r.r15,
    };
    const ret = zag.syscall.dispatch.dispatch(caller, syscall_word, args[0..]);

    // Only commit the syscall return into the saved frame if the
    // dispatched handler did NOT park `caller`. A handler that suspends
    // (recv / suspend / futex_wait / fault) clears this core's
    // `current_ec`; from that moment on `caller.ctx.regs.rax` is the
    // wake-side delivery slot — `propagateClosedTo*`,
    // `expireTimedRecvWaiters`, etc. running on a remote core write
    // E_CLOSED / E_TIMEOUT there directly. An unconditional assign of
    // `ret` (always 0 on the suspend path) would race with that remote
    // write and clobber the real wake value back to 0.
    const core_id_for_ret: u8 = @truncate(apic.coreID());
    if (scheduler.coreCurrentIs(core_id_for_ret, caller)) {
        r.rax = @bitCast(ret);
    }

    // Spec §[syscall_abi]: vreg 0 (`[user_rsp + 0]`) is the syscall
    // word — `recv` event delivery surfaces its return payload here
    // (reply_handle_id / event_type / pair_count / tstart) while vreg
    // 1 (rax) carries OK. The caller is still the running EC on this
    // core when dispatch returned without suspending us, and we are
    // still in the caller's CR3, so the user-page write is safe here.
    if (caller.pending_event_word_valid and
        scheduler.coreCurrentIs(@truncate(apic.coreID()), caller))
    {
        writeUserSyscallWord(ctx, caller.pending_event_word);
        caller.pending_event_word = 0;
        caller.pending_event_word_valid = false;

        // Spec §[event_state] vreg 14 — RIP at `[user_rsp + 8]`.
        // Staged alongside the syscall word in `port.deliverEvent`;
        // flush here while we are guaranteed to be in the receiver's
        // CR3 (the synchronous path through dispatch ran in the
        // caller's address space throughout). Tied to
        // `pending_event_word_valid` because both flags are set
        // together in `deliverEvent`.
        if (caller.pending_event_rip_valid) {
            writeUserVreg14(ctx, caller.pending_event_rip);
            caller.pending_event_rip = 0;
            caller.pending_event_rip_valid = false;
        }
    }

    // If the dispatch suspended the calling EC (recv/suspend/futex
    // wait), `current_ec` was cleared on this core and `caller.state`
    // was retargeted to `.suspended_on_port` / `.futex_wait`. The asm
    // epilogue would otherwise iretq back to the parked user mode and
    // run the suspended EC. Switch to whatever's next (or idle); the
    // saved register restore in the asm trampoline never executes
    // because switchTo's `loadEcContextAndReturn` is `noreturn`.
    if (scheduler.coreIsIdle(@truncate(apic.coreID()))) {
        scheduler.run();
    }

    // Last snapshot before the slow-path asm pops regs and iretq's.
    // `caller` is still the live EC for this core (suspend handlers
    // would have rerouted via `scheduler.run()` above and not returned
    // here). Captures the iret frame slots that are about to be
    // restored — most useful pre-iretq mark for the corruption hunt.
    if (scheduler.coreCurrentIs(@truncate(apic.coreID()), caller)) {
        ctx_trace.mark(caller, .slowpath_epilogue);
    }
}

/// SYSCALL entry point. Builds an iret-compatible cpu.Context frame so
/// the existing dispatch and context-switch paths work unchanged.
///
/// On entry (Intel SDM Vol 2B, "SYSCALL—Fast System Call"):
///   RCX = user RIP, R11 = user RFLAGS, RSP = user stack (unchanged).
///   CS/SS loaded from IA32_STAR[47:32]. RFLAGS masked by IA32_FMASK.
///
/// SWAPGS (Intel SDM Vol 3A §5.8.8) swaps GS.base ↔ IA32_KERNEL_GS_BASE.
/// KernelGsBase points to per-CPU SyscallScratch: [0]=kernel_rsp, [8]=scratch.
///
/// On exit (Intel SDM Vol 2B, "SYSRET—Return From Fast System Call"):
///   RIP=RCX, RFLAGS=R11&3C7FD7H|2, CS=STAR[63:48]+16|3, SS=STAR[63:48]+8|3.
///   Non-canonical RCX → #GP at CPL3 on kernel stack; checked before SYSRET.
///
/// All syscalls currently route through the slow path: a 176-byte
/// `cpu.Context` save, followed by the generic `syscallDispatch`
/// trampoline into `zag.syscall.dispatch`, then iretq. The slow path
/// preserves vregs 1-13 (= rax, rbx, rdx, rbp, rsi, rdi, r8, r9, r10,
/// r12, r13, r14, r15) across the call by saving them into the
/// Context frame on entry and restoring them on exit, so any handler
/// (including suspend/recv/reply) that does not modify those slots
/// returns to userspace with them unchanged — matching the contract
/// the L4-style IPC fast path below relies on to preserve them in
/// registers.
///
/// ═══════════════════════════════════════════════════════════════════
/// L4 IPC fast path — what it is and what makes it fast
/// ═══════════════════════════════════════════════════════════════════
///
/// The optimization is *not* doing the syscall faster in some clever
/// way. The optimization is *not pushing/popping the GPR file at all*.
/// The slow path's per-syscall cost is dominated by saving 15 GPRs
/// into a kernel-stack Context on entry and restoring them on exit;
/// the fast path skips that save/restore entirely and lets the
/// receiver's user-mode register file flow zero-copy into the sender's
/// user-mode register file across an IPC rendezvous.
///
/// Concretely, on a `suspend` (sender→receiver) or `reply`
/// (receiver→sender) rendezvous the kernel does not own the IPC
/// payload — userspace does, and it lives in the GPRs. The fast path
/// performs all correctness gating (cap-table walks, gen-lock
/// acquire/release, queue insertion, slot mints/frees, EC state
/// writes) using *only* (rcx, r11, rax-with-spill, memory). It then
/// stack-swaps to the receiver's kernel stack, swaps CR3 to the
/// receiver's address space, and `sysretq`s. The 15 IPC payload
/// registers were never touched, so on `sysretq` the receiver's
/// vreg-1..13 + RSP + (sender-restored) RCX/R11 ARE the sender's
/// resumption state.
///
/// Register discipline (HARD CONSTRAINT — violating it defeats the
/// optimization, since any clobbered register would have to be
/// spilled+reloaded, which is exactly what the slow path does):
///
///   rax, rbx, rdx, rbp, rsi, rdi, r8, r9, r10, r12, r13, r14, r15
///       ── IPC payload (vregs 1-13). MUST pass through untouched.
///          Whatever value is there at fast-path entry (= receiver's
///          user-mode register on sysret-return-to-receiver, or
///          sender's user-mode register on entry, depending on which
///          direction) is the value the *next* user-mode resumption
///          observes. Touching any of these means re-introducing the
///          slow-path's spill+reload.
///
///   rcx, r11
///       ── Free scratch. SYSCALL itself clobbered them on entry
///          (rcx ← user RIP, r11 ← user RFLAGS, per Intel SDM Vol 2B
///          "SYSCALL"), so userspace cannot put IPC payload in them
///          even in principle. The fast path uses them as its main
///          scratch for cap decoding, gen-lock CAS, port walks, etc.
///
///   rax
///       ── Free scratch BUT with a spill+reload contract. Used
///          unavoidably for `cmpxchg` on every gen-lock acquire. On
///          entry, spill the user-mode rax to a `gs:` slot (the
///          `SyscallScratch.fast_temp[0]` band) before the first
///          cmpxchg, work freely, and reload the *correct* user-side
///          value into rax just before sysretq — for suspend FP that's
///          the freshly-minted reply handle; for reply FP that's
///          either the receiver's spilled rax (zero-copy hand-off) or
///          0/E_TERM depending on the resume target.
///
///   rsp, gs base
///       ── Per-core kernel-mode state, swapped via ordinary
///          stack-swap and `swapgs`. Touching them is part of the
///          rendezvous, not a violation of the GPR contract.
///
/// Memory writes for kernel-side state (EC fields, gen-locks, queue
/// links, port slots, cap-table entries, `last_dispatched_core`,
/// `on_cpu`, etc.) are *fine* — they cost cycles but they are how
/// kernel correctness is encoded. The fast path does many such writes
/// per rendezvous. What's forbidden is *clobbering the 15 GPRs that
/// hold the IPC payload*, because that is what the optimization buys.
///
/// When fixing bugs in the fast-path asm: every state mutation the
/// slow path makes on the equivalent transition must have a
/// corresponding asm write in the fast path. The slow path does its
/// state machinery through Zig calls into `port.@"suspend"`,
/// `port.recv`, `port.reply`, `execution_context.parkSelfFaulted`,
/// etc. Any fast-path branch that skips one of those mutations is a
/// latent bug — see e.g. R5's discovery that the bare-reply branch
/// missed `receiver.on_cpu = 0` (commit log under
/// `.Lreply_atomic_recv_park` / `_fallback`).
///
/// L4 IPC fast path — fully inline asm rendezvous.
/// `.Lsyscall_suspend_fast` (below) handles the suspend syscall when
/// the syscall_word ≤ 13 (fast-suspend ABI: op directly encodes
/// payload_count). Predicate: self-suspend + receiver queued on the
/// destination port + caps OK (susp/read/write on target, bind on
/// port). On match the rendezvous mints a reply handle in the
/// receiver's CD, parks the sender, transfers vregs zero-copy
/// through the GPRs, swaps CR3, and sysretq's directly to the
/// receiver in user mode — never reaches `syscallDispatch`.
/// Predicate misses funnel into `.Lsyscall_lock_fail` →
/// `.Lsyscall_slow_path` and run through the regular dispatch path
/// (`port.@"suspend"` → `port.suspendEc`); dispatch.zig recognizes
/// 0..13 as a suspend with no attachments so observable state is
/// identical to the fast-path result (per spec §[port],
/// §[event_state]).
///
/// Phase 4 (CR3 + GS swap + sysretq inline in this naked stub) is not
/// yet wired: the Zig fast path still returns through the asm Context
/// restore + iretq epilogue, just bypassing the slow dispatch above.
/// Moving the receiver dispatch into the naked stub itself remains the
/// future work this scratch layout was provisioned for.
pub export fn syscallEntry() callconv(.naked) void {
    // asm-genlock: skip
    //
    // The check_gen_lock asm pass tracks lock state per-register at a
    // single-function granularity. This fast-path stub multiplexes
    // seven distinct lock windows (recv_cd, receiver_ec, sender_ec,
    // port, caller_ec) across hundreds of asm lines, hands ownership
    // of `gs:` scratch slots between phases, and bridges between the
    // suspend FP and reply FP through asm labels whose per-jump
    // state-merge the analyzer can't reconcile without label hints.
    // Lock discipline is documented inline at each phase boundary
    // (`Step 9.5` / `Step 12.5` / `R5a` / `R10.5` / `R13.5` / `R13.6` /
    // `R16` headers); spec-test parity at smp=4 verifies it. Until the
    // analyzer grows label-aware state tracking, opt out — silent
    // findings here would drown the kernel-wide signal from real bugs
    // in slow-path handlers.
    //
    // Slow-path Context layout:
    //   [RSP+0..112]   r15..rax (15 GPRs, 120 bytes)
    //   [RSP+120,128]  int_num, err_code
    //   [RSP+136..168] iret frame (rip, cs, rflags, rsp, ss)
    asm volatile (
    // ═══════════════════════════════════════════════════════════════
    // PHASE 1 — swapgs, stash user state, read syscall_word from user
    // stack BEFORE switching kernel stack so we can do it via plain
    // (%rsp). Sender vregs 1..13 (rax, rbx, rdx, rbp, rsi, rdi, r8,
    // r9, r10, r12-r15) are NEVER touched on the fast path — that's
    // the zero-copy contract. Free scratch: rcx, r11 (originals
    // already stashed at gs:16 / gs:24).
    // ═══════════════════════════════════════════════════════════════
        \\swapgs
        \\movq %%rcx, %%gs:16                 // user_rip (frees rcx)
        \\movq %%r11, %%gs:24                 // user_rflags (frees r11)
        \\stac
        \\movq (%%rsp), %%rcx                 // rcx = syscall_word (rsp still = user_rsp)
        \\clac
        \\movq %%rsp, %%gs:8                  // user_rsp
        \\movq %%gs:0, %%rsp                  // switch to kernel stack

    // ═══════════════════════════════════════════════════════════════
    // CLASSIFIER — two-arm fast path dispatch:
    //   1) suspend fast path: rcx ≤ 13 (the fast-suspend variants where
    //      the syscall_word IS the payload_count and upper bits must be
    //      zero — a single unsigned compare verifies both).
    //   2) reply fast path: syscall_num (rcx low 12 bits) == 52 AND
    //      pair_count (bits 12-19) == 0 AND recv_port_handle_id
    //      (bits 32-43) == 0 AND reserved bits 44-63 == 0. Spec §[reply]
    //      bare-reply: handle id at bits 20-31; no attachments, no recv.
    // On suspend fast-path entry: rcx = payload_count.
    // On reply fast-path entry:   rcx = syscall_word (full).
    //
    // Build-time gated independently per arm via
    // `-Dkernel_fastpath_suspend` / `-Dkernel_fastpath_reply` (both
    // default to `-Dkernel_fastpath`). When an arm is disabled its
    // classifier emit is comptime-substituted away so the corresponding
    // syscalls funnel into the slow Zig dispatch path — used for
    // attributing the per-leg perf delta in A/B sweeps.
    // ═══════════════════════════════════════════════════════════════
        ++ "\n"
        ++ (if (build_options.kernel_fastpath_suspend)
            \\cmpq $13, %%rcx
            \\jbe  .Lsyscall_suspend_fast
        else
            "")
        ++ "\n"
        ++ (if (build_options.kernel_fastpath_reply)
            // Fast path engages on:
            //   syscall_num (bits 0-11)  == 52 (.reply)
            //   pair_count  (bits 12-19) == 0  (no attachments)
            //   reserved    (bits 44-63) == 0
            // recv_port_handle_id (bits 32-43) is NOT gated — non-zero
            // selects the atomic-recv-park branch in the fast-path
            // body (caller parks on that port after the reply commits).
            \\movq %%rcx, %%r11
            \\andq $0xFFF, %%r11
            \\cmpq $52, %%r11
            \\jne  .Lsyscall_slow_path
            \\movq %%rcx, %%r11
            \\shrq $44, %%r11
            \\jnz  .Lsyscall_slow_path
            \\movq %%rcx, %%r11
            \\shrq $12, %%r11
            \\andq $0xFF, %%r11
            \\jz   .Lsyscall_reply_fast
        else
            "")
        ++ "\n"
        ++
    // ═══════════════════════════════════════════════════════════════
    // SLOW PATH — 176-byte Context save + dispatch + iretq. Vregs
    // 1-13 are saved/restored across the call so handlers that leave
    // them alone return them to userspace unchanged. `.Lsyscall_slow_path`
    // is the bail-out target for fast-path validation failures.
    // ═══════════════════════════════════════════════════════════════
        \\.Lsyscall_slow_path:
        \\movq %%gs:16, %%rcx                 // restore user_rip
        \\movq %%gs:24, %%r11                 // restore user_rflags
        // FP bails enter here with rsp = kstack.top - 192 (the suspend
        // and reply FP entries pre-decrement rsp by 192 so any non-IST
        // kernel-mode exception's iret-frame push lands clear of
        // ec.ctx). The classifier-direct entry has rsp = kstack.top.
        // Reset rsp from gs:0 unconditionally so the slow-path Context
        // buffer always lands at kstack.top - 176 = ec.ctx_addr (the
        // canonical pointer ec.ctx was given at EC create time).
        // Without this, FP bails would build the saved iret frame at
        // kstack.top - 368 and leave ec.ctx pointing elsewhere; later
        // setSyscallReturn(ec.ctx, ...) — e.g. a delete on a reply
        // handle resolving the suspended sender with E_ABANDONED —
        // writes to stale ec.ctx storage and the wake target resumes
        // with garbage rip/cs/ss/rsp.
        \\movq %%gs:0, %%rsp
        \\subq $176, %%rsp
        \\movq %%rbp, 80(%%rsp)
        \\movq %%gs:8, %%rbp
        \\movq %%rbp, 160(%%rsp)              // ctx.rsp = user RSP
        \\swapgs                              // restore user GS
        \\movq $0x1b, 168(%%rsp)              // ctx.ss
        \\movq %%r11, 152(%%rsp)              // ctx.rflags
        \\movq $0x23, 144(%%rsp)              // ctx.cs
        \\movq %%rcx, 136(%%rsp)              // ctx.rip
        \\movq $0,    128(%%rsp)              // ctx.err_code
        \\movq $0x80, 120(%%rsp)              // ctx.int_num
        \\movq %%rax, 112(%%rsp)
        \\movq %%rcx, 104(%%rsp)
        \\movq %%rdx, 96(%%rsp)
        \\movq %%rbx, 88(%%rsp)
        \\movq %%rsi, 72(%%rsp)
        \\movq %%rdi, 64(%%rsp)
        \\movq %%r8,  56(%%rsp)
        \\movq %%r9,  48(%%rsp)
        \\movq %%r10, 40(%%rsp)
        \\movq %%r11, 32(%%rsp)
        \\movq %%r12, 24(%%rsp)
        \\movq %%r13, 16(%%rsp)
        \\movq %%r14, 8(%%rsp)
        \\movq %%r15, 0(%%rsp)
        \\movq %%rsp, %%rdi
        \\call syscallDispatch
        \\movq 0(%%rsp), %%r15
        \\movq 8(%%rsp), %%r14
        \\movq 16(%%rsp), %%r13
        \\movq 24(%%rsp), %%r12
        \\movq 32(%%rsp), %%r11
        \\movq 40(%%rsp), %%r10
        \\movq 48(%%rsp), %%r9
        \\movq 56(%%rsp), %%r8
        \\movq 64(%%rsp), %%rdi
        \\movq 72(%%rsp), %%rsi
        \\movq 80(%%rsp), %%rbp
        \\movq 88(%%rsp), %%rbx
        \\movq 96(%%rsp), %%rdx
        \\movq 104(%%rsp), %%rcx
        \\movq 112(%%rsp), %%rax
        \\addq $120, %%rsp
        \\addq $16, %%rsp
        \\iretq

    // ═══════════════════════════════════════════════════════════════
    // FAST PATH — L4-style zero-copy IPC rendezvous.
    //
    // Entry: rcx = payload_count (0..13). All other GPRs are sender
    // vregs and MUST survive end-to-end (they ARE the §[event_state]
    // payload the receiver gets). Free scratch: rcx, r11, rax (after
    // we spill its target_id contents to gs:72).
    //
    // gs scratch slot map:
    //   gs:64  fast_temp[0]  payload_count spill
    //   gs:72  fast_temp[1]  target_id (rax) spill, restored on bail
    //   gs:80  fast_temp[2]  Port* spill during dequeue pop +
    //                        recv_cd_ptr spill during mint
    //   gs:88  fast_temp[3]  receiver EC* spill (persists through CD
    //                        acquire + mint + state mutations)
    //   gs:96  fast_temp[4]  reply slot id (u16 in low bits)
    //   gs:104 fast_temp[5]  recv_cd_gen
    //   gs:112 fast_temp[6]  &kernel_table[reply_slot]
    //   gs:120 fast_temp[7]  port_ptr (after port lock release)
    //
    // Bail handlers all funnel into .Lsyscall_lock_fail which restores
    // rax = target_id from gs:72 then jmps .Lsyscall_slow_path. The
    // slow path expects sender's vreg 1 in rax for syscallDispatch's
    // arg-reading contract.
    // ═══════════════════════════════════════════════════════════════
        \\.Lsyscall_suspend_fast:

    // ─── Step 0: drop rsp below ec.ctx so any non-IST kernel-mode
    // exception's hardware iret-frame push lands clear of the saved
    // context. PHASE 1 left rsp = ec.kstack.top; ec.ctx lives at
    // kstack.top - 176 with its iret-frame fields ending at
    // kstack.top - 8. A 5-qword push at rsp - 40 would otherwise
    // overlap ec.ctx.{rip,cs,rflags,rsp,ss} byte-for-byte and
    // silently poison the EC's saved frame. Slow path's `subq $176`
    // accomplishes the same — this mirrors that invariant for the
    // fast path. 192 = 176 ec.ctx + 16-byte alignment slack, matching
    // the buffer R12.5 (reply FP) reserves below sender.kstack.top.
    //
    // Bail-to-slow-path edges (.Lsyscall_lock_fail / .Lsyscall_no_receiver
    // / .Lreply_handle_invalid / .Lreply_lock_fail) inherit this rsp
    // delta; the slow-path entry resets rsp from gs:0 before doing its
    // own subq $176 so the Context buffer it builds always lands at
    // kstack.top - 176 = ec.ctx_addr regardless of which arm we came
    // from.
    // ────────────────────────────────────────────────────────────────
        \\subq $192, %%rsp

    // ─── Step 1: port handle bounds check (rbx = port_id). ─────────
        \\cmpq $0xFFF, %%rbx
        \\ja .Lsyscall_slow_path

    // ─── Step 2: port type-tag check at user_table[port_id].word0
    // bits 12-15 == .port. Spill payload_count (rcx) to gs:64 first.
    // user_table base cached at gs:48.
    // ────────────────────────────────────────────────────────────────
        \\movq %%rcx, %%gs:64
        \\movq %%gs:48, %%rcx
        \\lea (%%rbx, %%rbx, 2), %%r11
        \\movq (%%rcx, %%r11, 8), %%r11
        \\shrq $12, %%r11
        \\andq $0xF, %%r11
        ++ std.fmt.comptimePrint(
            "\ncmpq ${d}, %%r11\njne .Lsyscall_slow_path\n",
            .{@intFromEnum(CapabilityType.port)},
        ) ++

    // ─── Step 3: target validation (rax = target_id). Bounds check,
    // caps check (susp+read+write all set; bits 53-55 of word0), then
    // self-suspend predicate (kernel_table[target].ref.ptr ==
    // current_ec @ gs:32). rcx still holds user_table base.
    // ────────────────────────────────────────────────────────────────
        \\cmpq $0xFFF, %%rax
        \\ja .Lsyscall_slow_path
        \\lea (%%rax, %%rax, 2), %%r11
        \\movq (%%rcx, %%r11, 8), %%r11
        \\shrq $53, %%r11
        \\andq $7, %%r11
        \\cmpq $7, %%r11
        \\jne .Lsyscall_slow_path
        \\movq %%gs:56, %%rcx
        ++ std.fmt.comptimePrint(
            "\nimulq ${d}, %%rax, %%r11\n",
            .{@sizeOf(KernelHandle)},
        ) ++
        \\movq (%%rcx, %%r11), %%rcx
        \\cmpq %%gs:32, %%rcx
        \\jne .Lsyscall_slow_path

    // ─── Step 4: resolve Port* + acquire gen-validating spinlock.
    // Spill rax (target_id) to gs:72 — cmpxchg uses rax implicitly,
    // and bail paths from here onward must restore for slow path.
    // disp+index addressing folds the addq for the kernel_table walk.
    // CAS loop: success → past retry block; gen drift → bail; just
    // contention → spin and retry.
    // ────────────────────────────────────────────────────────────────
        \\movq %%rax, %%gs:72
        \\movq %%gs:56, %%rcx
        ++ std.fmt.comptimePrint(
            \\
            \\imulq ${[kh_size]d}, %%rbx, %%r11
            \\movq {[ref_gen_off]d}(%%rcx, %%r11), %%rax
            \\movq {[ref_ptr_off]d}(%%rcx, %%r11), %%rcx
            \\testq %%rcx, %%rcx
            \\jz .Lsyscall_lock_fail
            \\shlq $1, %%rax
            \\lea 1(%%rax), %%r11
            \\.Lacquire_port:
            \\lock cmpxchgq %%r11, {[port_lock_off]d}(%%rcx)
            \\je .Lport_acquired
            \\xorq %%r11, %%rax
            \\testq $-2, %%rax
            \\jnz .Lsyscall_lock_fail
            \\pause
            \\movq %%r11, %%rax
            \\andq $-2, %%rax
            \\jmp .Lacquire_port
            \\.Lport_acquired:
            \\
        ,
            .{
                .kh_size = @sizeOf(KernelHandle),
                .ref_ptr_off = @offsetOf(KernelHandle, "ref") + @offsetOf(zag.caps.capability.ErasedSlabRef, "ptr"),
                .ref_gen_off = @offsetOf(KernelHandle, "ref") + @offsetOf(zag.caps.capability.ErasedSlabRef, "gen"),
                .port_lock_off = @offsetOf(Port, "_gen_lock"),
            },
        ) ++

    // ─── Step 5: peek port.waiter_kind. Lock held; if not .receivers,
    // bail via .Lsyscall_no_receiver (releases lock).
    // ────────────────────────────────────────────────────────────────
        std.fmt.comptimePrint(
            "\ncmpb ${d}, {d}(%%rcx)\njne .Lsyscall_no_receiver\n",
            .{ @intFromEnum(WaiterKind.receivers), @offsetOf(Port, "waiter_kind") },
        ) ++

    // ─── Step 6: dequeue highest-priority receiver. Walk levels[3..0],
    // first non-null head wins. Pop block clobbers rcx briefly (spilled
    // to gs:80) for the new_head temp; on exit rcx = Port*, r11 =
    // receiver EC*, rax = &level (disposable).
    // ────────────────────────────────────────────────────────────────
        std.fmt.comptimePrint(
            \\
            \\movq {[w3_head]d}(%%rcx), %%r11
            \\testq %%r11, %%r11
            \\jnz .Lpop_3
            \\movq {[w2_head]d}(%%rcx), %%r11
            \\testq %%r11, %%r11
            \\jnz .Lpop_2
            \\movq {[w1_head]d}(%%rcx), %%r11
            \\testq %%r11, %%r11
            \\jnz .Lpop_1
            \\movq {[w0_head]d}(%%rcx), %%r11
            \\testq %%r11, %%r11
            \\jnz .Lpop_0
            \\ud2
            \\.Lpop_3:
            \\leaq {[w3]d}(%%rcx), %%rax
            \\jmp .Lpop_common
            \\.Lpop_2:
            \\leaq {[w2]d}(%%rcx), %%rax
            \\jmp .Lpop_common
            \\.Lpop_1:
            \\leaq {[w1]d}(%%rcx), %%rax
            \\jmp .Lpop_common
            \\.Lpop_0:
            \\leaq {[w0]d}(%%rcx), %%rax
            \\.Lpop_common:
            \\movq %%rcx, %%gs:80
            \\movq {[next_off]d}(%%r11), %%rcx
            \\movq %%rcx, {[head_off]d}(%%rax)
            \\testq %%rcx, %%rcx
            \\jnz .Ldequeue_keep_tail
            \\movq $0, {[tail_off]d}(%%rax)
            \\.Ldequeue_keep_tail:
            \\movq $0, {[next_off]d}(%%r11)
            \\movq %%gs:80, %%rcx
            \\
        ,
            .{
                .w0 = @offsetOf(Port, "waiters") + 0 * @sizeOf(EcQueueLevel),
                .w1 = @offsetOf(Port, "waiters") + 1 * @sizeOf(EcQueueLevel),
                .w2 = @offsetOf(Port, "waiters") + 2 * @sizeOf(EcQueueLevel),
                .w3 = @offsetOf(Port, "waiters") + 3 * @sizeOf(EcQueueLevel),
                .w0_head = @offsetOf(Port, "waiters") + 0 * @sizeOf(EcQueueLevel) + @offsetOf(EcQueueLevel, "head"),
                .w1_head = @offsetOf(Port, "waiters") + 1 * @sizeOf(EcQueueLevel) + @offsetOf(EcQueueLevel, "head"),
                .w2_head = @offsetOf(Port, "waiters") + 2 * @sizeOf(EcQueueLevel) + @offsetOf(EcQueueLevel, "head"),
                .w3_head = @offsetOf(Port, "waiters") + 3 * @sizeOf(EcQueueLevel) + @offsetOf(EcQueueLevel, "head"),
                .head_off = @offsetOf(EcQueueLevel, "head"),
                .tail_off = @offsetOf(EcQueueLevel, "tail"),
                .next_off = @offsetOf(ExecutionContext, "next"),
            },
        ) ++

    // ─── Step 6.5: snapshot receiver state under port lock for the
    // recv_cd + receiver_ec acquire chain that follows port release.
    // Port lock pins the receiver while held, so reads here are
    // gen-coherent. Stash:
    //   gs:104 = receiver_ec_gen   (snapshot for Step 9.5 lockWithGen)
    //   gs:80  = recv_cd_ptr        (overwritten by recv_cd value at
    //                                Step 10; we re-stash there)
    //   gs:96  = recv_cd_gen        (overwritten at Step 10 line ~800
    //                                with reply_slot id; we use it
    //                                in Step 9 acquire then it's free)
    //
    // Capturing receiver.domain.ptr/.gen here moves the analyzer-
    // flagged "receiver.domain via %r11: lock not held" read at
    // (former) Step 9 line 752 into the port-locked window where the
    // receiver is provably alive. Step 9 then uses cached values.
    // ────────────────────────────────────────────────────────────────
        std.fmt.comptimePrint(
            \\
            \\movq {[ec_lock_off]d}(%%r11), %%rax
            \\shrq $1, %%rax
            \\movq %%rax, %%gs:104
            \\movq {[dom_ptr_off]d}(%%r11), %%rax
            \\movq %%rax, %%gs:80
            \\movq {[dom_gen_off]d}(%%r11), %%rax
            \\movq %%rax, %%gs:96
            \\
        ,
            .{
                .ec_lock_off = @offsetOf(ExecutionContext, "_gen_lock"),
                .dom_ptr_off = @offsetOf(ExecutionContext, "domain"),
                .dom_gen_off = @offsetOf(ExecutionContext, "domain") + 8,
            },
        ) ++

    // ─── Step 7: maintain port.waiter_kind. Scan all 4 levels — if
    // all heads null, set .none. Otherwise leave .receivers intact.
    // ────────────────────────────────────────────────────────────────
        std.fmt.comptimePrint(
            \\
            \\movq {[w3_head]d}(%%rcx), %%rax
            \\testq %%rax, %%rax
            \\jnz .Lwaiter_kind_done
            \\movq {[w2_head]d}(%%rcx), %%rax
            \\testq %%rax, %%rax
            \\jnz .Lwaiter_kind_done
            \\movq {[w1_head]d}(%%rcx), %%rax
            \\testq %%rax, %%rax
            \\jnz .Lwaiter_kind_done
            \\movq {[w0_head]d}(%%rcx), %%rax
            \\testq %%rax, %%rax
            \\jnz .Lwaiter_kind_done
            \\movb ${[wk_none]d}, {[wk_off]d}(%%rcx)
            \\.Lwaiter_kind_done:
            \\
        ,
            .{
                .w0_head = @offsetOf(Port, "waiters") + 0 * @sizeOf(EcQueueLevel) + @offsetOf(EcQueueLevel, "head"),
                .w1_head = @offsetOf(Port, "waiters") + 1 * @sizeOf(EcQueueLevel) + @offsetOf(EcQueueLevel, "head"),
                .w2_head = @offsetOf(Port, "waiters") + 2 * @sizeOf(EcQueueLevel) + @offsetOf(EcQueueLevel, "head"),
                .w3_head = @offsetOf(Port, "waiters") + 3 * @sizeOf(EcQueueLevel) + @offsetOf(EcQueueLevel, "head"),
                .wk_none = @intFromEnum(WaiterKind.none),
                .wk_off = @offsetOf(Port, "waiter_kind"),
            },
        ) ++

    // ─── Step 8: spill port_ptr (sender.suspend_port mutation needs
    // it later) and release the port lock. Plain andq — we own the
    // word, no concurrent writer.
    // ────────────────────────────────────────────────────────────────
        \\movq %%rcx, %%gs:120
        ++ std.fmt.comptimePrint(
            "\nandq $-2, {[port_lock_off]d}(%%rcx)\n",
            .{ .port_lock_off = @offsetOf(Port, "_gen_lock") },
        ) ++

    // ─── Step 9: acquire receiver's CD gen-lock from cached snapshot
    // (Step 6.5: gs:80 = recv_cd_ptr, gs:96 = recv_cd_gen). Spill
    // receiver EC* to gs:88 (persists through everything that follows).
    // Lock order: recv_cd here is the ONLY lock held; we acquire
    // receiver_ec at Step 9.5 — canonical CD → EC.
    // ────────────────────────────────────────────────────────────────
        \\movq %%r11, %%gs:88
        \\movq %%gs:80, %%rcx
        \\movq %%gs:96, %%r11
        ++ std.fmt.comptimePrint(
            \\
            \\shlq $1, %%r11
            \\movq %%r11, %%rax
            \\incq %%r11
            \\.Lacquire_recv_cd:
            \\lock cmpxchgq %%r11, {[cd_lock_off]d}(%%rcx)
            \\je .Lrecv_cd_acquired
            \\xorq %%r11, %%rax
            \\testq $-2, %%rax
            \\jnz .Lrecv_cd_fail
            \\pause
            \\movq %%r11, %%rax
            \\andq $-2, %%rax
            \\jmp .Lacquire_recv_cd
            \\.Lrecv_cd_acquired:
            \\
        ,
            .{ .cd_lock_off = @offsetOf(CapabilityDomain, "_gen_lock") },
        ) ++

    // ─── Step 9.5: acquire receiver_ec gen-lock with snapshotted gen
    // from Step 6.5. Holds recv_cd lock — canonical CD → EC order.
    // Bail to .Lrecv_ec_destroyed (release recv_cd, jmp slow path) if
    // gen rotated under us between Step 6.5 and now (concurrent
    // destroy walked the receiver while we were between port release
    // and recv_cd acquire). Receiver_ec held through Step 15 — covers
    // every receiver field write (state, event_*, ctx) plus the
    // kernel_stack.top read in Step 14.
    //
    // Register map mirrors Step 9 acquire: rcx = base reg for the
    // cmpxchg memory operand, rax = expected (unlocked target),
    // r11 = desired (locked target). After success rcx holds
    // receiver_ec_ptr (was recv_cd_ptr coming in from Step 9) — Step
    // 10's first instructions reload rcx = recv_cd_ptr from gs:80
    // and r11 = recv_cd_gen from gs:96.
    // ────────────────────────────────────────────────────────────────
        \\movq %%gs:88, %%rcx
        \\movq %%gs:104, %%rax
        ++ std.fmt.comptimePrint(
            \\
            \\shlq $1, %%rax
            \\movq %%rax, %%r11
            \\incq %%r11
            \\.Lacquire_recv_ec:
            \\lock cmpxchgq %%r11, {[ec_lock_off]d}(%%rcx)
            \\je .Lrecv_ec_acquired
            \\xorq %%r11, %%rax
            \\testq $-2, %%rax
            \\jnz .Lrecv_ec_destroyed
            \\pause
            \\movq %%r11, %%rax
            \\andq $-2, %%rax
            \\jmp .Lacquire_recv_ec
            \\.Lrecv_ec_acquired:
            \\
        ,
            .{ .ec_lock_off = @offsetOf(ExecutionContext, "_gen_lock") },
        ) ++

    // ─── Step 9.7: acquire sender_ec gen-lock. Sender = current_ec
    // (gs:32). Snap gen comes from `scratch.current_ec_gen` (gs:176),
    // captured by `switchTo` and refreshed by every fast-path
    // current-EC swap (Step 14 / R14). Per the lock discipline, every
    // slab-field access uses lockWithGen against a snap — even when
    // "we are this EC" — because terminate-from-another-core (some
    // other EC holds a handle to us in its own CD) can fire between
    // syscall entry and here, rotating the gen and possibly
    // reallocating the slot to a different EC. Held through Step 12
    // (last sender field write); released at Step 12.5.
    //
    // Same-class nesting with receiver_ec (held since Step 9.5).
    // Discipline: in suspend fast path, receiver_ec is acquired
    // BEFORE sender_ec. The reply fast path never holds both
    // simultaneously, so no cross-path AB-BA. tools/check_gen_lock
    // will flag the nesting; the documented invariant is that this
    // is the only path that holds both ECs at once.
    //
    // Bail to .Lsender_ec_destroyed: hard panic. By this point recv_cd
    // and recv_ec are both held — there's no clean unwind that doesn't
    // race the destroyer, and "I shouldn't exist" is a hard invariant
    // break. Mirrors `.Lreply_caller_destroyed` / `.Lreply_sender_destroyed`.
    //
    // Register map: rcx = sender_ec_ptr, rax/r11 = lock-word values.
    // ────────────────────────────────────────────────────────────────
        \\movq %%gs:32, %%rcx
        ++ std.fmt.comptimePrint(
            \\
            \\movq %%gs:{[sc_cur_gen]d}, %%rax
            \\shlq $1, %%rax
            \\movq %%rax, %%r11
            \\incq %%r11
            \\.Lacquire_sender_ec:
            \\lock cmpxchgq %%r11, {[ec_lock_off]d}(%%rcx)
            \\je .Lsender_ec_acquired
            \\xorq %%r11, %%rax
            \\testq $-2, %%rax
            \\jnz .Lsender_ec_destroyed
            \\pause
            \\movq %%r11, %%rax
            \\andq $-2, %%rax
            \\jmp .Lacquire_sender_ec
            \\.Lsender_ec_acquired:
            \\
        ,
            .{
                .ec_lock_off = @offsetOf(ExecutionContext, "_gen_lock"),
                .sc_cur_gen = Offsets.sc_current_ec_gen,
            },
        ) ++

    // ─── Step 10: mint reply handle. recv_cd held by lock; receiver_ec
    // also held (Step 9.5). Reload rcx = recv_cd_ptr and r11 =
    // recv_cd_gen from the Step 6.5 stash since Step 9.5 left rcx =
    // receiver_ec_ptr. gs:104 still holds receiver_ec_gen from Step
    // 6.5; we overwrite it here with recv_cd_gen — receiver_ec_gen
    // is no longer needed (the lockWithGen acquire at Step 9.5
    // committed the gen check).
    // Pop free slot via cd.free_head + free-list link (kernel_table[slot]
    // .parent.slot at offset 32 within KernelHandle). Write
    // user_table[slot] (word0=caps|type|slot, field0/field1=0) and
    // kernel_table[slot] (ref={sender,sender_gen}, parent/first_child/
    // next_sibling=0). Set sender backpointers pending_reply_holder/
    // domain/slot. word0 caps for fast path:
    // ReplyCaps{move=1,xfer=1}=0b101=5; tag=.reply=7.
    // ────────────────────────────────────────────────────────────────
        \\movq %%gs:80, %%rcx
        \\movq %%gs:96, %%r11
        \\movq %%r11, %%gs:104
        ++ std.fmt.comptimePrint(
            \\
            \\movzwq {[fh_off]d}(%%rcx), %%rax
            \\cmpq $0xFFFF, %%rax
            \\je .Lcd_full
            \\movq %%rax, %%gs:96
            \\movq {[kt_off]d}(%%rcx), %%r11
            \\imulq ${[kh_size]d}, %%rax, %%rax
            \\movzwq 32(%%r11, %%rax), %%r11
            \\movw %%r11w, {[fh_off]d}(%%rcx)
            \\decw {[fc_off]d}(%%rcx)
            \\
        ,
            .{
                .fh_off = @offsetOf(CapabilityDomain, "free_head"),
                .fc_off = @offsetOf(CapabilityDomain, "free_count"),
                .kt_off = @offsetOf(CapabilityDomain, "kernel_table"),
                .kh_size = @sizeOf(KernelHandle),
            },
        ) ++
        std.fmt.comptimePrint(
            \\
            \\movq {[kt_off]d}(%%rcx), %%r11
            \\addq %%r11, %%rax
            \\movq %%gs:32, %%r11
            \\movq %%r11, {[ref_ptr_off]d}(%%rax)
            \\movq {[ec_gen_off]d}(%%r11), %%rcx
            \\shrq $1, %%rcx
            \\movq %%rcx, {[ref_gen_off]d}(%%rax)
            \\movq $0, {[par0]d}(%%rax)
            \\movq $0, {[par1]d}(%%rax)
            \\movq $0, {[par2]d}(%%rax)
            \\movq $0, {[fc0]d}(%%rax)
            \\movq $0, {[fc1]d}(%%rax)
            \\movq $0, {[fc2]d}(%%rax)
            \\movq $0, {[ns0]d}(%%rax)
            \\movq $0, {[ns1]d}(%%rax)
            \\movq $0, {[ns2]d}(%%rax)
            \\movq %%rax, %%gs:112
            \\
        ,
            .{
                .kt_off = @offsetOf(CapabilityDomain, "kernel_table"),
                .ref_ptr_off = @offsetOf(KernelHandle, "ref") + @offsetOf(zag.caps.capability.ErasedSlabRef, "ptr"),
                .ref_gen_off = @offsetOf(KernelHandle, "ref") + @offsetOf(zag.caps.capability.ErasedSlabRef, "gen"),
                // EC._gen_lock is NOT at offset 0: ExecutionContext is a
                // plain (auto-reordered) struct and `fpu_state: [576]u8
                // align(64)` lands first. Use the comptime offset so the
                // mint reads the actual gen-lock word, not fpu_state[0..7].
                .ec_gen_off = @offsetOf(ExecutionContext, "_gen_lock"),
                // KernelHandle.parent / first_child / next_sibling are
                // each 24-byte HandleLinks (extern struct asserts in
                // capability.zig pin the layout). Three quadword writes
                // each, at offsets +0/+8/+16.
                .par0 = @offsetOf(KernelHandle, "parent") + 0,
                .par1 = @offsetOf(KernelHandle, "parent") + 8,
                .par2 = @offsetOf(KernelHandle, "parent") + 16,
                .fc0 = @offsetOf(KernelHandle, "first_child") + 0,
                .fc1 = @offsetOf(KernelHandle, "first_child") + 8,
                .fc2 = @offsetOf(KernelHandle, "first_child") + 16,
                .ns0 = @offsetOf(KernelHandle, "next_sibling") + 0,
                .ns1 = @offsetOf(KernelHandle, "next_sibling") + 8,
                .ns2 = @offsetOf(KernelHandle, "next_sibling") + 16,
            },
        ) ++
        std.fmt.comptimePrint(
            \\
            \\movq %%gs:80, %%rcx
            \\movq {[ut_off]d}(%%rcx), %%r11
            \\movq %%gs:96, %%rax
            \\lea (%%rax, %%rax, 2), %%rax
            \\movabsq ${[w0_const]d}, %%rcx
            \\orq %%gs:96, %%rcx
            \\movq %%rcx, {[w0_off]d}(%%r11, %%rax, 8)
            \\movq $0, {[f0_off]d}(%%r11, %%rax, 8)
            \\movq $0, {[f1_off]d}(%%r11, %%rax, 8)
            \\
        ,
            .{
                .ut_off = @offsetOf(CapabilityDomain, "user_table"),
                .w0_const = (@as(u64, @as(u16, @bitCast(ReplyCaps{ .move = true, .xfer = true }))) << 48) | (@as(u64, @intFromEnum(CapabilityType.reply)) << 12),
                .w0_off = @offsetOf(zag.caps.capability.Capability, "word0"),
                .f0_off = @offsetOf(zag.caps.capability.Capability, "field0"),
                .f1_off = @offsetOf(zag.caps.capability.Capability, "field1"),
            },
        ) ++
        std.fmt.comptimePrint(
            \\
            \\movq %%gs:32, %%r11
            \\movq %%gs:112, %%rax
            \\movq %%rax, {[prh_off]d}(%%r11)
            \\movq %%gs:80, %%rax
            \\movq %%rax, {[prd_off]d}(%%r11)
            \\movq %%gs:104, %%rax
            \\movq %%rax, {[prd_gen_off]d}(%%r11)
            \\movb $1, {[prd_disc_off]d}(%%r11)
            \\movq %%gs:96, %%rax
            \\movw %%ax, {[prs_off]d}(%%r11)
            \\
        ,
            .{
                .prh_off = @offsetOf(ExecutionContext, "pending_reply_holder"),
                .prd_off = @offsetOf(ExecutionContext, "pending_reply_domain"),
                .prd_gen_off = @offsetOf(ExecutionContext, "pending_reply_domain") + 8,
                .prd_disc_off = @offsetOf(ExecutionContext, "pending_reply_domain") + 16,
                .prs_off = @offsetOf(ExecutionContext, "pending_reply_slot"),
            },
        ) ++

    // ─── Step 11: release recv_cd lock. ────────────────────────────
        \\movq %%gs:80, %%rcx
        ++ std.fmt.comptimePrint(
            "\nandq $-2, {[cd_lock_off]d}(%%rcx)\n",
            .{ .cd_lock_off = @offsetOf(CapabilityDomain, "_gen_lock") },
        ) ++

    // ─── Step 12: park sender state (sender = current_ec = gs:32).
    // state=.suspended_on_port, event_type=.suspension, suspend_port
    // = SlabRef(port_ptr, port_gen) (payload + disc), originating
    // write/read caps = true (we verified susp+read+write earlier),
    // on_cpu = false. Save user RIP/RFLAGS/RSP into sender.ctx so the
    // eventual reply can resume via the existing iretq epilogue.
    // ────────────────────────────────────────────────────────────────
        \\movq %%gs:32, %%r11
        ++ std.fmt.comptimePrint(
            \\
            \\movb ${[state_susp]d}, {[state_off]d}(%%r11)
            \\movb ${[event_susp]d}, {[event_off]d}(%%r11)
            \\movb $0, {[event_subcode_off]d}(%%r11)
            \\movq $0, {[event_addr_off]d}(%%r11)
            \\movb $1, {[orig_write_off]d}(%%r11)
            \\movb $1, {[orig_read_off]d}(%%r11)
            \\movb $0, {[on_cpu_off]d}(%%r11)
            \\movq %%gs:120, %%rax
            \\movq %%rax, {[susp_port_off]d}(%%r11)
            \\movq {[port_lock_off]d}(%%rax), %%rcx
            \\shrq $1, %%rcx
            \\movq %%rcx, {[susp_port_gen_off]d}(%%r11)
            \\movb $1, {[susp_port_disc_off]d}(%%r11)
            \\movq {[ctx_off]d}(%%r11), %%rax
            \\movq %%gs:16, %%rcx
            \\movq %%rcx, {[ctx_rip_off]d}(%%rax)
            \\movq %%gs:24, %%rcx
            \\movq %%rcx, {[ctx_rflags_off]d}(%%rax)
            \\movq %%gs:8, %%rcx
            \\movq %%rcx, {[ctx_rsp_off]d}(%%rax)
            \\
            \\# Step 12.5: release sender_ec gen-lock (acquired Step 9.7).
            \\# r11 still holds sender_ec_ptr from Step 12 entry. After
            \\# this point only receiver_ec is held; the rest of the fast
            \\# path (Steps 13-15) writes receiver fields under that lock.
            \\andq $-2, {[ec_unlock_off]d}(%%r11)
            \\
        ,
            .{
                .state_susp = @intFromEnum(zag.sched.execution_context.State.suspended_on_port),
                .event_susp = @intFromEnum(zag.sched.execution_context.EventType.suspension),
                .state_off = @offsetOf(ExecutionContext, "state"),
                .event_off = @offsetOf(ExecutionContext, "event_type"),
                .event_subcode_off = @offsetOf(ExecutionContext, "event_subcode"),
                .event_addr_off = @offsetOf(ExecutionContext, "event_addr"),
                .orig_write_off = @offsetOf(ExecutionContext, "originating_write_cap"),
                .orig_read_off = @offsetOf(ExecutionContext, "originating_read_cap"),
                .on_cpu_off = @offsetOf(ExecutionContext, "on_cpu"),
                .susp_port_off = @offsetOf(ExecutionContext, "suspend_port"),
                .susp_port_gen_off = @offsetOf(ExecutionContext, "suspend_port") + 8,
                .susp_port_disc_off = @offsetOf(ExecutionContext, "suspend_port") + 16,
                .ctx_off = @offsetOf(ExecutionContext, "ctx"),
                .ec_unlock_off = @offsetOf(ExecutionContext, "_gen_lock"),
                .port_lock_off = @offsetOf(Port, "_gen_lock"),
                .ctx_rip_off = @offsetOf(cpu.Context, "rip"),
                .ctx_rflags_off = @offsetOf(cpu.Context, "rflags"),
                .ctx_rsp_off = @offsetOf(cpu.Context, "rsp"),
            },
        ) ++ (if (build_options.kernel_ctx_trace)
            // Move rsp below ec.ctx [kstack.top-176, kstack.top) before the
            // `call` so the saved RIP and the trampoline's GPR pushes do
            // not stomp the very iret-frame slots ctx_trace is here to
            // observe. FP rsp = scratch.kernel_rsp = kstack.top throughout
            // the path, so `call`'s RIP push lands at top-8 = ctx.ss
            // and the first 5 pushes overwrite ctx.{ss,rsp,rflags,cs,rip}
            // without this guard. 192 B leaves the full 176 B Context
            // intact plus 16 B alignment slack; restored after ret.
            \\subq $192, %%rsp
            \\call ctxTraceMarkFromAsm_fp_suspend_step12
            \\addq $192, %%rsp
            \\
        else
            "") ++

    // ─── Step 13: wake receiver state (gs:88). state=.running,
    // event_type=.none, suspend_port disc=null, recv_deadline_ns=0.
    // Stale slot in timed_recv_waiters[] self-clears via the
    // expireTimedRecvWaiters re-check logic.
    // ────────────────────────────────────────────────────────────────
        \\movq %%gs:88, %%r11
        ++ std.fmt.comptimePrint(
            \\
            \\movb ${[state_run]d}, {[state_off]d}(%%r11)
            \\movb ${[event_none]d}, {[event_off]d}(%%r11)
            \\movb $0, {[susp_disc_off]d}(%%r11)
            \\movq $0, {[deadline_off]d}(%%r11)
            \\movb $0, {[pew_valid_off]d}(%%r11)
            \\movb $0, {[per_valid_off]d}(%%r11)
            \\
            \\# Inline removeTimedRecvWaiter for receiver (in r11). Mirrors
            \\# the slow-path rendezvousWithReceiver call. SpinLock state
            \\# at offset {[lock_state_off]d} (Zig auto-reorders fields by
            \\# alignment: 8-byte class pointer first, u32 atomic state
            \\# second). xchgl-based blocking acquire (cmpxchgl would need
            \\# a third register for the desired value; only rax/rcx are
            \\# scratch since r11 holds receiver_ec for the compare).
            \\movq %%gs:{[sc_lock_ptr]d}, %%rcx
            \\.Ltrl_acquire:
            \\movl $1, %%eax
            \\xchgl %%eax, {[lock_state_off]d}(%%rcx)
            \\testl %%eax, %%eax
            \\jz .Ltrl_have
            \\pause
            \\jmp .Ltrl_acquire
            \\.Ltrl_have:
            \\movq %%gs:{[sc_waiters_ptr]d}, %%rcx
            \\xorl %%eax, %%eax
            \\.Ltrw_scan:
            \\cmpl ${[trw_max]d}, %%eax
            \\jge .Ltrw_done
            \\cmpq (%%rcx, %%rax, 8), %%r11
            \\je .Ltrw_clear
            \\incl %%eax
            \\jmp .Ltrw_scan
            \\.Ltrw_clear:
            \\movq $0, (%%rcx, %%rax, 8)
            \\.Ltrw_done:
            \\movq %%gs:{[sc_lock_ptr]d}, %%rcx
            \\movl $0, {[lock_state_off]d}(%%rcx)
            \\
        ,
            .{
                .state_run = @intFromEnum(zag.sched.execution_context.State.running),
                .event_none = @intFromEnum(zag.sched.execution_context.EventType.none),
                .state_off = @offsetOf(ExecutionContext, "state"),
                .event_off = @offsetOf(ExecutionContext, "event_type"),
                .susp_disc_off = @offsetOf(ExecutionContext, "suspend_port") + 16,
                .deadline_off = @offsetOf(ExecutionContext, "recv_deadline_ns"),
                .pew_valid_off = @offsetOf(ExecutionContext, "pending_event_word_valid"),
                .per_valid_off = @offsetOf(ExecutionContext, "pending_event_rip_valid"),
                .trw_max = zag.sched.port.MAX_TIMED_RECV_WAITERS,
                .lock_state_off = @offsetOf(zag.utils.sync.spin_lock.SpinLock, "state"),
                .sc_lock_ptr = Offsets.sc_timed_recv_lock_ptr,
                .sc_waiters_ptr = Offsets.sc_timed_recv_waiters_ptr,
            },
        ) ++

    // ─── Step 14: per-core scheduler accounting + lazy-FPU policy.
    // Update gs:32/40/48/56/0 + *(gs:136). Also keep the scheduler-side
    // `PerCore.current_ec` (= `core_states[core].current_ec`) in sync —
    // pageFaultHandler / syscall dispatch / etc. all read EC identity
    // through `scheduler.currentEc()` which loads from `PerCore`, not
    // from `gs:32`. If the fast path leaves them divergent, the next
    // user fault on this core resolves the wrong domain (e.g. primary
    // serial.print MMIO traps look up COM1 in the previously-scheduled
    // child's CD → null → spurious memory_fault that retires the wrong
    // EC). Mirrors `switchTo` (this file, end of module). FPU: arm
    // CR0.TS iff receiver != per_core->last_fpu_owner.ptr; skip CR-write
    // if already in desired state (each MOV-CR0 is a vmexit under KVM).
    // migrateFlush is currently a no-op stub (scheduler.zig:466).
    // ────────────────────────────────────────────────────────────────
        (if (build_options.kernel_ec_log)
            // ec_log mark fires BEFORE the gs:32 write so the trampoline
            // observes prev=gs:32 (still the outgoing sender) alongside
            // next=gs:88 (= incoming receiver_ec_ptr). Like the
            // ctx_trace trampolines above, FP rsp = kstack.top here so
            // the `call` saved-RIP push and the trampoline's GPR
            // preserves would otherwise stomp ec.ctx; subq $192 leaves
            // the full 176 B Context intact plus 16 B alignment slack.
            \\subq $192, %%rsp
            \\call ecLogMarkFromAsm_FP_S14
            \\addq $192, %%rsp
            \\
        else
            "") ++
        std.fmt.comptimePrint(
            \\
            \\movq %%gs:88, %%r11
            \\movq %%r11, %%gs:32
            \\movq %%gs:128, %%rax
            \\movq %%r11, {[cur_ec_off]d}(%%rax)
            \\movq {[gen_off]d}(%%r11), %%rcx
            \\shrq $1, %%rcx
            \\movl %%ecx, {[cur_ec_gen_off]d}(%%rax)
            \\movb $1, {[cur_ec_disc_off]d}(%%rax)
            \\movq %%rcx, %%gs:{[sc_cur_gen]d}
            \\movb $1, {[on_cpu_off]d}(%%r11)
            \\movzbl %%gs:{[sc_core_id]d}, %%ecx
            \\movb %%cl, {[last_disp_off]d}(%%r11)
            \\movq %%gs:80, %%rax
            \\movq %%rax, %%gs:40
            \\movq {[ut_off]d}(%%rax), %%rcx
            \\movq %%rcx, %%gs:48
            \\movq {[kt_off]d}(%%rax), %%rcx
            \\movq %%rcx, %%gs:56
            \\movq {[kstack_top_off]d}(%%r11), %%rcx
            \\movq %%rcx, %%gs:0
            \\movq %%gs:136, %%rax
            \\movq %%rcx, (%%rax)
            \\movq %%gs:128, %%rax
            \\movq {[fpu_owner_off]d}(%%rax), %%rcx
            \\cmpq %%rcx, %%r11
            \\je .Lfpu_want_clear
            \\cmpb $1, {[fpu_armed_off]d}(%%rax)
            \\je .Lfpu_done
            \\movq %%cr0, %%rcx
            \\orq $0x8, %%rcx
            \\movq %%rcx, %%cr0
            \\movb $1, {[fpu_armed_off]d}(%%rax)
            \\jmp .Lfpu_done
            \\.Lfpu_want_clear:
            \\cmpb $0, {[fpu_armed_off]d}(%%rax)
            \\je .Lfpu_done
            \\clts
            \\movb $0, {[fpu_armed_off]d}(%%rax)
            \\.Lfpu_done:
            \\
        ,
            .{
                .ut_off = @offsetOf(CapabilityDomain, "user_table"),
                .kt_off = @offsetOf(CapabilityDomain, "kernel_table"),
                .kstack_top_off = @offsetOf(ExecutionContext, "kernel_stack") + @offsetOf(zag.memory.stack.Stack, "top"),
                .fpu_owner_off = @offsetOf(zag.sched.scheduler.PerCore, "last_fpu_owner"),
                .fpu_armed_off = @offsetOf(zag.sched.scheduler.PerCore, "fpu_trap_armed"),
                .cur_ec_off = @offsetOf(zag.sched.scheduler.PerCore, "current_ec"),
                .cur_ec_gen_off = @offsetOf(zag.sched.scheduler.PerCore, "current_ec") + 8,
                .cur_ec_disc_off = @offsetOf(zag.sched.scheduler.PerCore, "current_ec") + 16,
                // Same EC._gen_lock-vs-offset-0 trap as the mint above:
                // fpu_state pushes _gen_lock past offset 0; the comptime
                // offset is the only safe way to read the gen-lock word.
                .gen_off = @offsetOf(ExecutionContext, "_gen_lock"),
                .sc_cur_gen = Offsets.sc_current_ec_gen,
                .on_cpu_off = @offsetOf(ExecutionContext, "on_cpu"),
                .last_disp_off = @offsetOf(ExecutionContext, "last_dispatched_core"),
                .sc_core_id = Offsets.sc_core_id,
            },
        ) ++

    // ─── Step 15: stash recv_ctx, compose vreg 0 return word.
    //
    // recv_ctx (= receiver.ctx, a *cpu.Context) is needed for the
    // user RIP/RFLAGS/RSP reads after the CR3 swap. Park it in gs:88
    // (reusing the receiver_ec slot — no longer needed).
    //
    // vreg 0 layout per §[event_state]:
    //   bits 32-43: reply_handle_id
    //   bits 44-48: event_type (.suspension = 4)
    //   bits 49-55: payload_count
    // Compose in rcx using the gs spill values.
    // ────────────────────────────────────────────────────────────────
        \\movq %%gs:88, %%r11
        ++ std.fmt.comptimePrint(
            \\
            \\movq {[ctx_off]d}(%%r11), %%rcx
            \\
            \\# Step 15.5: release receiver_ec gen-lock acquired at
            \\# Step 9.5. This is the last receiver-EC field access in
            \\# the suspend fast path; subsequent code only uses the
            \\# *cpu.Context (`rcx` here) which is not a slab type.
            \\andq $-2, {[ec_unlock_off]d}(%%r11)
            \\
            \\movq %%rcx, %%gs:88
            \\movq {[ctx_rsp_off]d}(%%rcx), %%rax
            \\
        ,
            .{
                .ctx_off = @offsetOf(ExecutionContext, "ctx"),
                .ec_unlock_off = @offsetOf(ExecutionContext, "_gen_lock"),
                .ctx_rsp_off = @offsetOf(cpu.Context, "rsp"),
            },
        ) ++
        \\movq %%gs:96, %%rcx
        \\shlq $32, %%rcx
        ++ std.fmt.comptimePrint(
            "\nmovabsq ${d}, %%r11\norq %%r11, %%rcx\n",
            .{@as(u64, @intFromEnum(zag.sched.execution_context.EventType.suspension)) << 44},
        ) ++
        \\movq %%gs:64, %%r11
        \\shlq $49, %%r11
        \\orq %%r11, %%rcx

    // ─── Step 16: CR3 swap to receiver's address space (PCID-aware).
    // Plain CR3 write — no NO-FLUSH bit, so new PCID's TLB entries
    // get flushed conservatively. After the swap kernel mappings are
    // unchanged (copyKernelMappings invariant), so gs/scratch reads
    // continue to work.
    // ────────────────────────────────────────────────────────────────
        \\movq %%rcx, %%gs:104
        \\movq %%gs:80, %%rcx
        ++ std.fmt.comptimePrint(
            \\
            \\movq {[asr_off]d}(%%rcx), %%r11
            \\testb $1, %%gs:144
            \\jz .Lcr3_no_pcid
            \\movzwq {[asid_off]d}(%%rcx), %%rcx
            \\orq %%rcx, %%r11
            \\.Lcr3_no_pcid:
            \\
        ,
            .{
                .asr_off = @offsetOf(CapabilityDomain, "addr_space_root"),
                .asid_off = @offsetOf(CapabilityDomain, "addr_space_id"),
            },
        ) ++
        \\movq %%r11, %%cr3

    // ─── Step 17: write vregs 0/14 to receiver's user stack, set up
    // sysretq state, return to user mode.
    //
    // Stack writes use rax = recv_user_rsp (loaded pre-CR3-swap).
    // After CR3 = recv_cd's PML4, recv's user pages are mapped.
    //
    // vreg 0 staged in gs:104 (we spilled it pre-CR3 to free rcx).
    // vreg 14 (sender RIP) comes from gs:16.
    //
    // Sysretq state:
    //   rcx = recv_user_rip   (recv_ctx.rip @ 136)
    //   r11 = recv_user_rflags (recv_ctx.rflags @ 152)
    //   rsp = recv_user_rsp   (already in rax; copy after stack writes)
    //   rax = sender's target_id (gs:72) → receiver's vreg 1
    //
    // Vregs 1..13 (rax-r15 minus rcx/r11) flow zero-copy from sender's
    // hw regs through the kernel into receiver's hw regs. rax was the
    // sender's target_id, and that IS what the receiver sees as vreg 1
    // per §[event_state] — we restore it from the gs:72 spill.
    //
    // TODO §[event_state] vregs 15/16/17/18 (sender's RFLAGS, RSP,
    // FS.base, GS.base) — write to recv_user_rsp + 16/24/32/40. The
    // first two come from gs:24 / gs:8; FS.base/GS.base require rdmsr.
    // ────────────────────────────────────────────────────────────────
        \\stac
        \\movq %%gs:104, %%rcx
        \\movq %%rcx, (%%rax)
        \\movq %%gs:16, %%rcx
        \\movq %%rcx, 8(%%rax)
        \\clac
        \\movq %%gs:88, %%rcx
        ++ std.fmt.comptimePrint(
            \\
            \\movq {[ctx_rflags_off]d}(%%rcx), %%r11
            \\movq {[ctx_rip_off]d}(%%rcx), %%rcx
            \\
        ,
            .{
                .ctx_rip_off = @offsetOf(cpu.Context, "rip"),
                .ctx_rflags_off = @offsetOf(cpu.Context, "rflags"),
            },
        ) ++
        \\movq %%rax, %%rsp
        \\movq %%gs:72, %%rax
        \\swapgs
        \\sysretq

    // ─── Bail handlers ─────────────────────────────────────────────
        \\.Lcd_full:
        \\movq %%gs:80, %%rcx
        ++ std.fmt.comptimePrint(
            "\nandq $-2, {[cd_lock_off]d}(%%rcx)\n",
            .{ .cd_lock_off = @offsetOf(CapabilityDomain, "_gen_lock") },
        ) ++
        \\ud2
        \\.Lrecv_cd_fail:
        \\ud2
        // .Lrecv_ec_destroyed: Step 9.5 lockWithGen detected receiver
        // gen rotated under us (concurrent destroy walked receiver
        // between Step 8 port release and Step 9.5 acquire). Release
        // recv_cd and bail to slow path.
        \\.Lrecv_ec_destroyed:
        \\movq %%gs:80, %%rcx
        ++ std.fmt.comptimePrint(
            "\nandq $-2, {[cd_lock_off]d}(%%rcx)\n",
            .{ .cd_lock_off = @offsetOf(CapabilityDomain, "_gen_lock") },
        ) ++
        \\jmp .Lsyscall_lock_fail

        // .Lsender_ec_destroyed: Step 9.7 lockWithGen detected sender
        // (= current_ec) gen rotated between syscall entry's snap
        // (gs:176) and the acquire here — terminate-from-another-core
        // fired against us. Hard panic: recv_cd / recv_ec are still
        // held but the system invariant ("the EC running this syscall
        // exists") is broken; any clean unwind would still race the
        // destroyer. Mirror of `.Lreply_caller_destroyed`.
        \\.Lsender_ec_destroyed:
        \\ud2
        \\.Lsyscall_no_receiver:
        ++ std.fmt.comptimePrint(
            "\nandq $-2, {[port_lock_off]d}(%%rcx)\n",
            .{ .port_lock_off = @offsetOf(Port, "_gen_lock") },
        ) ++
        \\.Lsyscall_lock_fail:
        \\movq %%gs:72, %%rax                 // restore target_id for slow path
        \\jmp .Lsyscall_slow_path

    // ═══════════════════════════════════════════════════════════════
    // REPLY FAST PATH — L4-style direct rendezvous. Mirror of the
    // suspend fast path: the reply cap names a parked sender (no port
    // queue to walk — the cap IS the only path to that EC). We switch
    // this core to that sender via sysretq and the receiver's live
    // vregs flow zero-copy through the GPRs into sender's user-mode
    // resumption regs. Receiver gets pushed onto this core's run
    // queue with .ctx patched so its later re-dispatch returns to the
    // post-syscall RIP with rax=0.
    //
    // Entry: rcx = full syscall_word (low 12 = 52 = .reply,
    //              bits 12-23 = reply_handle_id, bits 24-63 = 0).
    //        All other GPRs are receiver vregs and MUST stay
    //        untouched — they ARE sender's resumption vregs. Free
    //        scratch: rcx, r11; rax is freed after the gs:64 spill
    //        and reloaded just before sysretq.
    //
    // Predicates (all under receiver CD lock so we can bail to slow
    // path BEFORE touching the slot):
    //   1. kernel_table[slot].ref.ptr != null
    //   2. user_table[slot].word0 type tag == .reply (= 7)
    //   3. ReplyCaps.abandoned bit (word0 bit 51) clear
    //   4. sender.iret_frame == null  (slow path uses iret_frame ?? ctx)
    //   5. sender.vcpu_arch_state == null  (vCPU writeback skipped)
    //   6. sender.originating_write_cap == true  (else slow path
    //      preserves sender's own regs; we'd clobber them)
    // After lock release + slot free, the only remaining failure is
    // the sender gen-lock acquire racing terminate → inline E_TERM
    // sysretq to the *receiver* (slot already freed, so re-entering
    // the slow path would mis-report E_BADCAP).
    //
    // Receiver semantics: libz `issueRegDiscard` (the reply asm)
    // declares all 13 vreg registers as clobbered, so the receiver
    // does NOT depend on them surviving the syscall. We are free to
    // hand them off to the sender wholesale — only `receiver.ctx.rax`
    // gets the explicit 0-write so the syscall return is 0 (success).
    // The other 12 ctx.regs.* slots stay whatever was there from a
    // prior preemption; per the libz contract that is in-spec garbage.
    //
    // gs scratch slot map (separate slot bands from suspend; only
    // one fast path runs per syscall trap):
    //   gs:64  fast_temp[0]  receiver's rax (vreg 1) spill;
    //                        becomes sender resumption rax
    //   gs:72  fast_temp[1]  sender_ec_ptr
    //   gs:80  fast_temp[2]  reply_slot id
    //   gs:88  fast_temp[3]  &kernel_table[reply_slot]
    //   gs:96  fast_temp[4]  sender_ec_gen (cap snapshot)
    //   gs:104 fast_temp[5]  sender_cd_ptr (after sender lock)
    //   gs:112 fast_temp[6]  (unused)
    //   gs:120 fast_temp[7]  (unused)
    // ═══════════════════════════════════════════════════════════════
        \\.Lsyscall_reply_fast:

    // ─── Step R0: drop rsp below ec.ctx. Same rationale as the
    // matching Step 0 above `.Lsyscall_suspend_fast` — non-IST
    // kernel-mode exceptions push their hardware iret frame onto the
    // current rsp, and ec.ctx.{rip,cs,rflags,rsp,ss} live at
    // kstack.top - 40 .. kstack.top - 8. 192 = 176 ec.ctx + 16-byte
    // alignment slack. Bail edges (.Lreply_handle_invalid /
    // .Lreply_lock_fail / .Lreply_sender_field_fail) inherit this
    // rsp delta; the slow-path entry resets rsp from gs:0 before its
    // own subq $176, so the Context buffer always lands at
    // kstack.top - 176 = ec.ctx_addr.
    // ────────────────────────────────────────────────────────────────
        \\subq $192, %%rsp

    // ─── Step R1: spill receiver's rax (vreg 1) to gs:64. cmpxchg
    // loops below clobber rax; we restore the original value by
    // copying it into sender.ctx.regs.rax (matches slow-path
    // copyEventStateGprs gated on sender.originating_write_cap).
    // ────────────────────────────────────────────────────────────────
        \\movq %%rax, %%gs:64

    // ─── Step R2: extract reply_slot from rcx bits 20-31 (gs:80) and
    // recv_port_handle_id from rcx bits 32-43 (gs:112). recv_port == 0
    // ⇒ bare reply (caller resumes after replyee). recv_port != 0 ⇒
    // atomic-recv-mode reply (caller parks on the named port after
    // the replyee resumes). gs:112 doubles as the branch flag at R13.
    // R4b will overlay gs:112 with the packed (recv_port | xfer<<12 |
    // port_gen<<32) once the recv_port handle has been validated.
    // ────────────────────────────────────────────────────────────────
        \\movq %%rcx, %%rax
        \\shrq $20, %%rax
        \\andq $0xFFF, %%rax
        \\movq %%rax, %%gs:80
        \\movq %%rcx, %%rax
        \\shrq $32, %%rax
        \\andq $0xFFF, %%rax
        \\movq %%rax, %%gs:112

    // ─── Step R3: acquire receiver's CD gen-lock. CD ptr at gs:40.
    // CAS pattern matches suspend fast path Step 9.
    // ────────────────────────────────────────────────────────────────
        ++ std.fmt.comptimePrint(
            \\
            \\movq %%gs:40, %%rcx
            \\movq {[cd_lock_off]d}(%%rcx), %%rax
            \\andq $-2, %%rax
            \\lea 1(%%rax), %%r11
            \\.Lreply_acquire_cd:
            \\lock cmpxchgq %%r11, {[cd_lock_off]d}(%%rcx)
            \\je .Lreply_cd_acquired
            \\xorq %%r11, %%rax
            \\testq $-2, %%rax
            \\jnz .Lreply_lock_fail
            \\pause
            \\movq %%r11, %%rax
            \\andq $-2, %%rax
            \\jmp .Lreply_acquire_cd
            \\.Lreply_cd_acquired:
            \\
        ,
            .{ .cd_lock_off = @offsetOf(CapabilityDomain, "_gen_lock") },
        ) ++

    // ─── Step R4: validate handle. Compute &kernel_table[slot] and
    // check ref.ptr != null; check user_table[slot].word0 has type
    // tag == .reply and the abandoned bit (word0 bit 51) is clear.
    // ────────────────────────────────────────────────────────────────
        std.fmt.comptimePrint(
            \\
            \\movq {[kt_off]d}(%%rcx), %%r11
            \\movq %%gs:80, %%rax
            \\imulq ${[kh_size]d}, %%rax, %%rax
            \\addq %%r11, %%rax
            \\movq %%rax, %%gs:88
            \\movq {[ref_ptr_off]d}(%%rax), %%r11
            \\testq %%r11, %%r11
            \\jz .Lreply_handle_invalid
            \\movq %%r11, %%gs:72
            \\movq {[ref_gen_off]d}(%%rax), %%r11
            \\movq %%r11, %%gs:96
            \\movq {[ut_off]d}(%%rcx), %%r11
            \\movq %%gs:80, %%rax
            \\leaq (%%rax, %%rax, 2), %%rax
            \\movq {[w0_off]d}(%%r11, %%rax, 8), %%rax
            \\movq %%rax, %%r11
            \\shrq $12, %%r11
            \\andq $0xF, %%r11
            \\cmpq ${[type_reply]d}, %%r11
            \\jne .Lreply_handle_invalid
            \\btq ${[abandoned_bit]d}, %%rax
            \\jc .Lreply_handle_invalid
            \\
        ,
            .{
                .kt_off = @offsetOf(CapabilityDomain, "kernel_table"),
                .ut_off = @offsetOf(CapabilityDomain, "user_table"),
                .kh_size = @sizeOf(KernelHandle),
                .ref_ptr_off = @offsetOf(KernelHandle, "ref") + @offsetOf(zag.caps.capability.ErasedSlabRef, "ptr"),
                .ref_gen_off = @offsetOf(KernelHandle, "ref") + @offsetOf(zag.caps.capability.ErasedSlabRef, "gen"),
                .w0_off = @offsetOf(zag.caps.capability.Capability, "word0"),
                .type_reply = @intFromEnum(CapabilityType.reply),
                // ReplyCaps lives in word0[48..63]; abandoned is bit 3 of
                // ReplyCaps → word0 bit 51. `testq` can't take a 64-bit
                // immediate so use `btq` (bit-test → CF).
                .abandoned_bit = 48 + 3,
            },
        ) ++

    // ─── Step R4b: atomic-recv-mode validation. Only fires when
    // gs:112 (recv_port_handle_id) is non-zero. Validates the named
    // port handle while the CD lock is still held (user_table /
    // kernel_table mutations are CD-protected). On any failure
    // (E_BADCAP for bad slot/type, E_PERM for missing recv cap),
    // bail to .Lreply_handle_invalid → slow path re-resolves and
    // returns the right error code with the reply handle intact
    // (spec §[reply] tests 22/23).
    //
    // Stashes after success:
    //   gs:120 = port_ec_ptr
    //   gs:112 = recv_port (bits 0-11) | xfer (bit 12) | port_gen (bits 32-63)
    //
    // After this block, rcx == receiver_cd (preserved for R6).
    // ────────────────────────────────────────────────────────────────
        std.fmt.comptimePrint(
            \\
            \\movq %%gs:112, %%rax
            \\testq %%rax, %%rax
            \\jz .Lreply_skip_recv_validate
            \\
            \\movq {[ut_off]d}(%%rcx), %%r11
            \\leaq (%%rax, %%rax, 2), %%rax
            \\movq {[w0_off]d}(%%r11, %%rax, 8), %%rax
            \\
            \\movq %%rax, %%r11
            \\shrq $12, %%r11
            \\andq $0xF, %%r11
            \\cmpq ${[type_port]d}, %%r11
            \\jne .Lreply_handle_invalid
            \\
            \\btq ${[recv_bit]d}, %%rax
            \\jnc .Lreply_handle_invalid
            \\
            \\movq %%gs:112, %%r11
            \\btq ${[xfer_bit]d}, %%rax
            \\jnc .Lreply_skip_xfer_set
            \\orq $0x1000, %%r11
            \\.Lreply_skip_xfer_set:
            \\movq %%r11, %%gs:112
            \\
            \\movq %%gs:112, %%rax
            \\andq $0xFFF, %%rax
            \\imulq ${[kh_size]d}, %%rax, %%rax
            \\addq {[kt_off]d}(%%rcx), %%rax
            \\movq {[ref_ptr_off]d}(%%rax), %%r11
            \\testq %%r11, %%r11
            \\jz .Lreply_handle_invalid
            \\movq %%r11, %%gs:120
            \\movl {[ref_gen_off]d}(%%rax), %%eax
            \\shlq $32, %%rax
            \\orq %%rax, %%gs:112
            \\
            \\.Lreply_skip_recv_validate:
            \\movq %%gs:40, %%rcx
            \\
        ,
            .{
                .ut_off = @offsetOf(CapabilityDomain, "user_table"),
                .kt_off = @offsetOf(CapabilityDomain, "kernel_table"),
                .w0_off = @offsetOf(zag.caps.capability.Capability, "word0"),
                .type_port = @intFromEnum(CapabilityType.port),
                .recv_bit = 48 + 3,
                .xfer_bit = 48 + 2,
                .kh_size = @sizeOf(KernelHandle),
                .ref_ptr_off = @offsetOf(KernelHandle, "ref") + @offsetOf(zag.caps.capability.ErasedSlabRef, "ptr"),
                .ref_gen_off = @offsetOf(KernelHandle, "ref") + @offsetOf(zag.caps.capability.ErasedSlabRef, "gen"),
            },
        ) ++

    // ─── Step R5a: acquire sender's gen-lock BEFORE reading sender
    // fields. Mirrors slow-path's `sender_ref.lockIrqSave(@src())` in
    // `port.reply` — every read of sender state happens under the
    // sender's gen-lock so a concurrent destroy/realloc of the slab
    // slot can't tear our predicate snapshot.
    //
    // Stash sender_cd_ptr (sender.domain.ptr) to gs:104 along the
    // way — needed for the per-core switch + CR3 swap below.
    //
    // Lock order: CD (R3) → sender_ec (here). Released sender_ec
    // (R10) → CD (R7). Acquire CD-then-EC matches port.recv ordering.
    //
    // Bails:
    //   .Lreply_eterm_under_cd : sender gen mismatch (slot recycled
    //                            since R4 snapshot). CD lock held,
    //                            handle NOT yet cleared. Release CD,
    //                            sysretq E_TERM to receiver.
    // ────────────────────────────────────────────────────────────────
        \\movq %%gs:72, %%rcx
        ++ std.fmt.comptimePrint(
            \\
            \\movq %%gs:96, %%rax
            \\shlq $1, %%rax
            \\movq %%rax, %%r11
            \\incq %%r11
            \\.Lreply_acquire_sender:
            \\lock cmpxchgq %%r11, {[ec_lock_off]d}(%%rcx)
            \\je .Lreply_sender_acquired
            \\xorq %%r11, %%rax
            \\testq $-2, %%rax
            \\jnz .Lreply_eterm_under_cd
            \\pause
            \\movq %%r11, %%rax
            \\andq $-2, %%rax
            \\jmp .Lreply_acquire_sender
            \\.Lreply_sender_acquired:
            \\movq {[dom_off]d}(%%rcx), %%r11
            \\movq %%r11, %%gs:104
            \\
        ,
            .{
                .dom_off = @offsetOf(ExecutionContext, "domain"),
                .ec_lock_off = @offsetOf(ExecutionContext, "_gen_lock"),
            },
        ) ++

    // ─── Step R5b: read sender predicate fields under sender lock.
    // rcx still holds sender_ec_ptr from R5a's cmpxchg target — keep
    // using it so the genlock analyzer can prove the lock-acquired
    // pointer and the field-access pointer are the same register.
    // Bail to .Lreply_sender_field_fail: releases sender lock first
    // (LIFO with R5a acquire), then falls into .Lreply_handle_invalid
    // which releases CD lock and jumps slow path.
    // ────────────────────────────────────────────────────────────────
        std.fmt.comptimePrint(
            \\
            \\movq {[ir_off]d}(%%rcx), %%rax
            \\testq %%rax, %%rax
            \\jnz .Lreply_sender_field_fail
            \\movq {[vcpu_off]d}(%%rcx), %%rax
            \\testq %%rax, %%rax
            \\jnz .Lreply_sender_field_fail
            \\cmpb $1, {[wcap_off]d}(%%rcx)
            \\jne .Lreply_sender_field_fail
            \\
        ,
            .{
                .ir_off = @offsetOf(ExecutionContext, "iret_frame"),
                .vcpu_off = @offsetOf(ExecutionContext, "vcpu_arch_state"),
                .wcap_off = @offsetOf(ExecutionContext, "originating_write_cap"),
            },
        ) ++

    // ─── Step R6: clearAndFreeSlot inline. R5a left rcx = sender_ec_ptr,
    // so reload rcx = receiver_cd from gs:40 first.
    //   user_table[slot] = {0, 0, 0}
    //   kernel_table[slot].ref = .{}                    (16 bytes)
    //   kernel_table[slot].parent = encodeFreeNext(cd.free_head)
    //     (16 bytes domain ErasedSlabRef = 0, then u16 slot =
    //      cd.free_head, then 6 bytes _reserved = 0)
    //   kernel_table[slot].first_child = .{}            (24 bytes 0)
    //   kernel_table[slot].next_sibling = .{}           (24 bytes 0)
    //   cd.free_head = slot
    //   cd.free_count += 1
    // ────────────────────────────────────────────────────────────────
        \\movq %%gs:40, %%rcx
        ++ std.fmt.comptimePrint(
            \\
            \\movq {[ut_off]d}(%%rcx), %%r11
            \\movq %%gs:80, %%rax
            \\leaq (%%rax, %%rax, 2), %%rax
            \\leaq (%%r11, %%rax, 8), %%r11
            \\movq $0, {[w0_off]d}(%%r11)
            \\movq $0, {[f0_off]d}(%%r11)
            \\movq $0, {[f1_off]d}(%%r11)
            \\movq %%gs:88, %%r11
            \\movq $0, {[ref_ptr_off]d}(%%r11)
            \\movq $0, {[ref_gen_off]d}(%%r11)
            \\movq $0, {[par0]d}(%%r11)
            \\movq $0, {[par1]d}(%%r11)
            \\movzwq {[fh_off]d}(%%rcx), %%rax
            \\movq %%rax, {[par2]d}(%%r11)
            \\movq $0, {[fc0]d}(%%r11)
            \\movq $0, {[fc1]d}(%%r11)
            \\movq $0, {[fc2]d}(%%r11)
            \\movq $0, {[ns0]d}(%%r11)
            \\movq $0, {[ns1]d}(%%r11)
            \\movq $0, {[ns2]d}(%%r11)
            \\movq %%gs:80, %%rax
            \\movw %%ax, {[fh_off]d}(%%rcx)
            \\incw {[fc_off]d}(%%rcx)
            \\
        ,
            .{
                .ut_off = @offsetOf(CapabilityDomain, "user_table"),
                .w0_off = @offsetOf(zag.caps.capability.Capability, "word0"),
                .f0_off = @offsetOf(zag.caps.capability.Capability, "field0"),
                .f1_off = @offsetOf(zag.caps.capability.Capability, "field1"),
                .ref_ptr_off = @offsetOf(KernelHandle, "ref") + @offsetOf(zag.caps.capability.ErasedSlabRef, "ptr"),
                .ref_gen_off = @offsetOf(KernelHandle, "ref") + @offsetOf(zag.caps.capability.ErasedSlabRef, "gen"),
                .par0 = @offsetOf(KernelHandle, "parent") + 0,
                .par1 = @offsetOf(KernelHandle, "parent") + 8,
                .par2 = @offsetOf(KernelHandle, "parent") + 16,
                .fc0 = @offsetOf(KernelHandle, "first_child") + 0,
                .fc1 = @offsetOf(KernelHandle, "first_child") + 8,
                .fc2 = @offsetOf(KernelHandle, "first_child") + 16,
                .ns0 = @offsetOf(KernelHandle, "next_sibling") + 0,
                .ns1 = @offsetOf(KernelHandle, "next_sibling") + 8,
                .ns2 = @offsetOf(KernelHandle, "next_sibling") + 16,
                .fh_off = @offsetOf(CapabilityDomain, "free_head"),
                .fc_off = @offsetOf(CapabilityDomain, "free_count"),
            },
        ) ++

    // ─── Step R7: release CD lock. ─────────────────────────────────
        std.fmt.comptimePrint(
            "\nandq $-2, {[cd_lock_off]d}(%%rcx)\n",
            .{ .cd_lock_off = @offsetOf(CapabilityDomain, "_gen_lock") },
        ) ++

    // ─── Step R8: (folded into R5a — sender's gen-lock is already
    // held by the time we reach here. sender_cd_ptr was stashed to
    // gs:104 in R5a. Just reload rcx = sender_ec_ptr for R9 below.)
    // ────────────────────────────────────────────────────────────────
        \\movq %%gs:72, %%rcx
        ++

    // ─── Step R9: resumeFromReply state writes on sender. Sender goes
    // straight to .running because we are about to switch this core
    // to it (no runqueue insertion for sender — direct dispatch).
    // Mirrors execution_context.resumeFromReply field-for-field.
    // ────────────────────────────────────────────────────────────────
        std.fmt.comptimePrint(
            \\
            \\movb ${[state_run]d}, {[state_off]d}(%%rcx)
            \\movb ${[event_none]d}, {[event_off]d}(%%rcx)
            \\movb $0, {[event_subcode_off]d}(%%rcx)
            \\movq $0, {[event_addr_off]d}(%%rcx)
            \\movb $0, {[susp_disc_off]d}(%%rcx)
            \\movq $0, {[prh_off]d}(%%rcx)
            \\movb $0, {[prd_disc_off]d}(%%rcx)
            \\movw $0, {[prs_off]d}(%%rcx)
            \\movb $0, {[orig_write_off]d}(%%rcx)
            \\movb $0, {[orig_read_off]d}(%%rcx)
            \\movb $0, {[ppc_off]d}(%%rcx)
            \\
        ,
            .{
                .state_run = @intFromEnum(zag.sched.execution_context.State.running),
                .event_none = @intFromEnum(zag.sched.execution_context.EventType.none),
                .state_off = @offsetOf(ExecutionContext, "state"),
                .event_off = @offsetOf(ExecutionContext, "event_type"),
                .event_subcode_off = @offsetOf(ExecutionContext, "event_subcode"),
                .event_addr_off = @offsetOf(ExecutionContext, "event_addr"),
                .susp_disc_off = @offsetOf(ExecutionContext, "suspend_port") + 16,
                .prh_off = @offsetOf(ExecutionContext, "pending_reply_holder"),
                .prd_disc_off = @offsetOf(ExecutionContext, "pending_reply_domain") + 16,
                .prs_off = @offsetOf(ExecutionContext, "pending_reply_slot"),
                .orig_write_off = @offsetOf(ExecutionContext, "originating_write_cap"),
                .orig_read_off = @offsetOf(ExecutionContext, "originating_read_cap"),
                .ppc_off = @offsetOf(ExecutionContext, "pending_pair_count"),
            },
        ) ++

    // ─── Step R10: release sender gen lock. ────────────────────────
        std.fmt.comptimePrint(
            "\nandq $-2, {[ec_lock_off]d}(%%rcx)\n",
            .{ .ec_lock_off = @offsetOf(ExecutionContext, "_gen_lock") },
        ) ++

    // ─── Step R10.5: acquire caller (= receiver = current_ec) gen-lock
    // before any receiver-EC field writes. R11..R13 mutate receiver.ctx
    // (rip/rsp/rflags/rax/cs/ss), receiver.state, receiver.event_*,
    // receiver.suspend_port, receiver.recv_port_xfer, receiver.next /
    // priority — every one of those is also a write target for unrelated
    // syscalls that other cores can issue against a handle to this same
    // EC (priority, setRegisters, kill, etc.). Per the lock discipline:
    // touching a slab-backed object's fields requires holding its
    // _gen_lock against a snapshotted gen.
    //
    // Snap is `scratch.current_ec_gen` (gs:176), captured by `switchTo`
    // alongside `current_ec`. Between R7 (CD release) and here the
    // caller_ec carries no held lock, so a concurrent terminate from
    // another core that holds a handle to *us* could fire (locks
    // caller_ec briefly, releases, then `destroyExecutionContext`
    // rotates gen to even; a fresh allocation could rotate it again
    // back to a different odd). A plain spin-acquire would lock the
    // wrong slab generation; lockWithGen catches the mismatch and
    // bails to `.Lreply_caller_destroyed`.
    //
    // Lock order: nothing else held at this point (R7 dropped CD, R10
    // dropped sender_ec). For the atomic-recv-park R13 branch the port
    // lock will nest under this lock (receiver_ec → port). Tag the
    // acquisition with ordered_group=2 (EC_NESTED_GROUP) so future asm
    // additions that need same-class nesting (sender_ec + receiver_ec
    // simultaneously, address-ordered) don't trip lockdep — though this
    // particular path holds only one EC at a time.
    // ────────────────────────────────────────────────────────────────
        \\movq %%gs:32, %%rcx
        ++ std.fmt.comptimePrint(
            \\
            \\movq %%gs:{[sc_cur_gen]d}, %%rax
            \\shlq $1, %%rax
            \\movq %%rax, %%r11
            \\incq %%r11
            \\.Lreply_acq_caller:
            \\lock cmpxchgq %%r11, {[ec_lock_off]d}(%%rcx)
            \\je .Lreply_caller_acquired
            \\xorq %%r11, %%rax
            \\testq $-2, %%rax
            \\jnz .Lreply_caller_destroyed
            \\pause
            \\movq %%r11, %%rax
            \\andq $-2, %%rax
            \\jmp .Lreply_acq_caller
            \\.Lreply_caller_acquired:
            \\
        ,
            .{
                .ec_lock_off = @offsetOf(ExecutionContext, "_gen_lock"),
                .sc_cur_gen = Offsets.sc_current_ec_gen,
            },
        ) ++

    // ─── Step R11: patch receiver.ctx so its eventual re-dispatch
    // through `switchTo` iretq's into post-syscall user mode with
    // rax=0 (success). Only 4 fields touched: regs.rax, rip, rflags,
    // rsp. The other 12 ctx.regs.* slots stay whatever was there
    // from a prior preemption — receiver's libz reply asm declares
    // them clobbered, so stale values are in-spec garbage.
    //
    // No Context push, no per-vreg copy — the live receiver vregs
    // remain in registers and ride sysretq into sender's user mode
    // zero-copy.
    // ────────────────────────────────────────────────────────────────
        \\movq %%gs:32, %%rcx
        ++ std.fmt.comptimePrint(
            \\
            \\movq {[ec_ctx_off]d}(%%rcx), %%rcx
            \\movq $0, {[reg_rax_off]d}(%%rcx)
            \\movq %%gs:16, %%r11
            \\movq %%r11, {[ctx_rip_off]d}(%%rcx)
            \\movq %%gs:24, %%r11
            \\movq %%r11, {[ctx_rflags_off]d}(%%rcx)
            \\movq %%gs:8, %%r11
            \\movq %%r11, {[ctx_rsp_off]d}(%%rcx)
            \\movq $0x23, {[ctx_cs_off]d}(%%rcx)
            \\movq $0x1b, {[ctx_ss_off]d}(%%rcx)
            \\
        ,
            .{
                .ec_ctx_off = @offsetOf(ExecutionContext, "ctx"),
                .reg_rax_off = @offsetOf(cpu.Context, "regs") + @offsetOf(cpu.Registers, "rax"),
                .ctx_rip_off = @offsetOf(cpu.Context, "rip"),
                .ctx_rflags_off = @offsetOf(cpu.Context, "rflags"),
                .ctx_rsp_off = @offsetOf(cpu.Context, "rsp"),
                .ctx_cs_off = @offsetOf(cpu.Context, "cs"),
                .ctx_ss_off = @offsetOf(cpu.Context, "ss"),
            },
        ) ++ (if (build_options.kernel_ctx_trace)
            // See suspend Step 12 mark above for the kstack-vs-ec.ctx
            // overlap rationale.
            \\subq $192, %%rsp
            \\call ctxTraceMarkFromAsm_fp_reply_r11
            \\addq $192, %%rsp
            \\
        else
            "") ++

    // ─── Step R12: enter the IRQ-disabled critical section. cli
    // covers the receiver-enqueue (`core_locks[i]` is taken from
    // IRQ context by `enqueueOnCore`), the per-core swap of identity
    // away from the receiver, and the CR3 switch — any IRQ landing
    // mid-transition would see PerCore.current_ec=sender alongside
    // a TSS.RSP0 still pointing at receiver's kstack and could
    // dispatch `switchTo(other)` over our half-completed swap.
    // sysretq's RFLAGS load (from the suspended sender's saved IF=1
    // RFLAGS in r11) re-enables IRQs in user mode, so no explicit sti.
    // ────────────────────────────────────────────────────────────────
        \\cli

    // ─── Step R13: park or enqueue the caller (= receiver of the
    // original event). Branches on gs:112 != 0:
    //
    //   recv_port == 0 (bare reply): caller goes on this core's run
    //   queue with state .ready. Existing path. Caller resumes via
    //   switchTo when scheduler picks it up.
    //
    //   recv_port != 0 (atomic-recv-mode): caller parks on the named
    //   port's wait queue with state .suspended_on_port, mirroring
    //   what slow-path port.recv would do. Lock order: port lock only
    //   (CD released at R7, sender released at R10). Acquires port's
    //   gen-lock with snapshot port_gen (gs:112 bits 32-63); if gen
    //   mismatch (port destroyed between R4b validation and now),
    //   fall back to run-queue enqueue — caller's syscall returns OK
    //   without parking. (Spec leaves this exact race undefined; the
    //   port-recv-cap holder is the caller itself, so port destruction
    //   from outside our domain is impossible here in practice.)
    // ────────────────────────────────────────────────────────────────
        \\movq %%gs:112, %%rax
        \\testq %%rax, %%rax
        \\jnz .Lreply_atomic_recv_park
        ++ std.fmt.comptimePrint(
            \\
            \\movq %%gs:{[sc_core_lock]d}, %%rcx
            \\.Lreply_acq_core:
            \\movl $1, %%eax
            \\xchgl %%eax, {[lock_state_off]d}(%%rcx)
            \\testl %%eax, %%eax
            \\jz .Lreply_have_core
            \\pause
            \\jmp .Lreply_acq_core
            \\.Lreply_have_core:
            \\
            \\movq %%gs:32, %%rcx
            \\movb ${[state_ready]d}, {[state_off]d}(%%rcx)
            \\movb $0, {[on_cpu_off]d}(%%rcx)
            \\
            \\movzbq {[priority_off]d}(%%rcx), %%r11
            \\shlq $4, %%r11
            \\movq %%gs:{[sc_per_core]d}, %%rax
            \\addq ${[run_queue_off]d}, %%rax
            \\addq %%r11, %%rax
            \\
            \\movq {[lvl_tail_off]d}(%%rax), %%r11
            \\testq %%r11, %%r11
            \\jz .Lreply_q_empty
            \\movq %%rcx, {[ec_next_off]d}(%%r11)
            \\jmp .Lreply_q_set_tail
            \\.Lreply_q_empty:
            \\movq %%rcx, {[lvl_head_off]d}(%%rax)
            \\.Lreply_q_set_tail:
            \\movq %%rcx, {[lvl_tail_off]d}(%%rax)
            \\movq $0, {[ec_next_off]d}(%%rcx)
            \\
            \\movq %%gs:{[sc_core_lock]d}, %%rcx
            \\movl $0, {[lock_state_off]d}(%%rcx)
            \\jmp .Lreply_R13_done
            \\
        ,
            .{
                .sc_core_lock = Offsets.sc_core_lock_ptr,
                .sc_per_core = Offsets.sc_per_core_ptr,
                .lock_state_off = @offsetOf(zag.utils.sync.spin_lock.SpinLock, "state"),
                .state_ready = @intFromEnum(zag.sched.execution_context.State.ready),
                .state_off = @offsetOf(ExecutionContext, "state"),
                .on_cpu_off = @offsetOf(ExecutionContext, "on_cpu"),
                .priority_off = @offsetOf(ExecutionContext, "priority"),
                .run_queue_off = @offsetOf(zag.sched.scheduler.PerCore, "run_queue"),
                .lvl_head_off = @offsetOf(EcQueueLevel, "head"),
                .lvl_tail_off = @offsetOf(EcQueueLevel, "tail"),
                .ec_next_off = @offsetOf(ExecutionContext, "next"),
            },
        ) ++

    // ─── Step R13 atomic-recv-park branch: caller parks on the
    // recv_port wait queue. Acquires port's gen-lock with snapshot
    // port_gen (gs:112 bits 32-63). port_ec_ptr in gs:120. Lock
    // order: port lock only — no other locks held at this point
    // (CD released R7, sender released R10). Mirrors slow-path
    // port.recv's enqueueReceiver path.
    //
    // Receiver fields written (matches slow-path port.recv):
    //   state            = .suspended_on_port
    //   suspend_port     = SlabRef{port_ec_ptr, port_gen} + Some
    //   event_type       = .none
    //   event_subcode    = 0
    //   event_addr       = 0
    //   pending_reply_*  = null/0
    //   recv_port_xfer   = bit 12 of packed gs:112
    //   on_cpu           = false
    //
    // Port fields written:
    //   waiters[priority]        — append receiver
    //   waiter_kind              = .receivers
    // ────────────────────────────────────────────────────────────────
        \\.Lreply_atomic_recv_park:
        ++ (if (build_options.kernel_ctx_trace)
            // See suspend Step 12 mark above for the kstack-vs-ec.ctx
            // overlap rationale.
            \\subq $192, %%rsp
            \\call ctxTraceMarkFromAsm_recv_park
            \\addq $192, %%rsp
            \\
        else
            "") ++ std.fmt.comptimePrint(
            \\
            \\movq %%gs:120, %%rcx
            \\movq %%gs:112, %%rax
            \\shrq $32, %%rax
            \\shlq $1, %%rax
            \\movq %%rax, %%r11
            \\incq %%r11
            \\.Lreply_acq_port:
            \\lock cmpxchgq %%r11, {[port_lock_off]d}(%%rcx)
            \\je .Lreply_port_acquired
            \\xorq %%r11, %%rax
            \\testq $-2, %%rax
            \\jnz .Lreply_atomic_recv_fallback
            \\pause
            \\movq %%r11, %%rax
            \\andq $-2, %%rax
            \\jmp .Lreply_acq_port
            \\.Lreply_port_acquired:
            \\
            \\movq %%gs:32, %%r11
            \\movzbq {[priority_off]d}(%%r11), %%rax
            \\shlq $4, %%rax
            \\movq %%gs:120, %%rcx
            \\addq ${[waiters_off]d}, %%rcx
            \\addq %%rax, %%rcx
            \\
            \\movq {[lvl_tail_off]d}(%%rcx), %%rax
            \\testq %%rax, %%rax
            \\jz .Lreply_port_q_empty
            \\movq %%r11, {[ec_next_off]d}(%%rax)
            \\jmp .Lreply_port_q_set_tail
            \\.Lreply_port_q_empty:
            \\movq %%r11, {[lvl_head_off]d}(%%rcx)
            \\.Lreply_port_q_set_tail:
            \\movq %%r11, {[lvl_tail_off]d}(%%rcx)
            \\movq $0, {[ec_next_off]d}(%%r11)
            \\
            \\movq %%gs:120, %%rcx
            \\movb ${[wk_recv]d}, {[waiter_kind_off]d}(%%rcx)
            \\
            \\movq %%gs:32, %%rcx
            \\movb ${[event_none]d}, {[event_off]d}(%%rcx)
            \\movb $0, {[event_subcode_off]d}(%%rcx)
            \\movq $0, {[event_addr_off]d}(%%rcx)
            \\movq $0, {[prh_off]d}(%%rcx)
            \\movb $0, {[prd_disc_off]d}(%%rcx)
            \\movw $0, {[prs_off]d}(%%rcx)
            \\
            \\movq %%gs:120, %%r11
            \\movq %%r11, {[susp_value_ptr_off]d}(%%rcx)
            \\movq %%gs:112, %%r11
            \\shrq $32, %%r11
            \\movl %%r11d, {[susp_value_gen_off]d}(%%rcx)
            \\movb $1, {[susp_disc_off]d}(%%rcx)
            \\
            \\movq %%gs:112, %%r11
            \\shrq $12, %%r11
            \\andq $1, %%r11
            \\movb %%r11b, {[recv_xfer_off]d}(%%rcx)
            \\
            \\movb ${[state_susp]d}, {[state_off]d}(%%rcx)
            \\movb $0, {[on_cpu_off]d}(%%rcx)
            \\
            \\movq %%gs:120, %%rcx
            \\andq $-2, {[port_lock_off]d}(%%rcx)
            \\jmp .Lreply_R13_done
            \\
            \\.Lreply_atomic_recv_fallback:
            \\movq %%gs:{[sc_core_lock_late]d}, %%rcx
            \\.Lreply_acq_core_fb:
            \\movl $1, %%eax
            \\xchgl %%eax, {[lock_state_off]d}(%%rcx)
            \\testl %%eax, %%eax
            \\jz .Lreply_have_core_fb
            \\pause
            \\jmp .Lreply_acq_core_fb
            \\.Lreply_have_core_fb:
            \\movq %%gs:32, %%rcx
            \\movb ${[state_ready]d}, {[state_off]d}(%%rcx)
            \\movb $0, {[on_cpu_off]d}(%%rcx)
            \\movzbq {[priority_off]d}(%%rcx), %%r11
            \\shlq $4, %%r11
            \\movq %%gs:{[sc_per_core_late]d}, %%rax
            \\addq ${[run_queue_off]d}, %%rax
            \\addq %%r11, %%rax
            \\movq {[lvl_tail_off]d}(%%rax), %%r11
            \\testq %%r11, %%r11
            \\jz .Lreply_q_empty_fb
            \\movq %%rcx, {[ec_next_off]d}(%%r11)
            \\jmp .Lreply_q_set_tail_fb
            \\.Lreply_q_empty_fb:
            \\movq %%rcx, {[lvl_head_off]d}(%%rax)
            \\.Lreply_q_set_tail_fb:
            \\movq %%rcx, {[lvl_tail_off]d}(%%rax)
            \\movq $0, {[ec_next_off]d}(%%rcx)
            \\movq %%gs:{[sc_core_lock_late]d}, %%rcx
            \\movl $0, {[lock_state_off]d}(%%rcx)
            \\
            \\.Lreply_R13_done:
            \\
            \\# Step R13.5: release caller (= receiver) gen-lock paired
            \\# with R10.5 acquire. After this point R14's per-core swap
            \\# moves gs:32 from receiver to sender, so the receiver's
            \\# lock window covers exactly the receiver-EC field writes
            \\# in R11..R13. Plain `andq $-2` mirrors R7/R10.
            \\movq %%gs:32, %%rcx
            \\andq $-2, {[ec_unlock_off]d}(%%rcx)
            \\
            \\# Step R13.6: re-acquire sender (= replyee) gen-lock
            \\# before R14's sender-EC field reads (kernel_stack.top at
            \\# R14, ctx pointer at R16). Sender was unlocked at R10
            \\# while we wrote the receiver, but R14 reads sender.
            \\# kernel_stack.top and R16 reads sender.ctx — both EC
            \\# fields whose race window opens whenever another core
            \\# holds a sender-EC handle and mounts a syscall against
            \\# it (priority/setRegisters/etc.). Spec §[reply] mandates
            \\# the sender resumes coherent register state; without
            \\# this lock-window, a concurrent setRegisters on another
            \\# core could overwrite ctx mid-sysretq-prep.
            \\#
            \\# Uses the lockWithGen pattern (R5a-style) against the
            \\# snapshotted sender_gen at gs:96: if a concurrent destroy
            \\# fired between R10 release and here, the gen has rotated
            \\# to even and our cmpxchg fails with bit-1+ set. We
            \\# detect that via xorq+testq and bail to a UAF-panic — the
            \\# fast path has already cleared the reply slot and parked
            \\# the receiver, so there's no clean unwind; landing on a
            \\# destroyed sender's ctx during sysretq is the worse
            \\# alternative.
            \\#
            \\# Lock order: only sender_ec held at this point. caller_ec
            \\# was just released (R13.5); CD released at R7. No nesting.
            \\movq %%gs:72, %%rcx
            \\movq %%gs:96, %%rax
            \\shlq $1, %%rax
            \\movq %%rax, %%r11
            \\incq %%r11
            \\.Lreply_acq_sender_r14:
            \\lock cmpxchgq %%r11, {[ec_unlock_off]d}(%%rcx)
            \\je .Lreply_sender_r14_acquired
            \\xorq %%r11, %%rax
            \\testq $-2, %%rax
            \\jnz .Lreply_sender_destroyed
            \\pause
            \\movq %%r11, %%rax
            \\andq $-2, %%rax
            \\jmp .Lreply_acq_sender_r14
            \\.Lreply_sender_r14_acquired:
            \\
        ,
            .{
                .ec_unlock_off = @offsetOf(ExecutionContext, "_gen_lock"),
                .port_lock_off = @offsetOf(zag.sched.port.Port, "_gen_lock"),
                .waiters_off = @offsetOf(zag.sched.port.Port, "waiters"),
                .waiter_kind_off = @offsetOf(zag.sched.port.Port, "waiter_kind"),
                .wk_recv = @intFromEnum(zag.sched.port.WaiterKind.receivers),
                .priority_off = @offsetOf(ExecutionContext, "priority"),
                .lvl_head_off = @offsetOf(EcQueueLevel, "head"),
                .lvl_tail_off = @offsetOf(EcQueueLevel, "tail"),
                .ec_next_off = @offsetOf(ExecutionContext, "next"),
                .state_off = @offsetOf(ExecutionContext, "state"),
                .state_susp = @intFromEnum(zag.sched.execution_context.State.suspended_on_port),
                .state_ready = @intFromEnum(zag.sched.execution_context.State.ready),
                .event_off = @offsetOf(ExecutionContext, "event_type"),
                .event_none = @intFromEnum(zag.sched.execution_context.EventType.none),
                .event_subcode_off = @offsetOf(ExecutionContext, "event_subcode"),
                .event_addr_off = @offsetOf(ExecutionContext, "event_addr"),
                .prh_off = @offsetOf(ExecutionContext, "pending_reply_holder"),
                .prd_disc_off = @offsetOf(ExecutionContext, "pending_reply_domain") + 16,
                .prs_off = @offsetOf(ExecutionContext, "pending_reply_slot"),
                .susp_value_ptr_off = @offsetOf(ExecutionContext, "suspend_port") + 0,
                .susp_value_gen_off = @offsetOf(ExecutionContext, "suspend_port") + 8,
                .susp_disc_off = @offsetOf(ExecutionContext, "suspend_port") + 16,
                .recv_xfer_off = @offsetOf(ExecutionContext, "recv_port_xfer"),
                .on_cpu_off = @offsetOf(ExecutionContext, "on_cpu"),
                .lock_state_off = @offsetOf(zag.utils.sync.spin_lock.SpinLock, "state"),
                .sc_core_lock_late = Offsets.sc_core_lock_ptr,
                .sc_per_core_late = Offsets.sc_per_core_ptr,
                .run_queue_off = @offsetOf(zag.sched.scheduler.PerCore, "run_queue"),
            },
        ) ++

    // ─── Step R14: per-core scheduler accounting + lazy-FPU policy.
    // Mirror image of suspend Step 14: switch this core's identity
    // from receiver → sender. Updates gs:32/40/48/56/0 + *(gs:136)
    // (TSS.RSP0) + PerCore.current_ec via gs:128.
    // ────────────────────────────────────────────────────────────────
        (if (build_options.kernel_ec_log)
            // ec_log mark fires BEFORE the gs:32 write so the trampoline
            // observes prev=gs:32 (still the outgoing receiver) alongside
            // next=gs:72 (= incoming sender_ec_ptr). See suspend Step 14
            // mark above for the kstack-vs-ec.ctx overlap rationale.
            \\subq $192, %%rsp
            \\call ecLogMarkFromAsm_FP_R14
            \\addq $192, %%rsp
            \\
        else
            "") ++
        std.fmt.comptimePrint(
            \\
            \\movq %%gs:72, %%r11
            \\movq %%r11, %%gs:32
            \\movq %%gs:128, %%rax
            \\movq %%r11, {[cur_ec_off]d}(%%rax)
            \\movq {[gen_off]d}(%%r11), %%rcx
            \\shrq $1, %%rcx
            \\movl %%ecx, {[cur_ec_gen_off]d}(%%rax)
            \\movb $1, {[cur_ec_disc_off]d}(%%rax)
            \\movq %%rcx, %%gs:{[sc_cur_gen]d}
            \\movb $1, {[on_cpu_off]d}(%%r11)
            \\movzbl %%gs:{[sc_core_id]d}, %%ecx
            \\movb %%cl, {[last_disp_off]d}(%%r11)
            \\movq %%gs:104, %%rax
            \\movq %%rax, %%gs:40
            \\movq {[ut_off]d}(%%rax), %%rcx
            \\movq %%rcx, %%gs:48
            \\movq {[kt_off]d}(%%rax), %%rcx
            \\movq %%rcx, %%gs:56
            \\movq {[kstack_top_off]d}(%%r11), %%rcx
            \\movq %%rcx, %%gs:0
            \\movq %%gs:136, %%rax
            \\movq %%rcx, (%%rax)
            \\movq %%gs:128, %%rax
            \\movq {[fpu_owner_off]d}(%%rax), %%rcx
            \\cmpq %%rcx, %%r11
            \\je .Lreply_fpu_want_clear
            \\cmpb $1, {[fpu_armed_off]d}(%%rax)
            \\je .Lreply_fpu_done
            \\movq %%cr0, %%rcx
            \\orq $0x8, %%rcx
            \\movq %%rcx, %%cr0
            \\movb $1, {[fpu_armed_off]d}(%%rax)
            \\jmp .Lreply_fpu_done
            \\.Lreply_fpu_want_clear:
            \\cmpb $0, {[fpu_armed_off]d}(%%rax)
            \\je .Lreply_fpu_done
            \\clts
            \\movb $0, {[fpu_armed_off]d}(%%rax)
            \\.Lreply_fpu_done:
            \\
        ,
            .{
                .ut_off = @offsetOf(CapabilityDomain, "user_table"),
                .kt_off = @offsetOf(CapabilityDomain, "kernel_table"),
                .kstack_top_off = @offsetOf(ExecutionContext, "kernel_stack") + @offsetOf(zag.memory.stack.Stack, "top"),
                .fpu_owner_off = @offsetOf(zag.sched.scheduler.PerCore, "last_fpu_owner"),
                .fpu_armed_off = @offsetOf(zag.sched.scheduler.PerCore, "fpu_trap_armed"),
                .cur_ec_off = @offsetOf(zag.sched.scheduler.PerCore, "current_ec"),
                .cur_ec_gen_off = @offsetOf(zag.sched.scheduler.PerCore, "current_ec") + 8,
                .cur_ec_disc_off = @offsetOf(zag.sched.scheduler.PerCore, "current_ec") + 16,
                .gen_off = @offsetOf(ExecutionContext, "_gen_lock"),
                .sc_cur_gen = Offsets.sc_current_ec_gen,
                .on_cpu_off = @offsetOf(ExecutionContext, "on_cpu"),
                .last_disp_off = @offsetOf(ExecutionContext, "last_dispatched_core"),
                .sc_core_id = Offsets.sc_core_id,
            },
        ) ++

    // ─── Step R15: CR3 swap to sender's address space (PCID-aware,
    // mirror of suspend Step 16). sender_cd_ptr still in gs:104.
    // ────────────────────────────────────────────────────────────────
        \\movq %%gs:104, %%rcx
        ++ std.fmt.comptimePrint(
            \\
            \\movq {[asr_off]d}(%%rcx), %%r11
            \\testb $1, %%gs:144
            \\jz .Lreply_cr3_no_pcid
            \\movzwq {[asid_off]d}(%%rcx), %%rcx
            \\orq %%rcx, %%r11
            \\.Lreply_cr3_no_pcid:
            \\
        ,
            .{
                .asr_off = @offsetOf(CapabilityDomain, "addr_space_root"),
                .asid_off = @offsetOf(CapabilityDomain, "addr_space_id"),
            },
        ) ++
        \\movq %%r11, %%cr3

    // ─── Step R16: load sysretq state from sender.ctx, restore live
    // rax (= receiver's reply-time vreg 1, becomes sender's vreg 1),
    // and return to user mode at sender's pre-suspend RIP. The 12
    // other live vregs (rbx, rdx, rbp, rsi, rdi, r8-r10, r12-r15)
    // were never touched and ride sysretq into sender's user mode
    // zero-copy.
    //
    // Lock discipline: sender_ec gen-lock (R13.6 acquire) is held
    // across ALL three ctx reads (rflags/rsp/rip), released after the
    // last ctx read but before sysretq. We stash user_rsp in gs:80
    // (no longer needed by R16 — it held reply_slot, consumed at R6)
    // so that we can read all three ctx fields under the lock without
    // running out of scratch registers — sysretq needs rcx=rip,
    // r11=rflags, rsp=user_rsp, rax=vreg1 simultaneously.
    // ────────────────────────────────────────────────────────────────
        ++ std.fmt.comptimePrint(
            \\
            \\movq %%gs:72, %%rcx
            \\movq {[ec_ctx_off]d}(%%rcx), %%rax
            \\movq {[ctx_rflags_off]d}(%%rax), %%r11
            \\movq {[ctx_rsp_off]d}(%%rax), %%rax
            \\movq %%rax, %%gs:80
            \\movq {[ec_ctx_off]d}(%%rcx), %%rax
            \\movq {[ctx_rip_off]d}(%%rax), %%rax
            \\andq $-2, {[ec_unlock_off]d}(%%rcx)
            \\movq %%rax, %%rcx
            \\movq %%gs:80, %%rsp
            \\movq %%gs:64, %%rax
            \\swapgs
            \\sysretq
            \\
        ,
            .{
                .ec_unlock_off = @offsetOf(ExecutionContext, "_gen_lock"),
                .ec_ctx_off = @offsetOf(ExecutionContext, "ctx"),
                .ctx_rip_off = @offsetOf(cpu.Context, "rip"),
                .ctx_rflags_off = @offsetOf(cpu.Context, "rflags"),
                .ctx_rsp_off = @offsetOf(cpu.Context, "rsp"),
            },
        ) ++

    // ─── Reply-fast bail handlers ──────────────────────────────────
    //
    // .Lreply_eterm_under_cd: sender gen-lock acquire (R5a) saw a
    // stale gen — sender slot recycled between our R4 snapshot and
    // our CAS. Handle is NOT yet cleared (R6 not run); CD lock IS
    // still held. Slow path's CD-locked re-resolve would also see
    // the stale gen via SlabRef and return E_TERM — short-circuit
    // it here: release CD, sysretq E_TERM.
        \\.Lreply_eterm_under_cd:
        \\movq %%gs:40, %%rcx
        ++ std.fmt.comptimePrint(
            "\nandq $-2, {[cd_lock_off]d}(%%rcx)\n",
            .{ .cd_lock_off = @offsetOf(CapabilityDomain, "_gen_lock") },
        ) ++
        std.fmt.comptimePrint(
            "\nmovq ${d}, %%rax\n",
            .{@as(u64, @bitCast(zag.syscall.errors.E_TERM))},
        ) ++
        \\movq %%gs:16, %%rcx
        \\movq %%gs:24, %%r11
        \\movq %%gs:8, %%rsp
        \\swapgs
        \\sysretq

    // .Lreply_sender_field_fail: sender field predicate (R5b) failed
    // while we hold both sender's gen-lock and CD lock. Release sender
    // lock first (LIFO with R5a acquire), then fall through to
    // .Lreply_handle_invalid which releases CD and jumps slow path.
        \\.Lreply_sender_field_fail:
        \\movq %%gs:72, %%rcx
        ++ std.fmt.comptimePrint(
            "\nandq $-2, {[ec_lock_off]d}(%%rcx)\n",
            .{ .ec_lock_off = @offsetOf(ExecutionContext, "_gen_lock") },
        ) ++

    // .Lreply_handle_invalid: bail with CD lock held. Release lock,
    // restore receiver's rax from gs:64, jmp slow path.
        \\.Lreply_handle_invalid:
        \\movq %%gs:40, %%rcx
        ++ std.fmt.comptimePrint(
            "\nandq $-2, {[cd_lock_off]d}(%%rcx)\n",
            .{ .cd_lock_off = @offsetOf(CapabilityDomain, "_gen_lock") },
        ) ++
        \\movq %%gs:64, %%rax
        \\jmp .Lsyscall_slow_path

    // .Lreply_lock_fail: CD acquire saw stale gen (no locks held).
    // Restore rax, jmp slow path.
        \\.Lreply_lock_fail:
        \\movq %%gs:64, %%rax
        \\jmp .Lsyscall_slow_path

    // .Lreply_sender_destroyed: R13.6 lockWithGen detected sender's
    // gen rotated under us — sender was destroyed between R10 release
    // and the R13.6 re-acquire. By this point the reply slot has
    // already been cleared (R6) and the receiver is parked or queued
    // (R13). There's no clean unwind: we cannot context-switch into a
    // destroyed sender, and we cannot un-park the receiver without
    // re-entering the slow paths. Hard panic — this is a rare race
    // (requires concurrent terminate on a .running EC) and an
    // explicit stop is preferable to silent UAF on the next sysretq.
        \\.Lreply_sender_destroyed:
        \\ud2

    // .Lreply_caller_destroyed: R10.5 lockWithGen detected caller (= our
    // current_ec) was destroyed between syscall entry (gs:176 snap) and
    // the caller-acquire here. Means another core called terminate(self)
    // against a handle to us, freed the slab, and possibly the slot has
    // been reallocated as a different EC. We cannot continue: any field
    // write into the (foreign or freed) slab corrupts unrelated state.
    // The reply slot has already been cleared (R6), so the receiver
    // sees the reply commit even though we panic.
        \\.Lreply_caller_destroyed:
        \\ud2
    );
}

pub fn prepareThreadContext(
    kstack_top: VAddr,
    ustack_top: ?VAddr,
    entry: *const fn () void,
    arg: u64,
) *ArchCpuContext {
    @setRuntimeSafety(false);
    // Match the real interrupt entry layout. TSS.RSP0 = kernel_stack.top
    // (page-aligned). CPU pushes 5 words (40 bytes), stub pushes 2 words
    // (16 bytes), prologue pushes 15 GP regs (120 bytes) = 176 total.
    // Under lazy FPU there is no FXSAVE area below Context — the per-
    // thread `fpu_state` buffer lives in the Thread struct, not on the
    // kernel stack.
    // kstack_top from caller is alignStack(top) = top-8, undo the -8:
    const raw_top: u64 = (kstack_top.addr + 8 + 15) & ~@as(u64, 15);
    const ctx_addr: u64 = raw_top - @sizeOf(cpu.Context);
    var ctx: *cpu.Context = @ptrFromInt(ctx_addr);

    const ring_3 = @intFromEnum(PrivilegeLevel.ring_3);

    @memset(std.mem.asBytes(ctx), 0);

    ctx.regs.rdi = arg;
    ctx.rip = @intFromPtr(entry);
    ctx.rflags = 0x202;

    if (ustack_top != null) {
        ctx.cs = gdt.USER_CODE_OFFSET | ring_3;
        ctx.ss = gdt.USER_DATA_OFFSET | ring_3;
        // SysV AMD64 ABI §3.4.1: at a function's first instruction
        // `rsp % 16 == 8` (the implicit CALL pushed an 8-byte return
        // address onto a 16-byte-aligned stack). `ustack_top` is page-
        // aligned (and therefore 16-byte aligned), so subtract 8 to
        // mimic the post-CALL skew the compiler relies on. Without
        // this skew, any 16-byte-aligned access the compiler emits
        // against `rsp+offset` (e.g. movaps/movdqa for XMM spills,
        // 16-byte struct copies) traps with #GP at the first
        // instruction. Mirrors the same fix applied to the initial
        // EC of a freshly-spawned capability domain in
        // `caps.capability_domain.patchInitialIretFrame`.
        ctx.rsp = ustack_top.?.addr - 8;
    } else {
        ctx.cs = gdt.KERNEL_CODE_OFFSET;
        ctx.ss = gdt.KERNEL_DATA_OFFSET;
        // Subtract 8 to simulate a CALL instruction's return-address
        // push so the entry function sees RSP ≡ 8 (mod 16) per the
        // SysV ABI. Kernel entry points never return.
        ctx.rsp = ctx_addr - 8;
    }

    return @ptrCast(ctx);
}

pub fn switchTo(ec: *ExecutionContext) void {
    const core_id = apic.coreID();
    const cid: u8 = @truncate(core_id);
    ctx_trace.mark(ec, .switchto_entry);

    // Cross-core terminate may have stashed a zombie EC on this core.
    // Decide whether it's safe to finalize: read live rsp via inline asm
    // and check whether it falls within the zombie's kstack range.
    //
    // We use the rsp range, not `current_ec.ptr == zombie`, because the
    // proxy is unreliable in two cases:
    //   1. Slow-path `switchTo` updates `current_ec` via `setCurrentEc`
    //      BEFORE arriving here. By the time we read `current_ec`, the
    //      OUTGOING EC's identity is already gone from that slot — the
    //      proxy would mis-classify "OUTGOING == zombie" as safe.
    //   2. `parkSelfFaulted` clears `current_ec` to null while leaving
    //      the EC's kstack as the active rsp on this core. Subsequent
    //      `switchTo` from `scheduler.run()` would see `current_ec=null`,
    //      `cur_is_zombie=false`, and finalize while still standing on
    //      the parked EC's kstack.
    {
        // core_locks[cid] serializes the read-modify-write against the
        // remote postZombie writer. Drop the lock before
        // finalizeDestroyMarkedDead so the unmap path doesn't run with
        // a per-core spinlock held — finalize takes its own locks.
        const zombie_to_reap: ?*ExecutionContext = blk: {
            const lock = &scheduler.core_locks[cid];
            const irq = lock.lockIrqSaveOrdered(@src(), scheduler.SCHED_CORE_GROUP);
            defer lock.unlockIrqRestore(irq);
            const slot = &(&scheduler.core_states[cid]).pending_zombie;
            const zr = slot.* orelse break :blk null;
            const z = zr.ptr;
            const rsp_addr = asm volatile ("movq %%rsp, %[out]"
                : [out] "=r" (-> u64),
            );
            const z_top = z.kernel_stack.top.addr;
            const z_base = z.kernel_stack.base.addr;
            const standing_on_zombie = rsp_addr >= z_base and rsp_addr < z_top;
            if (standing_on_zombie or ec == z) break :blk null;
            slot.* = null;
            break :blk z;
        };
        if (zombie_to_reap) |z| {
            zag.sched.execution_context.finalizeDestroyMarkedDead(z);
        }
    }

    const kstack = ec.kernel_stack.top.addr;
    gdt.coreTss(core_id).rsp0 = kstack;
    updateScratchKernelRsp(core_id, kstack);

    // caller-pinned: `ec` was selected by the scheduler for this core; its
    // domain is held live by the EC through the dispatch window (the
    // EC carries a SlabRef into the domain), so reading
    // `addr_space_root` / `addr_space_id` directly off the deref'd
    // pointer without re-locking the SlabRef is sound here.
    const dom = ec.domain.ptr;
    const new_root = dom.addr_space_root;
    if (new_root.addr != paging.getAddrSpaceRoot().addr) {
        paging.swapAddrSpace(new_root, dom.addr_space_id);
        std.debug.assert(paging.getAddrSpaceRoot().addr == new_root.addr);
    }

    // on_cpu transitions: clear the previous current_ec's flag (if any
    // and distinct from `ec`) and raise it on the freshly-dispatched
    // EC. Cross-core readers (`runningCoreOf`, terminate's defer-vs-
    // -finalize decision) snapshot this together with `current_ec` —
    // setting it here, after the kstack/CR3 work and before the asm
    // jump, gives terminate from another core a stable window in which
    // current_ec→ptr already names this EC.
    if ((&scheduler.core_states[cid]).current_ec) |prev_ref| {
        if (prev_ref.ptr != ec) {
            prev_ref.ptr.on_cpu.store(false, .release);
        }
    }
    scheduler.setCurrentEc(cid, ec);
    ec.on_cpu.store(true, .release);
    // Pointer-index `per_cpu_scratch[]`: see `updateScratchKernelRsp`.
    // Each direct `per_cpu_scratch[i].field` write would otherwise
    // memcpy the full 256 KiB array onto the dispatch stack frame.
    const scratch = &per_cpu_scratch[cid];
    scratch.current_ec = @intFromPtr(ec);
    scratch.current_ec_gen = ec._gen_lock.currentGen();
    scratch.current_domain = @intFromPtr(dom);
    scratch.current_user_table = @intFromPtr(dom.user_table);
    scratch.current_kernel_table = @intFromPtr(dom.kernel_table);

    // Lazy FPU: TS should be clear iff `ec` is the current owner on
    // this core, set otherwise. Track the desired state and only touch
    // CR0 when it changes — MOV-to-CR0 vmexits under KVM at ~1k+
    // cycles per write, so skipping no-op writes is critical.
    //
    // Cross-core migration: if the EC's FP state lives in a different
    // core's regs, flush it out via IPI first so the trap handler
    // restores from the right buffer contents.
    scheduler.migrateFlush(ec);
    const last_fpu = (&scheduler.core_states[cid]).last_fpu_owner;
    const desired_armed = if (last_fpu) |ref|
        // caller-pinned: identity compare against just-dispatched `ec`.
        ref.ptr != ec
    else
        true;
    if (desired_armed != (&scheduler.core_states[cid]).fpu_trap_armed) {
        if (desired_armed) cpu.fpuArmTrap() else cpu.fpuClearTrap();
        (&scheduler.core_states[cid]).fpu_trap_armed = desired_armed;
    }

    apic.endOfInterrupt();

    // Spec §[syscall_abi]: flush the recv-deferred syscall word into
    // user `[ctx.rsp + 0]` while we are guaranteed to be in the EC's
    // address space. `deliverEvent` stages the value when the receiver
    // is parked (rendezvous wake) — at that moment the kernel is still
    // running in the sender's CR3, so the write must be deferred to
    // the resume path. Flush after the CR3 swap above and before the
    // iretq trampoline; the EC's user stack page is mapped in the
    // domain we just switched into.
    if (ec.pending_event_word_valid) {
        writeUserSyscallWord(ec.ctx, ec.pending_event_word);
        ec.pending_event_word = 0;
        ec.pending_event_word_valid = false;

        // Spec §[event_state] vreg 14 — RIP at `[user_rsp + 8]`.
        // Staged in `port.deliverEvent` and flushed here on the
        // rendezvous wake path now that CR3 references the
        // receiver's address space.
        if (ec.pending_event_rip_valid) {
            writeUserVreg14(ec.ctx, ec.pending_event_rip);
            ec.pending_event_rip = 0;
            ec.pending_event_rip_valid = false;
        }
    }

    // lockdep: this asm `jmp interruptStubEpilogue` abandons the call stack
    // the IRQ-handler dispatcher (`dispatchInterrupt`) was using; its
    // `defer exitIrqContext` never executes. Re-balance the per-core IRQ
    // depth here so the counter doesn't drift upward each time an
    // IRQ-driven preemption produces a context switch. No-op when called
    // from non-IRQ paths (the depth is already zero there).
    sync_debug.resetIrqContextOnSwitch();

    // Last snapshot before the asm trampoline swaps rsp = ec.ctx and
    // jumps into interruptStubEpilogue's iretq. If ctx.cs has already
    // been corrupted by this point, the corruption happened inside
    // switchTo's body or before switchTo was even called.
    ctx_trace.mark(ec, .switchto_resume);

    asm volatile (
        \\movq %[new_stack], %%rsp
        \\jmp interruptStubEpilogue
        :
        : [new_stack] "r" (@intFromPtr(ec.ctx)),
    );
}

pub fn getInterruptStub(comptime int_num: u8, comptime does_push_err: bool) InterruptHandler {
    return struct {
        fn stub() callconv(.naked) void {
            if (does_push_err) {
                asm volatile (
                    \\pushq %[num]
                    \\jmp interruptStubPrologue
                    :
                    : [num] "i" (@as(u64, int_num)),
                );
            } else {
                asm volatile (
                    \\pushq $0
                    \\pushq %[num]
                    \\jmp interruptStubPrologue
                    :
                    : [num] "i" (@as(u64, int_num)),
                );
            }
        }
    }.stub;
}

pub fn registerVector(
    vector: u8,
    handler: Handler,
    kind: VectorKind,
) void {
    std.debug.assert(vector_table[vector].handler == null);
    vector_table[vector] = .{
        .handler = handler,
        .kind = kind,
    };
}

export fn interruptStubPrologue() callconv(.naked) void {
    // Re-arm SMAP before any kernel work runs. CLAC is a no-op on CPUs
    // that lack SMAP (RFLAGS.AC is already 0 for CPL-0 code that never
    // set it) but critically defends against an adversarial user that
    // sets RFLAGS.AC=1 via POPFQ before issuing a syscall — without this
    // the syscall dispatch would run with AC=1 and bypass SMAP for every
    // raw user pointer access. IRETQ in `interruptStubEpilogue` restores
    // the interrupted context's RFLAGS (including AC) from the iret
    // frame, so kernel code interrupted mid-`userAccessBegin` resumes
    // with AC=1 as expected. Single-byte-equivalent, no register clobber.
    asm volatile (
        \\clac
        \\pushq %rax
        \\pushq %rcx
        \\pushq %rdx
        \\pushq %rbx
        \\pushq %rbp
        \\pushq %rsi
        \\pushq %rdi
        \\pushq %r8
        \\pushq %r9
        \\pushq %r10
        \\pushq %r11
        \\pushq %r12
        \\pushq %r13
        \\pushq %r14
        \\pushq %r15
        \\
        // Lazy FPU: no FXSAVE here. Kernel is built without SSE so it
        // cannot dirty the FP/SIMD register file across the handler.
        // The previous owner of the FPU on this core (which may be the
        // userspace thread we just interrupted, or some other thread
        // whose state has been parked here) keeps its regs in place.
        \\movq %rsp, %rdi
        \\call dispatchInterrupt
        \\
        \\jmp interruptStubEpilogue
    );
}

export fn interruptStubEpilogue() callconv(.naked) void {
    asm volatile (
        \\popq %r15
        \\popq %r14
        \\popq %r13
        \\popq %r12
        \\popq %r11
        \\popq %r10
        \\popq %r9
        \\popq %r8
        \\popq %rdi
        \\popq %rsi
        \\popq %rbp
        \\popq %rbx
        \\popq %rdx
        \\popq %rcx
        \\popq %rax
        \\
        \\addq $16, %%rsp
        \\iretq
    );
}

pub fn setSyscallReturn(ctx: *ArchCpuContext, value: u64) void {
    ctx.regs.rax = value;
}

/// Write the syscall return word into vreg 0 — `[user_rsp + 0]` per
/// Spec §[syscall_abi]. MUST be called with the user's address space
/// active in CR3 (the syscall epilogue runs in the caller's CR3; the
/// resume path swaps via `switchTo` first). STAC opens user-page
/// access under SMAP; CLAC re-arms the trap. Aliased on aarch64 to
/// the matching `[sp + 0]` slot. Used by `recv` event delivery —
/// vreg 1 (rax) carries OK in that path while the composed
/// pair_count / tstart / reply_handle_id / event_type word lands at
/// vreg 0.
pub fn writeUserSyscallWord(ctx: *const ArchCpuContext, value: u64) void {
    cpu.stac();
    @as(*u64, @ptrFromInt(ctx.rsp)).* = value;
    cpu.clac();
}

/// Spec §[event_state] vreg 2 — rbx on x86-64.
pub fn setEventSubcode(ctx: *ArchCpuContext, value: u64) void {
    ctx.regs.rbx = value;
}

/// Spec §[event_state] vreg 3 — rdx on x86-64.
pub fn setEventAddr(ctx: *ArchCpuContext, value: u64) void {
    ctx.regs.rdx = value;
}

/// Spec §[event_state] vreg 4 — rbp on x86-64.
pub fn setEventVreg4(ctx: *ArchCpuContext, value: u64) void {
    ctx.regs.rbp = value;
}

pub fn setEventVreg5(ctx: *ArchCpuContext, value: u64) void {
    ctx.regs.rsi = value;
}

/// Spec §[event_state] vreg 14 read — the suspending EC's saved RIP.
/// For freshly created ECs `ctx.rip` carries the entry point set in
/// `prepareEcContext`; for ones suspended mid-execution it carries
/// the iret-frame RIP saved on syscall/exception entry.
pub fn getEventRip(ctx: *const ArchCpuContext) u64 {
    return ctx.rip;
}

/// Spec §[event_state] vreg 14 write into the resumed sender's saved
/// frame. Used by reply_transfer test 14 to commit a write-cap
/// receiver's RIP modification onto the suspended EC's iret frame.
pub fn setEventRip(ctx: *ArchCpuContext, value: u64) void {
    ctx.rip = value;
}

/// Spec §[event_state] vreg 14 write — writes the suspended EC's RIP
/// into the receiver's user stack at `[ctx.rsp + 8]`. STAC/CLAC
/// bracket the write under SMAP; caller MUST ensure CR3 already
/// references the receiver's address space (the stack page only
/// exists there). `vreg 0` lives at `[ctx.rsp + 0]` and is written by
/// `writeUserSyscallWord`; this is the next slot up.
pub fn writeUserVreg14(ctx: *const ArchCpuContext, value: u64) void {
    cpu.stac();
    @as(*u64, @ptrFromInt(ctx.rsp + 8)).* = value;
    cpu.clac();
}

/// Spec §[event_state] vreg 14 read — pulls the value the receiver
/// wrote at `[ctx.rsp + 8]` between recv and reply / reply_transfer.
/// Companion to `writeUserVreg14`. STAC/CLAC bracket the load under
/// SMAP; caller MUST ensure CR3 already references the receiver's
/// address space (the user stack page is only mapped there). Used
/// by reply_transfer §[reply] test 14 to commit a receiver's RIP
/// modification onto the resumed sender's saved frame.
pub fn readUserVreg14(ctx: *const ArchCpuContext) u64 {
    cpu.stac();
    const v = @as(*u64, @ptrFromInt(ctx.rsp + 8)).*;
    cpu.clac();
    return v;
}

/// Copy the §[event_state] GPR-backed vregs (vregs 1..13 on x86-64:
/// rax, rbx, rdx, rbp, rsi, rdi, r8, r9, r10, r12, r13, r14, r15) from
/// `src` to `dst`. Used by `reply` (Spec §[reply] test 05) to apply the
/// receiver's vreg modifications onto the suspended EC's saved iret
/// frame when the originating EC handle held the `write` cap. rcx and
/// r11 are intentionally excluded — they carry user RIP and RFLAGS on
/// SYSCALL return per the SysV/AMD64 SYSCALL ABI and are not part of the
/// vreg-1..13 set.
pub fn copyEventStateGprs(dst: *ArchCpuContext, src: *const ArchCpuContext) void {
    dst.regs.rax = src.regs.rax;
    dst.regs.rbx = src.regs.rbx;
    dst.regs.rdx = src.regs.rdx;
    dst.regs.rbp = src.regs.rbp;
    dst.regs.rsi = src.regs.rsi;
    dst.regs.rdi = src.regs.rdi;
    dst.regs.r8 = src.regs.r8;
    dst.regs.r9 = src.regs.r9;
    dst.regs.r10 = src.regs.r10;
    dst.regs.r12 = src.regs.r12;
    dst.regs.r13 = src.regs.r13;
    dst.regs.r14 = src.regs.r14;
    dst.regs.r15 = src.regs.r15;
}

/// Snapshot the suspending EC's GPR-backed vregs 1..13 in canonical
/// vreg order. Spec §[event_state] x86-64:
///   vreg 1 → rax, vreg 2 → rbx, vreg 3 → rdx, vreg 4 → rbp,
///   vreg 5 → rsi, vreg 6 → rdi, vreg 7 → r8,  vreg 8 → r9,
///   vreg 9 → r10, vreg 10 → r12, vreg 11 → r13, vreg 12 → r14,
///   vreg 13 → r15.
/// rcx / r11 are reserved by the SYSCALL ABI (user RIP/RFLAGS) and are
/// intentionally excluded.
pub fn getEventStateGprs(ctx: *const ArchCpuContext) [13]u64 {
    return .{
        ctx.regs.rax,
        ctx.regs.rbx,
        ctx.regs.rdx,
        ctx.regs.rbp,
        ctx.regs.rsi,
        ctx.regs.rdi,
        ctx.regs.r8,
        ctx.regs.r9,
        ctx.regs.r10,
        ctx.regs.r12,
        ctx.regs.r13,
        ctx.regs.r14,
        ctx.regs.r15,
    };
}

/// Project a vreg 1..13 GPR snapshot onto a receiving EC's frame in
/// canonical vreg order. Companion to `getEventStateGprs`.
pub fn setEventStateGprs(ctx: *ArchCpuContext, gprs: [13]u64) void {
    ctx.regs.rax = gprs[0];
    ctx.regs.rbx = gprs[1];
    ctx.regs.rdx = gprs[2];
    ctx.regs.rbp = gprs[3];
    ctx.regs.rsi = gprs[4];
    ctx.regs.rdi = gprs[5];
    ctx.regs.r8 = gprs[6];
    ctx.regs.r9 = gprs[7];
    ctx.regs.r10 = gprs[8];
    ctx.regs.r12 = gprs[9];
    ctx.regs.r13 = gprs[10];
    ctx.regs.r14 = gprs[11];
    ctx.regs.r15 = gprs[12];
}

export fn dispatchInterrupt(ctx: *cpu.Context) void {
    kprof.enter(.irq);
    defer kprof.exit(.irq);

    // Pointer-index `vector_table[]` to avoid Debug-mode codegen
    // copying the entire [256]VectorEntry array (~4 KiB) onto the IRQ
    // kernel stack on every interrupt. See the matching note in
    // sched.scheduler on `core_states[]`.
    const entry = &vector_table[ctx.int_num];
    if (entry.handler) |h| {
        // lockdep: an `external` vector is an asynchronous device/IPI/timer
        // interrupt — the CPU auto-masked IFLAG on entry (Intel SDM Vol 3A
        // §6.8.1) and the running thread was *interrupted*, not making a
        // synchronous call into the kernel. That is the only state in which
        // the IRQ-mode-mix detector should treat this acquire as "from an
        // IRQ handler." `exception` vectors (#PF, #GP, #UD, syscall stub at
        // 0x80) are synchronous — they execute on top of whatever IRQ-mode
        // discipline the interrupted code already chose, and must NOT count
        // as IRQ-handler context.
        const is_async_irq = entry.kind == .external;
        if (is_async_irq) sync_debug.enterIrqContext();
        defer if (is_async_irq) sync_debug.exitIrqContext();

        h(ctx);
        if (is_async_irq) {
            apic.endOfInterrupt();
        }
        return;
    }

    @panic("Unhandled interrupt!");
}
