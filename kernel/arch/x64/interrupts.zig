const std = @import("std");
const zag = @import("zag");

const apic = zag.arch.x64.apic;
const cpu = zag.arch.x64.cpu;
const fpu = zag.sched.fpu;
const gdt = zag.arch.x64.gdt;
const idt = zag.arch.x64.idt;
const paging = zag.arch.x64.paging;
const scheduler = zag.sched.scheduler;
const sync_debug = zag.utils.sync.debug;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const InterruptHandler = idt.interruptHandler;
const PrivilegeLevel = zag.arch.x64.cpu.PrivilegeLevel;
const VAddr = zag.memory.address.VAddr;

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
    /// Snapshot of `cpu.pcid_enabled` written at init. The fast path
    /// can't reach the global `var` symbol RIP-relative from a naked
    /// fn without operand interpolation, so we cache it here and
    /// branch on the byte.
    pcid_enabled: u8,
    /// Pad out to a full page.
    _pad: [4096 - (14 * 8 + 8 + 1)]u8,
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
    const sc_fast_temp_0: usize = 48;
    const sc_per_core_ptr: usize = 112;
    const sc_pcid_enabled: usize = 120;

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
    if (@offsetOf(SyscallScratch, "fast_temp") != Offsets.sc_fast_temp_0) @compileError("scratch.fast_temp drift");
    if (@offsetOf(SyscallScratch, "per_core_ptr") != Offsets.sc_per_core_ptr) @compileError("scratch.per_core_ptr drift");
    if (@offsetOf(SyscallScratch, "pcid_enabled") != Offsets.sc_pcid_enabled) @compileError("scratch.pcid_enabled drift");
    if (Offsets.ctx_rip != 136) @compileError("cpu.Context.rip not at 136");
    if (Offsets.ctx_rflags != 152) @compileError("cpu.Context.rflags not at 152");
    if (Offsets.ctx_rsp != 160) @compileError("cpu.Context.rsp not at 160");
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
    scratch.pcid_enabled = if (cpu.pcid_enabled) 1 else 0;
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
/// L4 IPC fast path (Phase 2 + 3): when the syscall word names
/// `suspend` we attempt `port.suspendFast` BEFORE building the args
/// slice or routing through the dispatch switch. The fast path handles
/// the dominant test-runner pattern (self-suspend with a receiver
/// already queued on the destination port). Predicate misses return
/// `null` and we fall straight through to the slow-path dispatch — the
/// observable behavior is identical because the slow path mints the
/// same state via `suspendEc` → `suspendOnPort`.
export fn syscallDispatch(ctx: *cpu.Context) void {
    const r = &ctx.regs;
    var syscall_word: u64 = undefined;
    cpu.stac();
    syscall_word = @as(*const u64, @ptrFromInt(ctx.rsp)).*;
    cpu.clac();
    const caller = scheduler.currentEc() orelse @panic("syscall with no current EC");

    // Phase 2: cheap classifier on the syscall number. Only `suspend`
    // unlocks the fast rendezvous below — every other syscall takes
    // the args[0..13] slice path.
    //
    // The fast path skips the §[handle_attachments] entry-validation
    // step, so when pair_count > 0 (syscall word bits 12-19) we MUST
    // fall through to the slow path so the per-entry checks (E_BADCAP
    // on invalid source ids, etc.) actually run.
    const SyscallNum = zag.syscall.dispatch.SyscallNum;
    const pair_count_bits: u8 = @truncate((syscall_word >> 12) & 0xFF);
    if ((syscall_word & 0xFFF) == @intFromEnum(SyscallNum.@"suspend") and pair_count_bits == 0) {
        // vreg 1 = rax = target EC handle; vreg 2 = rbx = port handle.
        if (zag.sched.port.suspendFast(caller, r.rax, r.rbx)) |fast_ret| {
            // Same wake-vs-syscall-return race as the slow-path tail
            // below: if `suspendFast` parked `caller`, a remote core may
            // already have written E_CLOSED into `caller.ctx.regs.rax`
            // via `propagateClosedTo*`, and an unconditional assign
            // would clobber it back to 0.
            if (scheduler.coreCurrentIs(@truncate(apic.coreID()), caller)) {
                r.rax = @bitCast(fast_ret);
            }
            // The fast path may have suspended `caller` (rendezvous
            // success): in that case `current_ec` was cleared and the
            // syscall epilogue would otherwise iretq back to the now-
            // parked user EC. Drive the scheduler to pick the next
            // ready EC (typically the just-readied receiver).
            // `&core_states[i]` (pointer) rather than the
            // `core_states[i].field` form: see the matching note in
            // `sched.scheduler.currentEc`. Debug-mode Zig codegens the
            // direct-array index as a 6 KiB memcpy of the entire
            // `core_states` array onto the syscall path's stack frame
            // — three such snapshots in this function consume ~18 KiB
            // and overflow the 48 KiB kernel stack on faulting paths.
            if (scheduler.coreIsIdle(@truncate(apic.coreID()))) {
                scheduler.run();
            }
            return;
        }
        // Predicate miss — fall through to the slow path below.
    }

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
/// the eventual L4-style IPC fast path is intended to preserve in
/// registers.
///
/// L4 IPC fast path — Phases 2 + 3 wired in `syscallDispatch` (Zig).
/// The asm prologue below still does the full Context save unchanged;
/// the short-circuit is taken inside `syscallDispatch` after a cheap
/// classifier on the syscall word: when the call is `suspend` and the
/// predicate matches (self-suspend + receiver queued + caps OK),
/// `port.suspendFast` performs the rendezvous inline without traversing
/// the args[0..13] copy or the dispatch switch. The receiver is made
/// ready and the caller is transitioned to `.suspended_on_port` with
/// `current_ec` cleared on this core so the post-dispatch hook drives
/// the scheduler at the bottom of `syscallDispatch`. Predicate misses
/// fall straight through to the slow path so suspend/reply still
/// executes via `kernel/sched/port.zig` (`suspendEc`, `recv`, `reply`,
/// `replyTransfer`) — observable state matches what the fast path is
/// specified to produce per spec §[port], §[reply], §[event_state].
///
/// Phase 4 (CR3 + GS swap + sysretq inline in this naked stub) is not
/// yet wired: the Zig fast path still returns through the asm Context
/// restore + iretq epilogue, just bypassing the slow dispatch above.
/// Moving the receiver dispatch into the naked stub itself remains the
/// future work this scratch layout was provisioned for.
pub export fn syscallEntry() callconv(.naked) void {
    // Slow-path Context layout:
    //   [RSP+0..112]   r15..rax (15 GPRs, 120 bytes)
    //   [RSP+120,128]  int_num, err_code
    //   [RSP+136..168] iret frame (rip, cs, rflags, rsp, ss)
    asm volatile (
    // ═══════════════════════════════════════════════════════════════
    // PHASE 1 — common prologue: swapgs, stash user RSP/RIP/RFLAGS,
    // switch to kernel stack. Kept distinct from the slow-path body
    // because it is the shared entry the future fast path will branch
    // out of without paying the full Context save.
    // ═══════════════════════════════════════════════════════════════
        \\swapgs                              // GS.base → SyscallScratch
        \\movq %%rsp, %%gs:8                  // user_rsp
        \\movq %%rcx, %%gs:16                 // user_rip (rcx clobbered by SYSCALL)
        \\movq %%r11, %%gs:24                 // user_rflags (r11 ditto)
        \\movq %%gs:0, %%rsp                  // switch to kernel stack

    // ═══════════════════════════════════════════════════════════════
    // SLOW PATH — 176-byte Context save + dispatch + iretq.
    // Restores rcx and r11 from gs scratch first so the iret frame
    // sees the original SYSCALL-saved values, not whatever the
    // prologue may have spilled into those regs. Vregs 1-13 (rax,
    // rbx, rdx, rbp, rsi, rdi, r8, r9, r10, r12, r13, r14, r15) are
    // saved into the Context on entry and restored on exit, so any
    // handler that leaves them alone returns them to userspace
    // unchanged — matching the L4 fast-path register-preservation
    // contract via the long route.
    // ═══════════════════════════════════════════════════════════════
        \\movq %%gs:16, %%rcx                 // restore user_rip
        \\movq %%gs:24, %%r11                 // restore user_rflags
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
        // `capdom.capability_domain.patchInitialIretFrame`.
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
    const kstack = ec.kernel_stack.top.addr;
    gdt.coreTss(core_id).rsp0 = kstack;
    updateScratchKernelRsp(core_id, kstack);

    // self-alive: `ec` was selected by the scheduler for this core; its
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

    const cid: u8 = @truncate(core_id);
    scheduler.setCurrentEc(cid, ec);
    // Pointer-index `per_cpu_scratch[]`: see `updateScratchKernelRsp`.
    // Each direct `per_cpu_scratch[i].field` write would otherwise
    // memcpy the full 256 KiB array onto the dispatch stack frame.
    const scratch = &per_cpu_scratch[cid];
    scratch.current_ec = @intFromPtr(ec);
    scratch.current_domain = @intFromPtr(dom);

    // Lazy FPU: TS should be clear iff `ec` is the current owner on
    // this core, set otherwise. Track the desired state and only touch
    // CR0 when it changes — MOV-to-CR0 vmexits under KVM at ~1k+
    // cycles per write, so skipping no-op writes is critical.
    //
    // Cross-core migration: if the EC's FP state lives in a different
    // core's regs, flush it out via IPI first so the trap handler
    // restores from the right buffer contents.
    //
    // Skipped under -Dlazy_fpu=false (eager baseline): the FPU regs
    // were already swapped in scheduler.switchToWithPmu and CR0.TS is
    // never armed, so no migration flush is needed either.
    if (comptime fpu.lazy_enabled) {
        scheduler.migrateFlush(ec);
        const last_fpu = (&scheduler.core_states[cid]).last_fpu_owner;
        const desired_armed = if (last_fpu) |ref|
            // self-alive: identity compare against just-dispatched `ec`.
            ref.ptr != ec
        else
            true;
        if (desired_armed != (&scheduler.core_states[cid]).fpu_trap_armed) {
            if (desired_armed) cpu.fpuArmTrap() else cpu.fpuClearTrap();
            (&scheduler.core_states[cid]).fpu_trap_armed = desired_armed;
        }
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
