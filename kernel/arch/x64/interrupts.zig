const build_options = @import("build_options");
const std = @import("std");
const zag = @import("zag");

const apic = zag.arch.x64.apic;
const cpu = zag.arch.x64.cpu;
const gdt = zag.arch.x64.gdt;
const idt = zag.arch.x64.idt;
const paging = zag.arch.x64.paging;
const scheduler = zag.sched.scheduler;
const sync_debug = zag.utils.sync.debug;

const CapabilityDomain = zag.capdom.capability_domain.CapabilityDomain;
const CapabilityType = zag.caps.capability.CapabilityType;
const EcQueue = zag.sched.scheduler.EcQueue;
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
    /// Pad out to a full page.
    _pad: [4096 - 168]u8,
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
    // CLASSIFIER — fast path iff syscall_op in 0..13 (the fast-suspend
    // variants where the op directly encodes payload_count). A single
    // unsigned compare verifies in one go: op in 0..13, AND all upper
    // bits 4-63 are zero (any nonzero upper bit pushes value > 13).
    // On fast-path entry: rcx = payload_count.
    //
    // Build-time gated by `-Dkernel_fastpath`. When false, the cmp+jbe
    // is comptime-substituted with an empty string so every syscall
    // (including suspend(0..13)) takes the slow Zig dispatch path —
    // exposes the slow-path-only baseline for A/B perf comparison.
    // ═══════════════════════════════════════════════════════════════
        ++ "\n"
        ++ (if (build_options.kernel_fastpath)
            \\cmpq $13, %%rcx
            \\jbe  .Lsyscall_suspend_fast
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
            "\nimulq ${d}, %%rbx, %%r11\n",
            .{@sizeOf(KernelHandle)},
        ) ++
        \\movq 8(%%rcx, %%r11), %%rax
        \\movq (%%rcx, %%r11), %%rcx
        \\testq %%rcx, %%rcx
        \\jz .Lsyscall_lock_fail
        \\shlq $1, %%rax
        \\lea 1(%%rax), %%r11
        \\.Lacquire_port:
        \\lock cmpxchgq %%r11, (%%rcx)
        \\je .Lport_acquired
        \\xorq %%r11, %%rax
        \\testq $-2, %%rax
        \\jnz .Lsyscall_lock_fail
        \\pause
        \\movq %%r11, %%rax
        \\andq $-2, %%rax
        \\jmp .Lacquire_port
        \\.Lport_acquired:

    // ─── Step 5: peek port.waiter_kind. Lock held; if not .receivers,
    // bail via .Lsyscall_no_receiver (releases lock).
    // ────────────────────────────────────────────────────────────────
        ++ std.fmt.comptimePrint(
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
            \\movq {[w3]d}(%%rcx), %%r11
            \\testq %%r11, %%r11
            \\jnz .Lpop_3
            \\movq {[w2]d}(%%rcx), %%r11
            \\testq %%r11, %%r11
            \\jnz .Lpop_2
            \\movq {[w1]d}(%%rcx), %%r11
            \\testq %%r11, %%r11
            \\jnz .Lpop_1
            \\movq {[w0]d}(%%rcx), %%r11
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
            \\movq %%rcx, (%%rax)
            \\testq %%rcx, %%rcx
            \\jnz .Ldequeue_keep_tail
            \\movq $0, 8(%%rax)
            \\.Ldequeue_keep_tail:
            \\movq $0, {[next_off]d}(%%r11)
            \\movq %%gs:80, %%rcx
            \\
        ,
            .{
                .w0 = @offsetOf(Port, "waiters") + 0 * 16,
                .w1 = @offsetOf(Port, "waiters") + 1 * 16,
                .w2 = @offsetOf(Port, "waiters") + 2 * 16,
                .w3 = @offsetOf(Port, "waiters") + 3 * 16,
                .next_off = @offsetOf(ExecutionContext, "next"),
            },
        ) ++

    // ─── Step 7: maintain port.waiter_kind. Scan all 4 levels — if
    // all heads null, set .none. Otherwise leave .receivers intact.
    // ────────────────────────────────────────────────────────────────
        std.fmt.comptimePrint(
            \\
            \\movq {[w3]d}(%%rcx), %%rax
            \\testq %%rax, %%rax
            \\jnz .Lwaiter_kind_done
            \\movq {[w2]d}(%%rcx), %%rax
            \\testq %%rax, %%rax
            \\jnz .Lwaiter_kind_done
            \\movq {[w1]d}(%%rcx), %%rax
            \\testq %%rax, %%rax
            \\jnz .Lwaiter_kind_done
            \\movq {[w0]d}(%%rcx), %%rax
            \\testq %%rax, %%rax
            \\jnz .Lwaiter_kind_done
            \\movb ${[wk_none]d}, {[wk_off]d}(%%rcx)
            \\.Lwaiter_kind_done:
            \\
        ,
            .{
                .w0 = @offsetOf(Port, "waiters") + 0 * 16,
                .w1 = @offsetOf(Port, "waiters") + 1 * 16,
                .w2 = @offsetOf(Port, "waiters") + 2 * 16,
                .w3 = @offsetOf(Port, "waiters") + 3 * 16,
                .wk_none = @intFromEnum(WaiterKind.none),
                .wk_off = @offsetOf(Port, "waiter_kind"),
            },
        ) ++

    // ─── Step 8: spill port_ptr (sender.suspend_port mutation needs
    // it later) and release the port lock. Plain andq — we own the
    // word, no concurrent writer.
    // ────────────────────────────────────────────────────────────────
        \\movq %%rcx, %%gs:120
        \\andq $-2, (%%rcx)

    // ─── Step 9: acquire receiver's CD gen-lock. Spill receiver EC*
    // to gs:88 (persists through everything that follows). recv_cd
    // ptr/gen come from receiver.domain (SlabRef field).
    // ────────────────────────────────────────────────────────────────
        \\movq %%r11, %%gs:88
        ++ std.fmt.comptimePrint(
            \\
            \\movq {[dom_off]d}(%%r11), %%rcx
            \\movq {[gen_off]d}(%%r11), %%r11
            \\
        ,
            .{
                .dom_off = @offsetOf(ExecutionContext, "domain"),
                .gen_off = @offsetOf(ExecutionContext, "domain") + 8,
            },
        ) ++
        \\shlq $1, %%r11
        \\movq %%r11, %%rax
        \\incq %%r11
        \\.Lacquire_recv_cd:
        \\lock cmpxchgq %%r11, (%%rcx)
        \\je .Lrecv_cd_acquired
        \\xorq %%r11, %%rax
        \\testq $-2, %%rax
        \\jnz .Lrecv_cd_fail
        \\pause
        \\movq %%r11, %%rax
        \\andq $-2, %%rax
        \\jmp .Lacquire_recv_cd
        \\.Lrecv_cd_acquired:

    // ─── Step 10: mint reply handle. recv_cd held by lock. Spill
    // recv_cd → gs:80 and recv_cd_gen → gs:104 for use after rcx/r11
    // get repurposed. Pop free slot via cd.free_head + free-list link
    // (kernel_table[slot].parent.slot at offset 32 within KernelHandle).
    // Write user_table[slot] (word0=caps|type|slot, field0/field1=0)
    // and kernel_table[slot] (ref={sender,sender_gen}, parent/
    // first_child/next_sibling=0). Set sender backpointers
    // pending_reply_holder/domain/slot. word0 caps for fast path:
    // ReplyCaps{move=1,xfer=1}=0b101=5; tag=.reply=7.
    // ────────────────────────────────────────────────────────────────
        \\movq %%rcx, %%gs:80
        \\shrq $1, %%r11
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
            \\movq %%r11, (%%rax)
            \\movq (%%r11), %%rcx
            \\shrq $1, %%rcx
            \\movq %%rcx, 8(%%rax)
            \\movq $0, 16(%%rax)
            \\movq $0, 24(%%rax)
            \\movq $0, 32(%%rax)
            \\movq $0, 40(%%rax)
            \\movq $0, 48(%%rax)
            \\movq $0, 56(%%rax)
            \\movq $0, 64(%%rax)
            \\movq $0, 72(%%rax)
            \\movq $0, 80(%%rax)
            \\movq %%rax, %%gs:112
            \\
        ,
            .{ .kt_off = @offsetOf(CapabilityDomain, "kernel_table") },
        ) ++
        std.fmt.comptimePrint(
            \\
            \\movq %%gs:80, %%rcx
            \\movq {[ut_off]d}(%%rcx), %%r11
            \\movq %%gs:96, %%rax
            \\lea (%%rax, %%rax, 2), %%rax
            \\movabsq ${[w0_const]d}, %%rcx
            \\orq %%gs:96, %%rcx
            \\movq %%rcx, (%%r11, %%rax, 8)
            \\movq $0, 8(%%r11, %%rax, 8)
            \\movq $0, 16(%%r11, %%rax, 8)
            \\
        ,
            .{
                .ut_off = @offsetOf(CapabilityDomain, "user_table"),
                .w0_const = (@as(u64, @as(u16, @bitCast(ReplyCaps{ .move = true, .xfer = true }))) << 48) | (@as(u64, @intFromEnum(CapabilityType.reply)) << 12),
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
        \\andq $-2, (%%rcx)

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
            \\movq (%%rax), %%rcx
            \\shrq $1, %%rcx
            \\movq %%rcx, {[susp_port_gen_off]d}(%%r11)
            \\movb $1, {[susp_port_disc_off]d}(%%r11)
            \\movq {[ctx_off]d}(%%r11), %%rax
            \\movq %%gs:16, %%rcx
            \\movq %%rcx, 136(%%rax)
            \\movq %%gs:24, %%rcx
            \\movq %%rcx, 152(%%rax)
            \\movq %%gs:8, %%rcx
            \\movq %%rcx, 160(%%rax)
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
            },
        ) ++

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
        std.fmt.comptimePrint(
            \\
            \\movq %%gs:88, %%r11
            \\movq %%r11, %%gs:32
            \\movq %%gs:128, %%rax
            \\movq %%r11, {[cur_ec_off]d}(%%rax)
            \\movq (%%r11), %%rcx
            \\shrq $1, %%rcx
            \\movl %%ecx, {[cur_ec_gen_off]d}(%%rax)
            \\movb $1, {[cur_ec_disc_off]d}(%%rax)
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
            "\nmovq {d}(%%r11), %%rcx\n",
            .{@offsetOf(ExecutionContext, "ctx")},
        ) ++
        \\movq %%rcx, %%gs:88
        \\movq 160(%%rcx), %%rax
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
        \\movq 152(%%rcx), %%r11
        \\movq 136(%%rcx), %%rcx
        \\movq %%rax, %%rsp
        \\movq %%gs:72, %%rax
        \\swapgs
        \\sysretq

    // ─── Bail handlers ─────────────────────────────────────────────
        \\.Lcd_full:
        \\movq %%gs:80, %%rcx
        \\andq $-2, (%%rcx)
        \\ud2
        \\.Lrecv_cd_fail:
        \\ud2
        \\.Lsyscall_no_receiver:
        \\andq $-2, (%%rcx)                   // release port lock (we hold it)
        \\.Lsyscall_lock_fail:
        \\movq %%gs:72, %%rax                 // restore target_id for slow path
        \\jmp .Lsyscall_slow_path
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
        // self-alive: identity compare against just-dispatched `ec`.
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
