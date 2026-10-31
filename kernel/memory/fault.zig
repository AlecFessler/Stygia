const std = @import("std");
const stygia = @import("stygia");
const build_options = @import("build_options");

const address = stygia.memory.address;
const arch = stygia.arch.dispatch;
const errors = stygia.syscall.errors;
const memory_init = stygia.memory.init;
const paging = stygia.memory.paging;
const pmm = stygia.memory.pmm;
const panic_mod = stygia.panic;
const pf_log = stygia.utils.pf_log;
const port = stygia.sched.port;
const scheduler = stygia.sched.scheduler;
const stack_mod = stygia.memory.stack;
const sync_debug = stygia.utils.sync.debug;
const vmar = stygia.memory.vmar;

const MemoryPerms = stygia.memory.address.MemoryPerms;
const PAddr = stygia.memory.address.PAddr;
const PageFaultContext = stygia.arch.dispatch.cpu.PageFaultContext;
const VAddr = stygia.memory.address.VAddr;
const DbgArchCpuContext = stygia.arch.dispatch.cpu.ArchCpuContext;

const PF_DIAG_BUDGET: u32 = 4096;
var pf_diag_prints: u32 = 0;

fn diagTag(thread: *const stygia.sched.thread.Thread) u64 {
    if (thread.diag_test_tag != 0) return thread.diag_test_tag;
    return thread.process.ptr.diag_test_tag;
}

fn logPfDiag(
    site: []const u8,
    thread: ?*const stygia.sched.thread.Thread,
    fault: *const PageFaultContext,
    rc: i64,
    subcode: u8,
) void {
    if (!build_options.kernel_spawn_diag) return;
    const n = @atomicRmw(u32, &pf_diag_prints, .Add, 1, .monotonic);
    if (n >= PF_DIAG_BUDGET) return;
    const tag: u64 = if (thread) |e| diagTag(e) else 0;
    arch.boot.print(
        "[pfdiag] site={s} tag=0x{x} thread=0x{x} far=0x{x} rip=0x{x} kpriv={d} w={d} x={d} uaccess={d} rc={d} sub={d}\n",
        .{
            site,
            tag,
            if (thread) |e| @intFromPtr(e) else 0,
            fault.faulting_address,
            fault.rip,
            @intFromBool(fault.is_kernel_privilege),
            @intFromBool(fault.is_write),
            @intFromBool(fault.is_exec),
            @intFromBool(fault.in_user_access_window),
            rc,
            subcode,
        },
    );
}

// TEMP DIAGNOSTIC (stygia-idc, REMOVE).
//
// The bare-metal cap is a recurring unhandled `memory_fault subcode=0`.
// Cycle 4's reporter dumped `thread.ctx` and produced a frame that is
// INTERNALLY INCONSISTENT: `elr` named `bfxil x9, x0, #0, #12` (a
// register-only instruction that cannot take a data abort) while every
// GPR in the same frame held its value from four instructions EARLIER,
// and the fault address (0x20) matches neither. All three readings
// cannot describe one event, so at most one of them is the fault.
//
// `thread.ctx` is assigned exactly once, at thread creation, and both
// `exceptionTrampoline` and `restoreContextAndEret` are built so the
// frame always lands at `kstack.top - 288`. That is an ASSUMPTION about
// where SP_EL1 was at entry, not a measurement. This stash records the
// LIVE fault context — the frame pointer the arch handler was actually
// handed, its `rip`, and the hardware fault address — so the reporter
// can print the real frame next to `thread.ctx` and say which (if either)
// is the fault. `live_ctx != thread.ctx` refutes the whole cycle-3/4 line
// of inference in one comparison.
const DbgFaultStash = struct {
    valid: bool = false,
    site: u8 = 0,
    kpriv: bool = false,
    is_write: bool = false,
    is_exec: bool = false,
    core: u8 = 0,
    rip: u64 = 0,
    far: u64 = 0,
    live_ctx: ?*const DbgArchCpuContext = null,
};

/// Indexed by core id. Written on the fault path immediately before
/// `port.fireMemoryFault`, read by `port.reportUnhandledFault` on the same
/// core before anything can preempt it.
pub var dbg_fault: [64]DbgFaultStash = @splat(.{});

fn dbgStashFault(fault: *const PageFaultContext, site: u8) void {
    const core: u8 = @truncate(arch.smp.coreID());
    if (core >= dbg_fault.len) return;
    dbg_fault[core] = .{
        .valid = true,
        .site = site,
        .kpriv = fault.is_kernel_privilege,
        .is_write = fault.is_write,
        .is_exec = fault.is_exec,
        .core = core,
        .rip = fault.rip,
        .far = fault.faulting_address,
        .live_ctx = fault.frame_ctx,
    };
}

/// Classifies invalid memory accesses for kernel diagnostics.
const MemoryFaultSubcode = enum(u8) {
    unmapped = 0,
    invalid_read = 1,
    invalid_write = 2,
    invalid_execute = 3,
    protection_fault = 4,
};

const KERNEL_PERMS = MemoryPerms{
    .read = true,
    .write = true,
    .exec = false,
};

fn demandPageKernel(faulting_virt: VAddr) void {
    const page_base = VAddr.fromInt(std.mem.alignBackward(u64, faulting_virt.addr, paging.PAGE4K));
    const kroot = memory_init.kernel_addr_space_root;

    if (arch.paging.resolveVaddr(kroot, page_base) != null) return;

    const pmm_mgr = &pmm.global_pmm.?;
    const page = pmm_mgr.create(paging.PageMem(.page4k)) catch
        @panic("OOM in kernel demand page fault");

    const phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
    arch.paging.mapPage(kroot, phys, page_base, KERNEL_PERMS, .kernel_data) catch
        @panic("mapPage failed in kernel demand page fault");
}

/// Report an unexpected kernel-privilege fault, lock-free, immediately
/// before panicking on it.
///
/// This used `arch.boot.print`, which takes `serial.print_lock`, and that
/// turned a diagnosable panic into an undiagnosable wedge. Two ways:
///
///   1. **Recursive acquire.** A kernel fault can be taken *from inside*
///      `serial.print` — that function keeps a 256-byte format buffer on
///      the stack, so it is one of the larger frames in the kernel and a
///      prime candidate for tipping a deep path over its stack guard.
///      When that happens `print_lock` is already held by this core, and
///      re-taking it trips the lockdep same-core recursive-acquire check,
///      which calls `@panic` itself. The original fault address is lost
///      and the kernel spins in the printer. Measured on the aarch64 rig
///      under 4-core spread: the real event was a kernel stack overflow
///      on core 3, and all that reached the wire was
///      `lockdep: recursive acquire core=3` with a backtrace through
///      `handlePageFault -> print -> lockIrqSave`.
///   2. **Deadlock in disguise.** Even without lockdep, spinning for a
///      lock whose holder is another core that is also panicking never
///      terminates.
///
/// `kernel/panic.zig` documents both hazards and avoids them by using
/// `printRaw` exclusively; this is the same reasoning applied to the
/// pre-panic diagnostic, which `claimPanic`'s doc comment already
/// anticipated ("fault-handler print -> @panic" from the same core
/// returns true, so claiming here does not lock `panic()` out).
///
/// Claiming the gate also stops concurrent faulting cores from
/// interleaving into each other's output — the earlier bare-metal logs
/// contain `KERKERNEL PAGE FAULT at 0xf` followed by a run of NULs,
/// which is two cores writing the same reporter at once.
/// Static home for the fatal-fault report. The reporter may be standing
/// on the very stack whose corruption it is reporting, with the
/// corrupting writer still active — on the Pi 5 rig a stack-resident
/// report died 11 hex digits in when the trampler caught up with it. So:
/// claim the gate, copy the evidence into statics, abandon the doomed
/// stack via `jumpOnStack`, and print from ground the trampler cannot
/// reach. One buffer suffices: `claimPanic` serializes reporters (losers
/// halt), and the winning core never leaves this path.
const FatalCapture = struct {
    addr: u64 = 0,
    pc: u64 = 0,
    lr: u64 = 0,
    fp: u64 = 0,
    is_write: bool = false,
    is_exec: bool = false,
    have_regs: bool = false,
    regs: arch.cpu.ArchCpuContext = undefined,
    /// Address the live exception frame was captured at, so the report
    /// can locate and hex-dump the interrupted stack region itself —
    /// the register copy alone cannot recover it.
    frame_at: u64 = 0,
    msg: []const u8 = "",
};
var fatal_capture: FatalCapture = .{};
var fatal_stack: [32 * 1024]u8 align(16) = undefined;

/// Report an unexpected kernel-privilege fault and panic, printing from
/// the static safe stack. Never returns.
fn reportKernelFaultFatal(fault: *const PageFaultContext, msg: []const u8) noreturn {
    if (!panic_mod.claimPanic()) arch.cpu.halt();
    fatal_capture.addr = fault.faulting_address;
    fatal_capture.pc = fault.rip;
    fatal_capture.lr = fault.lr;
    fatal_capture.fp = fault.fp;
    fatal_capture.is_write = fault.is_write;
    fatal_capture.is_exec = fault.is_exec;
    fatal_capture.msg = msg;
    if (fault.frame_ctx) |ctx| {
        fatal_capture.regs = ctx.*;
        fatal_capture.have_regs = true;
        fatal_capture.frame_at = @intFromPtr(ctx);
    } else {
        fatal_capture.have_regs = false;
        fatal_capture.frame_at = 0;
    }
    arch.cpu.jumpOnStack(
        @intFromPtr(&fatal_stack) + fatal_stack.len,
        &reportCapturedAndPanic,
    );
}

fn reportCapturedAndPanic() callconv(.c) noreturn {
    arch.boot.printRaw("KERNEL PAGE FAULT at 0x");
    panic_mod.printHex(fatal_capture.addr);
    arch.boot.printRaw(if (fatal_capture.is_write) " (write=true" else " (write=false");
    arch.boot.printRaw(if (fatal_capture.is_exec) " exec=true" else " exec=false");
    // The faulting PC names the instruction; `lr` names its caller when
    // the PC is a leaf (the bare-metal corruption faulted inside memset,
    // which tells you nothing without the caller). `core` distinguishes
    // "the BSP running the whole suite" from "a supposedly idle AP".
    arch.boot.printRaw(" pc=0x");
    panic_mod.printHex(fatal_capture.pc);
    arch.boot.printRaw(" lr=0x");
    panic_mod.printHex(fatal_capture.lr);
    arch.boot.printRaw(" core=0x");
    panic_mod.printHex(arch.smp.coreID());
    arch.boot.printRaw(")\n");
    if (fatal_capture.have_regs) arch.cpu.dumpFaultRegs(&fatal_capture.regs);
    dumpFrameChain(fatal_capture.fp);
    dumpCoreStatesRaw();
    // Raw bytes of the interrupted stack, from just below its SP upward
    // through its live frames. The register scraps identify corruption;
    // the raw bytes identify the WRITER — trample content is structured
    // (slices, enums, frame records) and pattern-matches offline against
    // the ELF far better than four sampled registers can.
    if (fatal_capture.frame_at != 0) {
        const interrupted_sp = fatal_capture.frame_at + @sizeOf(arch.cpu.ArchCpuContext) + 16;
        dumpStackRaw(interrupted_sp - 64, 512);
    }
    @panic(fatal_capture.msg);
}

fn dumpStackRaw(base: u64, len: u64) void {
    arch.boot.printRaw("  stack raw:\n");
    var addr = base & ~@as(u64, 7);
    const end = base + len;
    while (addr < end) : (addr += 64) {
        const first = VAddr.fromInt(std.mem.alignBackward(u64, addr, paging.PAGE4K));
        const last = VAddr.fromInt(std.mem.alignBackward(u64, addr + 63, paging.PAGE4K));
        if (arch.paging.resolveVaddr(memory_init.kernel_addr_space_root, first) == null) break;
        if (last.addr != first.addr and
            arch.paging.resolveVaddr(memory_init.kernel_addr_space_root, last) == null) break;
        arch.boot.printRaw("  ");
        panic_mod.printHex(addr);
        arch.boot.printRaw(":");
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            arch.boot.printRaw(" ");
            panic_mod.printHex(@as(*const u64, @ptrFromInt(addr + i * 8)).*);
        }
        arch.boot.printRaw("\n");
    }
}

/// One line per online core: park-stack range, current thread and its
/// kstack range, on_cpu, pending-zombie count. Racy cross-core reads,
/// printRaw only — this exists so a corruption report shows which
/// contexts could legally be writing near the victim address, instead
/// of that question costing another hardware cycle.
fn dumpCoreStatesRaw() void {
    const n = @min(arch.smp.coreCount(), scheduler.MAX_CORES);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const cs = &scheduler.core_states[i];
        arch.boot.printRaw("  core ");
        panic_mod.printHex(i);
        arch.boot.printRaw(" park=0x");
        panic_mod.printHex(cs.park_stack.base.addr);
        arch.boot.printRaw("..0x");
        panic_mod.printHex(cs.park_stack.top.addr);
        if (cs.current_thread) |cur| {
            arch.boot.printRaw(" cur=0x");
            panic_mod.printHex(@intFromPtr(cur));
            arch.boot.printRaw(" kstk=0x");
            panic_mod.printHex(cur.kernel_stack.base.addr);
            arch.boot.printRaw("..0x");
            panic_mod.printHex(cur.kernel_stack.top.addr);
            arch.boot.printRaw(" owner=");
            panic_mod.printHex(cur.owner_core);
            arch.boot.printRaw(" wait=");
            panic_mod.printHex(@intFromEnum(cur.wait.kind));
        } else {
            arch.boot.printRaw(" cur=null");
        }
        if (cs.teardown_pending) |req| {
            arch.boot.printRaw(" td_kind=");
            panic_mod.printHex(@intFromEnum(req.kind));
            arch.boot.printRaw(" td_process=0x");
            panic_mod.printHex(@intFromPtr(req.process.ptr));
        }
        arch.boot.printRaw("\n");
    }
}

/// Walk the interrupted context's frame-record chain and print each
/// return address. `[fp]` = caller's fp, `[fp+8]` = return address —
/// the layout is identical on aarch64 (AAPCS64 frame record) and x86-64
/// (rbp chain), so this is arch-generic.
///
/// This is the backtrace the panic machinery cannot produce: its
/// `StackIterator` starts from the panic call site and dies at the naked
/// exception trampoline, three frames in. The fp captured in the
/// exception frame predates the trampoline, so walking from it yields
/// the call chain of the code that actually faulted.
///
/// Lock-free (printRaw only), and every load is gated on the address
/// resolving in the kernel address space — the chain being walked
/// belongs to a context that just faulted, so it may itself be the
/// corrupted thing. A nested fault here would re-enter the reporter
/// with the gate already claimed and wedge the output.
pub fn dumpFrameChain(first_fp: u64) void {
    var fp = first_fp;
    var depth: usize = 0;
    while (depth < 16) : (depth += 1) {
        if (fp == 0 or fp % 16 != 0) break;
        // Canonicality, not just "above the user half": `resolveVaddr`
        // is a software walk indexed by VA bits [47:12], so a
        // NON-CANONICAL pointer whose low 48 bits alias a mapped kernel
        // VA (autopsied: fp=0x2FF0_0000_4009_5A70 aliasing the kstack at
        // 0xFFFF_0000_4009_5A70) resolves fine and then faults in
        // hardware on the actual load. The canonical kernel-half base is
        // the lowest kernel partition: kernel_code on aarch64
        // (0xFFFF_0000_...), kernel on x86-64 (0xFFFF_8000_...).
        const kernel_half_base = comptime @min(
            address.AddrSpacePartition.kernel.start,
            address.AddrSpacePartition.kernel_code.start,
        );
        if (fp < kernel_half_base) break;
        // fp and fp+8 sit in one 16-byte-aligned chunk — a single page
        // resolve covers both loads.
        const page = VAddr.fromInt(std.mem.alignBackward(u64, fp, paging.PAGE4K));
        if (arch.paging.resolveVaddr(memory_init.kernel_addr_space_root, page) == null) break;
        const rec: *const [2]u64 = @ptrFromInt(fp);
        arch.boot.printRaw("  frame fp=0x");
        panic_mod.printHex(fp);
        arch.boot.printRaw(" ret=0x");
        panic_mod.printHex(rec[1]);
        arch.boot.printRaw("\n");
        // Stacks grow down, so a well-formed chain strictly ascends;
        // anything else is a cycle or corruption — stop.
        if (rec[0] <= fp) break;
        fp = rec[0];
    }
}

/// Translate (is_write, is_exec) into the rwx triple consumed by
/// `vmar.handlePageFault` (R=1, W=2, X=4 per spec §[var]).
fn accessRwx(is_write: bool, is_exec: bool) u3 {
    if (is_exec) return 0b100;
    if (is_write) return 0b010;
    return 0b001;
}

fn accessSubcode(is_write: bool, is_exec: bool) MemoryFaultSubcode {
    if (is_exec) return .invalid_execute;
    if (is_write) return .invalid_write;
    return .invalid_read;
}

pub fn handlePageFault(fault: *const PageFaultContext) void {
    const faulting_virt = VAddr.fromInt(fault.faulting_address);
    const is_kernel_privilege = fault.is_kernel_privilege;
    const is_user_va = faulting_virt.addr < address.AddrSpacePartition.user.end;
    const is_write = fault.is_write;
    const is_exec = fault.is_exec;

    if (is_kernel_privilege and is_user_va) {
        // ── Wild kernel pointer vs. genuine syscall accessor ──────────
        //
        // The user half is the whole lower canonical half, so a NULL-ish
        // or otherwise wild KERNEL pointer lands here and is
        // indistinguishable, by address alone, from a syscall accessor
        // dereferencing a bad user pointer. The two need opposite
        // handling:
        //
        //   * accessor fault  — userspace supplied a pointer the kernel
        //     was asked to touch; deliver `memory_fault` to the thread.
        //   * wild pointer    — a kernel bug (corrupted stack slot,
        //     freed object, torn ref). Delivering `memory_fault` for it
        //     is actively harmful: the arm below abandons the faulting
        //     kernel frame via `yieldTo`/`hopParkRun` WITHOUT unwinding
        //     it, so every lock that frame holds stays locked in memory
        //     forever. `fireMemoryFault`'s unhandled-fault path then takes
        //     `caps.derivation.tree_mutex` and blocking-acquires the
        //     thread's process gen-lock — which, on the demand-
        //     paging path, is exactly one of the locks just leaked
        //     (fault.zig's own user arm took it, and vmar.handlePageFault
        //     took the VMAR's). The result is an unkillable spin holding
        //     a global mutex: captured live as
        //     `[UNHANDLED] memory_fault subcode=2 payload=0xfff` followed
        //     by whole-suite starvation.
        //
        // Two structural discriminators, both cheap and exact:
        //
        //   1. `[0, 0x1000)` is the §[address_space] NULL guard. No
        //      mapping path may ever install a leaf there, so no
        //      accessor can legitimately fault in it — any fault in
        //      that page is a wild pointer by construction.
        //   2. The CPU records whether the access was inside a marked
        //      copy-in/out window: x86-64 RFLAGS.AC (set by STAC in
        //      `userAccessBegin`, cleared by CLAC and by the interrupt
        //      stub prologue), aarch64 PSTATE.PAN. Outside that window
        //      the kernel had no business touching a user VA at all.
        //
        // Either one firing means "kernel bug": report it with full
        // registers, frame chain, core state and raw stack, and panic.
        if (faulting_virt.addr < address.UserVA.null_guard.end or
            !fault.in_user_access_window)
        {
            reportKernelFaultFatal(fault, "wild kernel pointer fault on a user VA");
        }

        // Kernel touched a user VA via a syscall accessor — surface as a
        // memory_fault on the thread whose syscall triggered the access.
        const thread = scheduler.currentThread() orelse {
            if (comptime pf_log.enabled) {
                pf_log.mark(null, .KERNEL_NO_THREAD, faulting_virt.addr, 0);
            }
            // This panic is one of the downstream shapes of the bare-metal
            // 4-core corruption (stygia-723); report the full frame so it
            // stops being a one-line dead end.
            reportKernelFaultFatal(fault, "kernel page fault on user VA with no current thread");
        };
        if (comptime pf_log.enabled) {
            pf_log.mark(thread, .KERNEL_ON_USER_VA, faulting_virt.addr, 0);
        }
        // Drain the per-core lockdep held-stack: the original syscall
        // (e.g. `reply` holds the sender thread's gen-lock across
        // `applyReplyStateToVcpu`'s SMAP-bracketed user-stack reads)
        // has its kernel frame abandoned by the yieldTo below, so the
        // defer-driven `unlockIrqRestore` never runs. Stale acquire
        // entries left on the per-core stack would otherwise pin those
        // classes forever and close spurious AB-BA cycles against the
        // next syscall on this core. The underlying lock bits in
        // memory remain set — that is a separate (pre-existing) leak.
        sync_debug.dropAllHeldOnAbandonedStack();
        dbgStashFault(fault, 3); // TEMP DIAGNOSTIC (stygia-idc, REMOVE)
        const subcode: u8 = @intFromEnum(accessSubcode(is_write, is_exec));
        logPfDiag("kernel_user_accessor", thread, fault, errors.E_BADADDR, subcode);
        port.fireMemoryFault(thread, subcode, faulting_virt.addr);
        // IRQs stay MASKED through the dispatch attempt: the fired
        // fault event may have suspended the thread with its kstack
        // release stashed on this core; an IRQ handler here could
        // spin on that very release (markReady's kstack barrier) —
        // a self-deadlock on our own pending stash.
        scheduler.yieldTo(null);
        // `fireMemoryFault`'s unhandled-fault path terminates `thread` and
        // clears `current_thread`; if the run queue is empty, returning
        // would iretq back into the now-stale faulting frame and re-
        // enter exception handling with `currentThread() == null`. Hand
        // control to `scheduler.run()` — it idles until an IRQ delivers
        // more work, at which point dispatch via
        // `loadThreadContextAndReturn` resets `rsp` and abandons this
        // kernel-stack frame.
        // Identity, not just null: the wake/destroy machinery can leave
        // `current_thread` naming a DIFFERENT thread. Returning would ERET into
        // the ORIGINAL faulter's frame on its kstack — a thread the
        // scheduler may be running elsewhere. Only `thread` itself may be
        // resumed through this frame.
        const cur_after = scheduler.currentThread();
        if (cur_after == null or cur_after.? != thread) scheduler.hopParkRun();
        return;
    }

    if (is_kernel_privilege) {
        switch (stack_mod.isKernelStackPage(faulting_virt)) {
            .usable => {
                if (comptime pf_log.enabled) {
                    pf_log.mark(scheduler.currentThread(), .KERNEL_DEMAND, faulting_virt.addr, 0);
                }
                demandPageKernel(faulting_virt);
                return;
            },
            .guard => {
                if (comptime pf_log.enabled) {
                    pf_log.mark(scheduler.currentThread(), .KERNEL_STACK_OVERFLOW, faulting_virt.addr, 0);
                }
                // Report before panicking. The panic backtrace is useless
                // for this particular fault: `StackIterator` cannot walk
                // past `exceptionTrampoline`, which is naked and breaks the
                // frame chain, so every stack-overflow panic prints the
                // same three fault-handling frames and nothing about the
                // call chain that actually consumed the stack.
                //
                // The report identifies it instead: the address says how
                // far into the guard page the push went, and the frame
                // chain walked from the captured x29 names the call path
                // that consumed the stack.
                reportKernelFaultFatal(fault, "Kernel stack overflow");
            },
            .not_stack => {},
        }

        const ka = address.KernelVA.KernelAllocators.range;
        if (faulting_virt.addr >= ka.start and faulting_virt.addr < ka.end) {
            if (comptime pf_log.enabled) {
                pf_log.mark(scheduler.currentThread(), .KERNEL_DEMAND, faulting_virt.addr, 0);
            }
            demandPageKernel(faulting_virt);
            return;
        }

        if (comptime pf_log.enabled) {
            pf_log.mark(scheduler.currentThread(), .KERNEL_VA_INVALID, faulting_virt.addr, 0);
        }
        reportKernelFaultFatal(fault, "unexpected kernel page fault");
    }

    const thread = scheduler.currentThread() orelse {
        if (comptime pf_log.enabled) {
            pf_log.mark(null, .USER_NO_THREAD, faulting_virt.addr, 0);
        }
        // Same rationale as the kernel-on-user-VA no-thread arm: this panic
        // is a recurring downstream shape of SMP corruption, and the
        // core + register frame are what make it attributable. The fp
        // here is a user fp, so the chain walk stops at the first
        // unresolvable (user) address — the header is still worth it.
        reportKernelFaultFatal(fault, "user page fault with no current thread");
    };

    // Per-PF debug print intentionally elided. Every demand-page
    // operation hits this path; the in-kernel-parallel test runner
    // spawns hundreds of tests whose initial ELF load each triggers
    // many PFs, and the resulting print storm (a) inflates each PF
    // handler's kernel-stack frame by the bufPrint formatter buffer
    // and (b) serialised the runner against print_lock under load
    // hard enough to mask real errors. If userland PF tracing is
    // wanted, gate it on a runtime flag rather than a default-on log.

    const dom_ref = thread.process;
    const dom_lr = dom_ref.lockIrqSave(@src()) catch {
        // Process torn down between exception entry and here — fire
        // memory_fault so the unhandled-fault path retires the thread.
        if (comptime pf_log.enabled) {
            pf_log.mark(thread, .USER_PROCESS_GONE, faulting_virt.addr, 0);
        }
        dbgStashFault(fault, 2); // TEMP DIAGNOSTIC (stygia-idc, REMOVE)
        const subcode: u8 = @intFromEnum(MemoryFaultSubcode.unmapped);
        logPfDiag("user_process_gone", thread, fault, errors.E_BADCAP, subcode);
        port.fireMemoryFault(thread, subcode, faulting_virt.addr);
        // IRQs stay MASKED through the dispatch attempt: the fired
        // fault event may have suspended the thread with its kstack
        // release stashed on this core; an IRQ handler here could
        // spin on that very release (markReady's kstack barrier) —
        // a self-deadlock on our own pending stash.
        scheduler.yieldTo(null);
        // See the kernel-on-user-VA branch above: the unhandled-fault path
        // drains `current_thread`; if no other thread is ready we MUST not iretq
        // back to the stale faulting frame.
        // Identity, not just null: the wake/destroy machinery can leave
        // `current_thread` naming a DIFFERENT thread. Returning would ERET into
        // the ORIGINAL faulter's frame on its kstack — a thread the
        // scheduler may be running elsewhere. Only `thread` itself may be
        // resumed through this frame.
        const cur_after = scheduler.currentThread();
        if (cur_after == null or cur_after.? != thread) scheduler.hopParkRun();
        return;
    };
    const dom = dom_lr.ptr;

    const rc = vmar.handlePageFault(dom, faulting_virt, accessRwx(is_write, is_exec));
    dom_ref.unlockIrqRestore(dom_lr.irq_state);

    // Spec v3 vmar.handlePageFault returns 0 on a resolved fault
    // (demand alloc, MMIO/port-IO virtualization, etc.). Any non-zero
    // return — E_BADADDR (no covering VMAR), E_PERM (rights mismatch),
    // E_NOMEM (demand alloc exhausted) — tears down the faulting process.
    // Yield the CPU after firing because this thread is no longer runnable.
    if (comptime pf_log.enabled) {
        if (rc == 0) {
            pf_log.mark(thread, .USER_RESOLVED, faulting_virt.addr, 0);
        } else {
            pf_log.mark(thread, .USER_INVALID, faulting_virt.addr, @bitCast(@as(i32, @truncate(rc))));
        }
    }
    if (rc != 0) {
        const subcode = if (rc == stygia.syscall.errors.E_BADADDR)
            MemoryFaultSubcode.unmapped
        else
            accessSubcode(is_write, is_exec);
        dbgStashFault(fault, 1); // TEMP DIAGNOSTIC (stygia-idc, REMOVE)
        logPfDiag("user_invalid", thread, fault, rc, @intFromEnum(subcode));
        port.fireMemoryFault(thread, @intFromEnum(subcode), faulting_virt.addr);
        // IRQs stay MASKED through the dispatch attempt: the fired
        // fault event may have suspended the thread with its kstack
        // release stashed on this core; an IRQ handler here could
        // spin on that very release (markReady's kstack barrier) —
        // a self-deadlock on our own pending stash.
        scheduler.yieldTo(null);
        // Same rationale as the kernel-on-user-VA branch.
        // Identity, not just null: the wake/destroy machinery can leave
        // `current_thread` naming a DIFFERENT thread. Returning would ERET into
        // the ORIGINAL faulter's frame on its kstack — a thread the
        // scheduler may be running elsewhere. Only `thread` itself may be
        // resumed through this frame.
        const cur_after = scheduler.currentThread();
        if (cur_after == null or cur_after.? != thread) scheduler.hopParkRun();
    }
}
