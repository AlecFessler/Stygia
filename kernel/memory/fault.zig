const std = @import("std");
const stygia = @import("stygia");

const address = stygia.memory.address;
const arch = stygia.arch.dispatch;
const kprof = stygia.kprof.trace_id;
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

/// Memory-fault sub-code carried in the event payload alongside
/// `EventType.memory_fault` per spec §[event_type] table 1840 ("invalid
/// read/write/execute, unmapped access, protection violation").
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
    } else {
        fatal_capture.have_regs = false;
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
    @panic(fatal_capture.msg);
}

/// One line per online core: park-stack range, current EC and its
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
        if (cs.current_ec) |ref| {
            arch.boot.printRaw(" cur=0x");
            panic_mod.printHex(@intFromPtr(ref.ptr));
            arch.boot.printRaw(" kstk=0x");
            panic_mod.printHex(ref.ptr.kernel_stack.base.addr);
            arch.boot.printRaw("..0x");
            panic_mod.printHex(ref.ptr.kernel_stack.top.addr);
            arch.boot.printRaw(if (ref.ptr.on_cpu.load(.monotonic)) " on_cpu=1" else " on_cpu=0");
        } else {
            arch.boot.printRaw(" cur=null");
        }
        var zpend: usize = 0;
        for (cs.pending_zombie) |mz| {
            if (mz != null) zpend += 1;
        }
        if (zpend != 0) {
            arch.boot.printRaw(" zpend=0x");
            panic_mod.printHex(zpend);
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
        if (fp < address.AddrSpacePartition.user.end) break;
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
    kprof.enter(.handle_page_fault);
    defer kprof.exit(.handle_page_fault);
    kprof.point(.handle_page_fault, fault.faulting_address);

    const faulting_virt = VAddr.fromInt(fault.faulting_address);
    const is_kernel_privilege = fault.is_kernel_privilege;
    const is_user_va = faulting_virt.addr < address.AddrSpacePartition.user.end;
    const is_write = fault.is_write;
    const is_exec = fault.is_exec;

    if (is_kernel_privilege and is_user_va) {
        // Kernel touched a user VA via a syscall accessor — surface as a
        // memory_fault on the EC whose syscall triggered the access.
        const ec = scheduler.currentEc() orelse {
            if (comptime pf_log.enabled) {
                pf_log.mark(null, .KERNEL_NO_EC, faulting_virt.addr, 0);
            }
            // This panic is one of the downstream shapes of the bare-metal
            // 4-core corruption (stygia-723); report the full frame so it
            // stops being a one-line dead end.
            reportKernelFaultFatal(fault, "kernel page fault on user VA with no current EC");
        };
        if (comptime pf_log.enabled) {
            pf_log.mark(ec, .KERNEL_ON_USER_VA, faulting_virt.addr, 0);
        }
        // Drain the per-core lockdep held-stack: the original syscall
        // (e.g. `reply` holds the sender EC's gen-lock across
        // `applyReplyStateToVcpu`'s SMAP-bracketed user-stack reads)
        // has its kernel frame abandoned by the yieldTo below, so the
        // defer-driven `unlockIrqRestore` never runs. Stale acquire
        // entries left on the per-core stack would otherwise pin those
        // classes forever and close spurious AB-BA cycles against the
        // next syscall on this core. The underlying lock bits in
        // memory remain set — that is a separate (pre-existing) leak.
        sync_debug.dropAllHeldOnAbandonedStack();
        port.fireMemoryFault(ec, @intFromEnum(accessSubcode(is_write, is_exec)), faulting_virt.addr);
        // IRQs stay MASKED through the dispatch attempt: the fired
        // fault event may have suspended the EC with its kstack
        // release stashed on this core; an IRQ handler here could
        // spin on that very release (markReady's kstack barrier) —
        // a self-deadlock on our own pending stash.
        scheduler.yieldTo(null);
        // `fireMemoryFault`'s no-route fallback terminates `ec` and
        // clears `current_ec`; if the run queue is empty, returning
        // would iretq back into the now-stale faulting frame and re-
        // enter exception handling with `currentEc() == null`. Hand
        // control to `scheduler.run()` — it idles until an IRQ delivers
        // more work, at which point dispatch via
        // `loadEcContextAndReturn` resets `rsp` and abandons this
        // kernel-stack frame.
        if (scheduler.currentEc() == null) scheduler.hopParkRun();
        return;
    }

    if (is_kernel_privilege) {
        switch (stack_mod.isKernelStackPage(faulting_virt)) {
            .usable => {
                if (comptime pf_log.enabled) {
                    pf_log.mark(scheduler.currentEc(), .KERNEL_DEMAND, faulting_virt.addr, 0);
                }
                demandPageKernel(faulting_virt);
                return;
            },
            .guard => {
                if (comptime pf_log.enabled) {
                    pf_log.mark(scheduler.currentEc(), .KERNEL_STACK_OVERFLOW, faulting_virt.addr, 0);
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
                pf_log.mark(scheduler.currentEc(), .KERNEL_DEMAND, faulting_virt.addr, 0);
            }
            demandPageKernel(faulting_virt);
            return;
        }

        if (comptime pf_log.enabled) {
            pf_log.mark(scheduler.currentEc(), .KERNEL_VA_INVALID, faulting_virt.addr, 0);
        }
        reportKernelFaultFatal(fault, "unexpected kernel page fault");
    }

    const ec = scheduler.currentEc() orelse {
        if (comptime pf_log.enabled) {
            pf_log.mark(null, .USER_NO_EC, faulting_virt.addr, 0);
        }
        // Same rationale as the kernel-on-user-VA no-EC arm: this panic
        // is a recurring downstream shape of SMP corruption, and the
        // core + register frame are what make it attributable. The fp
        // here is a user fp, so the chain walk stops at the first
        // unresolvable (user) address — the header is still worth it.
        reportKernelFaultFatal(fault, "user page fault with no current EC");
    };

    // Per-PF debug print intentionally elided. Every demand-page
    // operation hits this path; the in-kernel-parallel test runner
    // spawns hundreds of tests whose initial ELF load each triggers
    // many PFs, and the resulting print storm (a) inflates each PF
    // handler's kernel-stack frame by the bufPrint formatter buffer
    // and (b) serialised the runner against print_lock under load
    // hard enough to mask real errors. If userland PF tracing is
    // wanted, gate it on a runtime flag rather than a default-on log.

    const dom_ref = ec.domain;
    const dom_lr = dom_ref.lockIrqSave(@src()) catch {
        // Domain torn down between exception entry and here — fire
        // memory_fault so the no-route fallback retires the EC.
        if (comptime pf_log.enabled) {
            pf_log.mark(ec, .USER_DOMAIN_GONE, faulting_virt.addr, 0);
        }
        port.fireMemoryFault(ec, @intFromEnum(MemoryFaultSubcode.unmapped), faulting_virt.addr);
        // IRQs stay MASKED through the dispatch attempt: the fired
        // fault event may have suspended the EC with its kstack
        // release stashed on this core; an IRQ handler here could
        // spin on that very release (markReady's kstack barrier) —
        // a self-deadlock on our own pending stash.
        scheduler.yieldTo(null);
        // See the kernel-on-user-VA branch above: the no-route fallback
        // drains `current_ec`; if no other EC is ready we MUST not iretq
        // back to the stale faulting frame.
        if (scheduler.currentEc() == null) scheduler.hopParkRun();
        return;
    };
    const dom = dom_lr.ptr;

    const rc = vmar.handlePageFault(dom, faulting_virt, accessRwx(is_write, is_exec));
    dom_ref.unlockIrqRestore(dom_lr.irq_state);

    // Spec v3 vmar.handlePageFault returns 0 on a resolved fault
    // (demand alloc, MMIO/port-IO virtualization, etc.). Any non-zero
    // return — E_BADADDR (no covering VMAR), E_PERM (rights mismatch),
    // E_NOMEM (demand alloc exhausted) — routes through the EC's
    // memory_fault event. fireMemoryFault either suspends the EC on the
    // bound port or applies the no-route fallback (restart or destroy
    // the owning domain) per spec §[event_route]. Either outcome leaves
    // this EC unrunnable, so yield the CPU after firing.
    if (comptime pf_log.enabled) {
        if (rc == 0) {
            pf_log.mark(ec, .USER_RESOLVED, faulting_virt.addr, 0);
        } else {
            pf_log.mark(ec, .USER_INVALID, faulting_virt.addr, @bitCast(@as(i32, @truncate(rc))));
        }
    }
    if (rc != 0) {
        const subcode = if (rc == stygia.syscall.errors.E_BADADDR)
            MemoryFaultSubcode.unmapped
        else
            accessSubcode(is_write, is_exec);
        port.fireMemoryFault(ec, @intFromEnum(subcode), faulting_virt.addr);
        // IRQs stay MASKED through the dispatch attempt: the fired
        // fault event may have suspended the EC with its kstack
        // release stashed on this core; an IRQ handler here could
        // spin on that very release (markReady's kstack barrier) —
        // a self-deadlock on our own pending stash.
        scheduler.yieldTo(null);
        // Same rationale as the kernel-on-user-VA branch.
        if (scheduler.currentEc() == null) scheduler.hopParkRun();
    }
}
