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
fn reportKernelFault(addr: u64, is_write: bool, is_exec: bool, pc: u64) void {
    if (!panic_mod.claimPanic()) arch.cpu.halt();
    arch.boot.printRaw("KERNEL PAGE FAULT at 0x");
    panic_mod.printHex(addr);
    arch.boot.printRaw(if (is_write) " (write=true" else " (write=false");
    arch.boot.printRaw(if (is_exec) " exec=true" else " exec=false");
    // The faulting PC, which `PageFaultContext` has always carried and this
    // reporter has never printed. Without it the panic says only WHICH
    // address was touched, and the backtrace that follows starts inside the
    // panic machinery — so a wild store gives you the victim and not the
    // culprit. Chasing a write into `.rodata` on the bare-metal rig cost a
    // full hardware cycle for want of this one field.
    arch.boot.printRaw(" pc=0x");
    panic_mod.printHex(pc);
    // Current SP. aarch64's vector entry pushes onto whatever SP already
    // holds (no stack switch), so this is the faulting context's stack
    // pointer less the handler's own frames — close enough to say WHICH
    // region SP is in, which is the question that matters.
    //
    // Three different bare-metal panics (a write into .rodata, a branch
    // into .rodata, and a PC-alignment fault on an odd .rodata address)
    // are all one symptom if SP itself is pointing into .rodata: pushes
    // land in read-only data, and `ret` loads a return address out of it.
    // Printing SP distinguishes that from three unrelated wild pointers.
    arch.boot.printRaw(" fp=0x");
    panic_mod.printHex(@frameAddress());
    arch.boot.printRaw(")\n");
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
            @panic("kernel page fault on user VA with no current EC");
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
        arch.cpu.enableInterrupts();
        scheduler.yieldTo(null);
        // `fireMemoryFault`'s no-route fallback terminates `ec` and
        // clears `current_ec`; if the run queue is empty, returning
        // would iretq back into the now-stale faulting frame and re-
        // enter exception handling with `currentEc() == null`. Hand
        // control to `scheduler.run()` — it idles until an IRQ delivers
        // more work, at which point dispatch via
        // `loadEcContextAndReturn` resets `rsp` and abandons this
        // kernel-stack frame.
        if (scheduler.currentEc() == null) scheduler.run();
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
                // The two values here are what identify it instead. The
                // address says how far into the guard page the push went,
                // which combined with the slot geometry in `memory.stack`
                // gives the overshoot; the PC names the instruction doing
                // the pushing, which is the frame to look at.
                reportKernelFault(faulting_virt.addr, is_write, is_exec, fault.rip);
                @panic("Kernel stack overflow");
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
        reportKernelFault(faulting_virt.addr, is_write, is_exec, fault.rip);
        @panic("unexpected kernel page fault");
    }

    const ec = scheduler.currentEc() orelse {
        if (comptime pf_log.enabled) {
            pf_log.mark(null, .USER_NO_EC, faulting_virt.addr, 0);
        }
        @panic("user page fault with no current EC");
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
        arch.cpu.enableInterrupts();
        scheduler.yieldTo(null);
        // See the kernel-on-user-VA branch above: the no-route fallback
        // drains `current_ec`; if no other EC is ready we MUST not iretq
        // back to the stale faulting frame.
        if (scheduler.currentEc() == null) scheduler.run();
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
        arch.cpu.enableInterrupts();
        scheduler.yieldTo(null);
        // Same rationale as the kernel-on-user-VA branch.
        if (scheduler.currentEc() == null) scheduler.run();
    }
}
