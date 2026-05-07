const zag = @import("zag");

const cpu = zag.arch.x64.cpu;
const ctx_trace = zag.utils.ctx_trace;
const hang_detector = zag.utils.hang_detector;
const hpet_watchdog = zag.arch.x64.hpet_watchdog;
const pf_log = zag.utils.pf_log;
const execution_context = zag.sched.execution_context;
const fpu = zag.sched.fpu;
const gdt = zag.arch.x64.gdt;
const idt = zag.arch.x64.idt;
const interrupts = zag.arch.x64.interrupts;
const kprof = zag.kprof.trace_id;
const kprof_sample = zag.kprof.sample;
const mmio_decode = zag.arch.x64.mmio_decode;
const paging_mod = zag.arch.x64.paging;
const port = zag.sched.port;
const scheduler = zag.sched.scheduler;
const serial = zag.arch.x64.serial;
const vmar = zag.memory.vmar;

const CapabilityDomain = zag.caps.capability_domain.CapabilityDomain;
const DeviceRegion = zag.devices.device_region.DeviceRegion;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const GateType = zag.arch.x64.idt.GateType;
const PageFaultContext = zag.arch.x64.interrupts.PageFaultContext;
const PrivilegeLevel = zag.arch.x64.cpu.PrivilegeLevel;
const VMAR = zag.memory.vmar.VMAR;
const VAddr = zag.memory.address.VAddr;

/// thread_fault sub-codes for exception-derived faults (spec §[event_type]
/// row 2). Values are local to this file; the spec leaves sub-code
/// numbering to implementations and only the routed handler observes them.
const ThreadFaultSubcode = struct {
    const arithmetic: u8 = 1;
    const illegal_instruction: u8 = 2;
    const alignment: u8 = 3;
    const protection: u8 = 4;
};

/// memory_fault sub-codes for exception-derived faults (spec §[event_type]
/// row 1). Values are local to this file; the spec leaves sub-code
/// numbering to implementations and only the routed handler observes them.
const MemoryFaultSubcode = struct {
    const invalid_read: u8 = 1;
    const invalid_write: u8 = 2;
    const invalid_execute: u8 = 3;
};

/// Intel SDM Vol 3A, Table 7-1 — Protected-Mode Exceptions and Interrupts.
/// Vector assignments for architecturally defined exceptions (0-31).
/// Vector 15 is reserved; vectors 21-29 are reserved; vector 31 is reserved.
pub const Exception = enum(u5) {
    divide_by_zero = 0, // #DE — Fault, no error code
    single_step_debug = 1, // #DB — Fault/Trap, no error code
    non_maskable_interrupt = 2, // NMI — Interrupt, no error code
    breakpoint_debug = 3, // #BP — Trap, no error code
    overflow = 4, // #OF — Trap, no error code
    bound_range_exceeded = 5, // #BR — Fault, no error code
    invalid_opcode = 6, // #UD — Fault, no error code
    device_not_available = 7, // #NM — Fault, no error code
    double_fault = 8, // #DF — Abort, error code (zero)
    coprocessor_segment_overrun = 9, // reserved (Fault, no error code)
    invalid_task_state_segment = 10, // #TS — Fault, error code
    segment_not_present = 11, // #NP — Fault, error code
    stack_segment_fault = 12, // #SS — Fault, error code
    general_protection_fault = 13, // #GP — Fault, error code
    page_fault = 14, // #PF — Fault, error code (see PFErrCode)
    x87_floating_point = 16, // #MF — Fault, no error code
    alignment_check = 17, // #AC — Fault, error code (zero)
    machine_check = 18, // #MC — Abort, no error code
    simd_floating_point = 19, // #XM — Fault, no error code
    virtualization = 20, // #VE — Fault, no error code
    security = 30, // #SX — Fault, error code
};

/// Intel SDM Vol 3A §5.7, Figure 5-12 — Page-Fault Error Code.
/// Bit 0 (P): 0 = non-present page, 1 = protection violation.
/// Bit 1 (W/R): 0 = read access, 1 = write access.
/// Bit 2 (U/S): 0 = supervisor-mode access, 1 = user-mode access.
/// Bit 3 (RSVD): 1 = reserved bit set in paging-structure entry.
/// Bit 4 (I/D): 1 = instruction fetch (requires NXE=1 or SMEP=1).
/// Bit 5 (PK): 1 = protection-key violation.
/// Bit 6 (SS): 1 = shadow-stack access.
/// Bit 15 (SGX): 1 = SGX-specific access-control violation.
const PFErrCode = struct {
    present: bool,
    is_write: bool,
    from_user: bool,
    rsvd_violation: bool,
    instr_fetch: bool,
    pkey: bool,
    cet_shadow_stack: bool,
    sgx: bool,

    pub fn from(err: u64) PFErrCode {
        return .{
            .present = (err & 0x1) != 0,
            .is_write = (err >> 1) & 1 == 1,
            .from_user = (err >> 2) & 1 == 1,
            .rsvd_violation = (err >> 3) & 1 == 1,
            .instr_fetch = (err >> 4) & 1 == 1,
            .pkey = (err >> 5) & 1 == 1,
            .cet_shadow_stack = (err >> 6) & 1 == 1,
            .sgx = (err >> 15) & 1 == 1,
        };
    }
};

/// Intel SDM Vol 3A §7.2 — Vectors 0-31 are reserved for exceptions
/// and NMI; vectors 32-255 are available for external interrupts.
pub const NUM_ISR_ENTRIES = 32;

pub fn init() void {
    for (0..NUM_ISR_ENTRIES) |i| {
        const privilege = switch (i) {
            @intFromEnum(Exception.breakpoint_debug),
            @intFromEnum(Exception.single_step_debug),
            => PrivilegeLevel.ring_3,
            else => PrivilegeLevel.ring_0,
        };
        idt.openInterruptGate(
            @intCast(i),
            interrupts.stubs[i],
            gdt.KERNEL_CODE_OFFSET,
            privilege,
            GateType.interrupt_gate,
        );
    }
    interrupts.registerVector(
        @intFromEnum(Exception.page_fault),
        pageFaultHandler,
        .exception,
    );

    const exception_vectors = [_]u5{
        @intFromEnum(Exception.divide_by_zero),
        @intFromEnum(Exception.single_step_debug),
        @intFromEnum(Exception.non_maskable_interrupt),
        @intFromEnum(Exception.breakpoint_debug),
        @intFromEnum(Exception.overflow),
        @intFromEnum(Exception.bound_range_exceeded),
        @intFromEnum(Exception.invalid_opcode),
        @intFromEnum(Exception.device_not_available),
        @intFromEnum(Exception.double_fault),
        @intFromEnum(Exception.coprocessor_segment_overrun),
        @intFromEnum(Exception.invalid_task_state_segment),
        @intFromEnum(Exception.segment_not_present),
        @intFromEnum(Exception.stack_segment_fault),
        @intFromEnum(Exception.general_protection_fault),
        // page_fault already registered above
        @intFromEnum(Exception.x87_floating_point),
        @intFromEnum(Exception.alignment_check),
        @intFromEnum(Exception.machine_check),
        @intFromEnum(Exception.simd_floating_point),
        @intFromEnum(Exception.virtualization),
        @intFromEnum(Exception.security),
    };

    for (exception_vectors) |vec| {
        interrupts.registerVector(vec, exceptionHandler, .exception);
    }
}

/// Patch the IDT gate descriptors for #DF, #NMI, #MC, and #PF to use
/// the Interrupt Stack Table mechanism (Intel SDM Vol 3A §7.14.5).
/// Must run after `gdt.initIst(core_id)` has populated `TSS.IST[N]`
/// for every core that may take one of these exceptions — IST is per-
/// CPU TSS state, but the IDT (and therefore the IST index in each
/// gate) is global. Once patched, every exception of these vectors
/// will hardware-switch RSP to the per-core IST stack regardless of
/// the rsp value at the time of the fault.
///
/// Concretely this protects the L4 IPC fast path: that path runs with
/// `rsp = ec.kstack.top` and stores the user iret frame at
/// `ec.kstack.top - 40 .. ec.kstack.top - 8`, which exactly overlaps
/// `ec.ctx`'s iret slots. Without IST, a #PF taken in the fast path
/// would have the CPU push its own 5-word iret frame at `rsp - 40`,
/// corrupting `ec.ctx`. With IST, the CPU loads RSP from
/// `TSS.IST[IST_PAGE_FAULT]` first, so the in-flight `ec.ctx` window
/// is untouched.
pub fn wireIstGates() void {
    idt.setIst(@intFromEnum(Exception.double_fault), gdt.IST_DOUBLE_FAULT);
    idt.setIst(@intFromEnum(Exception.non_maskable_interrupt), gdt.IST_NMI);
    idt.setIst(@intFromEnum(Exception.machine_check), gdt.IST_MACHINE_CHECK);
    idt.setIst(@intFromEnum(Exception.page_fault), gdt.IST_PAGE_FAULT);
}

/// Event-route classification of an architectural exception. `null` for
/// vectors handled out-of-band (lazy FPU trap, single-step, NMI, machine
/// check, double fault).
const ExceptionEvent = union(enum) {
    thread_fault: u8,
    breakpoint,
};

fn exceptionEvent(vector: u5) ?ExceptionEvent {
    return switch (@as(Exception, @enumFromInt(vector))) {
        .divide_by_zero, .overflow, .bound_range_exceeded => .{ .thread_fault = ThreadFaultSubcode.arithmetic },
        .x87_floating_point, .simd_floating_point => .{ .thread_fault = ThreadFaultSubcode.arithmetic },
        .invalid_opcode => .{ .thread_fault = ThreadFaultSubcode.illegal_instruction },
        // device_not_available is handled out-of-band (lazy FPU trap)
        // before we reach exceptionEvent — see exceptionHandler.
        .device_not_available => null,
        .alignment_check => .{ .thread_fault = ThreadFaultSubcode.alignment },
        .general_protection_fault, .stack_segment_fault => .{ .thread_fault = ThreadFaultSubcode.protection },
        .invalid_task_state_segment, .segment_not_present => .{ .thread_fault = ThreadFaultSubcode.protection },
        .virtualization, .security => .{ .thread_fault = ThreadFaultSubcode.protection },
        .single_step_debug => null,
        .breakpoint_debug => .breakpoint,
        .double_fault, .machine_check => null,
        .non_maskable_interrupt, .coprocessor_segment_overrun => null,
        .page_fault => unreachable,
    };
}

/// Probe the user-mode instruction byte at `rip` against the HLT opcode
/// (0xF4, single byte — Intel SDM Vol 2A "HLT"). Walks the current EC's
/// capability-domain page tables so we don't depend on the page being
/// resident in any kernel-side cache. Returns false if there is no
/// current EC, the page is not resident, or the byte mismatches.
fn isUserHltAt(rip: u64) bool {
    const ec = scheduler.currentEc() orelse return false;
    // caller-pinned: currentEc() runs on this core; its bound capability
    // domain stays alive for the duration of this exception handler.
    const domain = ec.domain.ptr;
    const rip_page = VAddr.fromInt(rip & ~@as(u64, 0xFFF));
    const phys = paging_mod.resolveVaddr(domain.addr_space_root, rip_page) orelse
        return false;
    const physmap_base = VAddr.fromPAddr(phys, null).addr;
    const byte_ptr: *const u8 = @ptrFromInt(physmap_base + (rip & 0xFFF));
    return byte_ptr.* == 0xF4;
}

fn exceptionHandler(ctx: *cpu.Context) void {
    kprof.enter(.exception);
    defer kprof.exit(.exception);

    const vector: u5 = @intCast(ctx.int_num);
    const exception: Exception = @enumFromInt(vector);
    const ring_3 = @intFromEnum(PrivilegeLevel.ring_3);
    const from_user = (ctx.cs & ring_3) == ring_3;

    // Lazy-FPU trap. CR0.TS was set by switchTo when this EC last got
    // dispatched (because it wasn't the last FPU owner on this core).
    // Userspace's first FP/SSE instruction trapped #NM here — swap
    // state and return so the instruction re-executes.
    if (exception == .device_not_available) {
        const ec = scheduler.currentEc() orelse
            @panic("#NM with no current EC");
        fpu.handleTrap(ec);
        return;
    }

    if (from_user) {
        // Debug/single-step from userspace: just resume.
        if (exception == .single_step_debug) return;

        // EL0 hlt trap. Intel SDM Vol 2A "HLT" — executing HLT at CPL > 0
        // raises #GP(0). Park the EC in `.idle_wait` so it stops consuming
        // CPU but stays alive and suspendable; the aarch64 wfi-trap path
        // (kernel/arch/aarch64/exceptions.zig `.wf_trapped`) makes the
        // same choice for the same reason. Treating user-mode hlt as a
        // protection_fault would `parkSelfFaulted` the EC into `.exited`,
        // breaking any later `suspend(this_ec, port)` call (suspend's
        // gate rejects non-{running,ready,idle_wait} targets with
        // E_INVAL — the precise failure that flaked reply_transfer_14
        // aid=3 on x86 when W1's dummy entry got dispatched and trapped
        // before the test EC's suspend syscall observed it).
        if (exception == .general_protection_fault and
            ctx.err_code == 0 and
            isUserHltAt(ctx.rip))
        {
            const ec = scheduler.currentEc() orelse
                @panic("hlt trap with no current EC");
            ctx.rip += 1; // advance past the 1-byte HLT opcode
            execution_context.parkIdleWait(ec);
            cpu.enableInterrupts();
            scheduler.run();
        }

        if (exceptionEvent(vector)) |event| {
            const ec = scheduler.currentEc() orelse
                @panic("user exception with no current EC");
            // Diag: print vector + RIP + first byte at RIP for any user fault.
            // Helps catch silent EC terminations from `unreachable` (#UD)
            // and other faults during in-Zag compiler bring-up.
            const rip_byte: u8 = if (paging_mod.resolveVaddr(
                ec.domain.ptr.addr_space_root,
                VAddr.fromInt(ctx.rip & ~@as(u64, 0xFFF)),
            )) |phys| blk: {
                const physmap_base = VAddr.fromPAddr(phys, null).addr;
                const byte_ptr: *const u8 = @ptrFromInt(physmap_base + (ctx.rip & 0xFFF));
                break :blk byte_ptr.*;
            } else 0;
            serial.print("[USR-FAULT] vec={d} rip=0x{x} byte=0x{x}\n", .{
                vector, ctx.rip, rip_byte,
            });
            switch (event) {
                .thread_fault => |subcode| port.fireThreadFault(ec, subcode, ctx.rip),
                .breakpoint => port.fireBreakpoint(ec, 0),
            }
            cpu.enableInterrupts();
            scheduler.yieldTo(null);
            // If `yieldTo` dispatched a fresh EC it would never return
            // here (`loadEcContextAndReturn` is noreturn). Reaching this
            // line means the run queue was empty — the no-route fallback
            // (`parkSelfFaulted` for thread_fault, `markReady` of the
            // resumed EC was the last work) drained `current_ec` to null.
            // We CANNOT iretq back to the kernel-stack iret frame: that
            // frame still holds the now-stale faulting user context, and
            // returning there would re-fault on the same RIP and re-enter
            // this handler with `currentEc() == null`, hitting the
            // user-exception-with-no-current-EC panic.
            //
            // Instead jump into the scheduler's main loop (noreturn). It
            // will idle (`sti+hlt`) until any IRQ delivers more work, at
            // which point it dispatches via `loadEcContextAndReturn`
            // (which resets `rsp` to the new EC's saved context) — the
            // current kernel-stack frame is abandoned, which is the same
            // discipline the preempt-driven path uses.
            if (scheduler.currentEc() == null) scheduler.run();
            return;
        }
    }

    switch (exception) {
        .double_fault => @panic("Double fault"),
        .machine_check => @panic("Machine check exception"),
        .non_maskable_interrupt => {
            // lockdep blindspot: NMI is NOT wired into sync_debug.enterIrqContext.
            // Safe today only because the sole NMI consumer (kprof_sample.onNmi)
            // is intentionally lock-free (atomic-RMW BSS log emit, MSR-only
            // counter rearm — see kprof/sample.zig).
            //
            // Before adding any lock-taking code to an NMI path:
            //   1. Wrap the NMI handler body with sync_debug.enterIrqContext()
            //      / exitIrqContext() (mirror the pattern in
            //      arch/x64/interrupts.zig dispatchInterrupt).
            //   2. Add sync_debug.resetIrqContextOnSwitch() on any NMI-driven
            //      noreturn-jmp path (mirror arch/x64/interrupts.zig).
            // Without that wiring, the IRQ-mode-mix detector misclassifies
            // NMI-context acquires as state 2 (process + IRQs disabled =
            // "lockIrqSave / safe") instead of state 1 (async-IRQ-handler
            // context), and a class taken in both NMI and plain process
            // context will deadlock without warning.
            // HPET-NMI hang watchdog: when armed, every NMI is one of
            // ours. Drive `hang_detector.tickCheck()` from here so the
            // dump still fires when the LAPIC tick + every other periodic
            // kernel-side IRQ source has stalled. Same lock-free
            // discipline as kprof_sample.onNmi (atomic loads + a single
            // raw COM1 emit on detect).
            if (hpet_watchdog.isArmed()) {
                hang_detector.tickCheck();
                return;
            }
            // Watchdog build-enabled but HPET trigger path didn't arm
            // (e.g., QEMU HPET advertises neither FSB nor IOAPIC routing
            // we can hijack). Treat any NMI as an externally-injected
            // dump request — qemu monitor `nmi` is the operator hook.
            if (hpet_watchdog.enabled) {
                hang_detector.forceDump();
                return;
            }
            if (kprof_sample.onNmi(ctx.rip, ctx.regs.rbp)) return;
            @panic("NMI");
        },
        .general_protection_fault => {
            serial.print("GPF at rip=0x{x} err=0x{x}\n", .{ ctx.rip, ctx.err_code });
            @panic("General protection fault");
        },
        .page_fault => unreachable,
        else => {
            serial.print("Exception {d} at rip=0x{x} err=0x{x}\n", .{
                vector, ctx.rip, ctx.err_code,
            });
            @panic("Unhandled kernel exception");
        },
    }
}

/// Intel SDM Vol 3A §5.7 — #PF handler. CR2 holds the faulting linear
/// address; the error code on the stack encodes the fault reason per
/// Figure 5-12.
fn pageFaultHandler(ctx: *cpu.Context) void {
    kprof.enter(.page_fault);
    defer kprof.exit(.page_fault);

    if (scheduler.currentEc()) |ec_for_trace| {
        ctx_trace.mark(ec_for_trace, .pf_handler);
    }

    const pf_err = PFErrCode.from(ctx.err_code);
    if (pf_err.rsvd_violation) {
        if (comptime pf_log.enabled) {
            pf_log.mark(scheduler.currentEc(), .RSVD_PANIC, cpu.readCr2(), @truncate(ctx.err_code));
        }
        @panic("Page tables have reserved bits set (RSVD).");
    }
    const faulting_addr = cpu.readCr2();
    if (comptime pf_log.enabled) {
        pf_log.mark(scheduler.currentEc(), .ENTER, faulting_addr, @truncate(ctx.err_code));
    }
    kprof.point(.page_fault_hw, faulting_addr);
    const ring_3 = @intFromEnum(PrivilegeLevel.ring_3);
    const from_user = (ctx.cs & ring_3) == ring_3;

    // Intercept port-IO virtual_bar faults from userspace before the
    // generic handler. A VMAR mapped via `map_mmio` to a port-IO
    // device_region intentionally has no PTEs — every CPU access faults
    // and the kernel decodes the MOV, performs the port I/O on behalf
    // of the EC, and advances RIP. Spec §[port_io_virtualization].
    if (from_user and !pf_err.present) {
        const ec = scheduler.currentEc() orelse {
            if (comptime pf_log.enabled) {
                pf_log.mark(null, .USER_NO_EC, faulting_addr, @truncate(ctx.err_code));
            }
            @panic("user page fault with no current EC");
        };
        // caller-pinned: currentEc() runs on this core; its bound
        // capability domain is alive across this PF handler.
        const domain = ec.domain.ptr;
        if (vmar.findVmarCovering(domain, VAddr.fromInt(faulting_addr))) |v| {
            const v_irq = v._gen_lock.lockIrqSave(@src());
            const is_port_io = v.map == .mmio and
                v.device != null and
                // caller-pinned: device ref under v's gen-lock.
                v.device.?.ptr.device_type == .port_io;
            v._gen_lock.unlockIrqRestore(v_irq);
            if (is_port_io) {
                emulateVirtualBar(ctx, ec, v, faulting_addr, domain);
                if (comptime pf_log.enabled) {
                    pf_log.mark(ec, .USER_PORT_IO, faulting_addr, @truncate(ctx.err_code));
                    pf_log.mark(ec, .RESUME, faulting_addr, @truncate(ctx.err_code));
                }
                return;
            }
        }
    }

    if (from_user) {
        const ec_for_diag = scheduler.currentEc();
        const vmar_label: []const u8 = if (ec_for_diag) |ec_d| blk: {
            const cov = vmar.findVmarCovering(ec_d.domain.ptr, VAddr.fromInt(faulting_addr));
            break :blk if (cov) |_| "in-vmar" else "no-vmar";
        } else "no-ec";
        // Read instruction bytes at user RIP. Walk the EC's page tables so
        // we see the correct user-mode mapping (kernel page tables don't
        // include the user code).
        var rip_bytes: [16]u8 = @splat(0);
        if (ec_for_diag) |ec_b| {
            const rip_page = VAddr.fromInt(ctx.rip & ~@as(u64, 0xFFF));
            if (paging_mod.resolveVaddr(ec_b.domain.ptr.addr_space_root, rip_page)) |phys| {
                const physmap_base = VAddr.fromPAddr(phys, null).addr;
                const off = ctx.rip & 0xFFF;
                var i: usize = 0;
                while (i < 16 and (off + i) < 0x1000) : (i += 1) {
                    const byte_ptr: *const u8 = @ptrFromInt(physmap_base + off + i);
                    rip_bytes[i] = byte_ptr.*;
                }
            }
        }
        // Read GP registers at fault — useful for backtracking which reg
        // sourced the bad pointer.
        serial.print("[USR-PF] rip=0x{x} addr=0x{x} err=0x{x} w={} x={} {s}\n", .{
            ctx.rip, faulting_addr, ctx.err_code, pf_err.is_write, pf_err.instr_fetch, vmar_label,
        });
        serial.print("[USR-PF] insn={x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2}\n", .{
            rip_bytes[0],  rip_bytes[1],  rip_bytes[2],  rip_bytes[3],
            rip_bytes[4],  rip_bytes[5],  rip_bytes[6],  rip_bytes[7],
            rip_bytes[8],  rip_bytes[9],  rip_bytes[10], rip_bytes[11],
            rip_bytes[12], rip_bytes[13], rip_bytes[14], rip_bytes[15],
        });
        serial.print("[USR-PF] rax=0x{x} rbx=0x{x} rcx=0x{x} rdx=0x{x}\n", .{
            ctx.regs.rax, ctx.regs.rbx, ctx.regs.rcx, ctx.regs.rdx,
        });
        serial.print("[USR-PF] rsi=0x{x} rdi=0x{x} rbp=0x{x} rsp=0x{x}\n", .{
            ctx.regs.rsi, ctx.regs.rdi, ctx.regs.rbp, ctx.rsp,
        });
        serial.print("[USR-PF] r8=0x{x} r9=0x{x} r10=0x{x} r11=0x{x}\n", .{
            ctx.regs.r8, ctx.regs.r9, ctx.regs.r10, ctx.regs.r11,
        });
        serial.print("[USR-PF] r12=0x{x} r13=0x{x} r14=0x{x} r15=0x{x}\n", .{
            ctx.regs.r12, ctx.regs.r13, ctx.regs.r14, ctx.regs.r15,
        });
    }
    const pf_ctx = PageFaultContext{
        .faulting_address = faulting_addr,
        .is_kernel_privilege = !from_user,
        .is_write = pf_err.is_write,
        .is_exec = pf_err.instr_fetch,
        .rip = ctx.rip,
        .user_ctx = if (from_user) ctx else null,
    };
    zag.memory.fault.handlePageFault(&pf_ctx);

    // Resume snapshot. If `handlePageFault` yielded to another EC the
    // resumed RIP is for THAT EC; if it returned to the faulter the
    // RIP should advance past the faulting instruction OR the page
    // mapping should now resolve. The smp=4 fault-loop bug shows up
    // here as RESUME with rip == previous fault rip, repeatedly.
    if (comptime pf_log.enabled) {
        pf_log.mark(scheduler.currentEc(), .RESUME, faulting_addr, @truncate(ctx.err_code));
    }
}

/// Emulate a port I/O access through a port-IO VMAR.
/// Decodes the faulting instruction, performs the port I/O, writes back
/// the result (for reads), and advances RIP past the instruction.
///
/// Spec §[port_io_virtualization]: unsupported instruction forms (8-byte
/// MOV, LOCK prefixes, IN/OUT/INS/OUTS, undecodable bytes) deliver
/// `thread_fault` with the protection sub-code. Out-of-bounds offsets
/// and other access failures deliver `memory_fault` with read/write
/// sub-codes.
fn emulateVirtualBar(
    ctx: *cpu.Context,
    ec: *ExecutionContext,
    v: *VMAR,
    faulting_addr: u64,
    domain: *CapabilityDomain,
) void {
    // Snapshot under the lock then release before any path that may
    // suspend or terminate `ec`: the fault-routing handlers may unwind
    // through the scheduler and never return here, so holding the VMAR
    // lock across them would strand the gen and deadlock any future
    // walk of the domain's vars[]. The DeviceRegion pointer is stable
    // for the kernel's lifetime once bound and `base_vaddr` is
    // immutable on the VMAR, so the snapshot is safe to use unlocked.
    const v_irq = v._gen_lock.lockIrqSave(@src());
    // caller-pinned: device ref under v's gen-lock; the DeviceRegion is
    // stable for the kernel's lifetime once bound.
    const device: *DeviceRegion = v.device.?.ptr;
    const var_base_addr = v.base_vaddr.addr;
    v._gen_lock.unlockIrqRestore(v_irq);

    // Fetch instruction bytes from user RIP via the domain's page tables.
    // x86-64 instructions are at most 15 bytes and may straddle a page
    // boundary; gather from up to two consecutive user pages.
    const rip = ctx.rip;
    const page_off = rip & 0xFFF;
    const first_page_bytes: u8 = @intCast(@min(15, 4096 - page_off));

    const rip_page = VAddr.fromInt(rip & ~@as(u64, 0xFFF));
    const phys = paging_mod.resolveVaddr(domain.addr_space_root, rip_page) orelse {
        port.fireThreadFault(ec, ThreadFaultSubcode.protection, rip);
        cpu.enableInterrupts();
        scheduler.yieldTo(null);
        // `fireThreadFault`'s no-route fallback (`parkSelfFaulted`)
        // cleared `current_ec`; if `yieldTo` couldn't dispatch fresh
        // work, returning would iretq back to the now-stale faulting
        // user RIP. Hand off to `scheduler.run()` (noreturn) — it idles
        // until an IRQ delivers more work, at which point dispatch via
        // `loadEcContextAndReturn` resets `rsp` and abandons this
        // kernel-stack frame.
        if (scheduler.currentEc() == null) scheduler.run();
        unreachable;
    };

    const physmap_base = VAddr.fromPAddr(phys, null).addr + page_off;
    const insn_ptr: [*]const u8 = @ptrFromInt(physmap_base);
    var buf: [15]u8 = undefined;
    @memcpy(buf[0..first_page_bytes], insn_ptr[0..first_page_bytes]);

    // Top up across the page boundary if the instruction may extend
    // beyond this page. If the next page isn't mapped, hand decodeBytes
    // what we have — it will report IncompleteDecode and we'll fault.
    var fetched: u8 = first_page_bytes;
    if (first_page_bytes < 15) {
        const next_page = VAddr.fromInt((rip & ~@as(u64, 0xFFF)) + 0x1000);
        if (paging_mod.resolveVaddr(domain.addr_space_root, next_page)) |next_phys| {
            const next_base = VAddr.fromPAddr(next_phys, null).addr;
            const next_ptr: [*]const u8 = @ptrFromInt(next_base);
            const need: u8 = 15 - first_page_bytes;
            @memcpy(buf[first_page_bytes..15], next_ptr[0..need]);
            fetched = 15;
        }
    }

    // Decode the instruction
    const op = mmio_decode.decodeBytes(buf[0..fetched]) catch {
        port.fireThreadFault(ec, ThreadFaultSubcode.protection, rip);
        cpu.enableInterrupts();
        scheduler.yieldTo(null);
        // See the rip_page-resolve fallback above: if the run queue is
        // empty after firing the no-route park, return into
        // `scheduler.run()` rather than letting iretq return to a stale
        // user frame.
        if (scheduler.currentEc() == null) scheduler.run();
        unreachable;
    };

    // Compute the port offset and validate bounds
    const port_offset = faulting_addr - var_base_addr;
    if (port_offset + op.size > device.access.port_io.port_count) {
        const subcode: u8 = if (op.is_write)
            MemoryFaultSubcode.invalid_write
        else
            MemoryFaultSubcode.invalid_read;
        port.fireMemoryFault(ec, subcode, faulting_addr);
        cpu.enableInterrupts();
        scheduler.yieldTo(null);
        if (scheduler.currentEc() == null) scheduler.run();
        return;
    }

    const io_port: u16 = device.access.port_io.base_port + @as(u16, @truncate(port_offset));

    if (op.is_write) {
        const value: u32 = if (op.is_immediate)
            op.value
        else
            @truncate(readContextGpr(ctx, op.reg));

        switch (op.size) {
            1 => {
                cpu.outb(@truncate(value), io_port);
                hang_detector.noteProgressOnNewline(@truncate(value));
            },
            2 => cpu.outw(@truncate(value), io_port),
            4 => cpu.outd(value, io_port),
            else => {
                port.fireThreadFault(ec, ThreadFaultSubcode.protection, rip);
                cpu.enableInterrupts();
                scheduler.yieldTo(null);
                if (scheduler.currentEc() == null) scheduler.run();
                return;
            },
        }
    } else {
        const result: u32 = switch (op.size) {
            1 => @as(u32, cpu.inb(io_port)),
            2 => @as(u32, cpu.inw(io_port)),
            4 => cpu.ind(io_port),
            else => {
                port.fireThreadFault(ec, ThreadFaultSubcode.protection, rip);
                cpu.enableInterrupts();
                scheduler.yieldTo(null);
                if (scheduler.currentEc() == null) scheduler.run();
                unreachable;
            },
        };
        writeContextGpr(ctx, op.reg, op.size, result);
    }

    ctx.rip += op.len;
}

/// Read a general-purpose register from the interrupt context by ModRM index.
/// Intel SDM Vol 2A, Table 2-2 — 64-bit ModRM.reg encoding.
fn readContextGpr(ctx: *const cpu.Context, reg: u4) u64 {
    return switch (reg) {
        0 => ctx.regs.rax,
        1 => ctx.regs.rcx,
        2 => ctx.regs.rdx,
        3 => ctx.regs.rbx,
        4 => ctx.rsp,
        5 => ctx.regs.rbp,
        6 => ctx.regs.rsi,
        7 => ctx.regs.rdi,
        8 => ctx.regs.r8,
        9 => ctx.regs.r9,
        10 => ctx.regs.r10,
        11 => ctx.regs.r11,
        12 => ctx.regs.r12,
        13 => ctx.regs.r13,
        14 => ctx.regs.r14,
        15 => ctx.regs.r15,
    };
}

/// Write a port I/O read result to a GPR in the interrupt context by ModRM
/// index. Follows x86-64 partial register write semantics (Intel SDM Vol 1,
/// §3.4.1.1): 32-bit writes zero-extend to 64 bits; 8-bit and 16-bit writes
/// preserve the upper bits of the destination register.
fn writeContextGpr(ctx: *cpu.Context, reg: u4, size: u8, value: u32) void {
    const prev = readContextGpr(ctx, reg);
    const merged: u64 = switch (size) {
        1 => (prev & ~@as(u64, 0xFF)) | @as(u64, @as(u8, @truncate(value))),
        2 => (prev & ~@as(u64, 0xFFFF)) | @as(u64, @as(u16, @truncate(value))),
        4 => @as(u64, value),
        else => unreachable,
    };
    switch (reg) {
        0 => ctx.regs.rax = merged,
        1 => ctx.regs.rcx = merged,
        2 => ctx.regs.rdx = merged,
        3 => ctx.regs.rbx = merged,
        4 => ctx.rsp = merged,
        5 => ctx.regs.rbp = merged,
        6 => ctx.regs.rsi = merged,
        7 => ctx.regs.rdi = merged,
        8 => ctx.regs.r8 = merged,
        9 => ctx.regs.r9 = merged,
        10 => ctx.regs.r10 = merged,
        11 => ctx.regs.r11 = merged,
        12 => ctx.regs.r12 = merged,
        13 => ctx.regs.r13 = merged,
        14 => ctx.regs.r14 = merged,
        15 => ctx.regs.r15 = merged,
    }
}
