const std = @import("std");
const stygia = @import("stygia");

const apic = stygia.arch.x64.apic;
const cpu = stygia.arch.x64.cpu;
const device_region = stygia.devices.device_region;
const exceptions = stygia.arch.x64.exceptions;
const fpu = stygia.sched.fpu;
const futex = stygia.sched.futex;
const gdt = stygia.arch.x64.gdt;
const idt = stygia.arch.x64.idt;
const interrupts = stygia.arch.x64.interrupts;
const kprof = stygia.kprof.trace_id;
const kprof_dump = stygia.kprof.dump;
const kprof_log = stygia.kprof.log;
const paging_mod = stygia.arch.x64.paging;
const port = stygia.sched.port;
const sched = stygia.sched.scheduler;
const timer_wheel = stygia.sched.timer;
const timers = stygia.arch.x64.timers;

const ExecutionContext = stygia.sched.execution_context.ExecutionContext;
const GateType = stygia.arch.x64.idt.GateType;
const PrivilegeLevel = stygia.arch.x64.cpu.PrivilegeLevel;
const SpinLock = stygia.utils.sync.SpinLock;

/// 16 IRQ lines (vectors 32-47) — legacy ISA IRQs remapped above the 32 exception
/// vectors reserved by the architecture.
/// Intel SDM Vol 3A, §7.2 "Exception and Interrupt Vectors", Table 7-1 — vectors
/// 0-31 are reserved for exceptions; external device interrupts start at vector 32.
const num_irq_entries = 16;

var spurious_interrupts: u64 = 0;

/// I/O APIC MMIO base virtual address. Set during ACPI parsing.
var ioapic_base: u64 = 0;
var ioapic_lock: SpinLock = .{ .class = "irq.ioapic_lock" };

/// Vector → GSI translation. `deviceIrqHandler` consults this table to
/// recover the IOAPIC pin (= the kernel-internal `irq_source` key the
/// device_region table is indexed on) from the LAPIC vector the CPU
/// delivered. Populated by `bindVectorToGsi` when an IOAPIC redirection
/// entry is programmed; unbound vectors hold `VECTOR_GSI_NONE` so a
/// stray delivery on an unprogrammed vector lands as a silent drop in
/// `findDeviceByIrqSource` instead of mis-keying into pin 0.
///
/// Sized for the 256-entry x86 vector space; entries 0-31 (architectural
/// exceptions) are unused. Reads from `deviceIrqHandler` are unsynchronized
/// monotonic loads — once `bindVectorToGsi` publishes a GSI, the binding
/// is stable for the lifetime of the IOAPIC entry, and the device IRQ that
/// observes it has by construction been programmed by that bind. Writes
/// take `ioapic_lock` so concurrent rebinds against the same vector
/// serialize against IOAPIC programming.
const VECTOR_GSI_NONE: u32 = std.math.maxInt(u32);
var vector_to_gsi: [256]u32 = [_]u32{VECTOR_GSI_NONE} ** 256;

/// Publish a vector→GSI binding for `deviceIrqHandler`. Called from the
/// IOAPIC redirection-entry programmer immediately after writing the
/// vector field of a redirection-table entry, while `ioapic_lock` is
/// already held by the programmer. The binding stays in effect until
/// the entry is masked + reprogrammed; rebinds simply overwrite the
/// slot. Out-of-range vectors are silently ignored — the call site is
/// inside the IOAPIC programmer, which already constrains vector to
/// the 32..255 device range.
pub fn bindVectorToGsi(vector: u8, gsi: u32) void {
    vector_to_gsi[vector] = gsi;
}

/// Drop a previously-published vector→GSI binding. Called from the
/// IOAPIC redirection-entry programmer when an entry is decommissioned
/// (mask + zero) so a subsequent stray delivery on the orphaned vector
/// can't index a stale GSI back into the device_region table.
pub fn unbindVector(vector: u8) void {
    vector_to_gsi[vector] = VECTOR_GSI_NONE;
}

/// Sets up IDT gates for hardware IRQs, the spurious interrupt vector, the TLB
/// shootdown IPI vector, and the scheduler timer vector.
pub fn init() void {
    const offset = exceptions.NUM_ISR_ENTRIES;
    for (offset..offset + num_irq_entries) |i| {
        idt.openInterruptGate(
            @intCast(i),
            interrupts.stubs[i],
            gdt.KERNEL_CODE_OFFSET,
            PrivilegeLevel.ring_0,
            GateType.interrupt_gate,
        );
    }

    // Intel SDM Vol 3A, §13.9 "Spurious Interrupt" — the spurious-interrupt vector
    // register (SVR) at FEE0_00F0H specifies the vector delivered when the APIC
    // generates a spurious interrupt. Default after reset is 0xFF. The handler must
    // NOT send an EOI (spurious delivery does not set ISR).
    const spurious_int_vec = @intFromEnum(interrupts.IntVecs.spurious);
    idt.openInterruptGate(
        @intCast(spurious_int_vec),
        interrupts.stubs[spurious_int_vec],
        gdt.KERNEL_CODE_OFFSET,
        PrivilegeLevel.ring_0,
        GateType.interrupt_gate,
    );
    interrupts.registerVector(
        spurious_int_vec,
        spuriousHandler,
        .external,
    );

    const tlb_vec = @intFromEnum(interrupts.IntVecs.tlb_shootdown);
    idt.openInterruptGate(
        tlb_vec,
        interrupts.stubs[tlb_vec],
        gdt.KERNEL_CODE_OFFSET,
        PrivilegeLevel.ring_0,
        GateType.interrupt_gate,
    );
    interrupts.registerVector(
        tlb_vec,
        paging_mod.tlbShootdownHandler,
        .external,
    );

    const kprof_vec = @intFromEnum(interrupts.IntVecs.kprof_dump);
    idt.openInterruptGate(
        kprof_vec,
        interrupts.stubs[kprof_vec],
        gdt.KERNEL_CODE_OFFSET,
        PrivilegeLevel.ring_0,
        GateType.interrupt_gate,
    );
    interrupts.registerVector(
        kprof_vec,
        kprofDumpHandler,
        .external,
    );

    // Lazy-FPU cross-core flush IPI vector. Sent by `cpu.fpuFlushIpi`
    // when the scheduler migrates an EC whose FP regs still live on
    // a remote core's hardware. Receiver runs `fpuFlushIpiHandler` to
    // FXSAVE the requested EC's state from this core's regs into
    // the EC's `fpu_state` buffer, then acks the mailbox.
    const fpu_flush_vec = @intFromEnum(interrupts.IntVecs.fpu_flush);
    idt.openInterruptGate(
        fpu_flush_vec,
        interrupts.stubs[fpu_flush_vec],
        gdt.KERNEL_CODE_OFFSET,
        PrivilegeLevel.ring_0,
        GateType.interrupt_gate,
    );
    interrupts.registerVector(
        fpu_flush_vec,
        fpuFlushIpiHandler,
        .external,
    );

    const sched_int_vec = @intFromEnum(interrupts.IntVecs.sched);
    idt.openInterruptGate(
        @intCast(sched_int_vec),
        interrupts.stubs[sched_int_vec],
        gdt.KERNEL_CODE_OFFSET,
        PrivilegeLevel.ring_0,
        GateType.interrupt_gate,
    );
    interrupts.registerVector(
        sched_int_vec,
        schedTimerHandler,
        .external,
    );

    // Register device IRQ handlers for vectors 32-47 (ISA IRQ lines 0-15).
    // Intel SDM Vol 3A, §7.2 — vectors 32+ are available for external interrupts.
    for (offset..offset + num_irq_entries) |i| {
        interrupts.registerVector(
            @intCast(i),
            deviceIrqHandler,
            .external,
        );
    }

    // SYSCALL/SYSRET replaces the old INT 0x80 path. The SYSCALL entry
    // point is set via MSR_LSTAR in cpu.initSyscall(); no IDT gate needed.
    // Intel SDM Vol 3A, §8.5.4 "SYSCALL and SYSENTER" — SYSCALL transfers
    // control without the IDT, using IA32_LSTAR for the entry point RIP.
}

/// Device IRQ handler — called for vectors 32-47 (ISA IRQ lines 0-15).
/// Resolves the firing vector to its bound device_region and delegates
/// to the generic `device_region.onIrq` path which masks the line, bumps
/// every domain-local copy of `field1.irq_count`, and futex-wakes
/// waiters per Spec §[device_irq].
///
/// The device_region IRQ-source table is keyed on the IOAPIC pin (GSI),
/// NOT the LAPIC vector. The IOAPIC redirection-entry programmer
/// publishes the vector→GSI binding via `bindVectorToGsi` at the same
/// time it programs the redirection entry; this handler reads it back
/// through `vector_to_gsi`. Stray deliveries on unprogrammed vectors
/// (`VECTOR_GSI_NONE`) drop silently — same shape as a spurious IRQ.
///
/// This matches the aarch64 contract (`exceptions.dispatchIrq` stores
/// `intid - 32` as the table key, the dispatch shim adds 32 back when
/// poking the GIC), keeping `dispatch.irq.maskIrq` / `unmaskIrq` /
/// `endOfInterrupt` arch-uniform: the kernel-internal key on both
/// arches is "the index into the IRQ-source table", and the shim
/// translates to native controller geometry.
fn deviceIrqHandler(ctx: *cpu.Context) void {
    const vector: u8 = @truncate(ctx.int_num);
    const gsi = vector_to_gsi[vector];
    if (gsi == VECTOR_GSI_NONE) return;
    const snapshot = device_region.findDeviceByIrqSource(gsi) orelse return;
    device_region.onIrq(snapshot);
}

/// Intel SDM Vol 3A, §13.9 — spurious interrupt handler must return without EOI
/// because the APIC does not set the ISR bit for spurious deliveries.
fn spuriousHandler(ctx: *cpu.Context) void {
    _ = ctx;
    spurious_interrupts += 1;
}

/// Kprof-dump IPI handler: park this CPU inside kprof.dump so the
/// dumping core can quiesce every other CPU before serial-dumping.
/// Never returns — parkForDump halts after dump_done is observed.
fn kprofDumpHandler(_: *cpu.Context) void {
    kprof_dump.parkForDump();
}

/// IPI handler for the lazy-FPU cross-core flush. Reads the requested
/// EC from this core's mailbox, calls into the generic FPU module
/// (which checks if this core is still the owner and FXSAVEs if so),
/// then acks the mailbox so the requester unblocks.
fn fpuFlushIpiHandler(_: *cpu.Context) void {
    const core_id: u8 = @truncate(apic.coreID());
    const slot = &cpu.fpu_flush_mailbox[core_id];
    const opaque_ptr = @atomicLoad(?*anyopaque, &slot.requested_thread, .acquire) orelse {
        slot.ackDone();
        return;
    };
    const ec: *ExecutionContext = @ptrCast(@alignCast(opaque_ptr));
    fpu.flushIpiHandler(ec);
    slot.ackDone();
}

/// LAPIC-timer preemption tick. The scheduler reads the current EC and
/// per-core state from `core_states[apic.coreID()]` directly, so the
/// vector handler just delegates.
///
/// Both LAPIC one-shot and TSC-deadline mode disarm themselves on
/// fire (Intel SDM Vol 3A §13.5.4 / §13.5.4.1), so the handler must
/// re-arm before yielding to keep round-robin alive. The same vector
/// is also used by `apic.sendSchedulerIpi` for cross-core / self
/// preempt IPIs (`enqueueOnCore`, `yield`), which is harmless: each
/// invocation just resets the next tick to `TIMESLICE_NS` from now.
fn schedTimerHandler(ctx: *cpu.Context) void {
    _ = ctx;
    kprof.enter(.sched_tick);
    defer kprof.exit(.sched_tick);

    // Drive hang_detector.tickCheck from every per-core scheduler tick.
    // The threshold-based detector here is meant for the case where SOME
    // core is still ticking but the system as a whole is wedged
    // (e.g. runner parked + children deadlocked). The HPET-NMI watchdog
    // is the all-cores-idle backstop, but QEMU's HPET doesn't advertise
    // FSB delivery so the NMI tick never fires under the dev testbed —
    // making this in-band hook the only reliable trigger. Cheap fast
    // path: 1 atomic load + 1 TSC read + 1 compare when nothing is
    // wrong. NB: the all-cores-idle path is intentionally not reached
    // from here (current_ec != null inside any tick).
    stygia.utils.hang_detector.tickCheck();

    // No periodic debug print here. The runner emits its own per-batch
    // heartbeat over COM1, and any kernel-side periodic `serial.print`
    // races against the runner's user-side port-IO trap path
    // (`emulateVirtualBar` issues `cpu.outb` directly without
    // `print_lock`), interleaving kernel bytes between userspace bytes
    // and corrupting `[runner] PASS …` lines.
    //
    // Kprof session-end gate: once any CPU's per-CPU log fills, `emit`
    // sets `terminate_requested`. The first scheduler tick that
    // observes it set kicks off the IPI-coordinated stop-the-world
    // dump and never returns. No-op when kprof is compiled out.
    if (kprof_log.terminate_requested != 0) {
        kprof_dump.end(.log_full);
    }
    timers.getPreemptionTimer().armInterruptTimer(sched.TIMESLICE_NS);
    // Drive any deadline-based wakeups for recv-with-timeout and
    // futex_wait_val/futex_wait_change. No-op when nothing has expired.
    port.expireTimedRecvWaiters();
    futex.expireTimedWaiters();
    // Drain the per-core timer-object wheel — fires onFire for every
    // entry whose deadline_ns <= now and re-arms the LAPIC against
    // whatever entry sits at the heap top after draining (no-op when
    // empty). Spec §[timer].
    timer_wheel.wheelExpireDue();
    sched.preempt();
}

/// One-shot setter for the IOAPIC MMIO base. Called from ACPI MADT parsing.
/// No-op for repeat calls (only the first IOAPIC entry is honored — multi-
/// IOAPIC platforms would need a richer API but the testbed has one).
pub fn setIoapicBase(addr: u64) void {
    if (ioapic_base == 0) ioapic_base = addr;
}

/// Program an IOAPIC redirection entry to deliver as NMI on the BSP. Used by
/// the HPET-NMI hang watchdog when FSB delivery isn't available (QEMU's
/// HPET advertises only legacy IOAPIC routing). Sets delivery_mode = 100b
/// (NMI), destination_mode = 0 (physical), polarity = 0 (active high),
/// trigger_mode = 0 (edge), mask = 0 (unmasked), vector = 0x02 (cosmetic
/// — ignored for NMI). Destination = BSP APIC ID.
///
/// 82093AA IOAPIC Datasheet §3.2.4 "I/O Redirection Table Registers".
pub fn programIoapicNmi(gsi: u32, bsp_apic_id: u32) bool {
    if (ioapic_base == 0) return false;
    const reg_lo = 0x10 + gsi * 2;
    const reg_hi = reg_lo + 1;
    // Low dword: vector | (delivery_mode << 8) | (dest_mode << 11)
    //          | (polarity << 13) | (trigger << 15) | (mask << 16)
    const dm_nmi: u32 = 0b100;
    const lo: u32 = 0x02 | (dm_nmi << 8);
    // High dword: bits 24-31 are physical destination APIC ID
    const hi: u32 = bsp_apic_id << 24;
    const irq_state = ioapic_lock.lockIrqSave(@src());
    ioapicWrite(reg_hi, hi);
    ioapicWrite(reg_lo, lo);
    ioapic_lock.unlockIrqRestore(irq_state);
    return true;
}

/// Maximum IOAPIC redirection-table entry index. The legacy ISA-era
/// IOAPIC exposes 24 entries (pins 0..23); modern chips can expose up
/// to 240 but Stygia's testbed targets the ISA layout, and out-of-range
/// `irq_line` values would write into unrelated IOAPIC registers. The
/// gate here is defensive in depth: callers should already have mapped
/// device IRQs through a vector→GSI translation that yields a sane
/// pin index.
const IOAPIC_MAX_PIN: u32 = 240;

/// Mask an IRQ line by setting bit 16 (interrupt mask) of the low dword of
/// the I/O APIC redirection table entry for the given IRQ. `irq_line` is
/// the IOAPIC pin / GSI (NOT the LAPIC vector — the device_region table
/// is keyed on the GSI, and `deviceIrqHandler` translates vector→GSI
/// before dispatching `maskIrq`).
/// 82093AA I/O APIC Datasheet, §3.2.4 "I/O Redirection Table Registers" —
/// bit 16 of the low dword is the Interrupt Mask bit; 1 = masked.
/// Redirection table entry n occupies registers 0x10+2n (low) and 0x11+2n (high).
pub fn maskIrq(irq_line: u32) void {
    if (ioapic_base == 0) return;
    if (irq_line >= IOAPIC_MAX_PIN) return;
    const reg = @as(u32, 0x10) + irq_line * 2;
    const irq_state = ioapic_lock.lockIrqSave(@src());
    const val = ioapicRead(reg);
    ioapicWrite(reg, val | (1 << 16));
    ioapic_lock.unlockIrqRestore(irq_state);
}

/// Unmask an IRQ line by clearing bit 16 (interrupt mask) of the low dword of
/// the I/O APIC redirection table entry for the given IRQ. `irq_line`
/// is the IOAPIC pin / GSI; see `maskIrq` for the vector→GSI contract.
/// 82093AA I/O APIC Datasheet, §3.2.4 "I/O Redirection Table Registers" —
/// bit 16 of the low dword is the Interrupt Mask bit; 0 = unmasked.
pub fn unmaskIrq(irq_line: u32) void {
    if (ioapic_base == 0) return;
    if (irq_line >= IOAPIC_MAX_PIN) return;
    const reg = @as(u32, 0x10) + irq_line * 2;
    const irq_state = ioapic_lock.lockIrqSave(@src());
    const val = ioapicRead(reg);
    ioapicWrite(reg, val & ~@as(u32, 1 << 16));
    ioapic_lock.unlockIrqRestore(irq_state);
}

/// Read a 32-bit register from the I/O APIC via the indirect MMIO interface.
/// 82093AA I/O APIC Datasheet, §3.1 "I/O APIC Registers" — IOREGSEL at
/// base+0x00 selects the register index; IOWIN at base+0x10 is the data window.
fn ioapicRead(reg: u32) u32 {
    const sel: *volatile u32 = @ptrFromInt(ioapic_base);
    const win: *const volatile u32 = @ptrFromInt(ioapic_base + 0x10);
    sel.* = reg;
    return win.*;
}

/// Write a 32-bit register to the I/O APIC via the indirect MMIO interface.
/// 82093AA I/O APIC Datasheet, §3.1 "I/O APIC Registers" — IOREGSEL at
/// base+0x00 selects the register index; IOWIN at base+0x10 is the data window.
fn ioapicWrite(reg: u32, val: u32) void {
    const sel: *volatile u32 = @ptrFromInt(ioapic_base);
    const win: *volatile u32 = @ptrFromInt(ioapic_base + 0x10);
    sel.* = reg;
    win.* = val;
}
