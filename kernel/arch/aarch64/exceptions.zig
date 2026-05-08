//! AArch64 exception vector table and ESR_EL1 decoding.
//!
//! ARM exceptions use a vector table pointed to by VBAR_EL1. The table has
//! 16 entries (4 groups x 4 exception types), each 0x80 bytes apart.
//! This replaces x86's IDT entirely.
//!
//! Vector table layout (ARM ARM D1.10.2, Table D1-7):
//!   Offset  Source              Type
//!   0x000   Current EL, SP0     Synchronous
//!   0x080   Current EL, SP0     IRQ
//!   0x100   Current EL, SP0     FIQ
//!   0x180   Current EL, SP0     SError
//!   0x200   Current EL, SPx     Synchronous
//!   0x280   Current EL, SPx     IRQ
//!   0x300   Current EL, SPx     FIQ
//!   0x380   Current EL, SPx     SError
//!   0x400   Lower EL, AArch64   Synchronous  <- syscalls, page faults from EL0
//!   0x480   Lower EL, AArch64   IRQ          <- device interrupts from EL0
//!   0x500   Lower EL, AArch64   FIQ
//!   0x580   Lower EL, AArch64   SError
//!   0x600   Lower EL, AArch32   Synchronous  (not used -- we don't run AArch32)
//!   ...
//!
//! ESR_EL1 (Exception Syndrome Register) decoding -- ARM ARM D13.2.37:
//!   Bits [31:26] = EC (Exception Class):
//!     0x15 = SVC from AArch64 (syscall)
//!     0x20 = Instruction Abort from lower EL
//!     0x21 = Instruction Abort from same EL
//!     0x24 = Data Abort from lower EL (page fault)
//!     0x25 = Data Abort from same EL
//!     0x00 = Unknown reason
//!
//!   For Data/Instruction Aborts, bits [5:0] = DFSC/IFSC (Fault Status Code):
//!     0b0001xx = Translation fault (level 0-3)
//!     0b0010xx = Access flag fault (level 0-3)
//!     0b0011xx = Permission fault (level 0-3)
//!
//! FAR_EL1 holds the faulting virtual address (equivalent of x86 CR2).
//!
//! References:
//! - ARM ARM D1.10: Exception vectors
//! - ARM ARM D13.2.37: ESR_EL1
//! - ARM ARM D13.2.40: FAR_EL1

const zag = @import("zag");

const cpu = zag.arch.aarch64.cpu;
const device_region = zag.devices.device_region;
const fpu = zag.sched.fpu;
const futex = zag.sched.futex;
const gic = zag.arch.aarch64.gic;
const interrupts = zag.arch.aarch64.interrupts;
const kprof = zag.kprof.trace_id;
const kprof_dump = zag.kprof.dump;
const pmu = zag.arch.aarch64.pmu;
const port = zag.sched.port;
const scheduler = zag.sched.scheduler;
const serial = zag.arch.aarch64.serial;
const sync_debug = zag.utils.sync.debug;
const syscall_dispatch = zag.syscall.dispatch;
const timer_wheel = zag.sched.timer;
const timers = zag.arch.aarch64.timers;
const vmar = zag.memory.vmar;

const VAddr = zag.memory.address.VAddr;

const ArchCpuContext = zag.arch.aarch64.interrupts.ArchCpuContext;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const PageFaultContext = zag.arch.aarch64.interrupts.PageFaultContext;

/// ARM ARM D13.2.37 -- ESR_EL1 Exception Class field, bits [31:26].
/// Identifies the reason for the exception that was taken to EL1.
const ExceptionClass = enum(u6) {
    unknown = 0x00,
    wf_trapped = 0x01,
    sve_simd_fp_access = 0x07, // ARM ARM D13.2.37 — Access to FP/Advanced SIMD/SVE
    svc_aarch64 = 0x15,
    instruction_abort_lower_el = 0x20,
    instruction_abort_same_el = 0x21,
    pc_alignment = 0x22,
    data_abort_lower_el = 0x24,
    data_abort_same_el = 0x25,
    sp_alignment = 0x26,
    serror = 0x2f,
    breakpoint_lower_el = 0x30,
    breakpoint_same_el = 0x31,
    software_step_lower_el = 0x32,
    software_step_same_el = 0x33,
    watchpoint_lower_el = 0x34,
    watchpoint_same_el = 0x35,
    brk_instruction = 0x3c,
    _,
};

/// Extract the Exception Class from ESR_EL1 (bits [31:26]).
/// ARM ARM D13.2.37.
fn extractEc(esr: u64) ExceptionClass {
    return @enumFromInt(@as(u6, @truncate(esr >> 26)));
}

/// ARM ARM D13.2.37 -- For Data Aborts, bit 6 (WnR) indicates whether
/// the fault was caused by a write (1) or a read (0).
fn isWriteFault(esr: u64) bool {
    return (esr >> 6) & 1 == 1;
}

/// Stable sub-code values delivered alongside a `thread_fault` event
/// (spec §[event_type] line 1841: arithmetic / illegal_instruction /
/// alignment / stack_overflow). Numeric values are an arch contract
/// shared with userspace fault handlers; the spec leaves the mapping
/// to the implementation, so these are the kernel-internal canonical
/// encodings.
const ThreadFaultSubcode = enum(u8) {
    illegal_instruction = 0,
    alignment_fault = 1,
    protection_fault = 2,
    arithmetic = 3,
    stack_overflow = 4,
};

/// Sub-code delivered alongside a `breakpoint` event (spec §[event_type]
/// line 1842: software or hardware breakpoint trap).
const BreakpointSubcode = enum(u8) {
    software = 0,
    hardware = 1,
};

// ── Exception Vector Table ──────────────────────────────────────────────
//
// ARM ARM D1.10.2, Table D1-7: The vector table must be 2048-byte aligned.
// Each entry is 0x80 (128) bytes, containing actual code (not pointers).
// The hardware jumps directly to VBAR_EL1 + offset on exception.
//
// Each 0x80 entry has room for 32 instructions. The entry saves x0 and x30
// to the stack, loads the handler address into x0, and branches to a shared
// trampoline (exceptionTrampoline) that completes the register save, calls
// the handler, restores all registers, and executes ERET.
//
// Register save order matches ArchCpuContext layout:
//   x0-x30 (31 regs = 248 bytes), sp_el0 (8), elr_el1 (8), spsr_el1 (8)
//   Total: 272 bytes = 0x110

/// The exception vector table -- a single naked function whose code is laid
/// out as 16 entries of 0x80 bytes each. Each entry saves x0/x30, loads the
/// handler address, and branches to the shared trampoline.
///
/// ARM ARM D1.10.2, Table D1-7.
fn exceptionVectorTable() align(2048) callconv(.naked) void {
    // 0x000: Current EL SP0, Synchronous.
    //
    // This vector fires when an exception is taken at EL1 while
    // SPSel=0, i.e. the executing context was EL1t (kernel code
    // running on SP_EL0 rather than SP_EL1). Kernel threads created
    // by `vcpu.create` run at EL1t so their per-thread stack can be
    // restored via the normal SP_EL0 slot in ArchCpuContext — which
    // means their exceptions land here rather than at 0x200. Route
    // this to the same synchronous handler as Current EL SPx.
    asm volatile (
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[sync_current]
        \\add x0, x0, :lo12:%[sync_current]
        \\b %[trampoline]

        // 0x080: Current EL SP0, IRQ — kernel-thread IRQ delivery.
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[irq_current]
        \\add x0, x0, :lo12:%[irq_current]
        \\b %[trampoline]

        // 0x100: Current EL SP0, FIQ
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[unexpected]
        \\add x0, x0, :lo12:%[unexpected]
        \\b %[trampoline]

        // 0x180: Current EL SP0, SError
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[unexpected]
        \\add x0, x0, :lo12:%[unexpected]
        \\b %[trampoline]

        // 0x200: Current EL SPx, Synchronous (kernel faults)
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[sync_current]
        \\add x0, x0, :lo12:%[sync_current]
        \\b %[trampoline]

        // 0x280: Current EL SPx, IRQ (kernel IRQ)
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[irq_current]
        \\add x0, x0, :lo12:%[irq_current]
        \\b %[trampoline]

        // 0x300: Current EL SPx, FIQ
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[unexpected]
        \\add x0, x0, :lo12:%[unexpected]
        \\b %[trampoline]

        // 0x380: Current EL SPx, SError
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[unexpected]
        \\add x0, x0, :lo12:%[unexpected]
        \\b %[trampoline]

        // 0x400: Lower EL AArch64, Synchronous (syscalls, page faults)
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[sync_lower]
        \\add x0, x0, :lo12:%[sync_lower]
        \\b %[trampoline]

        // 0x480: Lower EL AArch64, IRQ (device interrupts from userspace)
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[irq_lower]
        \\add x0, x0, :lo12:%[irq_lower]
        \\b %[trampoline]

        // 0x500: Lower EL AArch64, FIQ
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[unexpected]
        \\add x0, x0, :lo12:%[unexpected]
        \\b %[trampoline]

        // 0x580: Lower EL AArch64, SError
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[unexpected]
        \\add x0, x0, :lo12:%[unexpected]
        \\b %[trampoline]

        // 0x600: Lower EL AArch32, Synchronous (not supported)
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[unexpected]
        \\add x0, x0, :lo12:%[unexpected]
        \\b %[trampoline]

        // 0x680: Lower EL AArch32, IRQ
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[unexpected]
        \\add x0, x0, :lo12:%[unexpected]
        \\b %[trampoline]

        // 0x700: Lower EL AArch32, FIQ
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[unexpected]
        \\add x0, x0, :lo12:%[unexpected]
        \\b %[trampoline]

        // 0x780: Lower EL AArch32, SError
        \\.balign 0x80
        \\stp x0, x30, [sp, #-16]!
        \\adrp x0, %[unexpected]
        \\add x0, x0, :lo12:%[unexpected]
        \\b %[trampoline]
        :
        : [trampoline] "S" (&exceptionTrampoline),
          [unexpected] "S" (&handleUnexpected),
          [sync_current] "S" (&handleSyncCurrentEl),
          [irq_current] "S" (&handleIrqCurrentEl),
          [sync_lower] "S" (&handleSyncLowerEl),
          [irq_lower] "S" (&handleIrqLowerEl),
    );
}

/// Shared trampoline called from each vector entry.
///
/// Entry contract:
///   - x0 = address of the Zig handler function to call
///   - x30 and original x0 are saved at [sp] (pushed by the vector stub)
///   - sp points to the pre-push stack minus 16 bytes
///
/// This function completes the full ArchCpuContext save, calls the handler
/// with a pointer to the context, then restores all registers and ERETs.
fn exceptionTrampoline() callconv(.naked) void {
    asm volatile (
    // x0 = handler address, [sp] = {saved_x0, saved_x30}
    // Move handler address to x30 (we'll restore the real x30 later).
        \\mov x30, x0

        // Restore original x0 from the vector stub's push.
        // The vector stub did: stp x0, x30, [sp, #-16]!
        // So [sp, #0] = original x0, [sp, #8] = original x30.
        \\ldr x0, [sp, #0]

        // Allocate full ArchCpuContext frame (272 bytes) below the 16-byte
        // save area. We adjust sp down by 272 and will store registers there.
        // After this: sp points to ArchCpuContext base.
        // The 16-byte save area is at sp + 272.
        \\sub sp, sp, #272

        // Save x0-x29 via stp pairs into the ArchCpuContext.
        \\stp x0, x1, [sp, #0]
        \\stp x2, x3, [sp, #16]
        \\stp x4, x5, [sp, #32]
        \\stp x6, x7, [sp, #48]
        \\stp x8, x9, [sp, #64]
        \\stp x10, x11, [sp, #80]
        \\stp x12, x13, [sp, #96]
        \\stp x14, x15, [sp, #112]
        \\stp x16, x17, [sp, #128]
        \\stp x18, x19, [sp, #144]
        \\stp x20, x21, [sp, #160]
        \\stp x22, x23, [sp, #176]
        \\stp x24, x25, [sp, #192]
        \\stp x26, x27, [sp, #208]
        \\stp x28, x29, [sp, #224]

        // Restore original x30 from the vector stub's save area (now at sp + 272 + 8).
        \\ldr x10, [sp, #280]
        \\str x10, [sp, #240]

        // Save SP_EL0 at offset 248 (ARM ARM D1.10).
        \\mrs x10, sp_el0
        \\str x10, [sp, #248]

        // Save ELR_EL1 at offset 256, SPSR_EL1 at offset 264.
        // ARM ARM D13.2.36 (ELR_EL1), D13.2.127 (SPSR_EL1).
        \\mrs x10, elr_el1
        \\mrs x11, spsr_el1
        \\stp x10, x11, [sp, #256]

        // Call the handler: x0 = pointer to ArchCpuContext, x30 = handler address.
        \\mov x0, sp
        \\blr x30

        // Restore ELR_EL1 and SPSR_EL1 from the context.
        \\ldp x10, x11, [sp, #256]
        \\msr elr_el1, x10
        \\msr spsr_el1, x11

        // Restore SP_EL0.
        \\ldr x10, [sp, #248]
        \\msr sp_el0, x10

        // Restore x30 from offset 240.
        \\ldr x30, [sp, #240]

        // Restore x0-x29.
        \\ldp x28, x29, [sp, #224]
        \\ldp x26, x27, [sp, #208]
        \\ldp x24, x25, [sp, #192]
        \\ldp x22, x23, [sp, #176]
        \\ldp x20, x21, [sp, #160]
        \\ldp x18, x19, [sp, #144]
        \\ldp x16, x17, [sp, #128]
        \\ldp x14, x15, [sp, #112]
        \\ldp x12, x13, [sp, #96]
        \\ldp x10, x11, [sp, #80]
        \\ldp x8, x9, [sp, #64]
        \\ldp x6, x7, [sp, #48]
        \\ldp x4, x5, [sp, #32]
        \\ldp x2, x3, [sp, #16]
        \\ldp x0, x1, [sp, #0]

        // Deallocate ArchCpuContext frame (272) + vector stub save area (16).
        // ARM ARM D1.10.1: ERET restores PC from ELR_EL1, PSTATE from SPSR_EL1.
        \\add sp, sp, #288
        \\eret
    );
}

/// Write VBAR_EL1 to install the exception vector table.
/// ARM ARM D13.2.143: VBAR_EL1 holds the base address of the EL1
/// exception vector table. The address must be 2048-byte aligned
/// (bits [10:0] are RES0).
pub fn install() void {
    const table_addr = @intFromPtr(&exceptionVectorTable);
    asm volatile ("msr vbar_el1, %[addr]"
        :
        : [addr] "r" (table_addr),
    );
    // ISB ensures the new VBAR_EL1 is visible before the next exception.
    asm volatile ("isb");
}

// ── Exception Handlers ──────────────────────────────────────────────────

/// Read ESR_EL1 -- Exception Syndrome Register.
/// ARM ARM D13.2.37.
fn readEsrEl1() u64 {
    var val: u64 = undefined;
    asm volatile ("mrs %[val], esr_el1"
        : [val] "=r" (val),
    );
    return val;
}

/// Read FAR_EL1 -- Fault Address Register.
/// ARM ARM D13.2.40: holds the faulting virtual address for Data Aborts,
/// Instruction Aborts, PC alignment faults, and watchpoint exceptions.
fn readFarEl1() u64 {
    var val: u64 = undefined;
    asm volatile ("mrs %[val], far_el1"
        : [val] "=r" (val),
    );
    return val;
}

/// Handler for synchronous exceptions from Lower EL (EL0 userspace).
/// ARM ARM D1.10.2, offset 0x400.
///
/// Dispatches based on ESR_EL1 Exception Class:
///   EC=0x15 (SVC64): syscall -- dispatch to syscall handler.
///   EC=0x24 (Data Abort from lower EL): page fault -- dispatch to fault handler.
///   EC=0x20 (Instruction Abort from lower EL): page fault -- dispatch to fault handler.
///   Others: route via `port.fireThreadFault` / `port.fireBreakpoint`.
/// Intercept a data-abort that hit a userspace port-IO VMAR (no PTEs
/// installed → every access faults) and forward the access to the
/// underlying port-IO device. Returns `true` when the fault was
/// handled; the caller skips the generic page-fault router and ERETs.
///
/// The data abort syndrome (ESR_EL1.ISS) provides:
///   ISS[24]   = ISV (instruction syndrome valid) — required for decode
///   ISS[23:22] = SAS (size: 0=byte, 1=hword, 2=word, 3=dword)
///   ISS[20:16] = SRT (Xt register holding the value, for stores)
///   ISS[6]    = WnR (write=1)
/// ARM ARM DDI 0487 §D13.2.37 ESR_EL1 (Data Abort).
///
/// On aarch64 the platform has no real port-IO bus; we route the
/// emulated access into the kernel's PL011 driver when the device's
/// declared base_port matches COM1 (0x3F8). This is the minimal
/// surface needed to land the test runner's `[runner] starting`
/// banner — full I/O port emulation will replace this when a generic
/// in-kernel I/O bus arrives.
fn interceptPortIoFault(ctx: *ArchCpuContext, esr: u64) bool {
    const ec_ptr = scheduler.currentEc() orelse return false;
    // caller-pinned: `ec_ptr` is the running EC of this core (we are mid-
    // synchronous-trap from it), so its domain SlabRef is live for the
    // duration of this handler. Mirrors arch/x64/interrupts.zig switchTo.
    const domain = ec_ptr.domain.ptr;
    const fault_va = VAddr.fromInt(readFarEl1());

    const v = vmar.findVmarCovering(domain, fault_va) orelse return false;

    const v_irq = v._gen_lock.lockIrqSave(@src());
    const is_port_io = v.map == .mmio and v.device != null and
        v.device.?.ptr.device_type == .port_io;
    v._gen_lock.unlockIrqRestore(v_irq);
    if (!is_port_io) return false;

    const iss: u32 = @truncate(esr & 0x1FFFFFF);
    const isv = (iss >> 24) & 1;

    var srt: u5 = 0;
    var sas: u32 = 0;
    var wnr: u32 = 0;

    if (isv != 0) {
        wnr = (iss >> 6) & 1;
        sas = (iss >> 22) & 0b11;
        srt = @truncate((iss >> 16) & 0x1F);
    } else {
        // QEMU TCG does not populate ISV for software-generated data
        // aborts. Decode the faulting instruction by hand. The runner's
        // serial output is a chain of `strb wN, [xM]` (STR (immediate
        // unsigned offset), 8-bit). DDI 0487 §C6.2.300 STRB (immediate)
        // unsigned offset: bits [31:22]=0011_1001_00, bits [21:10]=imm12,
        // bits [9:5]=Rn, bits [4:0]=Rt.
        const insn_ptr: *const u32 = @ptrFromInt(ctx.elr_el1);
        const insn = insn_ptr.*;
        const top10 = (insn >> 22) & 0x3FF;
        if (top10 != 0b00_1110_0100) return false; // not strb-imm-uoff
        wnr = 1;
        sas = 0; // byte
        srt = @truncate(insn & 0x1F);
    }

    if (wnr == 0) return false; // reads not yet implemented

    // Read the source register's value. AAPCS64 packs 31 GP regs as
    // x0..x30 in our `Registers` extern struct in declaration order.
    const regs_ptr: [*]const u64 = @ptrCast(&ctx.regs);
    const value: u64 = if (srt < 31) regs_ptr[srt] else 0;

    // Compute the offset within the port range. PL011 forwarding only
    // looks at the low byte of `value`; multi-byte stores get split.
    const dev = v.device.?.ptr;
    const base_port = dev.access.port_io.base_port;
    const port_offset_u64 = fault_va.addr - v.base_vaddr.addr;
    const port_offset: u16 = @truncate(port_offset_u64);
    const io_port: u16 = base_port + port_offset;

    // Width per SAS (ARM ARM §D13.2.37 SAS table).
    const width: u8 = switch (sas) {
        0 => 1,
        1 => 2,
        2 => 4,
        else => 8,
    };

    // Forward COM1 byte writes (port 0x3F8 + tx-data offset 0) into the
    // PL011 driver. Other ports / widths are currently dropped on the
    // floor — sufficient for runner banner output. The PL011 register
    // map differs from the 8250 (COM1), so even byte writes to UART
    // control/IER/etc. ports must NOT be forwarded blindly.
    if (io_port == 0x3F8 and width == 1) {
        const byte_buf = [_]u8{@as(u8, @truncate(value))};
        serial.printRaw(byte_buf[0..1]);
    }

    // Advance ELR_EL1 past the faulting instruction. AArch64 fixed-
    // length instructions are 4 bytes.
    ctx.elr_el1 += 4;
    return true;
}

fn handleSyncLowerEl(ctx: *ArchCpuContext) callconv(.c) void {
    kprof.enter(.exception);
    defer kprof.exit(.exception);

    const esr = readEsrEl1();
    const ec = extractEc(esr);

    switch (ec) {
        // Lazy-FPU trap. CPACR_EL1.FPEN was clamped to 0b01 (trap EL0)
        // by switchTo when this EC last got dispatched (because it
        // wasn't the last FPU owner on this core). Userspace's first
        // FP/SIMD instruction trapped here — swap state and return so
        // the instruction re-executes.
        .sve_simd_fp_access => {
            const ec_ptr = scheduler.currentEc() orelse
                @panic("FP/SIMD trap with no current EC");
            fpu.handleTrap(ec_ptr);
            return;
        },

        .svc_aarch64 => {
            // Spec §[syscall_abi] aarch64 ABI:
            //   - syscall_word at vreg 0 = `[sp_el0 + 0]` (user stack).
            //   - args[0..31] map to vregs 1..31 = x0..x30. Registers
            //     is an extern struct of 31 u64s declared in x0..x30
            //     order so we point the slice straight at it.
            //   - return: i64 → x0 (vreg 1).
            const regs_ptr: [*]const u64 = @ptrCast(&ctx.regs);
            const syscall_word: u64 = @as(*const u64, @ptrFromInt(ctx.sp_el0)).*;
            const caller = scheduler.currentEc() orelse
                @panic("syscall with no current EC");
            const ret = syscall_dispatch.dispatch(caller, syscall_word, regs_ptr[0..31]);

            // Only commit the syscall return into the saved frame if the
            // dispatched handler did NOT park `caller`. A handler that
            // suspends (recv / suspend / futex_wait / fault) clears this
            // core's `current_ec`; from that moment on `caller.ctx.regs.x0`
            // is the wake-side delivery slot — `propagateClosedTo*`,
            // `expireTimedRecvWaiters`, etc. running on a remote core
            // write E_CLOSED / E_TIMEOUT there directly. Unconditionally
            // assigning `ret` (always 0 on the suspend path) would race
            // with that remote write and clobber the real wake value
            // back to 0.
            const core: u8 = @truncate(gic.coreID());
            if (scheduler.coreCurrentIs(core, caller)) {
                ctx.regs.x0 = @bitCast(ret);
            }

            // Spec §[syscall_abi]: vreg 0 (`[user_sp + 0]`) carries the
            // recv-success syscall return word — `port.deliverEvent`
            // stages it in `pending_event_word` so the resume path can
            // flush it once TTBR0 references the receiver's address
            // space. The synchronous recv path (caller dequeued a
            // queued sender without blocking) returns through this tail
            // still in the caller's TTBR0, so flush here. Spec
            // §[event_state] vreg 14 = the suspended EC's saved PC; on
            // aarch64 vreg 14 is GPR-backed at x13 — write it into the
            // caller's saved frame so ERET surfaces it. Mirrors
            // arch/x64/interrupts.zig syscallDispatch.
            if (caller.pending_event_word_valid and
                scheduler.coreCurrentIs(core, caller))
            {
                interrupts.writeUserSyscallWord(ctx, caller.pending_event_word);
                caller.pending_event_word = 0;
                caller.pending_event_word_valid = false;

                if (caller.pending_event_rip_valid) {
                    interrupts.writeUserVreg14(ctx, caller.pending_event_rip);
                    caller.pending_event_rip = 0;
                    caller.pending_event_rip_valid = false;
                }
            }

            // Mirrors arch/x64/interrupts.zig syscallDispatch tail. If
            // the dispatched handler suspended `caller` (recv / suspend
            // / futex_wait), `current_ec` was cleared on this core. The
            // exception trampoline would otherwise ERET back to the
            // now-parked user EC; drive the scheduler instead so the
            // next ready EC takes over (or we idle).
            if (scheduler.coreIsIdle(core)) {
                scheduler.run();
            }
        },

        .data_abort_lower_el => {
            // Intercept port-IO virtual_bar faults from userspace before
            // the generic handler routes them through the vmar
            // page-fault dispatch (whose port_io decoder is currently
            // a stub on aarch64). Spec §[port_io_virtualization].
            // Mirrors the arch.x64.exceptions pageFaultHandler shortcut.
            if (interceptPortIoFault(ctx, esr)) return;

            const far = readFarEl1();
            kprof.point(.page_fault_hw, far);
            const pf_ctx = PageFaultContext{
                .faulting_address = far,
                .is_kernel_privilege = false,
                .is_write = isWriteFault(esr),
                .is_exec = false,
                .rip = ctx.elr_el1,
                .user_ctx = ctx,
            };
            zag.memory.fault.handlePageFault(&pf_ctx);
        },

        .instruction_abort_lower_el => {
            const far = readFarEl1();
            kprof.point(.page_fault_hw, far);
            const pf_ctx = PageFaultContext{
                .faulting_address = far,
                .is_kernel_privilege = false,
                .is_write = false,
                .is_exec = true,
                .rip = ctx.elr_el1,
                .user_ctx = ctx,
            };
            zag.memory.fault.handlePageFault(&pf_ctx);
        },

        .pc_alignment => {
            deliverThreadFault(.alignment_fault, readFarEl1());
        },

        .sp_alignment => {
            deliverThreadFault(.alignment_fault, ctx.sp_el0);
        },

        .breakpoint_lower_el => {
            deliverBreakpoint(.hardware);
        },

        .brk_instruction => {
            deliverBreakpoint(.software);
        },

        .software_step_lower_el, .watchpoint_lower_el => {
            // Single-step / watchpoint from userspace: resume silently.
            return;
        },

        .wf_trapped => {
            // EL0 wfi / wfe / wfit / wfet trap. SCTLR_EL1.{nTWI,nTWE}
            // remain at the reset value (0) so wait-for-event/interrupt
            // instructions issued at EL0 trap to EL1 with EC=0x01.
            // ARM ARM D13.2.118 (SCTLR_EL1) and D13.2.37 (ESR_EL1).
            //
            // Park the EC in the .idle_wait state so it stops consuming
            // CPU but stays alive and suspendable. Treating wfi as a
            // protection_fault would `parkSelfFaulted` the EC into
            // `.exited`, breaking any later `suspend(this_ec, port)`
            // call (suspend's gate rejects non-{running,ready,idle_wait}
            // targets with E_INVAL — the precise failure that flaked
            // reply_transfer_14 on Pi 5 KVM). Permitting native EL0 wfi
            // (SCTLR.nTWI=1) was the prior attempt; it left dummies
            // executing wfi forever in EL0 and the destroy walk's UAF
            // race against an actively-executing EC produced a hang
            // around test ~144 (batch 36..40).
            //
            // The .idle_wait path: advance ELR past the wait instruction
            // (so resume from suspend / re-dispatch lands at `b 1b` and
            // not on another immediate wfi-trap), park as .idle_wait
            // (off every queue, suspendOnPort treats it like .ready),
            // then dispatch whatever else this core has.
            ctx.elr_el1 += 4;
            const ec_ptr = scheduler.currentEc() orelse
                @panic("wfi trap with no current EC");
            zag.sched.execution_context.parkIdleWait(ec_ptr);
            cpu.enableInterrupts();
            scheduler.run();
        },

        .unknown => {
            // ARM ARM D13.2.37: EC=0x00 is taken for truly unallocated
            // instruction encodings, which includes `udf` (permanently-
            // undefined) and other UNDEFINED encodings that ARM treats
            // as an undefined-instruction exception. This is the direct
            // aarch64 analogue of x86 #UD (invalid opcode), so report
            // it as `illegal_instruction` per spec §[event_type].
            deliverThreadFault(.illegal_instruction, ctx.elr_el1);
        },

        else => {
            deliverThreadFault(.protection_fault, ctx.elr_el1);
        },
    }
}

/// Handler for IRQ from Lower EL (EL0 userspace).
/// ARM ARM D1.10.2, offset 0x480.
///
/// Acknowledges the interrupt via GIC (IHI 0069H, Section 12.11.1:
/// ICC_IAR1_EL1), dispatches to the registered device handler, and
/// signals end-of-interrupt (ICC_EOIR1_EL1).
fn handleIrqLowerEl(ctx: *ArchCpuContext) callconv(.c) void {
    kprof.enter(.irq);
    defer kprof.exit(.irq);

    // lockdep: hardware took the IRQ vector with PSTATE.I masked
    // (ARM ARM D1.10.4 — async exceptions auto-mask on entry), so any
    // lock acquired beneath here is in async-IRQ-handler context. The
    // synchronous-exception siblings (handleSyncLowerEl / handleSyncCurrentEl)
    // intentionally don't enter this state — they run on top of whatever
    // IRQ discipline the interrupted code chose.
    sync_debug.enterIrqContext();
    defer sync_debug.exitIrqContext();

    const intid = gic.acknowledgeInterrupt();

    // INTIDs 1020-1023 are all spurious / reserved (IHI 0069H §2.2.1,
    // IHI 0048B §2.2.1). `isSpurious` covers GICv3 (1023), the GICv2
    // non-aliased IAR (1023) and the GICv2 aliased AIAR (1022) cases.
    // No EOI needed for spurious interrupts.
    if (gic.isSpurious(intid)) return;

    // For level-sensitive timer PPIs (CNTV/CNTP, INTID 27/30), the GIC
    // line stays asserted as long as ISTATUS=1. Issuing EOI without
    // first masking the timer (IMASK=1) causes the GIC to immediately
    // re-mark the interrupt as pending, which then fires the moment the
    // CPU's I-mask drops on ERET — robbing the next dispatched EC of
    // its full timeslice. ARM ARM D11.2.4 + D13.8.20/D13.8.11 + IHI
    // 0048B §3.2 (level-sensitive PPI delivery).
    silenceTimerLineIfFiring(intid);

    // EOI must be issued BEFORE dispatchIrq because the timer / scheduler
    // IPI paths can call `scheduler.switchTo`, which is `noreturn` and
    // ERETs to a different thread. Anything queued after dispatchIrq is
    // unreachable on a context switch, leaving the interrupt permanently
    // in the active state and masking every subsequent delivery of that
    // same priority (IHI 0069H §4.6: an active interrupt blocks pending).
    gic.endOfInterrupt(intid);
    dispatchIrq(intid, ctx, .user);
}

/// Mask CNTP/CNTV at the source if their ISTATUS is asserted. Called
/// before EOI so the level-sensitive PPI line de-asserts at the GIC
/// before EOI clears the active bit — preventing an immediate re-pend
/// that would steal the next EC's timeslice. The matching unmask
/// (IMASK=0) is performed by `armInterruptTimer` writing CNTV_CTL=0x1
/// in the dispatch case 27,30 path.
fn silenceTimerLineIfFiring(intid: u32) void {
    if (intid != 27 and intid != 30) return;
    var cntp_ctl: u64 = undefined;
    var cntv_ctl: u64 = undefined;
    asm volatile ("mrs %[v], cntp_ctl_el0"
        : [v] "=r" (cntp_ctl),
    );
    asm volatile ("mrs %[v], cntv_ctl_el0"
        : [v] "=r" (cntv_ctl),
    );
    if ((cntp_ctl & 0x4) != 0) {
        asm volatile ("msr cntp_ctl_el0, %[val]"
            :
            : [val] "r" (@as(u64, 0x3)), // ENABLE=1, IMASK=1
        );
    }
    if ((cntv_ctl & 0x4) != 0) {
        asm volatile ("msr cntv_ctl_el0, %[val]"
            :
            : [val] "r" (@as(u64, 0x3)), // ENABLE=1, IMASK=1
        );
    }
}

/// Handler for synchronous exceptions from Current EL (kernel-mode).
/// ARM ARM D1.10.2, offset 0x200.
///
/// Only Data Aborts (demand paging) are expected in kernel mode.
/// All other exceptions are fatal.
fn handleSyncCurrentEl(ctx: *ArchCpuContext) callconv(.c) void {
    kprof.enter(.exception);
    defer kprof.exit(.exception);

    const esr = readEsrEl1();
    const ec = extractEc(esr);

    switch (ec) {
        .data_abort_same_el => {
            const is_write = isWriteFault(esr);
            const far = readFarEl1();
            kprof.point(.page_fault_hw, far);
            const pf_ctx = PageFaultContext{
                .faulting_address = far,
                .is_kernel_privilege = true,
                .is_write = is_write,
                .is_exec = false,
                .rip = ctx.elr_el1,
                .user_ctx = null,
            };
            zag.memory.fault.handlePageFault(&pf_ctx);
        },

        .instruction_abort_same_el => {
            const far = readFarEl1();
            kprof.point(.page_fault_hw, far);
            const pf_ctx = PageFaultContext{
                .faulting_address = far,
                .is_kernel_privilege = true,
                .is_write = false,
                .is_exec = true,
                .rip = ctx.elr_el1,
                .user_ctx = null,
            };
            zag.memory.fault.handlePageFault(&pf_ctx);
        },

        else => {
            serial.print("KERNEL EXCEPTION: EC=0x{x} ESR=0x{x} ELR=0x{x} FAR=0x{x}\n", .{
                @intFromEnum(ec), esr, ctx.elr_el1, readFarEl1(),
            });
            @panic("Unhandled kernel synchronous exception");
        },
    }
}

/// Handler for IRQ from Current EL (kernel-mode).
/// ARM ARM D1.10.2, offset 0x280.
fn handleIrqCurrentEl(ctx: *ArchCpuContext) callconv(.c) void {
    kprof.enter(.irq);
    defer kprof.exit(.irq);

    // lockdep: see handleIrqLowerEl. The kernel-mode IRQ vector is just as
    // much an async-IRQ-handler entry — the interrupted code may have been
    // holding any locks at all when the IRQ landed.
    sync_debug.enterIrqContext();
    defer sync_debug.exitIrqContext();

    const intid = gic.acknowledgeInterrupt();

    if (gic.isSpurious(intid)) return;

    // Silence level-sensitive timer PPI line before EOI — see
    // `handleIrqLowerEl` for rationale.
    silenceTimerLineIfFiring(intid);

    // EOI before dispatch — see handleIrqLowerEl for rationale.
    gic.endOfInterrupt(intid);
    dispatchIrq(intid, ctx, .kernel);
}

/// Panic handler for unexpected/unimplemented vector entries.
fn handleUnexpected(ctx: *ArchCpuContext) callconv(.c) void {
    const esr = readEsrEl1();
    serial.print("UNEXPECTED EXCEPTION: ESR=0x{x} ELR=0x{x} FAR=0x{x}\n", .{
        esr, ctx.elr_el1, readFarEl1(),
    });
    @panic("Unexpected exception vector taken");
}

/// Origin of an IRQ entry — names whether the interrupted context was
/// running at EL0 (user) or EL1 (kernel). Recorded in case the callee
/// needs to attribute time, but the per-core scheduler tick currently
/// derives that itself from `current_ec`.
const IrqOrigin = enum { user, kernel };

/// Dispatch a GIC interrupt to the appropriate handler.
/// The INTID namespace (IHI 0069H, Section 2.2):
///   0-15:    SGI (Software Generated Interrupts / IPIs)
///   16-31:   PPI (Private Peripheral Interrupts, e.g. timer)
///   32-1019: SPI (Shared Peripheral Interrupts, e.g. devices)
///
/// PPI 30 is the non-secure EL1 physical timer interrupt (ARM ARM
/// D11.2.4); this is the scheduler's preemption tick. It is routed
/// directly to `scheduler.preempt`, equivalent of the x64 LAPIC-timer
/// IDT vector.
fn dispatchIrq(intid: u32, ctx: *ArchCpuContext, origin: IrqOrigin) void {
    _ = origin;
    switch (intid) {
        // SGI 0 — scheduler IPI raised by `triggerSchedulerInterrupt` on
        // aarch64 (see `arch/dispatch.zig sched_ipi_vector`). Used by both
        // explicit `thread_yield` syscalls and cross-core wake-ups. Dispatch
        // it through the same path as the timer tick so the scheduler picks
        // a new runnable thread on this core.
        0 => {
            kprof.enter(.sched_tick);
            defer kprof.exit(.sched_tick);

            // Pi 5 KVM vGICv2 workaround: broadcast a scheduler tick
            // to all secondary cores whenever the BSP runs through
            // its scheduler (via yield self-IPI, cross-core wake,
            // etc). The PPI 30 (CNTP) handler does the same — we
            // hook both paths because empirically the BSP's dominant
            // tick source on Pi KVM is the self-yield SGI 0, not the
            // CNTP PPI, so gating purely off PPI 30 would leave
            // secondaries silent. `maybeBroadcastSchedTick` is
            // rate-limited to at most one broadcast per scheduler
            // timeslice (2 ms), so the fan-out stays bounded. See
            // gic.zig for full diagnosis and spec references.
            if (gic.coreID() == 0) {
                gic.maybeBroadcastSchedTick();
            }
            timers.getPreemptionTimer().armInterruptTimer(scheduler.TIMESLICE_NS);
            port.expireTimedRecvWaiters();
            futex.expireTimedWaiters();
            timer_wheel.wheelExpireDue();
            scheduler.preempt();
        },
        // SGI 1 — kprof-dump IPI. Park until the dumper bumps the epoch.
        1 => {
            kprof_dump.parkForDump();
        },
        // SGI 2 — lazy-FPU cross-core flush. The requesting core wrote
        // the target EC into this core's mailbox; we save the FPU regs
        // into the EC's `fpu_state` if we still own them, then ack so
        // the requester unblocks. See `cpu.fpuFlushIpi`.
        2 => {
            const core_idx: u8 = @truncate(gic.coreID());
            const slot = &cpu.fpu_flush_mailbox[core_idx];
            if (@atomicLoad(?*anyopaque, &slot.requested_thread, .acquire)) |opq| {
                // caller-pinned: the requesting core pins the target EC
                // across the IPI and waits for ack before releasing it;
                // we cannot observe a freed slot here.
                const target: *ExecutionContext = @ptrCast(@alignCast(opq));
                fpu.flushIpiHandler(target);
            }
            slot.ackDone();
        },
        gic.SGI_BCAST_TICK => {
            kprof.enter(.sched_tick);
            defer kprof.exit(.sched_tick);

            // BSP-driven broadcast scheduler tick (Pi 5 KVM vGICv2
            // workaround). The BSP's CNTP PPI 30 handler fans out an
            // SGI on INTID `SGI_BCAST_TICK` to every other core on
            // every tick, because Pi 5 KVM silently drops per-core
            // CNTV/CNTP PPI injections to secondaries once they run
            // EL0. The receiving core treats it as an ordinary
            // scheduler tick. See gic.zig `broadcastSchedTick` for
            // the full diagnosis and spec citations.
            timers.getPreemptionTimer().armInterruptTimer(scheduler.TIMESLICE_NS);
            port.expireTimedRecvWaiters();
            futex.expireTimedWaiters();
            timer_wheel.wheelExpireDue();
            scheduler.preempt();
        },
        23 => {
            // PMU overflow PPI. ARM ARM DDI 0487 K.a §D13.3.1 documents
            // INTID 23 as the GICv3-recommended, level-sensitive PPI
            // raised when PMOVSSET_EL0 has any bit set whose matching
            // PMINTENSET_EL1 bit is also set. The handler snapshots the
            // counter values, masks PMINTENSET / clears PMOVSCLR to
            // drop the line before ERET, and delivers a pmu_overflow
            // fault to the thread's process fault handler.
            pmu.pmiHandler(ctx);
        },
        27, 30 => {
            kprof.enter(.sched_tick);
            defer kprof.exit(.sched_tick);

            // EL1 timer preemption tick. Mask the firing line while we
            // run the scheduler tick; the scheduler re-arms via
            // `armInterruptTimer`, which writes ENABLE=1, IMASK=0 and
            // thereby unmasks the timer again. Without masking first,
            // ISTATUS stays asserted and the GIC would immediately
            // re-deliver the PPI after EOI.
            //
            // We accept INTID 30 (CNTP) as the primary preemption
            // source and INTID 27 (CNTV) as the fallback. The scheduler
            // programs CNTP via kernel/arch/aarch64/timers.zig, but
            // some KVM hosts (notably Pi 5 KVM vGICv2 without FEAT_ECV)
            // trap guest CNTP programming and re-route the deadline
            // through the virtual timer line, delivering PPI 27 to the
            // guest instead of PPI 30 — the guest is unaware of the
            // substitution, so both INTIDs must land on the same
            // scheduler path. Masking the CORRECT control register is
            // determined by ISTATUS: whichever of CNTP/CNTV is firing
            // has ISTATUS=1; we mask only that one so we don't disturb
            // a timer we didn't program.
            //
            // ARM ARM D13.8.11: CNTP_CTL_EL0 — IMASK (bit 1), ISTATUS (bit 2).
            // ARM ARM D13.8.20: CNTV_CTL_EL0 — same layout.
            // GIC IHI 0069H §2.2 / §8.10: INTID 27 = EL1 virtual timer,
            // INTID 30 = EL1 physical timer.
            var cntp_ctl: u64 = undefined;
            var cntv_ctl: u64 = undefined;
            asm volatile ("mrs %[v], cntp_ctl_el0"
                : [v] "=r" (cntp_ctl),
            );
            asm volatile ("mrs %[v], cntv_ctl_el0"
                : [v] "=r" (cntv_ctl),
            );
            if ((cntp_ctl & 0x4) != 0) {
                asm volatile ("msr cntp_ctl_el0, %[val]"
                    :
                    : [val] "r" (@as(u64, 0x3)), // ENABLE=1, IMASK=1
                );
            }
            if ((cntv_ctl & 0x4) != 0) {
                asm volatile ("msr cntv_ctl_el0, %[val]"
                    :
                    : [val] "r" (@as(u64, 0x3)), // ENABLE=1, IMASK=1
                );
            }
            // Pi 5 KVM vGICv2 workaround: fan the BSP's CNTP tick out
            // to every secondary core over a dedicated SGI so they
            // preempt even when their own per-core PPI injection is
            // being silently dropped by the in-kernel vGICv2. Gated
            // to the BSP (core 0) so this is a single broadcast per
            // tick, not an N² fan-out. Harmless on TCG GICv3 and
            // bare-metal where secondaries already see their PPI —
            // the extra tick just runs the normal scheduler handler.
            // See gic.zig `broadcastSchedTick` for spec citations.
            // Rate-limited variant because the SGI 0 handler also
            // calls it on every BSP yield self-IPI.
            if (gic.coreID() == 0) {
                gic.maybeBroadcastSchedTick();
            }
            timers.getPreemptionTimer().armInterruptTimer(scheduler.TIMESLICE_NS);
            port.expireTimedRecvWaiters();
            futex.expireTimedWaiters();
            timer_wheel.wheelExpireDue();
            scheduler.preempt();
        },
        else => {
            // SPI range — INTID 32..1019 per IHI 0069H §2.2 (GICv3) /
            // IHI 0048B §2.2.1 (GICv2). These carry device IRQs bound
            // to a `device_region` via the IRQ-source table. Resolve
            // the firing INTID to its bound region and delegate to
            // `device_region.onIrq`, which masks the line at the GIC
            // (so a level-sensitive line cannot re-pend before the
            // handling EC `ack`s) and bumps every domain-local copy
            // of `field1.irq_count`, futex-waking blocked readers per
            // Spec §[device_irq].
            //
            // The `irq_source` keyed in the device-region table is the
            // SPI line offset (`intid - 32`), full u32 width so SPI
            // INTIDs up to 1019 (line up to 987) survive without
            // truncation. The per-arch shim in `arch/dispatch/irq.zig`
            // adds 32 back when poking the GIC. The x86 side keys on
            // the IOAPIC pin (GSI) — `arch/x64/irq.zig deviceIrqHandler`
            // translates LAPIC vector → GSI before calling
            // `findDeviceByIrqSource`, so the table contract is
            // arch-uniform: "kernel-internal IRQ-source key, controller
            // geometry handled by the shim".
            //
            // EOI sequencing: `handleIrqLowerEl` /
            // `handleIrqCurrentEl` already wrote ICC_EOIR1_EL1 (GICv3)
            // / GICC_EOIR (GICv2) before invoking `dispatchIrq`. With
            // EOImode = 0 (initialized in `gic.initCpuInterface`),
            // that single write performs both the priority drop and
            // the deactivate atomically — IHI 0069H §8.13 / §12.11.5
            // (ICC_EOIR1_EL1, EOImode=0) and IHI 0048B §4.4.5
            // (GICC_EOIR with GICC_CTLR.EOImodeNS=0). Nothing further
            // is required from this branch on the EOI side; the SPI
            // is masked by `device_region.onIrq` until userspace
            // calls `device_region.ack`, which issues another EOI to
            // cover the next-pending edge that may have arrived
            // while the line was masked, and unmasks at the GIC.
            //
            // INTIDs above the SPI range that aren't otherwise
            // handled fall through to the original diagnostic.
            if (intid >= 32 and intid - 32 < device_region.MAX_IRQ_SOURCES) {
                const line: u32 = intid - 32;
                if (device_region.findDeviceByIrqSource(line)) |snapshot| {
                    device_region.onIrq(snapshot);
                    return;
                }
            }
            serial.print("K: IRQ intid={d} (unhandled)\n", .{intid});
        },
    }
}

/// Look up the running EC, fire a `thread_fault` event with `subcode`
/// and `payload`, then yield. Spec §[event_type] row 2.
fn deliverThreadFault(subcode: ThreadFaultSubcode, payload: u64) void {
    const ec = scheduler.currentEc() orelse
        @panic("user thread fault with no current EC");
    port.fireThreadFault(ec, @intFromEnum(subcode), payload);
    cpu.enableInterrupts();
    scheduler.yieldTo(null);
}

/// Look up the running EC, fire a `breakpoint` event with `subcode`,
/// then yield. Spec §[event_type] row 3.
fn deliverBreakpoint(subcode: BreakpointSubcode) void {
    const ec = scheduler.currentEc() orelse
        @panic("user breakpoint with no current EC");
    port.fireBreakpoint(ec, @intFromEnum(subcode));
    cpu.enableInterrupts();
    scheduler.yieldTo(null);
}
