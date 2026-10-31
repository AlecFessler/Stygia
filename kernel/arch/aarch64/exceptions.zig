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

const stygia = @import("stygia");
const build_options = @import("build_options");

const cpu = stygia.arch.aarch64.cpu;
const device_region = stygia.devices.device_region;
const thread_mod = stygia.sched.thread;
const fpu = stygia.sched.fpu;
const futex = stygia.sched.futex;
const gic = stygia.arch.aarch64.gic;
const interrupts = stygia.arch.aarch64.interrupts;
const port = stygia.sched.port;
const scheduler = stygia.sched.scheduler;
const serial = stygia.arch.aarch64.serial;
const sync_debug = stygia.utils.sync.debug;
const syscall_dispatch = stygia.syscall.dispatch;
const timers = stygia.arch.aarch64.timers;
const vmar = stygia.memory.vmar;
const watchdog = stygia.arch.aarch64.watchdog;

const VAddr = stygia.memory.address.VAddr;

const ArchCpuContext = stygia.arch.aarch64.interrupts.ArchCpuContext;
const Thread = stygia.sched.thread.Thread;
const PageFaultContext = stygia.arch.aarch64.interrupts.PageFaultContext;
const A64_PF_DIAG_BUDGET: u32 = 4096;

var a64_pf_diag_prints: u32 = 0;

/// ARM ARM D13.2.37 -- ESR_EL1 Exception Class field, bits [31:26].
/// Identifies the reason for the exception that was taken to EL1.
const ExceptionClass = enum(u6) {
    unknown = 0x00,
    wf_trapped = 0x01,
    sve_simd_fp_access = 0x07, // ARM ARM D13.2.37 — Access to FP/Advanced SIMD/SVE
    svc_aarch64 = 0x15,
    msr_mrs_sys_trapped = 0x18, // ARM ARM D13.2.37 — MSR/MRS/SYS trap (e.g. EL0 MRS MPIDR_EL1)
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

fn diagTag(thr: *Thread) u64 {
    return thr.diag_test_tag;
}

fn logLowerElAbort(
    kind: []const u8,
    ctx: *ArchCpuContext,
    esr: u64,
    far: u64,
    is_write: bool,
    is_exec: bool,
) void {
    if (!build_options.kernel_spawn_diag) return;
    const n = @atomicRmw(u32, &a64_pf_diag_prints, .Add, 1, .monotonic);
    if (n >= A64_PF_DIAG_BUDGET) return;
    const cur = scheduler.currentThread();
    serial.print(
        "[a64pf] kind={s} tag=0x{x} ec=0x{x} esr=0x{x} ec_class=0x{x} fsc=0x{x} far=0x{x} elr=0x{x} w={d} x={d} pan_window={d}\n",
        .{
            kind,
            if (cur) |e| diagTag(e) else 0,
            if (cur) |e| @intFromPtr(e) else 0,
            esr,
            @intFromEnum(extractEc(esr)),
            esr & 0x3f,
            far,
            ctx.elr_el1,
            @intFromBool(is_write),
            @intFromBool(is_exec),
            @intFromBool((ctx.spsr_el1 & interrupts.SPSR_PAN) == 0),
        },
    );
}

/// Kernel-internal sub-codes for unhandled user thread faults.
const ThreadFaultSubcode = enum(u8) {
    illegal_instruction = 0,
    alignment_fault = 1,
    protection_fault = 2,
    arithmetic = 3,
    stack_overflow = 4,
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
///   Others: handle via `port.fireThreadFault`.
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
    const thread_ptr = scheduler.currentThread() orelse return false;
    // caller-pinned: `thread_ptr` is the running thread of this core (we are mid-
    // synchronous-trap from it), so its process SlabRef is live for the
    // duration of this handler. Mirrors arch/x64/interrupts.zig switchTo.
    const process = thread_ptr.process.ptr;
    const fault_va = VAddr.fromInt(readFarEl1());

    const v = vmar.findVmarCovering(process, fault_va) orelse return false;

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
    const esr = readEsrEl1();
    const ec = extractEc(esr);
    const entry_cur = scheduler.currentThread();

    switch (ec) {
        // Lazy-FPU trap. CPACR_EL1.FPEN was clamped to 0b01 (trap EL0)
        // by switchTo when this thread last got dispatched (because it
        // wasn't the last FPU owner on this core). Userspace's first
        // FP/SIMD instruction trapped here — swap state and return so
        // the instruction re-executes.
        .sve_simd_fp_access => {
            const thread_ptr = scheduler.currentThread() orelse
                @panic("FP/SIMD trap with no current thread");
            fpu.handleTrap(thread_ptr);
            consumeEntrySuspendDirective(thread_ptr, ctx);
            return;
        },

        .svc_aarch64 => {
            // Spec §[syscall_abi] aarch64 ABI:
            //   - syscall_word at vreg 0 = `[sp_el0 + 0]` (user stack).
            //   - vregs 1..31 ride x0..x30 in `ctx.regs` order.
            //   - vregs 32..127 spill to the user stack at
            //     `[sp_el0 + (N-31)*8]`; reading them requires a
            //     PAN-gated load.
            //   - return: i64 → x0 (vreg 1).
            //
            // Read the syscall word, parse it for the syscall's
            // structurally-required upper vreg, then assemble the
            // dispatch args slice. For register-only syscalls
            // (max_vreg ≤ 31) the stack-read loop runs zero iterations,
            // matching the contract that `issueRawNoStack` reserves
            // only 16 bytes — so reading vregs 32+ would walk past the
            // mapped reservation into caller-frame territory we must
            // not touch.
            var args: [127]u64 = .{0} ** 127;
            cpu.panDisable();
            const syscall_word: u64 = @as(*const u64, @ptrFromInt(ctx.sp_el0)).*;
            const max_vreg: u8 = syscall_dispatch.expectedMaxVreg(syscall_word);
            if (max_vreg > 31) {
                var i: u8 = 32;
                while (i <= max_vreg) : (i += 1) {
                    const off: u64 = @as(u64, i - 31) * 8;
                    args[i - 1] = @as(*const u64, @ptrFromInt(ctx.sp_el0 + off)).*;
                }
            }
            cpu.panEnable();
            // Copy vregs 1..31 from ctx.regs into args[0..31]. The regs
            // struct is laid out as 31 u64s in x0..x30 order, so the
            // copy is a straight loop.
            const regs_ptr: [*]const u64 = @ptrCast(&ctx.regs);
            var ri: usize = 0;
            while (ri < 31) : (ri += 1) args[ri] = regs_ptr[ri];

            const caller = scheduler.currentThread() orelse
                @panic("syscall with no current thread");
            const dispatch_len: usize = @max(@as(usize, max_vreg), 31);
            const ret = syscall_dispatch.dispatch(caller, syscall_word, args[0..dispatch_len]);

            // Only commit the syscall return into the saved frame if the
            // dispatched handler did NOT park `caller`. A handler that
            // suspends (recv / suspend / futex_wait / fault) clears this
            // core's `current_thread`; from that moment on `caller.ctx.regs.x0`
            // is the wake-side delivery slot — `propagateClosedTo*`,
            // `expireTimedRecvWaiters`, etc. running on a remote core
            // write E_CLOSED / E_TIMEOUT there directly. Unconditionally
            // assigning `ret` (always 0 on the suspend path) would race
            // with that remote write and clobber the real wake value
            // back to 0.
            const core: u8 = @truncate(gic.coreID());
            if (scheduler.coreCurrentIsRunning(core, caller)) {
                ctx.regs.x0 = @bitCast(ret);
            }

            // Spec §[syscall_abi]: vreg 0 (`[user_sp + 0]`) carries the
            // recv-success syscall return word — `port.deliverEvent`
            // stages it in `pending_event_word` so the resume path can
            // flush it once TTBR0 references the receiver's address
            // space. The synchronous recv path (caller dequeued a
            // queued sender without blocking) returns through this tail
            // still in the caller's TTBR0, so flush here. Spec
            // §[event_state] vreg 14 = the suspended thread's saved PC; on
            // aarch64 vreg 14 is GPR-backed at x13 — write it into the
            // caller's saved frame so ERET surfaces it. Mirrors
            // arch/x64/interrupts.zig syscallDispatch.
            if (caller.pending_event_word_valid and
                scheduler.coreCurrentIsRunning(core, caller))
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
            // / futex_wait), `current_thread` was cleared on this core. The
            // exception trampoline would otherwise ERET back to the
            // now-parked user thread; drive the scheduler instead so the
            // next ready thread takes over (or we idle). Via the
            // park-kstack hop, not `run()` in place: this frame lives
            // on the suspended caller's kstack, which is already
            // claimable by wakers on other cores, and the hop also
            // publishes the caller's deferred `on_cpu` release.
            if (!scheduler.coreCurrentIsRunning(core, caller)) {
                scheduler.hopParkRun();
            }
            // Identity check, not just idle check. x64's syscall asm
            // re-validates the caller before its sysret; this tail only
            // checked for idle, so a handler that left `current_thread`
            // naming a DIFFERENT thread fell through to the trampoline
            // epilogue, which ERETs the CALLER's frame — resuming a thread
            // the scheduler had handed elsewhere, with SP_EL1 left on
            // the caller's kstack. The next kernel entry from that user
            // context then runs on a kstack whose thread is concurrently
            // executing on another core (measured on the Pi 5 rig:
            // core 0 mid-fault-path on slot 36 with current_thread owning
            // slot 37). The trampoline eret is only ever correct for
            // `caller`; anything else must go through the scheduler —
            // via the park-kstack hop: this frame IS the caller's
            // kstack, and a caller no longer current is claimable.
            if (!scheduler.coreCurrentIsRunning(core, caller)) {
                scheduler.hopParkRun();
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
            const is_write = isWriteFault(esr);
            logLowerElAbort("data_lower", ctx, esr, far, is_write, false);
            const pf_ctx = PageFaultContext{
                .faulting_address = far,
                .is_kernel_privilege = false,
                .is_write = is_write,
                .is_exec = false,
                .rip = ctx.elr_el1,
                .user_ctx = ctx,
                // For the no-current-thread panic path: the doomed context's
                // registers are the evidence (a disowned core running a
                // double-dispatched thread shows the SECOND resume's frame).
                .fp = ctx.regs.x29,
                .lr = ctx.regs.x30,
                .frame_ctx = ctx,
                // PAN in the SAVED PSTATE is the state at fault time —
                // see `PageFaultContext.in_user_access_window`.
                .in_user_access_window = (ctx.spsr_el1 & interrupts.SPSR_PAN) == 0,
            };
            stygia.memory.fault.handlePageFault(&pf_ctx);
        },

        .instruction_abort_lower_el => {
            const far = readFarEl1();
            logLowerElAbort("inst_lower", ctx, esr, far, false, true);
            const pf_ctx = PageFaultContext{
                .faulting_address = far,
                .is_kernel_privilege = false,
                .is_write = false,
                .is_exec = true,
                .rip = ctx.elr_el1,
                .user_ctx = ctx,
                .fp = ctx.regs.x29,
                .lr = ctx.regs.x30,
                .frame_ctx = ctx,
                // PAN in the SAVED PSTATE is the state at fault time —
                // see `PageFaultContext.in_user_access_window`.
                .in_user_access_window = (ctx.spsr_el1 & interrupts.SPSR_PAN) == 0,
            };
            stygia.memory.fault.handlePageFault(&pf_ctx);
        },

        .pc_alignment => {
            deliverThreadFault(.alignment_fault, readFarEl1());
        },

        .sp_alignment => {
            deliverThreadFault(.alignment_fault, ctx.sp_el0);
        },

        .breakpoint_lower_el => {
            deliverThreadFault(.illegal_instruction, ctx.elr_el1);
        },

        .brk_instruction => {
            deliverThreadFault(.illegal_instruction, ctx.elr_el1);
        },

        .software_step_lower_el => {
            // Single-step from userspace: resume silently.
            if (entry_cur) |thread_ptr| consumeEntrySuspendDirective(thread_ptr, ctx);
            return;
        },

        .watchpoint_lower_el => {
            // Watchpoint from userspace: resume silently.
            if (entry_cur) |thread_ptr| consumeEntrySuspendDirective(thread_ptr, ctx);
            return;
        },

        .wf_trapped => {
            // EL0 wfi / wfe / wfit / wfet trap. SCTLR_EL1.{nTWI,nTWE}
            // remain at the reset value (0) so wait-for-event/interrupt
            // instructions issued at EL0 trap to EL1 with EC=0x01.
            // ARM ARM D13.2.118 (SCTLR_EL1) and D13.2.37 (ESR_EL1).
            //
            // Park the thread in the .idle_wait state so it stops consuming
            // CPU but stays alive and suspendable. Treating wfi as a
            // protection_fault would `parkSelfFaulted` the thread into
            // `.exited`, breaking any later `suspend(this_thread, port)`
            // call (suspend's gate rejects non-{running,ready,idle_wait}
            // targets with E_INVAL — the precise failure that flaked
            // reply_transfer_14 on Pi 5 KVM). Permitting native EL0 wfi
            // (SCTLR.nTWI=1) was the prior attempt; it left dummies
            // executing wfi forever in EL0 and the destroy walk's UAF
            // race against an actively-executing thread produced a hang
            // around test ~144 (batch 36..40).
            //
            // The .idle_wait path: advance ELR past the wait instruction
            // (so resume from suspend / re-dispatch lands at `b 1b` and
            // not on another immediate wfi-trap), park as .idle_wait
            // (off every queue, suspendOnPort treats it like .ready),
            // then dispatch whatever else this core has.
            ctx.elr_el1 += 4;
            const thread_ptr = scheduler.currentThread() orelse
                @panic("wfi trap with no current thread");
            stygia.sched.thread.parkIdleWait(thread_ptr);
            // Park-kstack hop, IRQs kept masked: the thread is claimable
            // (`suspend` accepts `.idle_wait`) with its on_cpu release
            // stashed for the hop; running the scheduler loop in place
            // on its kstack raced its re-dispatch, and an IRQ here
            // could self-deadlock on our own pending release (see the
            // x86 hlt-trap twin).
            scheduler.hopParkRun();
        },

        .msr_mrs_sys_trapped => {
            // ARM ARM D13.2.40 — Trapped MSR/MRS/SYS access (a system
            // register that is accessible at EL0 but configured to trap
            // via SCTLR_EL1 / CPACR_EL1 / etc.). Currently nothing in
            // Stygia programs such traps, so any hit here is unexpected;
            // surface as a protection fault.
            //
            // (`mrs x, MPIDR_EL1` from EL0 is UNDEFINED — not "trapped"
            // — and lands in the `.unknown` arm below where we handle it
            // by emulating the read.)
            deliverThreadFault(.protection_fault, ctx.elr_el1);
        },

        .unknown => {
            // ARM ARM D13.2.37: EC=0x00 is taken for unallocated /
            // UNDEFINED instruction encodings, which includes:
            //   * `udf` (permanently-undefined) — true illegal_instruction.
            //   * `mrs x, MPIDR_EL1` from EL0 — RW at EL1, RO at EL2/EL3,
            //     UNDEFINED at EL0 (D17.2.99). Linux exposes MPIDR to
            //     userspace by emulating the read here; the in-kernel
            //     testing harness's `currentCoreId()` relies on it
            //     (spec §[affinity] tests 05/06 issue
            //     `mrs x, MPIDR_EL1` to verify the kernel honoured an
            //     `affinity` syscall by re-pinning the thread).
            //
            // Walk: peek the instruction at ELR_EL1, check the
            // `mrs x<rt>, MPIDR_EL1` bit pattern, emulate. Anything else
            // surfaces as `illegal_instruction` per spec §[event_type].
            //
            // `mrs <Xt>, MPIDR_EL1` encoding. The MRS-to-system-register
            // template is (ARM ARM C6.2.MRS):
            //   1101 0101 001 L o0 op1[2:0] CRn[3:0] CRm[3:0] op2[2:0] Rt[4:0]
            // L=1 (read), o0=1 iff op0=3. MPIDR_EL1 is op0=3 op1=0 CRn=c0
            // CRm=c0 op2=5 (ARM ARM D17.2.99), so op2 fills bits[7:5]=101
            // and the fixed prefix is:
            //   bits 31..0 : 1101 0101 0011 1000 0000 0000 101 <Rt:5>
            //              = 0xD538_00A0 | Rt          with mask 0xFFFF_FFE0
            // So a u32 instruction word `& 0xFFFF_FFE0 == 0xD538_00A0`
            // names this exact MRS; the low 5 bits select Rt (0..31).
            //
            // op2 is load-bearing: op2=0 is MIDR_EL1's encoding (0xD538_0000),
            // not MPIDR_EL1's. A constant of 0xD538_0000 here matches the
            // wrong system register and the EL0 MPIDR_EL1 read falls through
            // to illegal_instruction.
            const elr = ctx.elr_el1;
            cpu.panDisable();
            const insn: u32 = @as(*const u32, @ptrFromInt(elr)).*;
            cpu.panEnable();
            const MPIDR_MRS_BASE: u32 = 0xD538_00A0;
            const MPIDR_MRS_MASK: u32 = 0xFFFF_FFE0;
            if ((insn & MPIDR_MRS_MASK) == MPIDR_MRS_BASE) {
                const rt: u8 = @truncate(insn & 0x1F);
                var mpidr: u64 = undefined;
                asm volatile ("mrs %[v], mpidr_el1"
                    : [v] "=r" (mpidr),
                );
                // Report the LOGICAL core id in Aff0 rather than the raw
                // hardware affinity. The whole point of emulating this
                // read is to let a thread observe which core it is running
                // on (see the affinity tests above), and the kernel's
                // core numbering — affinity masks, run queues, per-core
                // state — is `gic.coreID()`, an index into the
                // firmware-described MPIDR table, NOT the raw Aff0.
                //
                // Those coincide only on a flat single-cluster topology.
                // On the Pi 5 (BCM2712) firmware describes the cores as
                // MPIDR 0x0 / 0x100 / 0x200 / 0x300 — the index lives in
                // Aff1 and **Aff0 reads 0 on all four cores** — so the
                // raw value made every core claim to be core 0 and no
                // affinity restriction could ever be observed as honoured.
                // Same MPIDR aliasing that `gic.coreID()` exists to
                // resolve; QEMU/KVM hands us a flat topology, which is
                // why this only ever failed on hardware.
                //
                // Aff1..Aff3 are left intact for anything that wants the
                // real topology; only Aff0 is rewritten.
                mpidr = (mpidr & ~@as(u64, 0xFF)) | (gic.coreID() & 0xFF);
                if (rt < 31) {
                    const regs_ptr: [*]u64 = @ptrCast(&ctx.regs);
                    regs_ptr[rt] = mpidr;
                } // rt == 31 (xzr): result discarded.
                ctx.elr_el1 += 4; // skip the emulated instruction
                if (entry_cur) |thread_ptr| consumeEntrySuspendDirective(thread_ptr, ctx);
                return;
            }
            deliverThreadFault(.illegal_instruction, ctx.elr_el1);
        },

        else => {
            deliverThreadFault(.protection_fault, ctx.elr_el1);
        },
    }
    if (entry_cur) |thread_ptr| consumeEntrySuspendDirective(thread_ptr, ctx);
}

fn consumeEntrySuspendDirective(thread_ptr: *Thread, ctx: *ArchCpuContext) void {
    const core: u8 = @truncate(gic.coreID());
    if (!scheduler.coreCurrentIsRunning(core, thread_ptr)) return;
    if (thread_mod.consumeSuspendDirective(thread_ptr, ctx)) {
        scheduler.hopParkRun();
    }
}

fn consumeIrqEntrySuspendDirective(thread_ptr: *Thread, ctx: *ArchCpuContext) void {
    const core: u8 = @truncate(gic.coreID());
    if (!scheduler.coreCurrentIsRunning(core, thread_ptr)) return;
    // Model/spec assumption: an armed user-mode scheduler tick consumes
    // the suspend directive before the scheduler requeue decision. This
    // runs after EOI, so the acknowledged IRQ is not left active, but
    // before `dispatchIrq`, whose SGI/timer arms may enter
    // `scheduler.preempt()` and never return. Do not hop here: the IRQ
    // body still has to run; the lower-EL tail's identity guard hops
    // after any returning handler.
    _ = thread_mod.consumeSuspendDirective(thread_ptr, ctx);
}

/// Handler for IRQ from Lower EL (EL0 userspace).
/// ARM ARM D1.10.2, offset 0x480.
///
/// Acknowledges the interrupt via GIC (IHI 0069H, Section 12.11.1:
/// ICC_IAR1_EL1), dispatches to the registered device handler, and
/// signals end-of-interrupt (ICC_EOIR1_EL1).
fn handleIrqLowerEl(ctx: *ArchCpuContext) callconv(.c) void {

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
    // CPU's I-mask drops on ERET — robbing the next dispatched thread of
    // its full timeslice. ARM ARM D11.2.4 + D13.8.20/D13.8.11 + IHI
    // 0048B §3.2 (level-sensitive PPI delivery).
    silenceTimerLineIfFiring(intid);

    // EOI must be issued BEFORE dispatchIrq because the timer / scheduler
    // IPI paths can call `scheduler.switchTo`, which is `noreturn` and
    // ERETs to a different thread. Anything queued after dispatchIrq is
    // unreachable on a context switch, leaving the interrupt permanently
    // in the active state and masking every subsequent delivery of that
    // same priority (IHI 0069H §4.6: an active interrupt blocks pending).
    const entry_cur = scheduler.currentThread();
    gic.endOfInterrupt(intid);
    if (entry_cur) |thread_ptr| consumeIrqEntrySuspendDirective(thread_ptr, ctx);
    dispatchIrq(intid);
    // Identity guard, same rationale as the svc tail: the trampoline
    // epilogue ERETs the INTERRUPTED frame, which is only correct while
    // `current_thread` still names the thread that owns it. If dispatchIrq's
    // scheduler work rewrote the slot and then RETURNED (switchTo's
    // non-dispatching exits), falling through would resume a frame the
    // scheduler handed elsewhere. Hop, don't run in place: this frame
    // sits on the interrupted thread's kstack, and a thread no longer current
    // is claimable by other cores.
    if (entry_cur) |thread_ptr| {
        if (!scheduler.coreCurrentIsRunning(@truncate(gic.coreID()), thread_ptr)) {
            scheduler.hopParkRun();
        }
    } else if (scheduler.currentThread() != null) {
        scheduler.hopParkRun();
    }
}

/// Mask CNTP/CNTV at the source if their ISTATUS is asserted. Called
/// before EOI so the level-sensitive PPI line de-asserts at the GIC
/// before EOI clears the active bit — preventing an immediate re-pend
/// that would steal the next thread's timeslice. The matching unmask
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
    const esr = readEsrEl1();
    const ec = extractEc(esr);

    switch (ec) {
        .data_abort_same_el => {
            const is_write = isWriteFault(esr);
            const far = readFarEl1();
            const pf_ctx = PageFaultContext{
                .faulting_address = far,
                .is_kernel_privilege = true,
                .is_write = is_write,
                .is_exec = false,
                .rip = ctx.elr_el1,
                .user_ctx = null,
                .fp = ctx.regs.x29,
                .lr = ctx.regs.x30,
                .frame_ctx = ctx,
                // PAN in the SAVED PSTATE is the state at fault time —
                // see `PageFaultContext.in_user_access_window`.
                .in_user_access_window = (ctx.spsr_el1 & interrupts.SPSR_PAN) == 0,
            };
            stygia.memory.fault.handlePageFault(&pf_ctx);
        },

        .instruction_abort_same_el => {
            const far = readFarEl1();
            const pf_ctx = PageFaultContext{
                .faulting_address = far,
                .is_kernel_privilege = true,
                .is_write = false,
                .is_exec = true,
                .rip = ctx.elr_el1,
                .user_ctx = null,
                .fp = ctx.regs.x29,
                .lr = ctx.regs.x30,
                .frame_ctx = ctx,
                // PAN in the SAVED PSTATE is the state at fault time —
                // see `PageFaultContext.in_user_access_window`.
                .in_user_access_window = (ctx.spsr_el1 & interrupts.SPSR_PAN) == 0,
            };
            stygia.memory.fault.handlePageFault(&pf_ctx);
        },

        else => {
            // Lock-free, same protocol as memory.fault.reportKernelFault:
            // a corrupted PC lands here (PC-alignment fault, EC=0x22, seen
            // on the bare-metal rig) and the interrupted code may hold
            // `serial.print_lock`, so `serial.print` can wedge the report.
            const panic_mod = stygia.panic;
            // Own-arch printer, not the dispatch facade.
            const boot = serial;
            if (!panic_mod.claimPanic()) cpu.halt();
            boot.printRaw("KERNEL EXCEPTION: EC=0x");
            panic_mod.printHex(@intFromEnum(ec));
            boot.printRaw(" ESR=0x");
            panic_mod.printHex(esr);
            boot.printRaw(" ELR=0x");
            panic_mod.printHex(ctx.elr_el1);
            boot.printRaw(" FAR=0x");
            panic_mod.printHex(readFarEl1());
            boot.printRaw(" core=0x");
            panic_mod.printHex(gic.coreID());
            boot.printRaw("\n");
            stygia.arch.aarch64.interrupts.dumpFaultRegs(ctx);
            stygia.memory.fault.dumpFrameChain(ctx.regs.x29);
            @panic("Unhandled kernel synchronous exception");
        },
    }
}

/// Handler for IRQ from Current EL (kernel-mode).
/// ARM ARM D1.10.2, offset 0x280.
fn handleIrqCurrentEl(ctx: *ArchCpuContext) callconv(.c) void {
    _ = ctx;

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
    const entry_cur = scheduler.currentThread();
    gic.endOfInterrupt(intid);
    dispatchIrq(intid);
    // Identity guard — see handleIrqLowerEl. Kernel-mode frames live on
    // the current thread's kstack; if the slot changed, that kstack may
    // already be executing elsewhere — hop off it before entering the
    // scheduler loop.
    if (scheduler.currentThread() != entry_cur) {
        scheduler.hopParkRun();
    }
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
/// derives that itself from `current_thread`.
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
fn dispatchIrq(intid: u32) void {

    // Bare-metal Pi 5 watchdog pet. A no-op — not even a load of the
    // reload constant — on every target whose devicetree has no
    // `brcm,bcm2712-pm` node, which is all of them except a real BCM2712
    // booted by `bootloader/pi5` (see `watchdog.zig`).
    //
    // Placed at the top of the shared dispatcher rather than inside the
    // timer-PPI arm below, for two reasons:
    //
    //   1. Several arms of this switch are `noreturn` in practice —
    //      `scheduler.preempt` can ERET into a different thread — so the
    //      only position that is guaranteed to execute is before the
    //      switch.
    //   2. The timer PPI is not by itself a reliable heartbeat. Both the
    //      SGI 0 (yield / cross-core wake) arm and the SGI_BCAST_TICK arm
    //      re-arm the preemption timer for a fresh full TIMESLICE_NS, so a
    //      workload that yields faster than the timeslice pushes the CNTV/
    //      CNTP deadline out indefinitely and PPI 27/30 may never fire.
    //      Petting from the dispatcher makes every interrupt a heartbeat,
    //      which is both cheaper to reason about and strictly safer.
    //
    // Cost is one uncached 32-bit store per interrupt, against a 15 s
    // window — orders of magnitude more often than strictly required, and
    // still far below the noise floor of an IRQ entry.
    //
    // Not open-ended: `pet()` disables itself once its from-boot budget
    // expires, so an unattended board still resets on its own after a run
    // that never terminates. See `watchdog.zig`.
    watchdog.pet();

    switch (intid) {
        // SGI 0 — scheduler IPI raised by `triggerSchedulerInterrupt` on
        // aarch64 (see `arch/dispatch.zig sched_ipi_vector`). Used by both
        // explicit `thread_yield` syscalls and cross-core wake-ups. Dispatch
        // it through the same path as the timer tick so the scheduler picks
        // a new runnable thread on this core.
        0 => {

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
            scheduler.preempt();
        },
        // SGI 2 — lazy-FPU cross-core flush. The requesting core wrote
        // the target thread into this core's mailbox; we save the FPU regs
        // into the thread's `fpu_state` if we still own them, then ack so
        // the requester unblocks. See `cpu.fpuFlushIpi`.
        2 => {
            const core_idx: u8 = @truncate(gic.coreID());
            const slot = &cpu.fpu_flush_mailbox[core_idx];
            if (@atomicLoad(?*anyopaque, &slot.requested_thread, .acquire)) |opq| {
                // caller-pinned: the requesting core pins the target thread
                // across the IPI and waits for ack before releasing it;
                // we cannot observe a freed slot here.
                const target: *Thread = @ptrCast(@alignCast(opq));
                fpu.flushIpiHandler(target);
            }
            slot.ackDone();
        },
        // SGI 3 — cross-core idle wake (`arch.dispatch.smp.sendWakeIpi`).
        // Intentionally EMPTY. The wake's entire job is to make a parked
        // core's `wfi` retire; `cpu.parkAndAwaitIRQ` then falls through
        // to `b scheduler_run_after_park`, which re-runs `run()` and
        // picks up the freshly enqueued thread.
        //
        // This handler must RETURN. Do not route the wake to SGI 0 or
        // otherwise call into `scheduler.preempt()` here. `parkAndAwaitIRQ`
        // takes its IRQ inside the single-instruction `msr daifclr, #2`
        // window between the `wfi` and the `b`, and
        // `scheduler_run_after_park` is the ONLY writer that clears the
        // previously-dispatched thread's `on_cpu` (by then `current_thread` is
        // already null, so `switchTo`'s prev-clear edge has nothing to
        // clear from — see the `post_park_clear_on_cpu` comment in
        // `sched.scheduler.parkAndAwaitIRQ`). A handler that dispatches
        // never returns, so the `b` is never reached, and that thread's
        // `on_cpu` is stranded `true` forever: `finalizeDestroyMarkedDead`
        // skips on_cpu=true, its zombie is never reaped, `postZombie`
        // spins, and the slab slot leaks. The next park overwrites
        // `post_park_clear_on_cpu`, losing the clear permanently.
        //
        // A wake is sent precisely because work was just enqueued, so a
        // dispatching handler would hit that path on nearly every wake
        // rather than rarely.
        3 => {},
        gic.SGI_BCAST_TICK => {

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
            scheduler.preempt();
        },
        27, 30 => {

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
            scheduler.preempt();
        },
        else => {
            // SPI range — INTID 32..1019 per IHI 0069H §2.2 (GICv3) /
            // IHI 0048B §2.2.1 (GICv2). These carry device IRQs bound
            // to a `device_region` via the IRQ-source table. Resolve
            // the firing INTID to its bound region and delegate to
            // `device_region.onIrq`, which masks the line at the GIC
            // (so a level-sensitive line cannot re-pend before the
            // handling thread `ack`s) and bumps every process-local copy
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

/// Look up the running thread, fire a `thread_fault` event with `subcode`
/// and `payload`, then yield after the faulting process is torn down.
fn deliverThreadFault(subcode: ThreadFaultSubcode, payload: u64) void {
    const thr = scheduler.currentThread() orelse
        @panic("user thread fault with no current thread");
    port.fireThreadFault(thr, @intFromEnum(subcode), payload);
    // Keep IRQs masked through fault teardown and the scheduler hop.
    scheduler.yieldTo(null);
    // `fireThreadFault`'s unhandled-fault path (`parkSelfFaulted`) cleared
    // this core's `current_thread`; if `yieldTo` couldn't dispatch fresh
    // work, ERET back through `exceptionTrampoline` would surface the
    // now-stale faulting user context, re-fault on the same PC, and
    // re-enter `handleSyncLowerEl` with `currentEc() == null` — hitting
    // the panic above. Hand off via the park-kstack hop (noreturn) —
    // this frame lives on the suspended thread's claimable kstack, and the
    // hop publishes its deferred on_cpu release before the scheduler
    // loop idles/dispatches.
    // Mirrors arch/x64/exceptions.zig user-exception handler tail.
    if (scheduler.currentThread() == null) scheduler.hopParkRun();
}
