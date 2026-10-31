//! AArch64 CPU context, register save/restore, and context switching.
//!
//! This is the aarch64 equivalent of x64/interrupts.zig. It defines the
//! ArchCpuContext layout, implements syscall/IPC register accessors, and
//! provides the thread context switch mechanism.
//!
//! ArchCpuContext layout — saved on exception entry by the vector stub:
//!   x0-x30:    31 general-purpose registers (248 bytes)
//!   sp_el0:    user stack pointer (8 bytes)
//!   elr_el1:   exception link register — return address (8 bytes)
//!   spsr_el1:  saved processor state (8 bytes)
//!   Total: 272 bytes
//!
//! Register conventions (AAPCS64, ARM IHI 0055):
//!   x0-x7:   arguments / return values
//!   x8:      indirect result / syscall number
//!   x9-x15:  caller-saved temporaries
//!   x16-x17: intra-procedure-call scratch (IP0/IP1)
//!   x18:     platform register (reserved)
//!   x19-x28: callee-saved
//!   x29:     frame pointer (FP)
//!   x30:     link register (LR)
//!
//! Syscall register mapping (matches dispatch.zig getSyscallArgs):
//!   x8  = syscall number
//!   x0  = arg0, x1 = arg1, x2 = arg2, x3 = arg3, x4 = arg4
//!   x5  = IPC handle, x6 = IPC metadata
//!   x0-x4 = IPC payload words
//!
//! Exception entry on ARM (ARM ARM D1.10):
//!   On exception, hardware saves PC → ELR_EL1, PSTATE → SPSR_EL1,
//!   sets PSTATE.{DAIF} to mask interrupts, jumps to VBAR_EL1 + offset.
//!   Software must save x0-x30 and SP_EL0 manually in the vector stub.
//!
//! Context switch:
//!   switchTo() restores the target thread's ArchCpuContext and executes ERET.
//!   ARM ARM D1.10.1: ERET restores PC from ELR_EL1, PSTATE from SPSR_EL1.
//!
//! Key functions to implement:
//!   prepareThreadContext()   — allocate ArchCpuContext on kernel stack
//!   switchTo()               — save current context, restore target, ERET
//!   serializeFaultRegs()     — ArchCpuContext → FaultRegSnapshot
//!   applyFaultRegs()         — FaultRegSnapshot → ArchCpuContext
//!   copyIpcPayload()         — copy x0-x4 between contexts
//!   restoreIpcPayload()      — restore x0-x4 from snapshot
//!   setSyscallReturn()       — write x0 in saved context
//!
//! References:
//! - ARM ARM D1.10: Exception entry/return
//! - ARM ARM D13.2.36: ELR_EL1
//! - ARM ARM D13.2.127: SPSR_EL1
//! - ARM IHI 0055: AAPCS64 (calling convention)

const stygia = @import("stygia");

const cpu = stygia.arch.aarch64.cpu;

pub const Registers = extern struct {
    x0: u64,
    x1: u64,
    x2: u64,
    x3: u64,
    x4: u64,
    x5: u64,
    x6: u64,
    x7: u64,
    x8: u64,
    x9: u64,
    x10: u64,
    x11: u64,
    x12: u64,
    x13: u64,
    x14: u64,
    x15: u64,
    x16: u64,
    x17: u64,
    x18: u64,
    x19: u64,
    x20: u64,
    x21: u64,
    x22: u64,
    x23: u64,
    x24: u64,
    x25: u64,
    x26: u64,
    x27: u64,
    x28: u64,
    x29: u64,
    x30: u64,
};

pub const ArchCpuContext = extern struct {
    regs: Registers,
    sp_el0: u64,
    elr_el1: u64,
    spsr_el1: u64,
};

pub const PageFaultContext = struct {
    faulting_address: u64,
    is_kernel_privilege: bool,
    is_write: bool,
    is_exec: bool,
    rip: u64 = 0,
    user_ctx: ?*ArchCpuContext = null,
    /// Interrupted context's x29 — root of its frame-record chain. The
    /// panic backtrace cannot recover this: `StackIterator` stops at the
    /// naked exception trampoline, but the x29 saved in the exception
    /// frame predates the break in the chain.
    fp: u64 = 0,
    /// Interrupted context's x30. When the faulting PC is a leaf
    /// (memset, memcpy), this names the caller.
    lr: u64 = 0,
    /// Full saved register frame, for the fatal-fault reporter's GPR
    /// dump. Unlike `user_ctx` this is set for kernel-mode faults too.
    frame_ctx: ?*const ArchCpuContext = null,
    /// True when the faulting access happened inside a marked
    /// copy-in/out window (`arch.dispatch.cpu.userAccessBegin` ..
    /// `userAccessEnd`). On aarch64 that window is PSTATE.PAN=0.
    /// See the x86-64 twin for how `memory.fault` consumes it.
    ///
    /// Defaults to `true` so a context built by a path that cannot
    /// determine the window degrades to the pre-existing (accessor)
    /// behaviour rather than a spurious kernel panic.
    in_user_access_window: bool = true,
};

/// SPSR_EL1.PAN — Arm ARM D17.2.116. PAN=1 means privileged access to
/// user-accessible memory traps; PAN=0 means the kernel is inside a
/// `userAccessBegin`/`userAccessEnd` window (or PAN is unimplemented).
pub const SPSR_PAN: u64 = 1 << 22;

/// Dump every saved GPR of a fault frame. printRaw only — this runs on
/// the fatal-fault path where `serial.print_lock` may already be held by
/// this core (see memory.fault.reportKernelFault).
pub fn dumpFaultRegs(ctx: *const ArchCpuContext) void {
    // Own-arch printer, not the dispatch facade — see the x64 twin.
    const boot = stygia.arch.aarch64.serial;
    const panic_mod = stygia.panic;
    inline for (@typeInfo(Registers).@"struct".fields, 0..) |f, i| {
        boot.printRaw(if (i % 4 == 0) "  " else " ");
        boot.printRaw(f.name ++ "=0x");
        panic_mod.printHex(@field(ctx.regs, f.name));
        if (i % 4 == 3) boot.printRaw("\n");
    }
    boot.printRaw("\n  sp_el0=0x");
    panic_mod.printHex(ctx.sp_el0);
    boot.printRaw(" elr=0x");
    panic_mod.printHex(ctx.elr_el1);
    boot.printRaw(" spsr=0x");
    panic_mod.printHex(ctx.spsr_el1);
    // Interrupted kernel SP: the vector stub pushed a 16-byte save area,
    // then the trampoline allocated the ArchCpuContext directly below it.
    boot.printRaw(" ksp=0x");
    panic_mod.printHex(@intFromPtr(ctx) + @sizeOf(ArchCpuContext) + 16);
    boot.printRaw("\n");
}

pub fn setSyscallReturn(ctx: *ArchCpuContext, value: u64) void {
    ctx.regs.x0 = value;
}

/// Spec §[event_state] vreg 2 — x1 on aarch64.
pub fn setEventSubcode(ctx: *ArchCpuContext, value: u64) void {
    ctx.regs.x1 = value;
}

/// Spec §[event_state] vreg 3 — x2 on aarch64.
pub fn setEventAddr(ctx: *ArchCpuContext, value: u64) void {
    ctx.regs.x2 = value;
}

pub fn setEventVreg5(ctx: *ArchCpuContext, value: u64) void {
    ctx.regs.x4 = value;
}

/// Spec §[event_state] vreg 32 read — the suspending thread's saved PC.
/// `elr_el1` carries the entry point set in `prepareThreadContext` for
/// freshly created Threads and the saved exception-return address for
/// ones suspended mid-execution.
pub fn getEventRip(ctx: *const ArchCpuContext) u64 {
    return ctx.elr_el1;
}

/// Spec §[event_state] vreg 32 write into the resumed sender's saved
/// frame. Used by reply_transfer test 14 to commit a write-cap
/// receiver's PC modification onto the suspended thread's saved frame.
pub fn setEventRip(ctx: *ArchCpuContext, value: u64) void {
    ctx.elr_el1 = value;
}

/// Companion read for `writeUserVreg14`. AArch64's saved PC is vreg 32
/// at [user_sp+8], after the syscall word. The caller must be running in
/// the receiver's address space before accessing this user page.
pub fn readUserVreg14(ctx: *const ArchCpuContext) u64 {
    cpu.panDisable();
    const value = @as(*const u64, @ptrFromInt(ctx.sp_el0 + 8)).*;
    cpu.panEnable();
    return value;
}

/// AArch64 §[event_state] vreg 32: saved PC at [user_sp+8].
/// Called only with the receiver's TTBR0 installed.
pub fn writeUserVreg14(ctx: *ArchCpuContext, value: u64) void {
    cpu.panDisable();
    @as(*u64, @ptrFromInt(ctx.sp_el0 + 8)).* = value;
    cpu.panEnable();
}

/// Spec §[syscall_abi]: vreg 0 sits at `[user_sp + 0]` on the user
/// stack — recv's success-return packs reply_handle_id / event_type /
/// pair_count / tstart there per §[event_state]. TTBR0_EL1 must
/// reference the thread's address space when called (the rendezvous wake
/// path defers this write to `loadThreadContextAndReturn` after the
/// TTBR0 swap). PAN is cleared for the write.
pub fn writeUserSyscallWord(ctx: *const ArchCpuContext, value: u64) void {
    cpu.panDisable();
    @as(*u64, @ptrFromInt(ctx.sp_el0)).* = value;
    cpu.panEnable();
}

/// Apply receiver modifications to x0..x30 only within the originating
/// event's declared window. The low 13 lanes retain the existing
/// zero-count behavior pending the §suspend ambiguity tracked in .371.7.
pub fn copyEventStateGprs(dst: *ArchCpuContext, src: *const ArchCpuContext, payload_count: u7) void {
    var values: [31]u64 = @bitCast(dst.regs);
    const source: [31]u64 = @bitCast(src.regs);
    // Keep the low-lane behavior used by existing zero-count suspensions
    // until the §suspend/§event_state conflict is resolved (.371.7).
    // Higher lanes are applied only when the sender declared them valid.
    const limit: usize = @max(13, @min(@as(usize, payload_count), 31));
    for (0..limit) |i| values[i] = source[i];
    dst.regs = @bitCast(values);
}

/// Snapshot all 31 AArch64 GPR-backed event-state vregs, x0..x30.
pub fn getEventStateGprs(ctx: *const ArchCpuContext) [31]u64 {
    return @bitCast(ctx.regs);
}

/// Project the x0..x30 event-state snapshot onto a receiver frame.
pub fn setEventStateGprs(ctx: *ArchCpuContext, gprs: [31]u64) void {
    ctx.regs = @bitCast(gprs);
}
