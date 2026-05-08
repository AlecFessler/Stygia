//! AArch64 CPU context, register save/restore, and context switching.
//!
//! This is the aarch64 equivalent of x64/interrupts.zig. It defines the
//! ArchCpuContext layout, implements syscall/IPC register accessors, and
//! provides the EC context switch mechanism.
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
//!   switchTo() restores the target EC's ArchCpuContext and executes ERET.
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

const zag = @import("zag");

const cpu = zag.arch.aarch64.cpu;

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
};

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

/// Spec §[event_state] vreg 4 — x3 on aarch64.
pub fn setEventVreg4(ctx: *ArchCpuContext, value: u64) void {
    ctx.regs.x3 = value;
}

pub fn setEventVreg5(ctx: *ArchCpuContext, value: u64) void {
    ctx.regs.x4 = value;
}

/// Spec §[event_state] vreg 32 read — the suspending EC's saved PC.
/// `elr_el1` carries the entry point set in `prepareEcContext` for
/// freshly created ECs and the saved exception-return address for
/// ones suspended mid-execution.
pub fn getEventRip(ctx: *const ArchCpuContext) u64 {
    return ctx.elr_el1;
}

/// Spec §[event_state] vreg 32 write into the resumed sender's saved
/// frame. Used by reply_transfer test 14 to commit a write-cap
/// receiver's PC modification onto the suspended EC's saved frame.
pub fn setEventRip(ctx: *ArchCpuContext, value: u64) void {
    ctx.elr_el1 = value;
}

/// Companion read for `writeUserVreg14`. Spec §[event_state] aarch64
/// maps vreg 14 onto x13, so the receiver's modification rides in the
/// saved x13 of its syscall frame — not on the user stack. Mirrors
/// `writeUserVreg14`'s `ctx.regs.x13` target.
pub fn readUserVreg14(ctx: *const ArchCpuContext) u64 {
    return ctx.regs.x13;
}

/// Spec §[event_state]: vreg 14 carries the suspended EC's saved PC
/// across both arches. On aarch64 vreg 14 is GPR-backed at x13 — write
/// the saved PC into the receiver's saved x13 so the recv-time
/// snapshot surfaces it. Mirrors x86-64's `[user_rsp + 8]` write but
/// targets a register slot rather than a user page, so no PAN gate is
/// needed and TTBR0 may reference any address space.
pub fn writeUserVreg14(ctx: *ArchCpuContext, value: u64) void {
    ctx.regs.x13 = value;
}

/// Spec §[syscall_abi]: vreg 0 sits at `[user_sp + 0]` on the user
/// stack — recv's success-return packs reply_handle_id / event_type /
/// pair_count / tstart there per §[event_state]. TTBR0_EL1 must
/// reference the EC's address space when called (the rendezvous wake
/// path defers this write to `loadEcContextAndReturn` after the
/// TTBR0 swap). PAN is cleared for the write.
pub fn writeUserSyscallWord(ctx: *const ArchCpuContext, value: u64) void {
    cpu.panDisable();
    @as(*u64, @ptrFromInt(ctx.sp_el0)).* = value;
    cpu.panEnable();
}

/// Copy the §[event_state] GPR-backed vregs (vregs 1..13 on aarch64:
/// x0..x12) from `src` to `dst`. Companion to x86-64's `copyEventStateGprs`;
/// used by `reply` (Spec §[reply] test 05) to apply the receiver's vreg
/// modifications onto the suspended EC's saved iret frame when the
/// originating EC handle held the `write` cap.
///
/// Only vregs 1..13 are propagated — those are the spec's writable
/// event-state GPR window. The wholesale `dst.regs = src.regs` shape
/// would clobber x13..x30 (vreg 14 = suspended PC, plus AAPCS64
/// callee-saved x19..x28, FP x29, and LR x30). LR corruption in
/// particular makes the resumed EC `RET` to the receiver's stack frame
/// instead of returning from its own `svc`, which silently traps the
/// post-resume control flow (including the `delete(SLOT_SELF)` tail in
/// `libz/start.zig`) — domains never tear down, leaked timer/PMM state
/// accumulates per test, and the in-kernel-parallel runner stalls in
/// `createCapabilityDomain` once PMM blocks are exhausted.
pub fn copyEventStateGprs(dst: *ArchCpuContext, src: *const ArchCpuContext) void {
    dst.regs.x0 = src.regs.x0;
    dst.regs.x1 = src.regs.x1;
    dst.regs.x2 = src.regs.x2;
    dst.regs.x3 = src.regs.x3;
    dst.regs.x4 = src.regs.x4;
    dst.regs.x5 = src.regs.x5;
    dst.regs.x6 = src.regs.x6;
    dst.regs.x7 = src.regs.x7;
    dst.regs.x8 = src.regs.x8;
    dst.regs.x9 = src.regs.x9;
    dst.regs.x10 = src.regs.x10;
    dst.regs.x11 = src.regs.x11;
    dst.regs.x12 = src.regs.x12;
}

/// Snapshot the suspending EC's GPR-backed vregs 1..13 in canonical
/// vreg order. Spec §[event_state] aarch64 maps vregs 1..13 onto
/// x0..x12.
pub fn getEventStateGprs(ctx: *const ArchCpuContext) [13]u64 {
    return .{
        ctx.regs.x0,
        ctx.regs.x1,
        ctx.regs.x2,
        ctx.regs.x3,
        ctx.regs.x4,
        ctx.regs.x5,
        ctx.regs.x6,
        ctx.regs.x7,
        ctx.regs.x8,
        ctx.regs.x9,
        ctx.regs.x10,
        ctx.regs.x11,
        ctx.regs.x12,
    };
}

/// Project a vreg 1..13 GPR snapshot onto a receiving EC's frame in
/// canonical vreg order. Companion to `getEventStateGprs`.
pub fn setEventStateGprs(ctx: *ArchCpuContext, gprs: [13]u64) void {
    ctx.regs.x0 = gprs[0];
    ctx.regs.x1 = gprs[1];
    ctx.regs.x2 = gprs[2];
    ctx.regs.x3 = gprs[3];
    ctx.regs.x4 = gprs[4];
    ctx.regs.x5 = gprs[5];
    ctx.regs.x6 = gprs[6];
    ctx.regs.x7 = gprs[7];
    ctx.regs.x8 = gprs[8];
    ctx.regs.x9 = gprs[9];
    ctx.regs.x10 = gprs[10];
    ctx.regs.x11 = gprs[11];
    ctx.regs.x12 = gprs[12];
}

/// Write syscall-return vreg `idx` per Spec §[syscall_abi] aarch64
/// mapping (`docs/kernel/specv3.md` §[syscall_abi], table "vreg mapping
/// (aarch64)"):
///   vreg 1..31  → x0..x30 (`vreg N → x(N-1)`)
///   vreg 32..127 → `[ctx.sp_el0 + (idx - 31) * 8]` on the user stack
///
/// Caller MUST already be in the target EC's address space (TTBR0_EL1)
/// when `idx >= 32`; PAN is cleared internally for the user-page write.
/// See `arch.dispatch.syscall.setSyscallVreg` for the cross-arch
/// contract.
pub fn setSyscallVreg(ctx: *ArchCpuContext, idx: u8, value: u64) void {
    switch (idx) {
        0 => @panic("setSyscallVreg: vreg 0 is the syscall word — use writeUserSyscallWord"),
        1 => ctx.regs.x0 = value,
        2 => ctx.regs.x1 = value,
        3 => ctx.regs.x2 = value,
        4 => ctx.regs.x3 = value,
        5 => ctx.regs.x4 = value,
        6 => ctx.regs.x5 = value,
        7 => ctx.regs.x6 = value,
        8 => ctx.regs.x7 = value,
        9 => ctx.regs.x8 = value,
        10 => ctx.regs.x9 = value,
        11 => ctx.regs.x10 = value,
        12 => ctx.regs.x11 = value,
        13 => ctx.regs.x12 = value,
        14 => ctx.regs.x13 = value,
        15 => ctx.regs.x14 = value,
        16 => ctx.regs.x15 = value,
        17 => ctx.regs.x16 = value,
        18 => ctx.regs.x17 = value,
        19 => ctx.regs.x18 = value,
        20 => ctx.regs.x19 = value,
        21 => ctx.regs.x20 = value,
        22 => ctx.regs.x21 = value,
        23 => ctx.regs.x22 = value,
        24 => ctx.regs.x23 = value,
        25 => ctx.regs.x24 = value,
        26 => ctx.regs.x25 = value,
        27 => ctx.regs.x26 = value,
        28 => ctx.regs.x27 = value,
        29 => ctx.regs.x28 = value,
        30 => ctx.regs.x29 = value,
        31 => ctx.regs.x30 = value,
        32...127 => {
            const off: u64 = @as(u64, idx - 31) * 8;
            cpu.panDisable();
            @as(*u64, @ptrFromInt(ctx.sp_el0 + off)).* = value;
            cpu.panEnable();
        },
        else => @panic("setSyscallVreg: vreg index out of range (0..127)"),
    }
}

