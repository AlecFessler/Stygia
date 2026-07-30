//! EL2 exception vectors for the Raspberry Pi 5 native loader.
//!
//! Without these, a fault in the loader has nowhere to land and the CPU wedges.
//! On this board a wedge is expensive in a way it is not on QEMU: `tryboot`'s
//! one-shot fallback is triggered by a RESET, and a hung core never resets, so
//! the board stays dark until someone physically pulls power — and a cold boot
//! erases the DRAM early log, destroying the only evidence of what went wrong.
//! That is not hypothetical; it is exactly how the first map-synthesis boot was
//! lost.
//!
//! So the contract here is: any exception logs the diagnostic registers and then
//! PSCI-resets. A reset both recovers the board unattended AND preserves the log
//! (DRAM survives the warm reset firmware performs), which converts a silent
//! brick into a precise, readable diagnosis.
//!
//! This is a debugging aid, not a fault handler — nothing is recoverable and
//! nothing resumes. It exists purely so failures are legible.
//!
//! ARM ARM D13.2.148: VBAR_EL2 must be 2 KiB aligned, and the table is 16 slots
//! of 0x80 bytes covering the four exception classes across four source states.
//!
//! This table serves BOTH exception levels. `install()` puts it in VBAR_EL2, and
//! `aarch64_el2_drop.zig :: dropToEl1` then mirrors VBAR_EL2 into VBAR_EL1, so it
//! also catches EL1 faults from the ERET until the kernel's `exceptions.install()`
//! replaces it a few calls into `kMain`. The trampoline reads the syndrome
//! registers of whichever EL it was entered at — see the comment there; getting
//! that wrong makes the EL1 half of the window silently undiagnosable.

const log = @import("early_log.zig");

const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;

/// Human-readable names for the 16 vector slots, so the log says what happened
/// instead of making the reader count offsets.
const SLOT_NAMES = [16][]const u8{
    "sync   (EL2t)",  "irq    (EL2t)",  "fiq    (EL2t)",  "serror (EL2t)",
    "sync   (EL2h)",  "irq    (EL2h)",  "fiq    (EL2h)",  "serror (EL2h)",
    "sync   (lower, A64)", "irq (lower, A64)", "fiq (lower, A64)", "serror (lower, A64)",
    "sync   (lower, A32)", "irq (lower, A32)", "fiq (lower, A32)", "serror (lower, A32)",
};

/// Decode the ESR exception class. Only the classes this loader can plausibly
/// hit are named; anything else prints raw. EC is ESR bits [31:26].
fn describeEc(ec: u64) []const u8 {
    return switch (ec) {
        0x00 => "unknown reason",
        0x07 => "SIMD/FP access trapped (CPACR/CPTR)",
        0x0E => "illegal execution state",
        0x16 => "HVC from EL2",
        0x18 => "trapped MSR/MRS/system insn",
        0x20 => "instruction abort, lower EL",
        0x21 => "instruction abort, same EL",
        0x22 => "PC alignment fault",
        0x24 => "data abort, lower EL",
        // The most likely landing spot for this loader while the MMU is off:
        // SCTLR_EL2.M=0 makes memory Device-nGnRnE, which forbids unaligned and
        // multi-register access, so a NEON struct copy shows up here as EC=0x25
        // with DFSC=0x21 (alignment fault) — NOT as EC=0x26.
        0x25 => "data abort, same EL",
        0x26 => "SP alignment fault",
        0x2F => "SError",
        else => "see ARM ARM D13.2.37 for EC",
    };
}

/// Data/instruction abort fault status code, ESR bits [5:0]. Distinguishing an
/// alignment fault from a translation fault is the whole ballgame when the MMU
/// is off.
fn describeDfsc(dfsc: u64) []const u8 {
    return switch (dfsc) {
        0x21 => "alignment fault",
        0x10 => "external abort (synchronous)",
        0x00...0x03 => "address size fault",
        0x04...0x07 => "translation fault",
        0x09...0x0B => "access flag fault",
        0x0D...0x0F => "permission fault",
        else => "other DFSC",
    };
}

export fn pi5FaultReport(esr: u64, elr: u64, far: u64, slot: u64, el: u64) noreturn {
    log.str("\n*** EL");
    log.dec(el);
    log.str(" EXCEPTION ***\n");
    log.str("  vector slot ");
    log.dec(slot);
    if (slot < SLOT_NAMES.len) {
        log.str("  ");
        log.str(SLOT_NAMES[slot]);
    }
    log.byte('\n');

    const ec = (esr >> 26) & 0x3F;
    log.str("  ESR = ");
    log.hex(esr);
    log.str("  EC=");
    log.hex(ec);
    log.str("  ");
    log.str(describeEc(ec));
    log.byte('\n');

    // FAR and the fault status code are only meaningful for aborts.
    if (ec == 0x20 or ec == 0x21 or ec == 0x24 or ec == 0x25) {
        const dfsc = esr & 0x3F;
        log.str("  DFSC = ");
        log.hex(dfsc);
        log.str("  ");
        log.str(describeDfsc(dfsc));
        log.byte('\n');
        log.str("  FAR = ");
        log.hex(far);
        log.byte('\n');
    }

    log.str("  ELR = ");
    log.hex(elr);
    log.str("   <- faulting instruction; disassemble the image at this address\n");
    log.str("  (loader links at 0x80000, so subtract that for a file offset)\n");
    log.commit();

    asm volatile ("smc #0"
        :
        : [fid] "{x0}" (PSCI_SYSTEM_RESET),
        : .{ .memory = true });

    log.str("*** PSCI SYSTEM_RESET returned after a fault; board will hang\n");
    log.commit();
    while (true) asm volatile ("wfe");
}

/// Install this table in VBAR_EL2. Call as early as possible — every line of
/// loader code that runs before this is a line whose faults are invisible.
pub fn install() void {
    const base = @intFromPtr(&pi5Vectors);
    // A misaligned VBAR silently truncates, sending exceptions to the wrong
    // address, so assert rather than debug that later.
    if (base & 0x7FF != 0) {
        log.str("*** vector table misaligned: ");
        log.hex(base);
        log.byte('\n');
        log.commit();
        return;
    }
    asm volatile (
        \\ msr vbar_el2, %[base]
        \\ isb
        :
        : [base] "r" (base),
        : .{ .memory = true });
}

/// The vector table itself.
///
/// Each of the 16 slots records its index in x3 and branches to the common
/// trampoline. `.balign 0x80` enforces the architectural slot spacing; the
/// leading `.balign 0x800` satisfies VBAR_EL2's 2 KiB alignment requirement
/// independently of where the linker places the section.
pub export fn pi5Vectors() align(2048) linksection(".text.vectors") callconv(.naked) noreturn {
    asm volatile (
        \\ .balign 0x800
        \\ mov x3, #0
        \\ b   pi5FaultCommon
        \\ .balign 0x80
        \\ mov x3, #1
        \\ b   pi5FaultCommon
        \\ .balign 0x80
        \\ mov x3, #2
        \\ b   pi5FaultCommon
        \\ .balign 0x80
        \\ mov x3, #3
        \\ b   pi5FaultCommon
        \\ .balign 0x80
        \\ mov x3, #4
        \\ b   pi5FaultCommon
        \\ .balign 0x80
        \\ mov x3, #5
        \\ b   pi5FaultCommon
        \\ .balign 0x80
        \\ mov x3, #6
        \\ b   pi5FaultCommon
        \\ .balign 0x80
        \\ mov x3, #7
        \\ b   pi5FaultCommon
        \\ .balign 0x80
        \\ mov x3, #8
        \\ b   pi5FaultCommon
        \\ .balign 0x80
        \\ mov x3, #9
        \\ b   pi5FaultCommon
        \\ .balign 0x80
        \\ mov x3, #10
        \\ b   pi5FaultCommon
        \\ .balign 0x80
        \\ mov x3, #11
        \\ b   pi5FaultCommon
        \\ .balign 0x80
        \\ mov x3, #12
        \\ b   pi5FaultCommon
        \\ .balign 0x80
        \\ mov x3, #13
        \\ b   pi5FaultCommon
        \\ .balign 0x80
        \\ mov x3, #14
        \\ b   pi5FaultCommon
        \\ .balign 0x80
        \\ mov x3, #15
        \\ b   pi5FaultCommon
        \\ .balign 0x80
        \\
        // Common trampoline. Switches to a dedicated fault stack before calling
        // into Zig, because the fault may itself have been a stack problem and
        // reusing a broken SP would fault again inside the handler — producing a
        // silent double-fault loop instead of a report.
        //
        // The EL check is not defensive padding. Once `handoff.zig` drops to EL1,
        // `dropToEl1` mirrors VBAR_EL2 into VBAR_EL1, so THIS table also handles
        // EL1 exceptions for the whole window between the ERET and the kernel's
        // `exceptions.install()`. `mrs x0, esr_el2` is UNDEFINED at EL1, so the
        // EL2-only version of this trampoline turned any fault in that window
        // into a synchronous exception inside the handler, i.e. an infinite
        // recursion that the watchdog eventually resets with an empty log — the
        // exact failure mode this file exists to prevent, arriving one exception
        // level down.
        \\pi5FaultCommon:
        \\ mrs  x4, CurrentEL
        \\ ubfx x4, x4, #2, #2
        \\ cmp  x4, #2
        \\ b.ne 6f
        \\ mrs  x0, esr_el2
        \\ mrs  x1, elr_el2
        \\ mrs  x2, far_el2
        \\ b    7f
        \\6:
        \\ mrs  x0, esr_el1
        \\ mrs  x1, elr_el1
        \\ mrs  x2, far_el1
        \\7:
        \\ ldr x5, =__fault_stack_top
        \\ mov sp, x5
        \\ bl  pi5FaultReport
        \\5:
        \\ wfe
        \\ b   5b
    );
}
