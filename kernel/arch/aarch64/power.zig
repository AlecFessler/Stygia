//! AArch64 power management via PSCI (Power State Coordination Interface).
//!
//! PSCI is ARM's standard firmware interface for power management. The kernel
//! calls PSCI functions via SMC (Secure Monitor Call) or HVC (Hypervisor Call)
//! depending on the conduit discovered from the ACPI FADT or device tree.
//!
//! PSCI calls used here (DEN0022D, Section 5): CPU_ON brings secondary
//! cores online; SYSTEM_RESET returns a completed test run to Pi OS.
//!
//! Conduit detection:
//!   ACPI FADT (Section 5.2.9): ARM Boot Architecture Flags bit 1 = PSCI compliant.
//!   PSCI node in ACPI DSDT gives the conduit method (SMC or HVC).
//!
//! Internal users: secondary-core bring-up and test-profile root reboot.
//!
//! References:
//! - ARM DEN 0022D: PSCI 1.1 Specification
//! - ACPI 6.5, Section 5.2.9: FADT ARM Boot Architecture Flags

const stygia = @import("stygia");

const cpu = stygia.arch.aarch64.cpu;
const watchdog = stygia.arch.aarch64.watchdog;
const serial = stygia.arch.aarch64.serial;

// --- PSCI function IDs (DEN0022D, Section 5) ---
const CPU_ON_64: u32 = 0xC4000003;
const SYSTEM_RESET: u32 = 0x84000009;

/// PSCI conduit: SMC (Secure Monitor Call) or HVC (Hypervisor Call).
/// DEN0022D, Section 5.2: The conduit is determined by firmware description
/// (ACPI FADT or device tree). SMC is the default for UEFI-based systems.
pub const Conduit = enum {
    smc,
    hvc,
};

/// Active conduit for PSCI calls. Defaults to SMC; init may switch to HVC
/// based on ACPI FADT or device tree PSCI node.
var conduit: Conduit = .smc;

/// Internal test-profile reboot action.
pub const PowerAction = enum(u8) { reboot = 1 };

/// Set the PSCI conduit. Called during init after parsing ACPI FADT or device
/// tree to determine whether firmware expects SMC or HVC.
pub fn setConduit(c: Conduit) void {
    conduit = c;
}

/// PSCI is required for supported aarch64 SMP targets.
/// Used by the retained system-info path until its separate removal.
pub fn psciAvailable() bool {
    return true;
}

/// Reboot after the test runner root service reports its verdict.
pub fn powerAction(action: PowerAction) i64 {
    switch (action) {
        .reboot => doReboot(),
    }
}

/// Bring a secondary CPU online via PSCI CPU_ON.
/// DEN0022D, Section 5.1.4: CPU_ON wakes a core at entry_point with
/// context_id passed in x0 to the target core.
///
/// Parameters:
///   target_mpidr: MPIDR affinity value of the target core.
///   entry_point:  Physical address the core will begin executing at.
///   context_id:   Value passed to the target core in x0 on entry.
///
/// Return values (DEN0022D, Table 10):
///   0  = SUCCESS
///  -1  = NOT_SUPPORTED
///  -2  = INVALID_PARAMETERS
///  -4  = ALREADY_ON
///  -5  = ON_PENDING
///  -9  = INTERNAL_FAILURE
pub fn cpuOn(target_mpidr: u64, entry_point: u64, context_id: u64) i64 {
    return psciCall(CPU_ON_64, target_mpidr, entry_point, context_id);
}

// --- Internal helpers ---

/// Reboot the system via PSCI SYSTEM_RESET.
/// DEN0022D, Section 5.1.8: SYSTEM_RESET performs a cold reset of the system.
/// Does not return on success.
fn doReboot() noreturn {
    // Drain the UART before handing over to PSCI.
    //
    // `serial.writeByte` only waits for the TX FIFO to be non-full, so up to 32
    // characters can still be queued here, and SYSTEM_RESET does not
    // drain the UART on its way out. Measured on the bare-metal Pi
    // 5 rig: the test runner's cross-run aggregate — the one line a whole
    // unattended run is judged on — arrived as
    // `[runner] === aggregate over 2 runs: 9`, truncated mid-number. A verdict
    // read off a serial console has to survive the reset that follows it.
    serial.flush();
    // Stop petting as a backstop if firmware reset does not complete; only
    // relevant if SYSTEM_RESET is unimplemented and this falls through to the
    // interrupt-taking park below, where continuing to pet would keep a board
    // alive that was asked to reset. On a bare-metal Pi 5 SYSTEM_RESET works
    // (it is the test-profile root-exit path) so this line is never reached
    // to any observable effect; no-op wherever no watchdog was discovered.
    watchdog.stopPetting();
    _ = psciCall(SYSTEM_RESET, 0, 0, 0);
    // SYSTEM_RESET should not return. If it does, halt forever.
    while (true) cpu.halt();
}

/// Invoke a PSCI function via the configured conduit (SMC or HVC).
/// DEN0022D, Section 5.2.1: SMC calling convention — function ID in w0/x0,
/// arguments in x1-x3, return value in x0.
fn psciCall(function_id: u32, arg1: u64, arg2: u64, arg3: u64) i64 {
    return switch (conduit) {
        .smc => smcCall(function_id, arg1, arg2, arg3),
        .hvc => hvcCall(function_id, arg1, arg2, arg3),
    };
}

/// Issue an SMC #0 instruction with the given arguments.
/// ARM ARM C6.2.236: SMC — Secure Monitor Call.
fn smcCall(function_id: u32, arg1: u64, arg2: u64, arg3: u64) i64 {
    // DEN0028E (SMCCC 1.4), Section 2.4: x4-x17 are caller-saved and may be
    // corrupted by the callee. x0-x3 are argument/result registers.
    return asm volatile ("smc #0"
        : [ret] "={x0}" (-> i64),
        : [fid] "{x0}" (@as(u64, function_id)),
          [a1] "{x1}" (arg1),
          [a2] "{x2}" (arg2),
          [a3] "{x3}" (arg3),
        : .{ .x1 = true, .x2 = true, .x3 = true, .x4 = true, .x5 = true, .x6 = true, .x7 = true, .x8 = true, .x9 = true, .x10 = true, .x11 = true, .x12 = true, .x13 = true, .x14 = true, .x15 = true, .x16 = true, .x17 = true, .memory = true });
}

/// Issue an HVC #0 instruction with the given arguments.
/// ARM ARM C6.2.99: HVC — Hypervisor Call.
fn hvcCall(function_id: u32, arg1: u64, arg2: u64, arg3: u64) i64 {
    return asm volatile ("hvc #0"
        : [ret] "={x0}" (-> i64),
        : [fid] "{x0}" (@as(u64, function_id)),
          [a1] "{x1}" (arg1),
          [a2] "{x2}" (arg2),
          [a3] "{x3}" (arg3),
        : .{ .x1 = true, .x2 = true, .x3 = true, .x4 = true, .x5 = true, .x6 = true, .x7 = true, .x8 = true, .x9 = true, .x10 = true, .x11 = true, .x12 = true, .x13 = true, .x14 = true, .x15 = true, .x16 = true, .x17 = true, .memory = true });
}
