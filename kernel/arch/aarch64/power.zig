//! AArch64 power management via PSCI (Power State Coordination Interface).
//!
//! PSCI is ARM's standard firmware interface for power management. The kernel
//! calls PSCI functions via SMC (Secure Monitor Call) or HVC (Hypervisor Call)
//! depending on the conduit discovered from the ACPI FADT or device tree.
//!
//! PSCI function IDs (DEN0022D, Section 5):
//!   PSCI_VERSION       (0x84000000): Query PSCI version — Section 5.1.1
//!   CPU_SUSPEND        (0xC4000001): Enter low-power state — Section 5.1.2
//!   CPU_OFF            (0x84000002): Power down calling core — Section 5.1.3
//!   CPU_ON             (0xC4000003): Bring a core online — Section 5.1.4
//!   SYSTEM_OFF         (0x84000008): Shutdown the system — Section 5.1.7
//!   SYSTEM_RESET       (0x84000009): Reboot the system — Section 5.1.8
//!   SYSTEM_RESET2      (0xC4000012): Reboot with reason code — Section 5.1.9
//!   SYSTEM_SUSPEND     (0xC400000E): Suspend to RAM — Section 5.1.10
//!
//! Conduit detection:
//!   ACPI FADT (Section 5.2.9): ARM Boot Architecture Flags bit 1 = PSCI compliant.
//!   PSCI node in ACPI DSDT gives the conduit method (SMC or HVC).
//!
//! Dispatch interface mapping:
//!   powerAction(.shutdown)   -> PSCI SYSTEM_OFF
//!   powerAction(.reboot)     -> PSCI SYSTEM_RESET
//!   powerAction(.sleep)      -> PSCI SYSTEM_SUSPEND
//!   cpuPowerAction(.set_idle) -> PSCI CPU_SUSPEND
//!
//! References:
//! - ARM DEN 0022D: PSCI 1.1 Specification
//! - ACPI 6.5, Section 5.2.9: FADT ARM Boot Architecture Flags

const stygia = @import("stygia");

const cpu = stygia.arch.aarch64.cpu;

// --- PSCI return codes (DEN0022D, Table 6) ---

const PSCI_SUCCESS: i64 = 0;
const PSCI_NOT_SUPPORTED: i64 = -1;
const PSCI_INVALID_PARAMETERS: i64 = -2;
const PSCI_DENIED: i64 = -3;
const PSCI_ALREADY_ON: i64 = -4;
const PSCI_ON_PENDING: i64 = -5;
const PSCI_INTERNAL_FAILURE: i64 = -6;
const PSCI_NOT_PRESENT: i64 = -7;
const PSCI_DISABLED: i64 = -8;
const PSCI_INVALID_ADDRESS: i64 = -9;

// --- Kernel error codes ---

const E_OK: i64 = 0;
const E_NODEV: i64 = -13;

// --- PSCI function IDs (DEN0022D, Section 5) ---
// SMC32 variants use 0x8400_xxxx prefix, SMC64 variants use 0xC400_xxxx.

const PSCI_VERSION: u32 = 0x84000000; // Section 5.1.1
const CPU_SUSPEND_64: u32 = 0xC4000001; // Section 5.1.2 (SMC64)
const CPU_OFF: u32 = 0x84000002; // Section 5.1.3
const CPU_ON_64: u32 = 0xC4000003; // Section 5.1.4 (SMC64)
const SYSTEM_OFF: u32 = 0x84000008; // Section 5.1.7
const SYSTEM_RESET: u32 = 0x84000009; // Section 5.1.8
const SYSTEM_RESET2_64: u32 = 0xC4000012; // Section 5.1.9 (SMC64)
const SYSTEM_SUSPEND_64: u32 = 0xC400000E; // Section 5.1.10 (SMC64)

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

/// System-wide power actions.
/// Spec SS2.19, SS4.61.
pub const PowerAction = enum(u8) {
    shutdown = 0,
    reboot = 1,
    sleep = 2,
    hibernate = 3,
    screen_off = 4,
};

/// Per-CPU power actions.
/// Spec SS2.19, SS4.62.
pub const CpuPowerAction = enum(u8) {
    set_freq = 0,
    set_idle = 1,
};

/// Set the PSCI conduit. Called during init after parsing ACPI FADT or device
/// tree to determine whether firmware expects SMC or HVC.
pub fn setConduit(c: Conduit) void {
    conduit = c;
}

/// True when PSCI is the platform power-management interface — the
/// kernel's only route for `power_set_idle` (CPU_SUSPEND) and the
/// system-level shutdown / reset / suspend actions on aarch64. PSCI is
/// mandatory on the targets the kernel currently supports (the BSP /
/// AP bring-up itself goes through PSCI CPU_ON), so by the time
/// userspace can call `info_cores` the answer is always true. Surfaces
/// through `info_cores` flag bit 1 (idle states supported) per spec
/// §[system_info].
pub fn psciAvailable() bool {
    return true;
}

/// Perform a system-wide power action.
/// Spec SS4.61; systems.md SS25.
pub fn powerAction(action: PowerAction) i64 {
    switch (action) {
        .shutdown => doShutdown(),
        .reboot => doReboot(),
        .sleep => return doSuspend(),
        .hibernate => return E_NODEV,
        .screen_off => return E_NODEV,
    }
}

/// Perform a per-CPU power action.
/// Spec SS4.62; systems.md SS25.
pub fn cpuPowerAction(action: CpuPowerAction, value: u64) i64 {
    return switch (action) {
        .set_freq => E_NODEV,
        .set_idle => {
            // DEN0022D, Section 5.1.2: CPU_SUSPEND enters a low-power state.
            // The power_state parameter encodes the target idle level.
            // Bits [27:24] = StateType (0=standby, 1=powerdown),
            // Bits [15:0] = StateID (platform-specific).
            return psciCall(CPU_SUSPEND_64, value, 0, 0);
        },
    };
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

/// Shutdown the system via PSCI SYSTEM_OFF.
/// DEN0022D, Section 5.1.7: SYSTEM_OFF powers down the entire system.
/// Does not return on success.
fn doShutdown() noreturn {
    _ = psciCall(SYSTEM_OFF, 0, 0, 0);
    // SYSTEM_OFF should not return. If it does, halt forever.
    while (true) cpu.halt();
}

/// Reboot the system via PSCI SYSTEM_RESET.
/// DEN0022D, Section 5.1.8: SYSTEM_RESET performs a cold reset of the system.
/// Does not return on success.
fn doReboot() noreturn {
    _ = psciCall(SYSTEM_RESET, 0, 0, 0);
    // SYSTEM_RESET should not return. If it does, halt forever.
    while (true) cpu.halt();
}

/// Suspend the system to RAM via PSCI SYSTEM_SUSPEND.
/// DEN0022D, Section 5.1.10: SYSTEM_SUSPEND suspends the system; on resume,
/// execution continues at the provided entry point.
/// Returns PSCI_SUCCESS (0) on successful resume, or a negative error code.
fn doSuspend() i64 {
    // entry_point = 0 means resume at the return address (caller context).
    // context_id = 0: no context needed for resume.
    const ret = psciCall(SYSTEM_SUSPEND_64, 0, 0, 0);
    return if (ret == PSCI_SUCCESS) E_OK else mapPsciError(ret);
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

/// Map PSCI error codes to kernel error codes.
fn mapPsciError(psci_ret: i64) i64 {
    return switch (psci_ret) {
        PSCI_SUCCESS => E_OK,
        PSCI_NOT_SUPPORTED => E_NODEV,
        PSCI_INVALID_PARAMETERS => E_NODEV,
        PSCI_DENIED => E_NODEV,
        PSCI_ALREADY_ON => E_OK,
        PSCI_ON_PENDING => E_OK,
        PSCI_INTERNAL_FAILURE => E_NODEV,
        PSCI_NOT_PRESENT => E_NODEV,
        PSCI_DISABLED => E_NODEV,
        PSCI_INVALID_ADDRESS => E_NODEV,
        else => E_NODEV,
    };
}
