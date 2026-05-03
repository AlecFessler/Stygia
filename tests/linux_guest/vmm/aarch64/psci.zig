//! VMM-side PSCI (Power State Coordination Interface) handler.
//!
//! Arm DEN 0022F defines the SMCCC function namespace PSCI guests call via
//! HVC/SMC. The kernel's `kernel/arch/aarch64/kvm/psci.zig` currently
//! returns NOT_SUPPORTED for every function and (per M7) will forward the
//! HVC exit to the VMM unchanged. This module supplies real bodies for
//! the subset a single-vCPU Linux arm64 guest actually calls during boot.
//!
//! Only the SMC64 entry points (bit 30 set) are exposed to the guest via
//! the FDT; we still accept the SMC32 aliases for robustness. Linux's
//! drivers/firmware/psci/psci.c logs the PSCI version and queries
//! FEATURES / AFFINITY_INFO / CPU_ON during SMP bringup.

pub const PSCI_VERSION_1_2: u32 = 0x0001_0002;

pub const Function = struct {
    pub const VERSION: u32 = 0x8400_0000;
    pub const CPU_SUSPEND32: u32 = 0x8400_0001;
    pub const CPU_OFF: u32 = 0x8400_0002;
    pub const CPU_ON32: u32 = 0x8400_0003;
    pub const AFFINITY_INFO32: u32 = 0x8400_0004;
    pub const MIGRATE32: u32 = 0x8400_0005;
    pub const MIGRATE_INFO_TYPE: u32 = 0x8400_0006;
    pub const MIGRATE_INFO_UP_CPU32: u32 = 0x8400_0007;
    pub const SYSTEM_OFF: u32 = 0x8400_0008;
    pub const SYSTEM_RESET: u32 = 0x8400_0009;
    pub const FEATURES: u32 = 0x8400_000A;
    pub const CPU_SUSPEND64: u32 = 0xC400_0001;
    pub const CPU_ON64: u32 = 0xC400_0003;
    pub const AFFINITY_INFO64: u32 = 0xC400_0004;
    pub const MIGRATE64: u32 = 0xC400_0005;
    pub const MIGRATE_INFO_UP_CPU64: u32 = 0xC400_0007;
};

/// DEN 0022F §5.2.2 Table 5-2. Negative values because the guest
/// interprets the return as a signed 32-bit.
pub const Ret = struct {
    pub const SUCCESS: u64 = 0;
    pub const NOT_SUPPORTED: u64 = @bitCast(@as(i64, -1));
    pub const INVALID_PARAMETERS: u64 = @bitCast(@as(i64, -2));
    pub const DENIED: u64 = @bitCast(@as(i64, -3));
    pub const ALREADY_ON: u64 = @bitCast(@as(i64, -4));
    pub const INTERNAL_FAILURE: u64 = @bitCast(@as(i64, -6));
};

/// AFFINITY_INFO values (DEN 0022F §5.1.8).
pub const Aff = struct {
    pub const ON: u64 = 0;
    pub const OFF: u64 = 1;
    pub const ON_PENDING: u64 = 2;
};

pub const Outcome = struct {
    /// Value the guest should observe in X0 when the HVC resumes.
    x0: u64,
    /// Set by SYSTEM_OFF / SYSTEM_RESET to tell the main loop to stop.
    terminate: bool = false,
};

/// Dispatch a PSCI call. `x0..x3` are the SMCCC argument registers as
/// the guest presented them at the HVC instruction.
pub fn dispatch(x0: u64, x1: u64, x2: u64, x3: u64) Outcome {
    _ = x2;
    _ = x3;
    const fid: u32 = @truncate(x0);

    return switch (fid) {
        Function.VERSION => .{ .x0 = PSCI_VERSION_1_2 },

        Function.SYSTEM_OFF => .{ .x0 = Ret.SUCCESS, .terminate = true },
        Function.SYSTEM_RESET => .{ .x0 = Ret.SUCCESS, .terminate = true },

        Function.CPU_OFF => .{ .x0 = Ret.SUCCESS, .terminate = true },

        // Only vCPU 0 exists in the M7 skeleton. Any CPU_ON for a
        // non-zero affinity value is reported as NOT_SUPPORTED so Linux
        // continues as a UP kernel.
        Function.CPU_ON32, Function.CPU_ON64 => if (x1 == 0)
            .{ .x0 = Ret.ALREADY_ON }
        else
            .{ .x0 = Ret.NOT_SUPPORTED },

        Function.AFFINITY_INFO32, Function.AFFINITY_INFO64 => if (x1 == 0)
            .{ .x0 = Aff.ON }
        else
            .{ .x0 = Aff.OFF },

        Function.FEATURES => switch (@as(u32, @truncate(x1))) {
            Function.VERSION,
            Function.CPU_OFF,
            Function.CPU_ON64,
            Function.AFFINITY_INFO64,
            Function.SYSTEM_OFF,
            Function.SYSTEM_RESET,
            Function.FEATURES,
            => .{ .x0 = Ret.SUCCESS },
            else => .{ .x0 = Ret.NOT_SUPPORTED },
        },

        Function.MIGRATE_INFO_TYPE => .{ .x0 = 2 }, // "Trusted OS not present"

        else => .{ .x0 = Ret.NOT_SUPPORTED },
    };
}
