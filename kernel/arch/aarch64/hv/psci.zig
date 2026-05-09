//! ARM PSCI (Power State Coordination Interface) hypercall dispatch.
//!
//! Arm DEN 0022F defines an SMCCC-compatible function namespace in
//! 0x8400_0000..0x8400_001F (SMC32) and 0xC400_0000..0xC400_001F (SMC64)
//! that guests use for CPU on/off, system reset, and version discovery.
//!
//! Linux's arm64 boot protocol requires the firmware to respond to PSCI
//! calls to bring up secondary CPUs (Documentation/arm64/booting.rst,
//! "CPU Power States"). For the busybox-init bring-up path we run a
//! single-vCPU guest and SMP=1 Linux works with PSCI returning
//! NOT_SUPPORTED for all real ops — `init` brings the system up before
//! any CPU_ON call is needed.
//!
//! References:
//! - Arm DEN 0022F: Arm Power State Coordination Interface (PSCI)
//! - Arm DEN 0028D: SMC Calling Convention (SMCCC)

const stygia = @import("stygia");

const vm_hw = stygia.arch.aarch64.vm;

const GuestState = vm_hw.GuestState;

/// SMCCC function IDs for PSCI. Values taken from DEN 0022F Table 5.1.
pub const FunctionId = enum(u32) {
    psci_version = 0x8400_0000,
    cpu_suspend = 0xC400_0001,
    cpu_off = 0x8400_0002,
    cpu_on = 0xC400_0003,
    affinity_info = 0xC400_0004,
    migrate = 0xC400_0005,
    migrate_info_type = 0x8400_0006,
    migrate_info_up_cpu = 0xC400_0007,
    system_off = 0x8400_0008,
    system_reset = 0x8400_0009,
    psci_features = 0x8400_000A,
    _,
};

/// PSCI return codes (DEN 0022F §5.2.2).
pub const ReturnCode = enum(i32) {
    success = 0,
    not_supported = -1,
    invalid_parameters = -2,
    denied = -3,
    already_on = -4,
    on_pending = -5,
    internal_failure = -6,
    not_present = -7,
    disabled = -8,
    invalid_address = -9,
};

pub const VERSION_1_2: u32 = 0x0001_0002;

/// Dispatch result.
///   `handled`        — call resolved inline, x0 written, caller should
///                      advance PC and resume the guest.
///   `forward_to_vmm` — fid outside PSCI window or deferred function;
///                      surface as an SMCCC exit.
pub const Outcome = enum { handled, forward_to_vmm };

/// Dispatch an HVC/SMC call whose X0 holds an SMCCC function ID. For
/// the single-vCPU busybox boot path:
///   * PSCI_VERSION returns 1.2 so Linux's PSCI driver registers a real
///     version (returning NOT_SUPPORTED here makes Linux print
///     "PSCIv65535.65535 detected" and bias its boot path on a bogus
///     value — confuses the early arm-timer init).
///   * AFFINITY_INFO(self, 0) returns 0 (ON); other targets return 1
///     (OFF) so a single-vCPU guest doesn't try to bring up CPU 1.
///   * MIGRATE_INFO_TYPE returns 2 (MIGRATE not required).
///   * Everything else returns NOT_SUPPORTED — single-vCPU guests don't
///     hit CPU_ON/CPU_OFF in this path.
pub fn dispatch(guest_state: *GuestState) Outcome {
    const fid_raw: u32 = @truncate(guest_state.x0);
    const fid: FunctionId = @enumFromInt(fid_raw);

    const reply: u64 = switch (fid) {
        .psci_version => @as(u64, VERSION_1_2),
        .affinity_info => blk: {
            // x1 = target affinity (MPIDR). Single-vCPU guest: only 0 is ON.
            const target_aff: u64 = guest_state.x1;
            break :blk if (target_aff == 0) 0 else 1; // ON / OFF
        },
        .migrate_info_type => @as(u64, 2), // MIGRATE not required (DEN0022F §5.10)
        .cpu_suspend,
        .cpu_off,
        .cpu_on,
        .migrate,
        .migrate_info_up_cpu,
        .system_off,
        .system_reset,
        .psci_features,
        => @bitCast(@as(i64, @intFromEnum(ReturnCode.not_supported))),
        _ => return .forward_to_vmm,
    };

    guest_state.x0 = reply;
    return .handled;
}

/// SMCCC function-ID range reserved for PSCI (DEN 0022F §5.1).
pub const SMCCC_PSCI_RANGE_LOW: u32 = 0x8400_0000;
pub const SMCCC_PSCI_RANGE_HIGH: u32 = 0x8400_001F;
pub const SMCCC_PSCI_RANGE64_LOW: u32 = 0xC400_0000;
pub const SMCCC_PSCI_RANGE64_HIGH: u32 = 0xC400_001F;

pub fn isPsciFid(fid: u32) bool {
    return (fid >= SMCCC_PSCI_RANGE_LOW and fid <= SMCCC_PSCI_RANGE_HIGH) or
        (fid >= SMCCC_PSCI_RANGE64_LOW and fid <= SMCCC_PSCI_RANGE64_HIGH);
}
