//! AArch64 VM dispatch surface.
//!
//! The aarch64 KVM port is not in the spec-v3 critical path — the test
//! runner is x86_64-only — so this module exposes only the small dispatch
//! surface `arch/dispatch/vm.zig` and the boot handoff path require:
//! `vmInit`, `hyp_stub_installed`, plus the `VmPolicy` per-arch struct
//! seeded by `create_virtual_machine`.

/// Set true by the bootloader-driven boot handoff path when the kernel
/// arrived at EL2 (UEFI drops us at EL1 and leaves this false). Public
/// so `dispatch/vm.zig` can flip it before `installHypVectors`.
pub var hyp_stub_installed: bool = false;

/// Global VM subsystem init. Stubbed — the spec-v3 aarch64 port does
/// not advertise hardware virtualization, so `vmSupported`-style
/// callers in the dispatch layer naturally short-circuit.
pub fn vmInit() void {}

/// Per-core hardware-virtualization init. Stub on aarch64 until the
/// EL2 / stage-2 scaffolding is restored.
pub fn vmPerCoreInit() void {}

/// Per-arch VM policy struct seeded into the policy page frame at
/// create_virtual_machine time. Spec §[vm_policy] aarch64 layout:
///
///     offset    field
///     0..991    id_reg_responses[62]              (62 * 16 = 992)
///     992..995  num_id_reg_responses (u32)
///     996..999  _pad0 (u32)
///     1000..1767 sysreg_policies[32]              (32 * 24 = 768)
///     1768..1771 num_sysreg_policies (u32)
///     1772..1775 _pad1 (u32)
///
/// Total = 1776 bytes — fits inside a single 4 KiB page.
///
/// Sysreg identifiers `(op0, op1, crn, crm, op2)` follow Arm ARM C5.3.
pub const VmPolicy = extern struct {
    /// Pre-configured `ID_AA64*` register responses. A guest read of
    /// an ID register matching `(op0, op1, crn, crm, op2)` here resumes
    /// with `value` inline; non-matching ID reads deliver a vm_exit.
    /// Writes to ID registers are silently ignored per spec.
    id_reg_responses: [MAX_ID_REG_RESPONSES]IdRegResponse =
        .{IdRegResponse{}} ** MAX_ID_REG_RESPONSES,
    num_id_reg_responses: u32 = 0,
    _pad0: u32 = 0,

    /// Sysreg access policies. A guest sysreg read matching the tuple
    /// here resumes with `read_value`; a guest write is applied masked
    /// by `write_mask`. Non-matching sysreg accesses deliver a vm_exit.
    sysreg_policies: [MAX_SYSREG_POLICIES]SysregPolicy =
        .{SysregPolicy{}} ** MAX_SYSREG_POLICIES,
    num_sysreg_policies: u32 = 0,
    _pad1: u32 = 0,

    pub const MAX_ID_REG_RESPONSES = 62;
    pub const MAX_SYSREG_POLICIES = 32;

    pub const IdRegResponse = extern struct {
        op0: u8 = 0,
        op1: u8 = 0,
        crn: u8 = 0,
        crm: u8 = 0,
        op2: u8 = 0,
        _pad: [3]u8 = .{0} ** 3,
        value: u64 = 0,
    };

    pub const SysregPolicy = extern struct {
        op0: u8 = 0,
        op1: u8 = 0,
        crn: u8 = 0,
        crm: u8 = 0,
        op2: u8 = 0,
        _pad: [3]u8 = .{0} ** 3,
        read_value: u64 = 0,
        write_mask: u64 = 0,
    };
};

comptime {
    const std = @import("std");
    // Spec §[vm_policy] aarch64: VmPolicy is 1776 bytes; lock the
    // size in so any layout drift trips a build error.
    std.debug.assert(@sizeOf(VmPolicy) == 1776);
    std.debug.assert(@offsetOf(VmPolicy, "num_id_reg_responses") == 992);
    std.debug.assert(@offsetOf(VmPolicy, "num_sysreg_policies") == 1768);
}
