//! AArch64 KVM object layer index. Mirrors `kernel/arch/x64/hv/hv.zig`.
//! Built on top of the arch-specific primitive layer in `arch/aarch64/vm.zig`.
//! `vgic.zig` is the aarch64 equivalent of `x64/hv/lapic.zig` + `x64/hv/ioapic.zig`.
pub const psci = @import("psci.zig");
pub const vcpu = @import("vcpu.zig");
pub const vgic = @import("vgic.zig");
pub const vm = @import("vm.zig");
