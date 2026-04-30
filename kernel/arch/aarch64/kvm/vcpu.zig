//! Aarch64 VCpu dispatch backing.
//!
//! Per-vCPU arch state is a single 4 KiB PMM page hung off the EC's
//! `vcpu_arch_state` slot. The cell is the parking spot for the future
//! aarch64 KVM run-loop's per-vCPU EL2 state (saved guest GPRs/sysregs,
//! vGIC list-register snapshot, last-exit ESR/HPFAR, etc.). Until the
//! EL2 scaffolding is restored the cell carries no payload — alloc /
//! free is enough for `create_vcpu` to return a valid handle and for
//! teardown to release the page.

const std = @import("std");
const zag = @import("zag");

const paging = zag.memory.paging;
const pmm = zag.memory.pmm;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const VirtualMachine = zag.capdom.virtual_machine.VirtualMachine;

pub const VcpuArchState = extern struct {
    _placeholder: u64 align(paging.PAGE4K) = 0,
    _pad: [paging.PAGE4K - @sizeOf(u64)]u8 = undefined,
};

comptime {
    std.debug.assert(@sizeOf(VcpuArchState) == paging.PAGE4K);
    std.debug.assert(@alignOf(VcpuArchState) == paging.PAGE4K);
}

pub fn allocVcpuArchState(vm: *VirtualMachine, vcpu_ec: *ExecutionContext) !void {
    _ = vm;
    const cell = pmm.global_pmm.?.create(VcpuArchState) catch
        return error.OutOfMemory;
    cell.* = .{};
    vcpu_ec.vcpu_arch_state = @ptrCast(cell);
}

pub fn freeVcpuArchState(vcpu_ec: *ExecutionContext) void {
    const erased = vcpu_ec.vcpu_arch_state orelse return;
    const cell: *VcpuArchState = @ptrCast(@alignCast(erased));
    pmm.global_pmm.?.destroy(cell);
    vcpu_ec.vcpu_arch_state = null;
}
