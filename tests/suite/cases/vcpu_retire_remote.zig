// Exercise vCPU retirement while its owner core may be dispatching it.
// The vCPU is pinned away from this test thread. Repeated create/terminate
// cycles also reuse arch-state pages and thread slots, making a premature
// free visible as a kernel fault or a missing suite result. The final vCPU
// is left live for process teardown to exercise destroyThreadRefLockedMode.
// This suite's reply helper does not construct a runnable guest state, so
// this test covers remote ownership/finalization and synthetic initial exits;
// it does not itself exercise VMRESUME with a cached arch-state pointer.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const VM_POLICY_BYTES: usize = 32 * 24 + 8 + 8 * 24 + 8;
const CYCLES = 32;

pub fn main(_: u64) void {
    const pf = syscall.createPageFrame(@as(u64, (caps.PfCap{ .r = true, .w = true }).toU16()), 0, 1);
    if (testing.isHandleError(pf.v1)) return testing.fail(1);
    const pf_handle: caps.HandleId = @truncate(pf.v1 & 0xfff);

    const vmar = syscall.createVmar(@as(u64, (caps.VmarCap{ .r = true, .w = true }).toU16()), 0b011, 1, 0, 0);
    if (testing.isHandleError(vmar.v1)) return testing.fail(1);
    const vmar_handle: caps.HandleId = @truncate(vmar.v1 & 0xfff);
    if (syscall.mapPf(vmar_handle, &.{ 0, pf_handle }).v1 != @intFromEnum(errors.Error.OK)) return testing.fail(1);

    const policy: [*]volatile u8 = @ptrFromInt(vmar.v2);
    for (0..VM_POLICY_BYTES) |i| policy[i] = 0;

    const vm = syscall.createVirtualMachine(@as(u64, (caps.VmCap{ .policy = true }).toU16()), pf_handle);
    if (vm.v1 == @intFromEnum(errors.Error.E_NODEV)) return testing.pass();
    if (testing.isHandleError(vm.v1)) return testing.fail(1);
    const vm_handle: caps.HandleId = @truncate(vm.v1 & 0xfff);

    const port = syscall.createPort(@as(u64, (caps.PortCap{ .bind = true, .recv = true }).toU16()));
    if (testing.isHandleError(port.v1)) return testing.fail(1);
    const port_handle: caps.HandleId = @truncate(port.v1 & 0xfff);

    // The suite boots with four cores. Pin the vCPU to a different core
    // from the current test thread even when the runner changes placement.
    const other_core = (testing.currentCoreId() + 1) % 4;
    const remote_affinity: u64 = @as(u64, 1) << @intCast(other_core);
    const vcpu_caps = @as(u64, (caps.ThreadCap{ .term = true }).toU16());

    for (0..CYCLES) |i| {
        const vcpu = syscall.createVcpu(vcpu_caps, vm_handle, remote_affinity, port_handle);
        if (testing.isHandleError(vcpu.v1)) return testing.fail(2);
        const vcpu_handle: caps.HandleId = @truncate(vcpu.v1 & 0xfff);
        // Half the cycles retire immediately, racing remote dispatch.
        // The others consume the initial exit first: recv proves that
        // the remote owner actually dispatched the vCPU, then terminate
        // must safely detach its outstanding reply and state page.
        if (i % 2 == 0) {
            _ = syscall.yieldThread(0);
        } else {
            const exit = syscall.recv(port_handle, 0);
            if (errors.isError(exit.regs.v1)) return testing.fail(3);
        }
        if (syscall.terminate(vcpu_handle).v1 != @intFromEnum(errors.Error.OK)) return testing.fail(4);
    }

    // This last vCPU is destroyed by process teardown after report().
    const last = syscall.createVcpu(vcpu_caps, vm_handle, remote_affinity, port_handle);
    if (testing.isHandleError(last.v1)) return testing.fail(5);
    testing.pass();
}
