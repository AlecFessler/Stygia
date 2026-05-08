const builtin = @import("builtin");
const zag = @import("zag");

const x64 = zag.arch.x64;

const DeviceRegion = zag.devices.device_region.DeviceRegion;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const VAddr = zag.memory.address.VAddr;

/// Emulate a userspace MOV that page-faulted on a port-IO MMIO VMAR.
/// Spec §[port_io_virtualization] tests 04-11.
///
/// `var_base` is a pre-snapshot copy of the VMAR's base virtual address
/// taken under (and released by) the VMAR gen-lock by the caller. The
/// emulator may fire `thread_fault` / `memory_fault` inline and yield
/// the EC; in that case it does not return.
///
/// On non-x86-64 this dispatch is unreachable: spec test 01 rejects
/// `map_mmio` of port-IO device_regions outside x86-64, so a port-IO
/// VMAR cannot exist there and the caller's `.mmio` page-fault branch
/// can never reach this entry.
pub fn emulatePortIoFault(
    ec: *ExecutionContext,
    fault_vaddr: VAddr,
    var_base: u64,
    dev: *DeviceRegion,
) i64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.port_io.emulatePortIoFault(ec, fault_vaddr, var_base, dev),
        .aarch64 => unreachable,
        else => unreachable,
    };
}
