//! x86_64 system-information bootstrap.
//!
//! Currently only discovers the bus frequency via CPUID leaf 0x16 (Intel
//! SDM Vol 2 "CPUID") and stashes it for future per-core sampling.
//! Per-core sampling and the `sys_info` syscall surface are not wired up
//! in spec-v3 yet — when they land they will read this `bus_freq_hz`
//! and the per-core MSRs documented in Intel SDM Vol 3 §15.7-§15.8.

const stygia = @import("stygia");

const cpu = stygia.arch.x64.cpu;

/// Fallback bus frequency when `CPUID.16h` does not advertise a value.
/// 100 MHz matches the external bus clock on every mainstream Intel part
/// since Nehalem (Intel SDM Vol 3 §15.7 "Processor-Specific Power
/// Management").
const DEFAULT_BUS_FREQ_HZ: u64 = 100_000_000;

/// Bus frequency in hertz discovered once at boot. Used to convert the
/// `IA32_PERF_STATUS` ratio into an absolute frequency in future
/// per-core samplers.
var bus_freq_hz: u64 = DEFAULT_BUS_FREQ_HZ;

/// True when the running CPU is `GenuineIntel`. Reserved for future
/// per-core thermal/perf MSR readers; see Intel SDM Vol 4 for the MSR
/// definitions and the AMD note in the original sysinfo blob.
var intel_msrs_available: bool = false;

/// Detect `GenuineIntel` via CPUID leaf 0 (Intel SDM Vol 2 "CPUID").
fn isGenuineIntel() bool {
    const r = cpu.cpuid(.basic_max, 0);
    return r.ebx == 0x756e6547 and r.edx == 0x49656e69 and r.ecx == 0x6c65746e;
}

/// One-time system-info bring-up on the bootstrap core.
pub fn sysInfoInit() void {
    if (!isGenuineIntel()) return;
    intel_msrs_available = true;

    const max_basic = cpu.cpuid(.basic_max, 0).eax;
    if (max_basic >= 0x16) {
        const leaf = cpu.cpuidRaw(0x16, 0);
        const bus_mhz: u64 = leaf.ecx & 0xFFFF;
        if (bus_mhz != 0) {
            bus_freq_hz = bus_mhz * 1_000_000;
            return;
        }
    }
}
