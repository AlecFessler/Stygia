//! PL031 Real Time Clock driver for AArch64.
//!
//! The PL031 is ARM's standard RTC IP used on the QEMU `virt` machine
//! (base 0x09010000) and on many physical ARM SoCs. It exposes a 32-bit
//! counter that increments once per second and is initialized by the
//! firmware to seconds-since-1970-epoch. Unlike the x86 MC146818 CMOS
//! RTC there is no BCD conversion, no per-field register layout, and
//! no UIP race window — a single 32-bit MMIO read yields the value.
//!
//! Only the read path (RTCDR) is implemented.
//!
//! References:
//! - ARM DDI 0224B: PrimeCell Real Time Clock (PL031) Technical Reference Manual
//!   §3.3.1 RTCDR (Data Register, offset 0x000)
//!
//! The MMIO base is set by `setBase` during ACPI parsing (or hardcoded
//! fallback for the QEMU `virt` machine, which has no ACPI table
//! advertising PL031). If the base has not been mapped, `readRtc`
//! returns 0 — the same sentinel the dispatch layer returned before
//! the driver existed.

/// PL031 register offsets.
/// DDI0224B §3.3.
const offsets = struct {
    /// Data Register — current counter value (seconds since epoch).
    /// DDI0224B §3.3.1.
    const rtcdr = 0x000;
};

/// MMIO base virtual address of the PL031, set at runtime after the
/// MMIO page has been mapped into the kernel physmap. Null until
/// `setBase` is called.
var base_addr: ?u64 = null;

/// Install the PL031 MMIO base virtual address. Called once during
/// ACPI parsing after the MMIO page has been mapped as Device memory.
pub fn setBase(addr: u64) void {
    base_addr = addr;
}

/// Read the PL031 counter and return Unix nanoseconds since
/// 1970-01-01T00:00:00Z. Returns 0 if the driver has not been
/// initialized (base unmapped).
pub fn readRtc() u64 {
    const base = base_addr orelse return 0;
    const dr_ptr: *volatile u32 = @ptrFromInt(base + offsets.rtcdr);
    const seconds: u64 = dr_ptr.*;
    return seconds * 1_000_000_000;
}
