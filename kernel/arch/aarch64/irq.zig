//! AArch64 IRQ routing and device interrupt management.
//!
//! Maps device interrupts (GIC SPIs) to their owning DeviceRegion, handles
//! masking/unmasking, and tracks spurious interrupts. This is the aarch64
//! equivalent of x64/irq.zig.
//!
//! ARM interrupt topology:
//!   SGI  (0-15):    Software Generated Interrupts — IPIs, handled by gic.zig.
//!   PPI  (16-31):   Private Peripheral Interrupts — per-core timer.
//!   SPI  (32-1019): Shared Peripheral Interrupts — device IRQs.
//!
//! Device IRQs on ARM are SPIs. The mapping from device → SPI number comes
//! from ACPI (DSDT/SSDT _CRS resources, or IORT for MSI). The GIC routes
//! each SPI to a target core via GICD_IROUTER (GICv3) or GICD_ITARGETSR (GICv2).
//!
//! Dispatch interface mapping:
//!   maskIrq(irq)            → GICD_ICENABLER (disable the SPI)
//!   unmaskIrq(irq)          → GICD_ISENABLER (enable the SPI)
//!   findIrqForDevice(dev)   → look up SPI number for a DeviceRegion
//!
//! References:
//! - ARM IHI 0069H: GICv3 Architecture Specification, Section 3 (SPI routing)
//! - ACPI 6.5, Section 6.2.13: _CRS interrupt resource descriptors

// AArch64 IRQ routing — to be implemented when device IRQ delivery
// reaches aarch64. SPI mask/unmask helpers and DeviceRegion → INTID
// lookup will land here, mirroring `arch/x64/irq.zig`.
