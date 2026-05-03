//! AArch64 vGIC (GICv3 virtual CPU interface + GICD/GICR MMIO emulation).
//!
//! Reserved for spec-v3 VM bring-up. The full distributor/redistributor
//! emulator and list-register manager will be reinstated here once the
//! vCPU run loop is wired up.

/// Maximum number of SPIs we plan to emulate. INTIDs 32..(32+MAX_SPIS-1).
pub const MAX_SPIS: u16 = 256;

/// Total distributor INTID count = 32 (SGI/PPI) + MAX_SPIS.
/// Note: SGI/PPI state is per-vCPU and lives in the redistributor;
/// distributor SPI state starts at INTID 32. GICv3 §2.2.1.
pub const TOTAL_DIST_INTIDS: u16 = 32 + MAX_SPIS;
