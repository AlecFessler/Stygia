//! ARM PSCI (Power State Coordination Interface) hypercall dispatch.
//!
//! Reserved for future VM bring-up — once HVC trap delivery and the
//! exit handler are wired up, the SMCCC PSCI dispatch (CPU_SUSPEND,
//! CPU_OFF, CPU_ON, AFFINITY_INFO, MIGRATE_INFO_TYPE, SYSTEM_OFF,
//! SYSTEM_RESET) will be reinstated here.
//!
//! References:
//! - Arm DEN 0022D: Arm Power State Coordination Interface (PSCI)
//! - Arm DEN 0028D: SMC Calling Convention (SMCCC)
