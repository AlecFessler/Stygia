//! Bit-level definitions for the EL2 system registers we touch.
//!
//! Every constant here has a citation back to ARM ARM (DDI 0487K.a) so
//! the reader can verify against the architecture spec. The page numbers
//! refer to the K.a issue of the manual checked in at
//! `docs/aarch64/DDI0487_arm_arm.pdf`; section numbers are stable across
//! issues and are the more important reference.
//!
//! Naming convention: `<REGISTER>_<FIELD>` for single bits;
//! `<REGISTER>_<FIELD>_SHIFT` / `_MASK` for multi-bit fields.
//!
//! Where this file diverges from the spec, it is because we only encode
//! the subset of fields the v1 hypervisor actually programs. Adding more
//! fields is a pure mechanical port from the same spec sections.

// ===========================================================================
// HCR_EL2 -- Hypervisor Configuration Register
// ARM ARM K.a §D23.2.53, p7685.
// ===========================================================================

/// Virtualization enable. When VM=1, EL1&0 stage-2 translation is enabled
/// and behaves as described in §D8.4. Required for any VM.
pub const HCR_EL2_VM: u64 = 1 << 0;

/// SWIO -- Set/Way Invalidation Override. When 1, EL1 cache invalidate
/// by set/way operations are upgraded to clean+invalidate. Recommended
/// to be set so that a guest that uses set/way invalidates on its
/// kernel-image data does not silently lose dirty lines.
pub const HCR_EL2_SWIO: u64 = 1 << 1;

/// PTW -- Protected Table Walk. When 1, a stage-2 table walk for a
/// stage-1 descriptor that targets Device memory is reported as a
/// Permission fault. Mainly defends against Device-attributed page
/// tables (which would be UNPREDICTABLE).
pub const HCR_EL2_PTW: u64 = 1 << 2;

/// FMO -- Physical FIQ Routing. When 1, physical FIQs are taken to EL2
/// and `vFIQ` virtual interrupts can be signaled to EL1.
pub const HCR_EL2_FMO: u64 = 1 << 3;

/// IMO -- Physical IRQ Routing. When 1, physical IRQs are taken to EL2
/// and `vIRQ` virtual interrupts can be signaled to EL1. (102142 §6.1.)
pub const HCR_EL2_IMO: u64 = 1 << 4;

/// AMO -- SError Routing. When 1, SError is taken to EL2 and `vSError`
/// virtual exceptions can be signaled to EL1.
pub const HCR_EL2_AMO: u64 = 1 << 5;

/// VF -- Virtual FIQ pending. Setting this bit registers a vFIQ; the
/// guest will take it on the next opportunity (subject to PSTATE.F).
pub const HCR_EL2_VF: u64 = 1 << 6;

/// VI -- Virtual IRQ pending. Setting this bit registers a vIRQ.
pub const HCR_EL2_VI: u64 = 1 << 7;

/// VSE -- Virtual SError pending.
pub const HCR_EL2_VSE: u64 = 1 << 8;

/// FB -- Force Broadcast. When 1, certain TLB and cache maintenance
/// instructions executed at EL1 are broadcast within the inner shareable
/// domain regardless of the guest's choice.
pub const HCR_EL2_FB: u64 = 1 << 9;

/// DC -- Default Cacheability. When 1, stage-1 attributes are forced to
/// Normal Inner/Outer Write-Back Cacheable; useful during early guest
/// boot before its MMU is on. (102142 §4.4.)
pub const HCR_EL2_DC: u64 = 1 << 12;

/// TWI -- Trap WFI. When 1, EL0/EL1 WFI generates an exception to EL2
/// (EC=0x01 with ISS.TI=0). (102142 §5.)
pub const HCR_EL2_TWI: u64 = 1 << 13;

/// TWE -- Trap WFE. When 1, EL0/EL1 WFE generates an exception to EL2
/// (EC=0x01 with ISS.TI=1).
pub const HCR_EL2_TWE: u64 = 1 << 14;

/// TID0 -- Trap ID Group 0 (cache type registers).
pub const HCR_EL2_TID0: u64 = 1 << 15;

/// TID1 -- Trap ID Group 1 (auxiliary control & limited ID regs).
pub const HCR_EL2_TID1: u64 = 1 << 16;

/// TID2 -- Trap ID Group 2 (cache id, csselr).
pub const HCR_EL2_TID2: u64 = 1 << 17;

/// TID3 -- Trap ID Group 3 (most ID_* feature registers).
pub const HCR_EL2_TID3: u64 = 1 << 18;

/// TSC -- Trap SMC. When 1, SMC from EL1 generates an exception to EL2
/// (EC=0x17). Used so the hypervisor can intercept PSCI / firmware calls.
pub const HCR_EL2_TSC: u64 = 1 << 19;

/// TIDCP -- Trap implementation-defined functionality.
pub const HCR_EL2_TIDCP: u64 = 1 << 20;

/// TACR -- Trap Auxiliary Control Register accesses.
pub const HCR_EL2_TACR: u64 = 1 << 21;

/// TSW -- Trap data/unified cache maintenance instructions by set/way.
pub const HCR_EL2_TSW: u64 = 1 << 22;

/// TPC -- Trap data/unified cache maintenance instructions to PoC.
pub const HCR_EL2_TPC: u64 = 1 << 23;

/// TPU -- Trap cache maintenance instructions to PoU.
pub const HCR_EL2_TPU: u64 = 1 << 24;

/// TTLB -- Trap TLB maintenance instructions.
pub const HCR_EL2_TTLB: u64 = 1 << 25;

/// TVM -- Trap Virtual Memory controls. When 1, EL1 writes to the
/// stage-1 control registers (SCTLR_EL1, TTBR0_EL1, TTBR1_EL1, TCR_EL1,
/// MAIR_EL1, AMAIR_EL1, CONTEXTIDR_EL1) generate an exception to EL2
/// (EC=0x18). Used for lazy context-switch bookkeeping.
/// (102142 §5.)
pub const HCR_EL2_TVM: u64 = 1 << 26;

/// TGE -- Trap General Exceptions. Repurposes EL1 to EL2; we DO NOT set
/// this for a guest VM (it is the bit that "turns the host into EL2").
pub const HCR_EL2_TGE: u64 = 1 << 27;

/// TDZ -- Trap DC ZVA.
pub const HCR_EL2_TDZ: u64 = 1 << 28;

/// HCD -- Disable HVC. We leave this 0 so guests can issue HVC for PSCI.
pub const HCR_EL2_HCD: u64 = 1 << 29;

/// TRVM -- Trap reads of stage-1 control registers (counterpart to TVM).
pub const HCR_EL2_TRVM: u64 = 1 << 30;

/// RW -- Register Width control for lower ELs. 1 = EL1 is AArch64. We
/// always require this for our 64-bit guests.
pub const HCR_EL2_RW: u64 = 1 << 31;

// Upper-half bits we touch:

/// CD -- Stage-1 Cacheability Disable override. (102142 §4.4.)
pub const HCR_EL2_CD: u64 = 1 << 32;

/// ID -- Stage-1 Instruction Cacheability Disable override.
pub const HCR_EL2_ID: u64 = 1 << 33;

/// E2H -- EL2 Host. The VHE bit. We do NOT set this for guests; the
/// kernel itself runs at EL1, so VHE is not in play here.
pub const HCR_EL2_E2H: u64 = 1 << 34;

/// FWB -- Forced Write-Back stage-2 attributes (v8.4+). Lets the
/// hypervisor force coherent attributes regardless of the guest's
/// stage-1 view. (102142 §4.4.)
pub const HCR_EL2_FWB: u64 = 1 << 46;

// ===========================================================================
// VTCR_EL2 -- Virtualization Translation Control Register
// ARM ARM K.a §D23.2.202, p8492.
// ===========================================================================

/// T0SZ[5:0] -- size offset of the IPA region that VTTBR_EL2 addresses.
/// For a 40-bit IPA: T0SZ = 64 - 40 = 24.
pub const VTCR_EL2_T0SZ_SHIFT: u6 = 0;
pub const VTCR_EL2_T0SZ_MASK: u64 = 0x3F;

/// SL0[7:6] -- starting level for stage-2 walks.
///   00 = level 2
///   01 = level 1
///   10 = level 0
///   11 = level 3 (only for some granule/IPA combos)
/// For 40-bit IPA + 4K granule we walk from level 1 (SL0 = 01).
pub const VTCR_EL2_SL0_SHIFT: u6 = 6;
pub const VTCR_EL2_SL0_MASK: u64 = 0x3 << 6;
pub const VTCR_EL2_SL0_LEVEL1: u64 = 0x1 << 6;

/// IRGN0[9:8] -- inner shareable cacheability of stage-2 table walks.
/// 01 = Normal, Inner Write-Back Read-Allocate Write-Allocate.
pub const VTCR_EL2_IRGN0_SHIFT: u6 = 8;
pub const VTCR_EL2_IRGN0_WB_RAWA: u64 = 0x1 << 8;

/// ORGN0[11:10] -- outer shareable cacheability of stage-2 table walks.
pub const VTCR_EL2_ORGN0_SHIFT: u6 = 10;
pub const VTCR_EL2_ORGN0_WB_RAWA: u64 = 0x1 << 10;

/// SH0[13:12] -- shareability of stage-2 table walks. 11 = Inner.
pub const VTCR_EL2_SH0_SHIFT: u6 = 12;
pub const VTCR_EL2_SH0_INNER: u64 = 0x3 << 12;

/// TG0[15:14] -- granule size for stage-2.
///   00 = 4KB
///   01 = 64KB
///   10 = 16KB
pub const VTCR_EL2_TG0_4K: u64 = 0x0 << 14;

/// PS[18:16] -- Physical Address Size.
///   000 = 32 bits
///   001 = 36
///   010 = 40
///   011 = 42
///   100 = 44
///   101 = 48
///   110 = 52
pub const VTCR_EL2_PS_SHIFT: u6 = 16;
pub const VTCR_EL2_PS_40BIT: u64 = 0x2 << 16;

/// VS[19] -- VMID size. 0 = 8-bit, 1 = 16-bit (v8.1+).
pub const VTCR_EL2_VS_16BIT: u64 = 1 << 19;

/// HA[21] -- stage-2 hardware Access flag update enable (v8.1+).
pub const VTCR_EL2_HA: u64 = 1 << 21;

/// HD[22] -- stage-2 hardware Dirty state update enable (v8.1+).
pub const VTCR_EL2_HD: u64 = 1 << 22;

/// RES1[31] -- bit 31 is RES1 (must be set).
pub const VTCR_EL2_RES1: u64 = 1 << 31;

// ===========================================================================
// VTTBR_EL2 -- Virtualization Translation Table Base Register
// ARM ARM K.a §D23.2.203, p8502.
// ===========================================================================

/// BADDR -- the stage-2 root table physical address.
/// Bits [47:x] depending on T0SZ; alignment requirements are in the spec.
/// For 40-bit IPA + 4K granule + SL0=1, BADDR alignment = 4KB.
pub const VTTBR_EL2_BADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

/// VMID[63:48] -- 16-bit VMID (or 8-bit if VTCR_EL2.VS=0).
pub const VTTBR_EL2_VMID_SHIFT: u6 = 48;

// ===========================================================================
// ESR_EL2 -- Exception Syndrome Register (EL2)
// ARM ARM K.a §D23.2.41, p7526.
//
// Layout:
//   [63:56]  RES0
//   [55:32]  ISS2     (extended syndrome; FEAT_LS64 and friends)
//   [31:26]  EC       (exception class; selects the ISS encoding)
//   [25]     IL       (instruction length: 0 = 16-bit T32, 1 = 32-bit)
//   [24:0]   ISS      (instruction-specific syndrome)
// ===========================================================================

pub const ESR_EL2_EC_SHIFT: u6 = 26;
pub const ESR_EL2_EC_MASK: u64 = 0x3F << 26;

pub const ESR_EL2_IL: u64 = 1 << 25;

pub const ESR_EL2_ISS_MASK: u64 = (1 << 25) - 1; // bits [24:0]

/// Exception class encodings, ARM ARM K.a §D23.2.41 Table D23-2.
/// Only the values we explicitly handle are listed. Anything else
/// surfaces as `unknown_ec` and is forwarded to the VMM.
pub const EC = enum(u6) {
    /// Unknown reason. Indicates a misconfigured trap.
    unknown = 0x00,
    /// Trapped WFI/WFE. ISS.TI: 0=WFI, 1=WFE.
    wfi_wfe = 0x01,
    /// Trapped MCR/MRC (CP15 32-bit, AArch32).
    cp15_32 = 0x03,
    /// Trapped MCRR/MRRC (CP15 64-bit, AArch32).
    cp15_64 = 0x04,
    /// Trapped MCR/MRC (CP14, AArch32).
    cp14_32 = 0x05,
    /// LDC/STC trap.
    ldc_stc = 0x06,
    /// Trapped FPSIMD/SVE access (CPTR_EL2.TFP or .TZ set).
    fpsimd_sve = 0x07,
    /// Trapped HVC from AArch32.
    hvc32 = 0x12,
    /// Trapped SMC from AArch32.
    smc32 = 0x13,
    /// Trapped HVC from AArch64. ISS = imm16.
    hvc64 = 0x16,
    /// Trapped SMC from AArch64.
    smc64 = 0x17,
    /// Trapped MSR/MRS or system instruction. ISS encodes
    /// op0/op1/CRn/CRm/op2/Rt/direction.
    sysreg = 0x18,
    /// Pointer authentication failure.
    ptr_auth = 0x1C,
    /// Instruction abort from a lower EL (stage-1 or stage-2 fault on
    /// a guest fetch). HPFAR_EL2 is valid for stage-2 faults.
    iabt_lower = 0x20,
    /// Instruction abort from same EL (kernel bug if seen).
    iabt_same = 0x21,
    /// PC alignment fault.
    pc_align = 0x22,
    /// Data abort from a lower EL. Stage-2 faults bring along HPFAR_EL2.
    /// ISS contains: ISV/SAS/SSE/SRT/SF/AR/WnR/DFSC.
    dabt_lower = 0x24,
    /// Data abort from same EL.
    dabt_same = 0x25,
    /// SP alignment fault.
    sp_align = 0x26,
    /// Trapped FP exception (AArch64).
    fp_exc = 0x2C,
    /// SError interrupt.
    serror = 0x2F,
    /// Breakpoint from lower EL.
    bp_lower = 0x30,
    /// Software step from lower EL.
    sstep_lower = 0x32,
    /// Watchpoint from lower EL.
    wp_lower = 0x34,
    /// BRK instruction execution.
    brk = 0x3C,
    _,
};

// ----- Data Abort ISS (ESR_EL2.EC == 0x24/0x25) -----
// ARM ARM K.a §D23.2.41 "ISS encoding for an exception from a Data Abort".

/// ISV[24] -- valid bit for the SAS/SSE/SRT/SF/AR fields. When 0 the
/// hypervisor must software-decode the faulting instruction.
pub const DABT_ISS_ISV: u32 = 1 << 24;
/// SAS[23:22] -- access size: 0=byte, 1=halfword, 2=word, 3=doubleword.
pub const DABT_ISS_SAS_SHIFT: u5 = 22;
pub const DABT_ISS_SAS_MASK: u32 = 0x3 << 22;
/// SSE[21] -- sign-extension flag for sign-extending loads.
pub const DABT_ISS_SSE: u32 = 1 << 21;
/// SRT[20:16] -- destination register index (xN, 0..30, 31=XZR).
pub const DABT_ISS_SRT_SHIFT: u5 = 16;
pub const DABT_ISS_SRT_MASK: u32 = 0x1F << 16;
/// SF[15] -- 64-bit access flag (1 = 64-bit destination).
pub const DABT_ISS_SF: u32 = 1 << 15;
/// AR[14] -- acquire/release semantics flag.
pub const DABT_ISS_AR: u32 = 1 << 14;
/// WnR[6] -- write not read (1 = store, 0 = load).
pub const DABT_ISS_WNR: u32 = 1 << 6;
/// DFSC[5:0] -- data fault status code; 0x07 = stage-2 translation fault,
/// 0x0F = permission fault, etc. See ARM ARM Table D23-... for full list.
pub const DABT_ISS_DFSC_MASK: u32 = 0x3F;

// ----- MSR/MRS ISS (ESR_EL2.EC == 0x18) -----
// ARM ARM K.a §D23.2.41 "ISS encoding for a trapped MSR, MRS, or system
// instruction execution in AArch64 state".

/// Op0[21:20]
pub const SYSREG_ISS_OP0_SHIFT: u5 = 20;
pub const SYSREG_ISS_OP0_MASK: u32 = 0x3 << 20;
/// Op2[19:17]
pub const SYSREG_ISS_OP2_SHIFT: u5 = 17;
pub const SYSREG_ISS_OP2_MASK: u32 = 0x7 << 17;
/// Op1[16:14]
pub const SYSREG_ISS_OP1_SHIFT: u5 = 14;
pub const SYSREG_ISS_OP1_MASK: u32 = 0x7 << 14;
/// CRn[13:10]
pub const SYSREG_ISS_CRN_SHIFT: u5 = 10;
pub const SYSREG_ISS_CRN_MASK: u32 = 0xF << 10;
/// Rt[9:5] -- target register
pub const SYSREG_ISS_RT_SHIFT: u5 = 5;
pub const SYSREG_ISS_RT_MASK: u32 = 0x1F << 5;
/// CRm[4:1]
pub const SYSREG_ISS_CRM_SHIFT: u5 = 1;
pub const SYSREG_ISS_CRM_MASK: u32 = 0xF << 1;
/// Direction[0]: 1 = MRS (read), 0 = MSR (write).
pub const SYSREG_ISS_DIR_READ: u32 = 1 << 0;

// ===========================================================================
// HPFAR_EL2 -- Hypervisor IPA Fault Address Register
// ARM ARM K.a §D23.2.65, p7870.
//
// On a stage-2 abort, FIPA[51:8] contains bits [51:8] of the faulting
// IPA. To recover the full IPA, OR with FAR_EL2[11:0]:
//     guest_phys = (HPFAR_EL2[51:8] << 8) | (FAR_EL2 & 0xFFF)
// (FAR_EL2 is the guest virtual address; only its low 12 bits are
// meaningful for forming the IPA, since the rest came from the stage-1
// page walk which produced HPFAR_EL2 in the first place.)
// ===========================================================================

pub const HPFAR_EL2_FIPA_SHIFT: u6 = 4; // FIPA stored at bits [43:4]
pub const HPFAR_EL2_FIPA_MASK: u64 = 0x000F_FFFF_FFF0;

// ===========================================================================
// CPTR_EL2 -- Architectural Feature Trap Register (EL2)
// ARM ARM K.a §D23.2.34, p7439.
// ===========================================================================

/// TFP[10] -- trap FPSIMD register accesses to EL2.
pub const CPTR_EL2_TFP: u64 = 1 << 10;

/// TZ[8] -- trap SVE accesses (v8.2+).
pub const CPTR_EL2_TZ: u64 = 1 << 8;

/// RES1 mask for the non-VHE form of CPTR_EL2 (bits [13:12,9,7:0] are
/// RES1 per §D23.2.34).
pub const CPTR_EL2_RES1: u64 = 0x33FF;

// ===========================================================================
// CNTVOFF_EL2 -- Counter-timer Virtual Offset Register
// ARM ARM K.a §D23.10.30, p9468.
//
// CNTVCT_EL0 = CNTPCT_EL0 - CNTVOFF_EL2.
// Per VM, written before entry. (102142 §7.)
// ===========================================================================

// (No bit fields; the entire 64-bit value is the offset.)
