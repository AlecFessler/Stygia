//! AArch64 hardware virtualization primitive layer — layer-neutral types.
//!
//! This file is the base of a three-file split:
//!
//!   * `vm.zig`     — layer-neutral VM types (`GuestState`, `VmExitInfo`,
//!                    `VmPolicy`, HCR_EL2 bits, exception injection,
//!                    ESR decoding, global/per-core init, HVC ABI).
//!   * `hyp.zig`    — EL2 world-switch machinery (`vmResume`, the
//!                    `__hyp_vectors` table and HVC stubs, host-side
//!                    FPSIMD save/restore, kernel-VA→PA resolver).
//!   * `stage2.zig` — stage-2 translation tables (`VmControlBlock`,
//!                    `mapGuestPage` / `unmapGuestPage`,
//!                    `invalidateStage2Ipa`, sysreg passthrough).
//!
//! Mirrors `kernel/arch/x64/vm.zig`. Where x64 has to pick between Intel VMX
//! and AMD SVM at runtime, ARMv8-A has exactly one virtualization mechanism:
//! EL2 (the Hypervisor Exception Level), driven by system registers (no
//! VMCS/VMCB control structures). So there is no runtime backend dispatch
//! here; the EL2 helpers live in `hyp.zig` and the stage-2 page-table
//! management in `stage2.zig`.
//!
//! Architectural references (all local PDFs under `docs/aarch64/`):
//!   - ARM ARM (DDI 0487)      — the authoritative spec
//!       - D1     "The AArch64 Application Level Programmers' Model"
//!       - D1.4   Exception levels and Security states
//!       - D1.11  Synchronous and asynchronous exceptions (entry/return)
//!       - D5     VMSAv8-64 address translation (Stage 1 and Stage 2)
//!       - D5.4   Stage 2 translation
//!       - D5.5   Memory attribute fields in VMSAv8-64 translation descriptors
//!       - D13.2  AArch64 system register descriptions
//!           HCR_EL2, VTCR_EL2, VTTBR_EL2, ESR_EL2, HPFAR_EL2, FAR_EL2,
//!           SPSR_EL2, ELR_EL2, VBAR_EL2, CPTR_EL2, MDCR_EL2, MAIR_EL2,
//!           TCR_EL2, ID_AA64MMFR1_EL1, ID_AA64PFR0_EL1.
//!   - 102142 "Learn the architecture - AArch64 virtualization"
//!       - §2  Virtualization in AArch64 (EL2 overview)
//!       - §3  Stage 2 translation
//!       - §4  Virtual exceptions and trapping
//!       - §5  Virtual interrupts (tied to GICv3 vCPU interface)
//!
//! Concept map from x86 to ARM (for reviewers coming from the x64 code):
//!   VMCS/VMCB  → a handful of EL2 system registers set directly before ERET
//!   EPT root   → VTTBR_EL2 (Virtualization Translation Table Base Register)
//!   EPT ptes   → Stage-2 descriptors (ARM ARM D5.5)
//!   VMRUN/VMRESUME → ERET from EL2 to EL1 with HCR_EL2.TGE=0
//!   VMEXIT     → exception taken to EL2 (vectored via VBAR_EL2)
//!   CR0/CR4    → SCTLR_EL1 + HCR_EL2 virtualization bits
//!   CPUID      → MRS of ID_AA64* registers, optionally trapped via HCR_EL2.TID*
//!   MSR bitmap → HCR_EL2 trap bits + per-register trap controls (no bitmap)
//!   LAPIC/IOAPIC → GICv3 virtual CPU interface (ICH_* sysregs) + emulated
//!                  GICD/GICR MMIO pages (see arch/aarch64/kvm/vgic.zig)

// ===========================================================================
// Guest register state snapshot
// ===========================================================================

/// Full guest register state, saved on VM exit and restored on VM entry.
///
/// AArch64 analogue of the x64 GuestState struct. Layout is chosen so the
/// save/restore asm in `vmResume` can spill registers to a contiguous
/// block with minimal per-field math.
///
/// What has to round-trip across an EL2 exception on a single vCPU:
///   - x0..x30     general-purpose registers                       (ARM ARM B1.2.1)
///   - sp_el0/el1  guest stack pointers                            (D1.7)
///   - pc          guest program counter (taken from ELR_EL2 on exit)
///   - pstate      processor state (taken from SPSR_EL2 on exit)   (C5.2)
///   - EL1 sysregs that form the guest's virtual CPU state         (D13.2)
///   - FPSIMD V0..V31 + FPCR/FPSR                                   (B1.2.2)
///
/// The EL1 system registers listed here are the ones the guest kernel
/// normally reads/writes during scheduling and exception handling.  They
/// are context-switched per vCPU on entry/exit (see `vmResume`).  Trap
/// control registers (HCR_EL2, VTCR_EL2, VTTBR_EL2, etc.) live in the VM's
/// arch_structures block instead because they are per-VM, not per-vCPU GPR
/// state visible to the VMM.
pub const GuestState = extern struct {
    // General-purpose registers (ARM ARM B1.2.1)
    x0: u64 = 0,
    x1: u64 = 0,
    x2: u64 = 0,
    x3: u64 = 0,
    x4: u64 = 0,
    x5: u64 = 0,
    x6: u64 = 0,
    x7: u64 = 0,
    x8: u64 = 0,
    x9: u64 = 0,
    x10: u64 = 0,
    x11: u64 = 0,
    x12: u64 = 0,
    x13: u64 = 0,
    x14: u64 = 0,
    x15: u64 = 0,
    x16: u64 = 0,
    x17: u64 = 0,
    x18: u64 = 0,
    x19: u64 = 0,
    x20: u64 = 0,
    x21: u64 = 0,
    x22: u64 = 0,
    x23: u64 = 0,
    x24: u64 = 0,
    x25: u64 = 0,
    x26: u64 = 0,
    x27: u64 = 0,
    x28: u64 = 0,
    x29: u64 = 0, // frame pointer
    x30: u64 = 0, // link register

    /// Guest stack pointer for EL0 (ARM ARM D13.2.128).
    sp_el0: u64 = 0,
    /// Guest stack pointer for EL1 (ARM ARM D13.2.129).
    sp_el1: u64 = 0,
    /// Guest program counter; loaded into ELR_EL2 on entry, read back on exit.
    pc: u64 = 0,
    /// Processor state bits; loaded into SPSR_EL2 on entry (ARM ARM C5.2).
    /// For a freshly-created EL1 guest we typically set this to EL1h with
    /// DAIF all masked until the guest kernel is ready (see vcpu.zig).
    pstate: u64 = 0,

    // ----- EL1 system registers (ARM ARM D13.2) -----
    //
    // These form the stable on-vCPU view of the guest kernel state. The
    // VMM can read/write them via vm_vcpu_{get,set}_state so it can
    // initialize a freshly loaded kernel image, take crash dumps, etc.

    /// SCTLR_EL1 — system control (MMU enable, cache enable, endianness).
    /// ARM ARM D13.2.110.  After reset, SCTLR_EL1 reads as RES1 pattern
    /// 0x30C50830 (various RES1 bits).  The kernel loader flips M to enable
    /// stage-1 translation; until then the guest executes with VA==PA.
    sctlr_el1: u64 = 0x30C50830,
    /// TTBR0_EL1 / TTBR1_EL1 — guest stage-1 translation roots (D13.2.145).
    ttbr0_el1: u64 = 0,
    ttbr1_el1: u64 = 0,
    /// TCR_EL1 — stage-1 translation control (D13.2.135).
    tcr_el1: u64 = 0,
    /// MAIR_EL1 — memory attribute indirection (D13.2.83).
    mair_el1: u64 = 0,
    /// AMAIR_EL1 — auxiliary MAIR (IMPL DEF; passthrough) (D13.2.11).
    amair_el1: u64 = 0,
    /// CPACR_EL1 — coprocessor (FPSIMD / SVE) access control (D13.2.28).
    cpacr_el1: u64 = 0,
    /// CONTEXTIDR_EL1 — ASID + context id used for tracing (D13.2.26).
    contextidr_el1: u64 = 0,
    /// TPIDR_EL0 / TPIDR_EL1 / TPIDRRO_EL0 — thread pointers (D13.2.139-141).
    tpidr_el0: u64 = 0,
    tpidr_el1: u64 = 0,
    tpidrro_el0: u64 = 0,
    /// VBAR_EL1 — guest exception vector base (D13.2.152).
    vbar_el1: u64 = 0,
    /// Guest-side exception scratch registers. Saved/restored so that
    /// taking an EL2 exception does not clobber an in-flight EL1 exception.
    elr_el1: u64 = 0,
    spsr_el1: u64 = 0,
    esr_el1: u64 = 0,
    far_el1: u64 = 0,
    /// AFSR0_EL1 / AFSR1_EL1 — auxiliary fault status (IMPL DEF; passthrough).
    afsr0_el1: u64 = 0,
    afsr1_el1: u64 = 0,
    /// MDSCR_EL1 — debug control (breakpoints, single-step) (D13.3.15).
    mdscr_el1: u64 = 0,

    /// CNTV_CVAL_EL0 / CNTV_CTL_EL0 — guest virtual timer state (D11.2).
    /// Saved/restored per vCPU so each vCPU has its own virtual timer.
    cntv_cval_el0: u64 = 0,
    cntv_ctl_el0: u64 = 0,
    /// CNTKCTL_EL1 — EL0 access to timers (D11.2.4).
    cntkctl_el1: u64 = 0,
    /// CNTVOFF_EL2 — virtual timer offset (per VM, not per vCPU).
    /// Tracked here for convenience; loaded during entry (D11.2.7).
    cntvoff_el2: u64 = 0,
};

/// FPSIMD/SVE save area. We use plain FPSIMD (V0..V31 + FPCR + FPSR) for
/// now: 32 × 16 = 512 bytes, plus 8 bytes for FPCR/FPSR, rounded up to
/// 576 for alignment headroom.
///
/// Name `FxsaveArea` is intentionally identical to the x64 type so that
/// `dispatch.zig` can keep a common `FxsaveArea` alias. On ARM this is the
/// FPSIMD context, not an Intel FXSAVE region.
///
/// ARM ARM B1.2.2 describes V0..V31; FPCR/FPSR are D13.2.48/D13.2.52.
pub const FxsaveArea = [576]u8;

// ===========================================================================
// VM exit reasons (decoded from ESR_EL2)
// ===========================================================================

/// Decoded VM exit reason.
///
/// On ARM, every exit is an "exception taken to EL2" and the exception
/// class lives in ESR_EL2.EC (ARM ARM D13.2.39, Table D13-45). The list
/// below covers every EC value we intend to handle in the v1
/// implementation; any unrecognized EC surfaces as `.unknown` so the exit
/// handler can forward it to the VMM for triage.
///
/// Equivalents to x86 VmExitInfo variants:
///   cpuid          → sysreg_trap reading an ID_AA64* register
///   io             → (no port I/O on ARM; device I/O is MMIO on stage-2)
///   mmio           → stage2_fault on a guest physical address that the
///                    VMM has mapped as an MMIO region
///   cr_access      → sysreg_trap on SCTLR_EL1/CPACR_EL1/… (HCR_EL2.TVM)
///   msr_read/write → sysreg_trap on any trapped system register
///   ept_violation  → stage2_fault
///   exception      → synchronous_el1 when a guest instruction itself faults
pub const VmExitInfo = union(enum) {
    /// EC=0x20 (instruction abort from a lower EL) or 0x24 (data abort from
    /// a lower EL): a stage-2 fault. HPFAR_EL2[39:4] << 8 holds the IPA of
    /// the faulting access; FAR_EL2 holds the guest VA (D13.2.55, D13.2.59).
    stage2_fault: Stage2Fault,

    /// EC=0x16 (HVC execution from AArch64 EL1). ISS holds the 16-bit
    /// immediate encoded in the HVC instruction.
    hvc: HvcExit,

    /// EC=0x17 (SMC execution from AArch64 EL1). Non-secure hypervisors
    /// normally synthesize PSCI via HVC; SMC is typically forwarded to the
    /// VMM unchanged.
    smc: SmcExit,

    /// EC=0x18 (trapped MSR/MRS or system instruction). ISS encodes
    /// Op0/Op1/CRn/CRm/Op2/Rt/Direction.
    sysreg_trap: SysregTrap,

    /// EC=0x01 (trapped WFI/WFE). Used for guest idle; the kernel may
    /// convert this into a scheduler yield inline.
    wfi_wfe: WfiWfeExit,

    /// EC=0x00 (unknown reason). Typically a signal that the trap config
    /// is wrong; surfaced to VMM for debugging.
    unknown_ec: u8,

    /// Guest-side synchronous exception that the VMM asked to see.
    /// Payload is the raw ESR_EL2 value.
    synchronous_el1: u64,

    /// Guest-triggered halt/shutdown state. Maps to x86 .hlt / .shutdown.
    halt: void,
    shutdown: void,

    /// Anything else; `raw` is the full ESR_EL2.
    unknown: u64,

    /// Stage-2 fault payload. Must fit in 24 bytes so that the enclosing
    /// `VmExitInfo` union lays out as 24-byte payload + 1-byte tag (total
    /// 32 bytes after alignment) — the layout the spec §4.2.5 tests and
    /// the hyprvOS VMM rely on. See `hyprvOS/vmm/aarch64/main.zig`.
    pub const Stage2Fault = extern struct {
        /// Guest physical address of the faulting access, derived from
        /// HPFAR_EL2[39:4] << 8 | (FAR_EL2 & 0xFFF).
        guest_phys: u64,
        /// Guest virtual address from FAR_EL2 (may be UNKNOWN for some
        /// fault classes; see ARM ARM D13.2.55).
        guest_virt: u64,
        /// Size of the access encoded in ISS.SAS (0=byte, 1=halfword,
        /// 2=word, 3=doubleword). Only meaningful when ISS.ISV=1.
        access_size: u8,
        /// Destination register index (ISS.SRT) for loads. Valid only
        /// when ISS.ISV=1.
        srt: u8,
        /// Data/Instruction Fault Status Code (ISS.DFSC for EC=0x24 or
        /// ISS.IFSC for EC=0x20). Low 6 bits. See ARM ARM D13.2.39
        /// Table D13-46.
        fsc: u8,
        /// Bitfield packing boolean flags so the whole struct fits in
        /// 24 bytes:
        ///   bit 0: is_instruction (EC=0x20 instruction abort)
        ///   bit 1: is_write (ISS.WnR, data abort only)
        ///   bit 2: iss_valid (ISS.ISV)
        ///   bit 3: sign_extend (ISS.SSE)
        ///   bit 4: reg64 (ISS.SF)
        ///   bit 5: acqrel (ISS.AR)
        flags: u8,
        _pad: [4]u8 = .{0} ** 4,

        pub const FLAG_IS_INSTRUCTION: u8 = 1 << 0;
        pub const FLAG_IS_WRITE: u8 = 1 << 1;
        pub const FLAG_ISS_VALID: u8 = 1 << 2;
        pub const FLAG_SIGN_EXTEND: u8 = 1 << 3;
        pub const FLAG_REG64: u8 = 1 << 4;
        pub const FLAG_ACQREL: u8 = 1 << 5;

        pub fn isWrite(self: Stage2Fault) bool {
            return (self.flags & FLAG_IS_WRITE) != 0;
        }
        pub fn issValid(self: Stage2Fault) bool {
            return (self.flags & FLAG_ISS_VALID) != 0;
        }
    };

    pub const HvcExit = struct {
        /// 16-bit immediate encoded in the HVC instruction (ISS[15:0]).
        imm: u16,
    };

    pub const SmcExit = struct {
        imm: u16,
    };

    pub const SysregTrap = struct {
        /// Raw ISS field so callers can decode further if they want.
        iss: u32,
        op0: u2,
        op1: u3,
        crn: u4,
        crm: u4,
        op2: u3,
        /// Destination/source register index.
        rt: u5,
        /// 1 = MRS (read), 0 = MSR (write).
        is_read: bool,
    };

    pub const WfiWfeExit = struct {
        /// 0 = WFI, 1 = WFE (ISS.TI).
        is_wfe: bool,
    };
};

comptime {
    // Spec §4.2.5 tests and hyprvOS rely on VmExitInfo laying out as a
    // 24-byte payload + tag byte (total 32 after alignment), matching the
    // x86_64 VmExitInfo. If any variant grows past 24 bytes, Zig bumps the
    // union payload size and the tag offset drifts — breaking the binary
    // contract. Keep the payload exactly 24 bytes.
    if (@sizeOf(VmExitInfo.Stage2Fault) != 24) {
        @compileError("Stage2Fault must be 24 bytes — spec §4.2.5 layout contract");
    }
    if (@sizeOf(VmExitInfo) != 32) {
        @compileError("VmExitInfo must be 32 bytes — spec §4.2.5 layout contract");
    }
}

// ===========================================================================
// Interrupt / exception injection types
// ===========================================================================

/// Virtual interrupt to inject into a guest vCPU. Unlike x86 (where a
/// vector is enough), on ARM an "interrupt" is delivered via the vGIC
/// and must say which virtual interrupt _line_ it is (SGI/PPI/SPI).
/// The vGIC translates this into an LR write; see `vgic.injectInterrupt`.
///
/// ARM ARM D13.2 HCR_EL2.VI/VF/VSE, GICv3 §4.7 "Virtual interrupts".
pub const GuestInterrupt = extern struct {
    /// Interrupt ID (INTID). 0..15 = SGI, 16..31 = PPI, 32..1019 = SPI.
    intid: u32,
    /// Priority (0 = highest, 0xFF = lowest).
    priority: u8,
    /// Interrupt type: 0 = vIRQ, 1 = vFIQ, 2 = vSError.
    kind: u8,
    _pad: [2]u8 = .{0} ** 2,
};

/// Exception to inject into the guest at EL1. Injecting means: set
/// SPSR_EL1 = current PSTATE, ELR_EL1 = current PC, ESR_EL1 = syndrome,
/// and redirect PC to VBAR_EL1 + offset (ARM ARM D1.11).
pub const GuestException = extern struct {
    /// ESR_EL1 syndrome value the guest kernel will observe.
    esr: u64,
    /// FAR_EL1 fault address value (for data/instruction aborts).
    far: u64,
    /// Which vector to branch to: 0 = SP_EL1 sync, 1 = SP_EL1 IRQ, …
    /// 4 = lower-EL (aarch64) sync, etc. See ARM ARM D1.11 Table D1-7.
    vector_slot: u8,
    _pad: [7]u8 = .{0} ** 7,
};

// ===========================================================================
// VmPolicy — inline-handled exits
// ===========================================================================

/// Per-VM inline-exit policy table. x86 lets the VMM pre-register CPUID
/// and CR-access responses; on ARM the analogous hook is system register
/// traps.
///
/// Two pools:
///   - `id_reg_responses` — ID_AA64* register reads. The ARM equivalent of
///     CPUID: the VMM wants to lie about the CPU identity to hide features
///     from the guest. The kernel handles these inline by returning
///     `value` and advancing PC.
///   - `sysreg_policies` — arbitrary trapped sysregs. For each entry the
///     kernel either (a) returns a fixed read value and/or (b) silently
///     swallows the write, without exiting to the VMM.
///
/// Both tables are read-only after vm_create so require no locking.
pub const VmPolicy = extern struct {
    id_reg_responses: [MAX_ID_REG_RESPONSES]IdRegResponse =
        .{IdRegResponse{}} ** MAX_ID_REG_RESPONSES,
    num_id_reg_responses: u32 = 0,
    _pad0: u32 = 0,

    sysreg_policies: [MAX_SYSREG_POLICIES]SysregPolicy =
        .{SysregPolicy{}} ** MAX_SYSREG_POLICIES,
    num_sysreg_policies: u32 = 0,
    _pad1: u32 = 0,

    pub const MAX_ID_REG_RESPONSES = 64;
    pub const MAX_SYSREG_POLICIES = 32;

    /// One entry in the ID_AA64* response table. Op0/Op1/CRn/CRm/Op2
    /// uniquely identifies a system register (ARM ARM C5.3).
    pub const IdRegResponse = extern struct {
        op0: u8 = 0,
        op1: u8 = 0,
        crn: u8 = 0,
        crm: u8 = 0,
        op2: u8 = 0,
        _pad: [3]u8 = .{0} ** 3,
        value: u64 = 0,
    };

    /// One entry in the sysreg trap policy table. `read_value` is what a
    /// trapped MRS observes; `write_mask` controls which bits a trapped
    /// MSR is allowed to set (0 = ignore the write entirely).
    pub const SysregPolicy = extern struct {
        op0: u8 = 0,
        op1: u8 = 0,
        crn: u8 = 0,
        crm: u8 = 0,
        op2: u8 = 0,
        _pad: [3]u8 = .{0} ** 3,
        read_value: u64 = 0,
        write_mask: u64 = 0,
    };
};

// ===========================================================================
// Global / per-core init
// ===========================================================================

/// Set to true by `vmInit()` when ID_AA64PFR0_EL1.EL2 indicates EL2 is
/// implemented and usable. Queried by `vmSupported()` and by vm_create.
var vm_supported: bool = false;

/// Set to true by the direct-kernel boot path after VBAR_EL2 has been
/// loaded with `__hyp_vectors`. UEFI boot enters at EL1 and never gets
/// the chance to install a hyp stub, so this stays false there — making
/// `vmSupported()` honest about whether EL2 is actually reachable from
/// EL1 via HVC. See `kernel/arch/aarch64/boot/start.S` (direct-kernel
/// path) and `directKernelEntry` in `boot/direct_kernel.zig`.
pub var hyp_stub_installed: bool = false;

/// Set to true once `installHypVectors()` (in `hyp.zig`) has run on any
/// core. Guards secondary cores from re-issuing the install HVC: on APs
/// we do not currently control EL2 (they come up via PSCI CPU_ON without
/// the bootloader's EL2 drop sequence), so a second HVC could trap into
/// an unknown EL2 handler. Tracked as a global because all cores share
/// the same VMM toolchain state; until a dedicated per-core EL2 bringup
/// path exists, VM runs are pinned to the BSP. Public so `hyp.zig` can
/// observe/update the installed state.
/// TODO(smp): install vectors on every core once AP EL2 bringup lands.
pub var hyp_vectors_installed: bool = false;

/// Read ID_AA64PFR0_EL1 (ARM ARM K.a §D23.2.79, p7932).
///
/// Field map (bits → field):
///   [3:0]    EL0          AArch64/AArch32 support at EL0
///   [7:4]    EL1          AArch64/AArch32 support at EL1
///   [11:8]   EL2          0=not implemented, 1=A64 only, 2=A64+A32
///   [15:12]  EL3          analogous
///   [19:16]  FP           floating-point support
///   [23:20]  AdvSIMD      advanced SIMD support
///   ...      (CSV2/RME/DIT/AMU/MPAM/SEL2/SVE/RAS/GIC)
///
/// We only consult EL2 here; the GIC field (bits [27:24]) is checked by
/// the GIC driver, not us.
inline fn readIdAa64Pfr0() u64 {
    var v: u64 = undefined;
    asm volatile ("mrs %[v], id_aa64pfr0_el1"
        : [v] "=r" (v),
    );
    return v;
}

/// Global VM subsystem init. Called once at boot from `arch.vmInit()`.
///
/// Responsibilities:
///   1. Read ID_AA64PFR0_EL1 and check bits [11:8] for EL2 support. A
///      value of 0 means EL2 is not implemented; any non-zero value means
///      EL2 is implemented (1 = AArch64 only, 2 = AArch64 + AArch32).
///   2. Initialize the VMID allocator (see `stage2.zig`).
///
/// We deliberately do NOT consult ID_AA64MMFR1_EL1.VH here. The Zag
/// kernel itself runs at EL1 (entered at EL1 by PSCI), so we never use
/// VHE to host the kernel itself; we only care that stage-2 translation
/// and EL2 routing are available. EL2-without-VHE works for our needs.
pub fn vmInit() void {
    const pfr0 = readIdAa64Pfr0();
    const el2_field: u4 = @truncate((pfr0 >> 8) & 0xF);
    vm_supported = el2_field != 0;
    // TODO(impl): init VMID allocator
}

/// Per-core VM initialization. Called from `sched.perCoreInit()` on every
/// CPU after global init. On ARM the per-core setup is small: ensure EL2
/// vectors are installed and that per-core trap configuration (HCR_EL2
/// RES1 bits, MDCR_EL2 for PMU trap sharing, etc.) reflects the boot-time
/// defaults. All real state is per-VM, so this is essentially a no-op on
/// a hypervisor that does not switch between host and guest VMIDs outside
/// of a vCPU run.
///
/// The vector-install step lives in `hyp.zig` and is driven by the
/// `dispatch/vm.zig` dispatcher directly — keeping vm.zig's init free of
/// a cross-file call-out to the EL2 machinery.
/// Returns true if hardware virtualization is available AND reachable
/// from this kernel build. Two conditions must hold:
///
///   1. `ID_AA64PFR0_EL1.EL2 != 0` — the CPU implements EL2.
///   2. `hyp_stub_installed` — the boot path actually loaded VBAR_EL2
///      with our hyp vector table. This requires entering at EL2 (the
///      direct-kernel boot path under `-M virt,virtualization=on`); the
///      UEFI path enters at EL1 with no way to write VBAR_EL2, so even
///      a CPU that advertises EL2 in its ID register is unreachable.
///
/// On any environment failing either condition, vm_* syscalls
/// short-circuit with `E_NODEV` and the s4_2 test suite reports SKIP
/// (see `tests/tests/libz/test.zig :: skipIfNoVm`).
pub fn vmSupported() bool {
    return vm_supported and hyp_stub_installed;
}

// ===========================================================================
// Hyp-call ABI (host → EL2 dispatcher)
// ===========================================================================
//
// The direct-kernel EL2 hyp stub in `hyp.zig` exposes a tiny hypercall
// interface to the EL1 kernel via `hvc #0`:
//
//   x0 = hypercall id (see `HypCallId`)
//   x1 = argument (id-specific: a raw value or a physical-address pointer)
//
// The stub writes the result into x0 and ERETs to the instruction after
// the HVC (ARM ARM D1.10.2 — HVC preferred exception return address is
// the instruction following HVC).
//
// Non-VHE hyp only: the kernel itself runs at EL1, EL2 is used purely as
// a thin dispatcher reached via HVC. There is no "host at EL2" mode.
//
// The ABI lives here (layer-neutral vm.zig) rather than in `hyp.zig`
// because stage-2 code (`stage2.invalidateStage2Ipa`) also calls through
// `hypCall` to reach `hvc_tlbi_ipa`; keeping the wrapper in vm.zig lets
// both hyp.zig and stage2.zig depend on vm.zig without either depending
// on the other.

pub const HypCallId = enum(u64) {
    /// Return `arg ^ 1`. Round-trip smoke test; no side effects.
    noop = 0,
    /// `arg` = physical address of a WorldSwitchCtx. Enter the guest;
    /// return when the guest exits with the exit info stored in the
    /// WorldSwitchCtx. Returns 0 on success, non-zero on entry failure.
    vcpu_run = 1,
    /// `arg` = guest IPA of a stage-2 entry that was just mutated.
    /// Dispatches to `hvc_tlbi_ipa` which issues
    /// `tlbi ipas2e1is, arg>>12; dsb ish; tlbi vmalle1is; dsb ish; isb`
    /// at EL2. Required because `TLBI IPAS2E1IS` is EL2-only
    /// (ARM ARM D7.7); the EL1 kernel therefore cannot issue it
    /// directly. Returns 0.
    tlbi_ipa = 2,
    /// No argument. Returns `(ICH_VTR_EL2 & 0x1F) + 1` in x0 — the
    /// number of vGIC list registers implemented on this PE. ICH_VTR_EL2
    /// is EL2-only (GICv3 §12.5.30 / ARM ARM D13.8.50) so the EL1
    /// kernel must probe it via an hvc stub. Dispatches to
    /// `hvc_vgic_detect_lrs`.
    vgic_detect_lrs = 3,
    /// `arg` = physical/EL1-VA pointer to a `vgic.VcpuHwShadow`. The
    /// stub writes ICH_LR0..15_EL2, ICH_AP0R0_EL2, ICH_AP1R0_EL2,
    /// ICH_VMCR_EL2, and ICH_HCR_EL2 (with EN forced on) from the
    /// shadow. Returns 0. Dispatches to `hvc_vgic_prepare_entry`.
    /// All ICH_*_EL2 registers are EL2-only (ARM ARM D13.8) so this
    /// path replaces the direct msr issued from EL1 code.
    vgic_prepare_entry = 4,
    /// `arg` = pointer to a `vgic.VcpuHwShadow`. The stub reads
    /// ICH_LR0..15_EL2, ICH_AP0R0_EL2, ICH_AP1R0_EL2 back into the
    /// shadow and then clears ICH_HCR_EL2 (disabling the virtual CPU
    /// interface for the host-running window). Returns 0. Dispatches
    /// to `hvc_vgic_save_exit`.
    vgic_save_exit = 5,
    /// `arg` = pointer to a `vtimer.VtimerState`. If `primed == 0` the
    /// stub seeds `cntvoff_el2` from CNTPCT_EL0 and sets `primed = 1`
    /// before programming. Then writes CNTVOFF_EL2 (EL2-only, ARM ARM
    /// D13.11.9), CNTKCTL_EL1, CNTV_CVAL_EL0, and finally CNTV_CTL_EL0.
    /// Returns 0. Dispatches to `hvc_vtimer_load_guest`.
    vtimer_load_guest = 6,
    /// `arg` = pointer to a `vtimer.VtimerState`. Reads CNTV_CTL_EL0,
    /// CNTV_CVAL_EL0, and CNTKCTL_EL1 back into the shadow, then writes
    /// CNTV_CTL_EL0 = 0x2 (IMASK=1, ENABLE=0) to mask any post-exit
    /// host-side virtual timer expiry (ARM ARM D13.11.17). Returns 0.
    /// Dispatches to `hvc_vtimer_save_guest`.
    vtimer_save_guest = 7,
};

/// Issue `hvc #0` with (id, arg) and return the 64-bit result in x0.
///
/// Marked `inline` because the `hvc` instruction is only legal in kernel
/// code paths that know EL2 is present — we want the callsite to be a
/// bare hvc, not a call through a function pointer.
pub inline fn hypCall(id: HypCallId, arg: u64) u64 {
    var ret: u64 = undefined;
    asm volatile (
        \\hvc #0
        : [ret] "={x0}" (ret),
        : [id] "{x0}" (@intFromEnum(id)),
          [arg] "{x1}" (arg),
        : .{
          // Hyp stubs use x2, x3 as temporaries (see hvc_tlbi_ipa,
          // hvc_vgic_prepare_entry, etc.) so mark every AArch64
          // caller-saved GPR as clobbered. Only x19..x30 are
          // preserved across the EL1↔EL2 hand-off.
          .memory = true,
          .x1 = true,
          .x2 = true,
          .x3 = true,
          .x4 = true,
          .x5 = true,
          .x6 = true,
          .x7 = true,
          .x8 = true,
          .x9 = true,
          .x10 = true,
          .x11 = true,
          .x12 = true,
          .x13 = true,
          .x14 = true,
          .x15 = true,
          .x16 = true,
          .x17 = true,
          .x18 = true,
        });
    return ret;
}

// ===========================================================================
// HCR_EL2 bits and baseline
// ===========================================================================

// HCR_EL2 bits (ARM ARM D13.2.46, "HCR_EL2, Hypervisor Configuration Register").
// Only the bits this file actually touches are named; the rest stay 0 unless
// a future change explicitly opts them in.
pub const HCR_EL2_VM: u64 = 1 << 0; // stage-2 translation enable
pub const HCR_EL2_SWIO: u64 = 1 << 1; // set/way IO is set-to-one (RES1 on modern impls)
pub const HCR_EL2_FMO: u64 = 1 << 3; // route physical FIQ to EL2 / enable vFIQ
pub const HCR_EL2_IMO: u64 = 1 << 4; // route physical IRQ to EL2 / enable vIRQ
pub const HCR_EL2_AMO: u64 = 1 << 5; // route physical SError to EL2 / enable vSError
pub const HCR_EL2_VF: u64 = 1 << 6; // virtual FIQ pending (set by vgic inject)
pub const HCR_EL2_VI: u64 = 1 << 7; // virtual IRQ pending (set by vgic inject)
pub const HCR_EL2_TWI: u64 = 1 << 13; // trap WFI from EL1/EL0 to EL2
pub const HCR_EL2_TWE: u64 = 1 << 14; // trap WFE from EL1/EL0 to EL2
pub const HCR_EL2_TID0: u64 = 1 << 15; // trap ID group 0 reads (AArch32 feature ids)
pub const HCR_EL2_TID1: u64 = 1 << 16; // trap ID group 1 reads
pub const HCR_EL2_TID2: u64 = 1 << 17; // trap ID group 2 reads (CTR/DCZID/CCSIDR...)
pub const HCR_EL2_TID3: u64 = 1 << 18; // trap ID group 3 reads (ID_AA64*_EL1)
pub const HCR_EL2_TSC: u64 = 1 << 19; // trap SMC from EL1 to EL2
pub const HCR_EL2_TIDCP: u64 = 1 << 20; // trap impl-defined sysregs at EL1
pub const HCR_EL2_TACR: u64 = 1 << 21; // trap ACTLR_EL1 access
pub const HCR_EL2_TTLB: u64 = 1 << 25; // trap TLB maintenance (NOT set — too slow)
pub const HCR_EL2_TVM: u64 = 1 << 26; // trap VM sysregs writes (NOT set — too slow)
pub const HCR_EL2_TGE: u64 = 1 << 27; // "host EL2" — MUST stay 0 for an EL1 guest
pub const HCR_EL2_TRVM: u64 = 1 << 30; // trap VM sysregs reads (NOT set — too slow)
pub const HCR_EL2_RW: u64 = 1 << 31; // EL1 execution state = AArch64 (not AArch32)

/// Default HCR_EL2 mask for a freshly constructed AArch64 Linux guest.
///
/// Rationale per bit (ARM ARM D13.2.46):
///   VM    : stage-2 translation on — without this, guest PAs pass straight
///           through to host PA and the whole IPA abstraction collapses.
///   SWIO  : set/way IO treated as inner-shareable. Linux issues set/way
///           maintenance during early boot; letting those escape to the
///           host would evict host lines. RES1 on ARMv8.0+.
///   FMO/IMO/AMO : physical FIQ/IRQ/SError route to EL2 and the matching
///           virtual {F,I,SE} delivery is enabled. Required for any vGIC
///           or vSError injection to be visible to the guest.
///   TWI   : trap WFI so guest halts exit cleanly into the run loop.
///   TWE   : trap WFE — optional, but keeps spinlock-loop stalls observable
///           to the VMM instead of burning guest TIME.
///   TID0/1/2/3 : trap ID register reads. Needed so the VmPolicy ID register
///           response table (see `VmPolicy.id_reg_responses`) can virtualize
///           ID_AA64*_EL1 per-VM rather than leaking the raw host features.
///   TSC   : trap SMC so guest SMC calls exit to the hyp and are decoded by
///           the SMCCC shim, not silently forwarded to EL3.
///   TIDCP : trap implementation-defined sysregs at EL1. Belt-and-braces
///           against CPU-errata knobs the guest has no business poking.
///   TACR  : trap ACTLR_EL1 (implementation-defined auxiliary control).
///   RW    : lower EL (EL1/EL0) runs in AArch64. We do not support AArch32
///           guests in this port.
///
/// Bits deliberately left zero:
///   TGE   : if TGE=1, EL1 exceptions get forwarded to EL2 as "host EL2"
///           routing, which breaks every EL1 guest. Linux guests MUST see
///           TGE=0.
///   TVM/TRVM : trapping the VM sysreg family (SCTLR/TTBR*/TCR/MAIR/...) on
///           every guest access is a performance catastrophe — Linux
///           programs SCTLR_EL1 dozens of times during early boot. We let
///           the guest manage its own stage-1 state and rely on stage-2
///           containment.
///   TTLB  : trapping TLB maintenance is likewise too expensive; stage-2
///           VMID tagging already isolates guest TLB entries from the
///           host (ARM ARM D5.10.1).
///   VI/VF : cleared at entry time. `vgic.prepareEntry` OR's them in when
///           a virtual interrupt is pending; clearing them here gives the
///           vgic a known starting point each run.
///   TLOR  : not set — LORegions are not emulated.
///   HA/HD : not set in VTCR_EL2 either; hw access/dirty flag updates are
///           a later-wave optimisation.
pub const HCR_EL2_LINUX_GUEST: u64 = HCR_EL2_VM |
    HCR_EL2_SWIO |
    HCR_EL2_FMO |
    HCR_EL2_IMO |
    HCR_EL2_AMO |
    HCR_EL2_TWI |
    HCR_EL2_TWE |
    HCR_EL2_TID0 |
    HCR_EL2_TID1 |
    HCR_EL2_TID2 |
    HCR_EL2_TID3 |
    HCR_EL2_TSC |
    HCR_EL2_TIDCP |
    HCR_EL2_TACR |
    HCR_EL2_RW;

// ===========================================================================
// ESR_EL2 decoding
// ===========================================================================

/// Decode ESR_EL2 into a typed VmExitInfo. Covers the minimum set of
/// exception classes needed for nop-guest bring-up; deep ISS decode is
/// left to later waves.
///
/// ARM ARM D13.2.39 Table D13-45.
pub fn decodeEsrEl2(esr: u64, far: u64, hpfar: u64) VmExitInfo {
    const ec: u8 = @intCast((esr >> 26) & 0x3F);
    const iss: u32 = @intCast(esr & 0x01FF_FFFF);
    return switch (ec) {
        0x01 => .{ .wfi_wfe = .{ .is_wfe = (iss & 1) != 0 } },
        0x16 => .{ .hvc = .{ .imm = @intCast(iss & 0xFFFF) } },
        0x17 => .{ .smc = .{ .imm = @intCast(iss & 0xFFFF) } },
        0x18 => .{ .sysreg_trap = .{
            .iss = iss,
            .op0 = @intCast((iss >> 20) & 0x3),
            .op1 = @intCast((iss >> 14) & 0x7),
            .crn = @intCast((iss >> 10) & 0xF),
            .crm = @intCast((iss >> 1) & 0xF),
            .op2 = @intCast((iss >> 17) & 0x7),
            .rt = @intCast((iss >> 5) & 0x1F),
            .is_read = (iss & 1) != 0,
        } },
        0x20, 0x24 => blk: {
            // ARM ARM D13.2.39 ESR_EL2 ISS for Data Abort / Instruction
            // Abort from a lower Exception level. HPFAR_EL2 bits [39:4]
            // hold IPA bits [47:12]; FAR_EL2 supplies the low 12 bits.
            const guest_phys = ((hpfar & 0x0FFF_FFFF_FFF0) << 8) | (far & 0xFFF);
            const iss_valid = (iss & (1 << 24)) != 0;
            const S2F = VmExitInfo.Stage2Fault;
            var flags: u8 = 0;
            if (ec == 0x20) flags |= S2F.FLAG_IS_INSTRUCTION;
            if ((iss & (1 << 6)) != 0) flags |= S2F.FLAG_IS_WRITE;
            if (iss_valid) flags |= S2F.FLAG_ISS_VALID;
            if ((iss & (1 << 21)) != 0) flags |= S2F.FLAG_SIGN_EXTEND;
            if ((iss & (1 << 15)) != 0) flags |= S2F.FLAG_REG64;
            if ((iss & (1 << 14)) != 0) flags |= S2F.FLAG_ACQREL;
            break :blk .{ .stage2_fault = .{
                .guest_phys = guest_phys,
                .guest_virt = far,
                .access_size = @intCast((iss >> 22) & 0x3),
                .srt = @intCast((iss >> 16) & 0x1F),
                .fsc = @intCast(iss & 0x3F),
                .flags = flags,
            } };
        },
        0x00 => .{ .unknown_ec = 0 },
        else => .{ .unknown = esr },
    };
}

