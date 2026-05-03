//! linux_guest aarch64 VM-exit syscall wrappers (spec §[vm_exit_state] aarch64).
//!
//! `recvVmExit` and `replyVmExit` wrap the spec recv/reply syscalls
//! for the wide vm_exit state vreg window (vregs 32..127). aarch64
//! vreg ABI:
//!   vreg 0     = [sp + 0]
//!   vreg 1..31 = x0..x30
//!   vreg N     = [sp + (N-31)*8] for 32 <= N <= 127
//!
//! All 31 x-registers are vreg-bound for VM exit delivery, which
//! leaves zero scratch registers. We bridge by sacrificing x16/x17
//! (AAPCS64 IP scratch, vregs 17/18) inside the asm: the inline asm
//! reloads them from the buffer right before `svc` and re-stores their
//! kernel-returned values back into the buffer afterwards. Zig reads
//! them from the buffer post-asm.

const lib = @import("lib");

const buildWord = lib.syscall.buildWord;
const SyscallNum = lib.syscall.SyscallNum;

pub const VmExitState = extern struct {
    // vregs 1..31 = x0..x30 (register-backed)
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
    x29: u64 = 0,
    x30: u64 = 0,

    // vregs 32..35 — pc/pstate/sp_el0/sp_el1
    pc: u64 = 0,
    pstate: u64 = 0,
    sp_el0: u64 = 0,
    sp_el1: u64 = 0,

    // vregs 36..54 — 19 EL1 sysregs
    sctlr_el1: u64 = 0,
    ttbr0_el1: u64 = 0,
    ttbr1_el1: u64 = 0,
    tcr_el1: u64 = 0,
    mair_el1: u64 = 0,
    amair_el1: u64 = 0,
    cpacr_el1: u64 = 0,
    contextidr_el1: u64 = 0,
    tpidr_el0: u64 = 0,
    tpidr_el1: u64 = 0,
    tpidrro_el0: u64 = 0,
    vbar_el1: u64 = 0,
    elr_el1: u64 = 0,
    spsr_el1: u64 = 0,
    esr_el1: u64 = 0,
    far_el1: u64 = 0,
    afsr0_el1: u64 = 0,
    afsr1_el1: u64 = 0,
    mdscr_el1: u64 = 0,

    // vregs 55..73 (CPU ident + ID_AA64*) — read-only / projected zero
    // by the kernel until the VmPolicy id_reg_responses path is wired.
    midr_el1: u64 = 0,
    mpidr_el1: u64 = 0,
    revidr_el1: u64 = 0,
    id_aa64pfr0_el1: u64 = 0,
    id_aa64pfr1_el1: u64 = 0,
    id_aa64zfr0_el1: u64 = 0,
    id_aa64smfr0_el1: u64 = 0,
    id_aa64dfr0_el1: u64 = 0,
    id_aa64dfr1_el1: u64 = 0,
    id_aa64afr0_el1: u64 = 0,
    id_aa64afr1_el1: u64 = 0,
    id_aa64isar0_el1: u64 = 0,
    id_aa64isar1_el1: u64 = 0,
    id_aa64isar2_el1: u64 = 0,
    id_aa64mmfr0_el1: u64 = 0,
    id_aa64mmfr1_el1: u64 = 0,
    id_aa64mmfr2_el1: u64 = 0,
    id_aa64mmfr3_el1: u64 = 0,
    id_aa64mmfr4_el1: u64 = 0,

    // vregs 74..81 — timers
    cntv_cval_el0: u64 = 0,
    cntv_ctl_el0: u64 = 0,
    cntv_tval_el0: u64 = 0,
    cntp_cval_el0: u64 = 0,
    cntp_ctl_el0: u64 = 0,
    cntp_tval_el0: u64 = 0,
    cntkctl_el1: u64 = 0,
    cntvoff_el2: u64 = 0,

    // vregs 82..101 — debug regs
    dbgbvr_el1: [6]u64 = .{0} ** 6,
    dbgbcr_el1: [6]u64 = .{0} ** 6,
    dbgwvr_el1: [4]u64 = .{0} ** 4,
    dbgwcr_el1: [4]u64 = .{0} ** 4,

    // vregs 102..115 — PMU regs
    pmcr_el0: u64 = 0,
    pmcntenset_el0: u64 = 0,
    pmcntenclr_el0: u64 = 0,
    pmovsr_el0: u64 = 0,
    pmovsset_el0: u64 = 0,
    pmselr_el0: u64 = 0,
    pmccntr_el0: u64 = 0,
    pmxevtyper_el0: u64 = 0,
    pmxevcntr_el0: u64 = 0,
    pmccfiltr_el0: u64 = 0,
    pmintenset_el1: u64 = 0,
    pmintenclr_el1: u64 = 0,
    pmuserenr_el0: u64 = 0,
    pmevcntr_aggregate: u64 = 0,

    // vreg 116 — packed pending (vIRQ/vFIQ/vSError)
    pending_intr: u64 = 0,

    // vreg 117 — exit sub-code
    exit_subcode: u64 = 0,
    // vregs 118..120 — exit payload
    exit_payload: [3]u64 = .{ 0, 0, 0 },
};

// Spec §[vm_exit_state] aarch64 sub-codes.
pub const VmExitSubcode = enum(u8) {
    stage2_fault = 0,
    hvc = 1,
    smc = 2,
    sysreg = 3,
    wfi_wfe = 4,
    unknown_ec = 5,
    sync_el1 = 6,
    halt = 7,
    shutdown = 8,
    unknown = 9,
    initial_state = 10,
    _,
};

// Static buffer holding the §[vm_exit_state] stack-spilled vregs
// (vregs 32..127) plus the slots used by our scratch-register bridge.
//
// Layout convention: index `i` of the buffer corresponds to vreg
// `31 + i` (so buf[1] = vreg 32 = PC, buf[2] = vreg 33 = PSTATE, ...,
// buf[97] = vreg 127). Buffer is 160 u64 = 1280 bytes (covers the
// vreg window with headroom for our scratch + post-svc register dump).
//
// Slot map past the vreg window:
//   SCRATCH_X16   = buf[100]   guest x16 input staging (asm reloads pre-svc)
//   SCRATCH_X17   = buf[101]   guest x17 input staging
//   SAVED_SP      = buf[102]   user sp at asm entry
//   POST_X18..30  = buf[110..123]  asm writes kernel-returned x18..x30 here
//                                  so Zig can read them without exceeding
//                                  the inline-asm output operand cap.
//
// `export` makes the symbol globally addressable so the inline asm
// can use `adrp + :lo12:` to load its base without a register-backed
// input operand.
const BUF_SLOTS: usize = 160;
const SCRATCH_X16: usize = 100;
const SCRATCH_X17: usize = 101;
const SAVED_SP: usize = 102;
const POST_X18_BASE: usize = 110; // x18..x30 land at buf[110..123]

export var vm_exit_buf: [BUF_SLOTS]u64 align(16) = .{0} ** BUF_SLOTS;

pub const RecvVmExitResult = struct {
    /// Syscall error code (vreg 1 / x0 on syscall return). 0 on
    /// success — the kernel delivered an event. Non-zero per
    /// §[error_codes] (E_TIMEOUT / E_BADCAP / E_PERM / etc.).
    err: u64,
    /// Reply handle id from syscall-word bits 32-43.
    reply_handle_id: u12,
    /// Event type from syscall-word bits 44-48.
    event_type: u8,
    /// Full §[vm_exit_state] state. Valid only when err == 0.
    state: VmExitState,
};

const VregOffsets = struct {
    // Each vreg N>=32 is at buf[N-31]. Subtraction below names the slots.
    const PC: usize = 1;
    const PSTATE: usize = 2;
    const SP_EL0: usize = 3;
    const SP_EL1: usize = 4;
    const SCTLR_EL1: usize = 5;
    const TTBR0_EL1: usize = 6;
    const TTBR1_EL1: usize = 7;
    const TCR_EL1: usize = 8;
    const MAIR_EL1: usize = 9;
    const AMAIR_EL1: usize = 10;
    const CPACR_EL1: usize = 11;
    const CONTEXTIDR_EL1: usize = 12;
    const TPIDR_EL0: usize = 13;
    const TPIDR_EL1: usize = 14;
    const TPIDRRO_EL0: usize = 15;
    const VBAR_EL1: usize = 16;
    const ELR_EL1: usize = 17;
    const SPSR_EL1: usize = 18;
    const ESR_EL1: usize = 19;
    const FAR_EL1: usize = 20;
    const AFSR0_EL1: usize = 21;
    const AFSR1_EL1: usize = 22;
    const MDSCR_EL1: usize = 23;
    const MIDR_EL1: usize = 24;
    const MPIDR_EL1: usize = 25;
    const REVIDR_EL1: usize = 26;
    const ID_AA64_BASE: usize = 27; // 16 ID_AA64* slots
    const CNTV_CVAL_EL0: usize = 43;
    const CNTV_CTL_EL0: usize = 44;
    const CNTV_TVAL_EL0: usize = 45;
    const CNTP_CVAL_EL0: usize = 46;
    const CNTP_CTL_EL0: usize = 47;
    const CNTP_TVAL_EL0: usize = 48;
    const CNTKCTL_EL1: usize = 49;
    const CNTVOFF_EL2: usize = 50;
    const DBG_BASE: usize = 51; // 20 debug slots
    const PMU_BASE: usize = 71; // 14 PMU slots
    const PENDING_INTR: usize = 85;
    const EXIT_SUBCODE: usize = 86;
    const EXIT_PAYLOAD_BASE: usize = 87; // 3 payload slots
};

inline fn writeBufFrom(state: VmExitState) void {
    const buf = &vm_exit_buf;
    buf[0] = 0; // syscall_word slot — overwritten by the asm
    buf[VregOffsets.PC] = state.pc;
    buf[VregOffsets.PSTATE] = state.pstate;
    buf[VregOffsets.SP_EL0] = state.sp_el0;
    buf[VregOffsets.SP_EL1] = state.sp_el1;
    buf[VregOffsets.SCTLR_EL1] = state.sctlr_el1;
    buf[VregOffsets.TTBR0_EL1] = state.ttbr0_el1;
    buf[VregOffsets.TTBR1_EL1] = state.ttbr1_el1;
    buf[VregOffsets.TCR_EL1] = state.tcr_el1;
    buf[VregOffsets.MAIR_EL1] = state.mair_el1;
    buf[VregOffsets.AMAIR_EL1] = state.amair_el1;
    buf[VregOffsets.CPACR_EL1] = state.cpacr_el1;
    buf[VregOffsets.CONTEXTIDR_EL1] = state.contextidr_el1;
    buf[VregOffsets.TPIDR_EL0] = state.tpidr_el0;
    buf[VregOffsets.TPIDR_EL1] = state.tpidr_el1;
    buf[VregOffsets.TPIDRRO_EL0] = state.tpidrro_el0;
    buf[VregOffsets.VBAR_EL1] = state.vbar_el1;
    buf[VregOffsets.ELR_EL1] = state.elr_el1;
    buf[VregOffsets.SPSR_EL1] = state.spsr_el1;
    buf[VregOffsets.ESR_EL1] = state.esr_el1;
    buf[VregOffsets.FAR_EL1] = state.far_el1;
    buf[VregOffsets.AFSR0_EL1] = state.afsr0_el1;
    buf[VregOffsets.AFSR1_EL1] = state.afsr1_el1;
    buf[VregOffsets.MDSCR_EL1] = state.mdscr_el1;
    buf[VregOffsets.MIDR_EL1] = state.midr_el1;
    buf[VregOffsets.MPIDR_EL1] = state.mpidr_el1;
    buf[VregOffsets.REVIDR_EL1] = state.revidr_el1;
    buf[VregOffsets.ID_AA64_BASE + 0] = state.id_aa64pfr0_el1;
    buf[VregOffsets.ID_AA64_BASE + 1] = state.id_aa64pfr1_el1;
    buf[VregOffsets.ID_AA64_BASE + 2] = state.id_aa64zfr0_el1;
    buf[VregOffsets.ID_AA64_BASE + 3] = state.id_aa64smfr0_el1;
    buf[VregOffsets.ID_AA64_BASE + 4] = state.id_aa64dfr0_el1;
    buf[VregOffsets.ID_AA64_BASE + 5] = state.id_aa64dfr1_el1;
    buf[VregOffsets.ID_AA64_BASE + 6] = state.id_aa64afr0_el1;
    buf[VregOffsets.ID_AA64_BASE + 7] = state.id_aa64afr1_el1;
    buf[VregOffsets.ID_AA64_BASE + 8] = state.id_aa64isar0_el1;
    buf[VregOffsets.ID_AA64_BASE + 9] = state.id_aa64isar1_el1;
    buf[VregOffsets.ID_AA64_BASE + 10] = state.id_aa64isar2_el1;
    buf[VregOffsets.ID_AA64_BASE + 11] = state.id_aa64mmfr0_el1;
    buf[VregOffsets.ID_AA64_BASE + 12] = state.id_aa64mmfr1_el1;
    buf[VregOffsets.ID_AA64_BASE + 13] = state.id_aa64mmfr2_el1;
    buf[VregOffsets.ID_AA64_BASE + 14] = state.id_aa64mmfr3_el1;
    buf[VregOffsets.ID_AA64_BASE + 15] = state.id_aa64mmfr4_el1;
    buf[VregOffsets.CNTV_CVAL_EL0] = state.cntv_cval_el0;
    buf[VregOffsets.CNTV_CTL_EL0] = state.cntv_ctl_el0;
    buf[VregOffsets.CNTV_TVAL_EL0] = state.cntv_tval_el0;
    buf[VregOffsets.CNTP_CVAL_EL0] = state.cntp_cval_el0;
    buf[VregOffsets.CNTP_CTL_EL0] = state.cntp_ctl_el0;
    buf[VregOffsets.CNTP_TVAL_EL0] = state.cntp_tval_el0;
    buf[VregOffsets.CNTKCTL_EL1] = state.cntkctl_el1;
    buf[VregOffsets.CNTVOFF_EL2] = state.cntvoff_el2;
    inline for (state.dbgbvr_el1, 0..) |v, i| buf[VregOffsets.DBG_BASE + i] = v;
    inline for (state.dbgbcr_el1, 0..) |v, i| buf[VregOffsets.DBG_BASE + 6 + i] = v;
    inline for (state.dbgwvr_el1, 0..) |v, i| buf[VregOffsets.DBG_BASE + 12 + i] = v;
    inline for (state.dbgwcr_el1, 0..) |v, i| buf[VregOffsets.DBG_BASE + 16 + i] = v;
    buf[VregOffsets.PMU_BASE + 0] = state.pmcr_el0;
    buf[VregOffsets.PMU_BASE + 1] = state.pmcntenset_el0;
    buf[VregOffsets.PMU_BASE + 2] = state.pmcntenclr_el0;
    buf[VregOffsets.PMU_BASE + 3] = state.pmovsr_el0;
    buf[VregOffsets.PMU_BASE + 4] = state.pmovsset_el0;
    buf[VregOffsets.PMU_BASE + 5] = state.pmselr_el0;
    buf[VregOffsets.PMU_BASE + 6] = state.pmccntr_el0;
    buf[VregOffsets.PMU_BASE + 7] = state.pmxevtyper_el0;
    buf[VregOffsets.PMU_BASE + 8] = state.pmxevcntr_el0;
    buf[VregOffsets.PMU_BASE + 9] = state.pmccfiltr_el0;
    buf[VregOffsets.PMU_BASE + 10] = state.pmintenset_el1;
    buf[VregOffsets.PMU_BASE + 11] = state.pmintenclr_el1;
    buf[VregOffsets.PMU_BASE + 12] = state.pmuserenr_el0;
    buf[VregOffsets.PMU_BASE + 13] = state.pmevcntr_aggregate;
    buf[VregOffsets.PENDING_INTR] = state.pending_intr;
    buf[VregOffsets.EXIT_SUBCODE] = state.exit_subcode;
    buf[VregOffsets.EXIT_PAYLOAD_BASE + 0] = state.exit_payload[0];
    buf[VregOffsets.EXIT_PAYLOAD_BASE + 1] = state.exit_payload[1];
    buf[VregOffsets.EXIT_PAYLOAD_BASE + 2] = state.exit_payload[2];
    // Pre-stage guest x16 / x17 — the asm clobbers them as scratch and
    // reloads from these slots right before `svc`.
    buf[SCRATCH_X16] = state.x16;
    buf[SCRATCH_X17] = state.x17;
}

inline fn readBufInto(state: *VmExitState) void {
    const buf = &vm_exit_buf;
    state.pc = buf[VregOffsets.PC];
    state.pstate = buf[VregOffsets.PSTATE];
    state.sp_el0 = buf[VregOffsets.SP_EL0];
    state.sp_el1 = buf[VregOffsets.SP_EL1];
    state.sctlr_el1 = buf[VregOffsets.SCTLR_EL1];
    state.ttbr0_el1 = buf[VregOffsets.TTBR0_EL1];
    state.ttbr1_el1 = buf[VregOffsets.TTBR1_EL1];
    state.tcr_el1 = buf[VregOffsets.TCR_EL1];
    state.mair_el1 = buf[VregOffsets.MAIR_EL1];
    state.amair_el1 = buf[VregOffsets.AMAIR_EL1];
    state.cpacr_el1 = buf[VregOffsets.CPACR_EL1];
    state.contextidr_el1 = buf[VregOffsets.CONTEXTIDR_EL1];
    state.tpidr_el0 = buf[VregOffsets.TPIDR_EL0];
    state.tpidr_el1 = buf[VregOffsets.TPIDR_EL1];
    state.tpidrro_el0 = buf[VregOffsets.TPIDRRO_EL0];
    state.vbar_el1 = buf[VregOffsets.VBAR_EL1];
    state.elr_el1 = buf[VregOffsets.ELR_EL1];
    state.spsr_el1 = buf[VregOffsets.SPSR_EL1];
    state.esr_el1 = buf[VregOffsets.ESR_EL1];
    state.far_el1 = buf[VregOffsets.FAR_EL1];
    state.afsr0_el1 = buf[VregOffsets.AFSR0_EL1];
    state.afsr1_el1 = buf[VregOffsets.AFSR1_EL1];
    state.mdscr_el1 = buf[VregOffsets.MDSCR_EL1];
    state.midr_el1 = buf[VregOffsets.MIDR_EL1];
    state.mpidr_el1 = buf[VregOffsets.MPIDR_EL1];
    state.revidr_el1 = buf[VregOffsets.REVIDR_EL1];
    state.id_aa64pfr0_el1 = buf[VregOffsets.ID_AA64_BASE + 0];
    state.id_aa64pfr1_el1 = buf[VregOffsets.ID_AA64_BASE + 1];
    state.id_aa64zfr0_el1 = buf[VregOffsets.ID_AA64_BASE + 2];
    state.id_aa64smfr0_el1 = buf[VregOffsets.ID_AA64_BASE + 3];
    state.id_aa64dfr0_el1 = buf[VregOffsets.ID_AA64_BASE + 4];
    state.id_aa64dfr1_el1 = buf[VregOffsets.ID_AA64_BASE + 5];
    state.id_aa64afr0_el1 = buf[VregOffsets.ID_AA64_BASE + 6];
    state.id_aa64afr1_el1 = buf[VregOffsets.ID_AA64_BASE + 7];
    state.id_aa64isar0_el1 = buf[VregOffsets.ID_AA64_BASE + 8];
    state.id_aa64isar1_el1 = buf[VregOffsets.ID_AA64_BASE + 9];
    state.id_aa64isar2_el1 = buf[VregOffsets.ID_AA64_BASE + 10];
    state.id_aa64mmfr0_el1 = buf[VregOffsets.ID_AA64_BASE + 11];
    state.id_aa64mmfr1_el1 = buf[VregOffsets.ID_AA64_BASE + 12];
    state.id_aa64mmfr2_el1 = buf[VregOffsets.ID_AA64_BASE + 13];
    state.id_aa64mmfr3_el1 = buf[VregOffsets.ID_AA64_BASE + 14];
    state.id_aa64mmfr4_el1 = buf[VregOffsets.ID_AA64_BASE + 15];
    state.cntv_cval_el0 = buf[VregOffsets.CNTV_CVAL_EL0];
    state.cntv_ctl_el0 = buf[VregOffsets.CNTV_CTL_EL0];
    state.cntv_tval_el0 = buf[VregOffsets.CNTV_TVAL_EL0];
    state.cntp_cval_el0 = buf[VregOffsets.CNTP_CVAL_EL0];
    state.cntp_ctl_el0 = buf[VregOffsets.CNTP_CTL_EL0];
    state.cntp_tval_el0 = buf[VregOffsets.CNTP_TVAL_EL0];
    state.cntkctl_el1 = buf[VregOffsets.CNTKCTL_EL1];
    state.cntvoff_el2 = buf[VregOffsets.CNTVOFF_EL2];
    inline for (&state.dbgbvr_el1, 0..) |*v, i| v.* = buf[VregOffsets.DBG_BASE + i];
    inline for (&state.dbgbcr_el1, 0..) |*v, i| v.* = buf[VregOffsets.DBG_BASE + 6 + i];
    inline for (&state.dbgwvr_el1, 0..) |*v, i| v.* = buf[VregOffsets.DBG_BASE + 12 + i];
    inline for (&state.dbgwcr_el1, 0..) |*v, i| v.* = buf[VregOffsets.DBG_BASE + 16 + i];
    state.pmcr_el0 = buf[VregOffsets.PMU_BASE + 0];
    state.pmcntenset_el0 = buf[VregOffsets.PMU_BASE + 1];
    state.pmcntenclr_el0 = buf[VregOffsets.PMU_BASE + 2];
    state.pmovsr_el0 = buf[VregOffsets.PMU_BASE + 3];
    state.pmovsset_el0 = buf[VregOffsets.PMU_BASE + 4];
    state.pmselr_el0 = buf[VregOffsets.PMU_BASE + 5];
    state.pmccntr_el0 = buf[VregOffsets.PMU_BASE + 6];
    state.pmxevtyper_el0 = buf[VregOffsets.PMU_BASE + 7];
    state.pmxevcntr_el0 = buf[VregOffsets.PMU_BASE + 8];
    state.pmccfiltr_el0 = buf[VregOffsets.PMU_BASE + 9];
    state.pmintenset_el1 = buf[VregOffsets.PMU_BASE + 10];
    state.pmintenclr_el1 = buf[VregOffsets.PMU_BASE + 11];
    state.pmuserenr_el0 = buf[VregOffsets.PMU_BASE + 12];
    state.pmevcntr_aggregate = buf[VregOffsets.PMU_BASE + 13];
    state.pending_intr = buf[VregOffsets.PENDING_INTR];
    state.exit_subcode = buf[VregOffsets.EXIT_SUBCODE];
    state.exit_payload[0] = buf[VregOffsets.EXIT_PAYLOAD_BASE + 0];
    state.exit_payload[1] = buf[VregOffsets.EXIT_PAYLOAD_BASE + 1];
    state.exit_payload[2] = buf[VregOffsets.EXIT_PAYLOAD_BASE + 2];
    // Pull kernel's x16/x17 reply from the scratch slots the asm
    // wrote post-svc.
    state.x16 = buf[SCRATCH_X16];
    state.x17 = buf[SCRATCH_X17];
}

/// Recv on a vCPU's exit_port. Blocks until an exit fires (or
/// `timeout_ns` elapses; 0 = block indefinitely). On success populates
/// `state` with the §[vm_exit_state] vreg window and returns the reply
/// handle id (in the syscall word). On error, `state` is undefined and
/// `err` carries the error code.
pub fn recvVmExit(port: u12, timeout_ns: u64) RecvVmExitResult {
    const word = buildWord(.recv, 0);
    // Stage the syscall word at vreg 0 (= [sp]) in the buffer, plus
    // anywhere else the kernel reads input from. Inputs for vregs
    // 1..31 ride in x0..x30 directly; for recv only x0..x2 carry
    // input (port handle, _, timeout); the rest are output-only.
    const state: VmExitState = .{};
    writeBufFrom(state);
    vm_exit_buf[0] = word;

    var ox0: u64 = undefined;
    var ox1: u64 = undefined;
    var ox2: u64 = undefined;
    var ox3: u64 = undefined;
    var ox4: u64 = undefined;
    var ox5: u64 = undefined;
    var ox6: u64 = undefined;
    var ox7: u64 = undefined;
    var ox8: u64 = undefined;
    var ox9: u64 = undefined;
    var ox10: u64 = undefined;
    var ox11: u64 = undefined;
    var ox12: u64 = undefined;
    var ox13: u64 = undefined;
    var ox14: u64 = undefined;

    // Asm structure (Zig caps inline asm at 15 outputs / 31 inputs):
    //   * Pre-svc: switch sp to vm_exit_buf, save user sp, reload
    //     guest x16/x17 from scratch slots.
    //   * svc #0
    //   * Post-svc: stash kernel-returned x15, x16, x17, x18..x30
    //     into buffer slots so Zig can read them. x0..x14 ride out
    //     as asm output operands.
    //   * Restore sp.
    asm volatile (
        \\ adrp x16, vm_exit_buf
        \\ add  x16, x16, :lo12:vm_exit_buf
        \\ mov  x17, sp
        \\ mov  sp, x16
        \\ str  x17, [sp, #(102 * 8)]
        \\ ldr  x16, [sp, #(100 * 8)]
        \\ ldr  x17, [sp, #(101 * 8)]
        \\ svc  #0
        \\ str  x15, [sp, #(124 * 8)]
        \\ str  x16, [sp, #(100 * 8)]
        \\ str  x17, [sp, #(101 * 8)]
        \\ str  x18, [sp, #(110 * 8)]
        \\ str  x19, [sp, #(111 * 8)]
        \\ str  x20, [sp, #(112 * 8)]
        \\ str  x21, [sp, #(113 * 8)]
        \\ str  x22, [sp, #(114 * 8)]
        \\ str  x23, [sp, #(115 * 8)]
        \\ str  x24, [sp, #(116 * 8)]
        \\ str  x25, [sp, #(117 * 8)]
        \\ str  x26, [sp, #(118 * 8)]
        \\ str  x27, [sp, #(119 * 8)]
        \\ str  x28, [sp, #(120 * 8)]
        \\ str  x29, [sp, #(121 * 8)]
        \\ str  x30, [sp, #(122 * 8)]
        \\ ldr  x16, [sp, #(102 * 8)]
        \\ mov  sp, x16
        : [v1] "={x0}" (ox0),
          [v2] "={x1}" (ox1),
          [v3] "={x2}" (ox2),
          [v4] "={x3}" (ox3),
          [v5] "={x4}" (ox4),
          [v6] "={x5}" (ox5),
          [v7] "={x6}" (ox6),
          [v8] "={x7}" (ox7),
          [v9] "={x8}" (ox8),
          [v10] "={x9}" (ox9),
          [v11] "={x10}" (ox10),
          [v12] "={x11}" (ox11),
          [v13] "={x12}" (ox12),
          [v14] "={x13}" (ox13),
          [v15] "={x14}" (ox14),
        : [iv1] "{x0}" (@as(u64, port)),
          [iv2] "{x1}" (@as(u64, 0)),
          [iv3] "{x2}" (timeout_ns),
        : .{ .x15 = true, .x18 = true, .x19 = true, .x20 = true,
             .x21 = true, .x22 = true, .x23 = true, .x24 = true,
             .x25 = true, .x26 = true, .x27 = true, .x28 = true,
             .x29 = true, .x30 = true, .memory = true });

    // The §[recv] return word lands at [sp + 0] which is vm_exit_buf[0]
    // because we kept sp = &vm_exit_buf during the syscall.
    const oword = vm_exit_buf[0];

    var result = RecvVmExitResult{
        .err = 0,
        .reply_handle_id = 0,
        .event_type = 0,
        .state = .{},
    };

    result.reply_handle_id = @truncate((oword >> 32) & 0xFFF);
    result.event_type = @truncate((oword >> 44) & 0x1F);

    if (result.event_type == 0) {
        // Fast-failure (E_TIMEOUT etc.). vreg 1 (x0) carries the error.
        result.err = ox0;
        return result;
    }

    // Project x0..x14 (asm output operands) into vregs 1..15.
    result.state.x0 = ox0;
    result.state.x1 = ox1;
    result.state.x2 = ox2;
    result.state.x3 = ox3;
    result.state.x4 = ox4;
    result.state.x5 = ox5;
    result.state.x6 = ox6;
    result.state.x7 = ox7;
    result.state.x8 = ox8;
    result.state.x9 = ox9;
    result.state.x10 = ox10;
    result.state.x11 = ox11;
    result.state.x12 = ox12;
    result.state.x13 = ox13;
    result.state.x14 = ox14;

    // Pull x15 (vreg 16) from the dedicated buffer slot.
    result.state.x15 = vm_exit_buf[124];

    // Pull x18..x30 (vregs 19..31) from buffer slots the asm wrote
    // post-svc.
    result.state.x18 = vm_exit_buf[POST_X18_BASE + 0];
    result.state.x19 = vm_exit_buf[POST_X18_BASE + 1];
    result.state.x20 = vm_exit_buf[POST_X18_BASE + 2];
    result.state.x21 = vm_exit_buf[POST_X18_BASE + 3];
    result.state.x22 = vm_exit_buf[POST_X18_BASE + 4];
    result.state.x23 = vm_exit_buf[POST_X18_BASE + 5];
    result.state.x24 = vm_exit_buf[POST_X18_BASE + 6];
    result.state.x25 = vm_exit_buf[POST_X18_BASE + 7];
    result.state.x26 = vm_exit_buf[POST_X18_BASE + 8];
    result.state.x27 = vm_exit_buf[POST_X18_BASE + 9];
    result.state.x28 = vm_exit_buf[POST_X18_BASE + 10];
    result.state.x29 = vm_exit_buf[POST_X18_BASE + 11];
    result.state.x30 = vm_exit_buf[POST_X18_BASE + 12];

    readBufInto(&result.state);

    return result;
}

/// Reply to a vm_exit event with `state` as the new guest state.
pub fn replyVmExit(reply_handle_id: u12, state: VmExitState) u64 {
    const word: u64 =
        (@as(u64, @intFromEnum(SyscallNum.reply)) & 0xFFF) |
        (@as(u64, reply_handle_id) << 12);

    writeBufFrom(state);
    vm_exit_buf[0] = word;

    // Pre-stage x18..x30 inputs at known buffer slots; asm reloads
    // them into the GPRs right before svc since Zig's input operand
    // cap can't bind that many register-class inputs alongside the
    // x16/x17 scratch dance.
    const buf = &vm_exit_buf;
    buf[POST_X18_BASE + 0] = state.x18;
    buf[POST_X18_BASE + 1] = state.x19;
    buf[POST_X18_BASE + 2] = state.x20;
    buf[POST_X18_BASE + 3] = state.x21;
    buf[POST_X18_BASE + 4] = state.x22;
    buf[POST_X18_BASE + 5] = state.x23;
    buf[POST_X18_BASE + 6] = state.x24;
    buf[POST_X18_BASE + 7] = state.x25;
    buf[POST_X18_BASE + 8] = state.x26;
    buf[POST_X18_BASE + 9] = state.x27;
    buf[POST_X18_BASE + 10] = state.x28;
    buf[POST_X18_BASE + 11] = state.x29;
    buf[POST_X18_BASE + 12] = state.x30;

    var ox0: u64 = undefined;
    asm volatile (
        \\ adrp x16, vm_exit_buf
        \\ add  x16, x16, :lo12:vm_exit_buf
        \\ mov  x17, sp
        \\ mov  sp, x16
        \\ str  x17, [sp, #(102 * 8)]
        \\ ldr  x18, [sp, #(110 * 8)]
        \\ ldr  x19, [sp, #(111 * 8)]
        \\ ldr  x20, [sp, #(112 * 8)]
        \\ ldr  x21, [sp, #(113 * 8)]
        \\ ldr  x22, [sp, #(114 * 8)]
        \\ ldr  x23, [sp, #(115 * 8)]
        \\ ldr  x24, [sp, #(116 * 8)]
        \\ ldr  x25, [sp, #(117 * 8)]
        \\ ldr  x26, [sp, #(118 * 8)]
        \\ ldr  x27, [sp, #(119 * 8)]
        \\ ldr  x28, [sp, #(120 * 8)]
        \\ ldr  x29, [sp, #(121 * 8)]
        \\ ldr  x30, [sp, #(122 * 8)]
        \\ ldr  x16, [sp, #(100 * 8)]
        \\ ldr  x17, [sp, #(101 * 8)]
        \\ svc  #0
        \\ ldr  x16, [sp, #(102 * 8)]
        \\ mov  sp, x16
        : [v1] "={x0}" (ox0),
        : [iv1] "{x0}" (state.x0),
          [iv2] "{x1}" (state.x1),
          [iv3] "{x2}" (state.x2),
          [iv4] "{x3}" (state.x3),
          [iv5] "{x4}" (state.x4),
          [iv6] "{x5}" (state.x5),
          [iv7] "{x6}" (state.x6),
          [iv8] "{x7}" (state.x7),
          [iv9] "{x8}" (state.x8),
          [iv10] "{x9}" (state.x9),
          [iv11] "{x10}" (state.x10),
          [iv12] "{x11}" (state.x11),
          [iv13] "{x12}" (state.x12),
          [iv14] "{x13}" (state.x13),
          [iv15] "{x14}" (state.x14),
          [iv16] "{x15}" (state.x15),
        : .{ .x1 = true, .x2 = true, .x3 = true, .x4 = true, .x5 = true,
             .x6 = true, .x7 = true, .x8 = true, .x9 = true, .x10 = true,
             .x11 = true, .x12 = true, .x13 = true, .x14 = true, .x15 = true,
             .x18 = true, .x19 = true, .x20 = true, .x21 = true, .x22 = true,
             .x23 = true, .x24 = true, .x25 = true, .x26 = true, .x27 = true,
             .x28 = true, .x29 = true, .x30 = true, .memory = true });
    return ox0;
}
