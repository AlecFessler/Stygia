// linux_guest VM exit syscall wrappers (spec §[vm_exit_state] x86-64).
//
// `recvVmExit` and `replyVmExit` wrap the spec recv/reply syscalls for
// the wide vm_exit state vreg window (vregs 14..73). They route the
// window through a static buffer (`vm_exit_buf`) by pointing rsp at it
// for the syscall and restoring user rsp after — every GPR except rcx/r11
// is vreg-bound during the syscall, so a global is required to hold the
// saved-rsp pointer.
//
// Single-threaded VMM only — linux_guest's main loop is the only consumer.

const lib = @import("lib");

const buildWord = lib.syscall.buildWord;
const SyscallNum = lib.syscall.SyscallNum;

pub const SegmentReg = extern struct {
    base: u64 = 0,
    limit: u32 = 0,
    selector: u16 = 0,
    access_rights: u16 = 0,
};

pub const VmExitState = extern struct {
    // GPRs (vregs 1..13, register-backed).
    rax: u64 = 0,
    rbx: u64 = 0,
    rdx: u64 = 0,
    rbp: u64 = 0,
    rsi: u64 = 0,
    rdi: u64 = 0,
    r8: u64 = 0,
    r9: u64 = 0,
    r10: u64 = 0,
    r12: u64 = 0,
    r13: u64 = 0,
    r14: u64 = 0,
    r15: u64 = 0,

    // vregs 14..18 (RIP, RFLAGS, RSP, RCX, R11)
    rip: u64 = 0,
    rflags: u64 = 0x2,
    rsp: u64 = 0,
    rcx: u64 = 0,
    r11: u64 = 0,

    // vregs 19..25 (CR0, CR2, CR3, CR4, CR8, EFER, APIC_BASE)
    cr0: u64 = 0,
    cr2: u64 = 0,
    cr3: u64 = 0,
    cr4: u64 = 0,
    cr8: u64 = 0,
    efer: u64 = 0,
    apic_base: u64 = 0,

    // vregs 26..41 (8 segment registers × 2 vregs each).
    cs: SegmentReg = .{},
    ds: SegmentReg = .{},
    es: SegmentReg = .{},
    fs: SegmentReg = .{},
    gs: SegmentReg = .{},
    ss: SegmentReg = .{},
    tr: SegmentReg = .{},
    ldtr: SegmentReg = .{},

    // vregs 42..45 (GDTR base, GDTR limit, IDTR base, IDTR limit).
    gdtr_base: u64 = 0,
    gdtr_limit: u64 = 0,
    idtr_base: u64 = 0,
    idtr_limit: u64 = 0,

    // vregs 46..55 (STAR, LSTAR, CSTAR, SFMASK, KERNEL_GS_BASE,
    // SYSENTER_CS, SYSENTER_ESP, SYSENTER_EIP, PAT, TSC_AUX).
    star: u64 = 0,
    lstar: u64 = 0,
    cstar: u64 = 0,
    sfmask: u64 = 0,
    kernel_gs_base: u64 = 0,
    sysenter_cs: u64 = 0,
    sysenter_esp: u64 = 0,
    sysenter_eip: u64 = 0,
    pat: u64 = 0,
    tsc_aux: u64 = 0,

    // vregs 56..61 (DR0..DR3, DR6, DR7).
    dr0: u64 = 0,
    dr1: u64 = 0,
    dr2: u64 = 0,
    dr3: u64 = 0,
    dr6: u64 = 0,
    dr7: u64 = 0x400,

    // vregs 62..65 (vcpu_events).
    vcpu_event_exception: u64 = 0,
    vcpu_event_exception_payload: u64 = 0,
    vcpu_event_intr_nmi: u64 = 0,
    vcpu_event_sipi_smi_triple: u64 = 0,

    // vregs 66..69 (interrupt_bitmap, 256 bits = 4 u64s).
    interrupt_bitmap: [4]u64 = .{ 0, 0, 0, 0 },

    // vregs 70..73 (exit sub-code + 3-vreg payload).
    exit_subcode: u64 = 0,
    exit_payload: [3]u64 = .{ 0, 0, 0 },
};

// Spec §[vm_exit_state] x86-64 sub-codes.
pub const VmExitSubcode = enum(u8) {
    cpuid = 0,
    io = 1,
    mmio = 2,
    cr = 3,
    msr_r = 4,
    msr_w = 5,
    ept = 6,
    except = 7,
    intwin = 8,
    hlt = 9,
    shutdown = 10,
    triple = 11,
    unknown = 12,
    _,
};

// Static backing for the §[vm_exit_state] vreg window. recvVmExit /
// replyVmExit point rsp at `vm_exit_buf` for the syscall (so the kernel
// reads/writes vregs into it) and restore user rsp from
// `vm_exit_saved_rsp` afterward.
//
// `export` makes the symbols globally visible so inline asm can use
// RIP-relative addressing without a register-backed input operand
// (every GPR except rcx/r11 is vreg-backed during the syscall and
// can't be reserved as scratch).
export var vm_exit_saved_rsp: u64 align(16) = 0;
export var vm_exit_buf: [128]u64 align(16) = .{0} ** 128;

pub const RecvVmExitResult = struct {
    /// Syscall error code (vreg 1 / rax on syscall return). 0 on
    /// success — the kernel delivered an event. Non-zero values per
    /// spec §[error_codes] (E_TIMEOUT / E_BADCAP / E_PERM / E_CLOSED /
    /// E_FULL).
    err: u64,
    /// Reply handle id from syscall-word bits 32-43. Valid only when
    /// `err == 0`. Pass to `replyVmExit` to resume the vCPU.
    reply_handle_id: u12,
    /// Event type from syscall-word bits 44-48. For vm_exit, this is
    /// 5 (per spec §[event_type]).
    event_type: u8,
    /// Full §[vm_exit_state] state. Valid only when `err == 0`.
    state: VmExitState,
};

/// Recv on a vCPU's exit_port. Blocks until an exit fires (or
/// `timeout_ns` elapses; 0 = block indefinitely). On success populates
/// `state` with the §[vm_exit_state] vreg window and returns the reply
/// handle id (in the syscall word). On error, `state` is undefined and
/// `err` carries the error code.
pub fn recvVmExit(port: u12, timeout_ns: u64) RecvVmExitResult {
    const word = buildWord(.recv, 0);

    var ov1: u64 = undefined;
    var ov2: u64 = undefined;
    var ov3: u64 = undefined;
    var ov4: u64 = undefined;
    var ov5: u64 = undefined;
    var ov6: u64 = undefined;
    var ov7: u64 = undefined;
    var ov8: u64 = undefined;
    var ov9: u64 = undefined;
    var ov10: u64 = undefined;
    var ov11: u64 = undefined;
    var ov12: u64 = undefined;
    var ov13: u64 = undefined;
    var oword: u64 = undefined;

    asm volatile (
        \\ movq %%rsp, vm_exit_saved_rsp(%%rip)
        \\ leaq vm_exit_buf(%%rip), %%rsp
        \\ movq %%rcx, (%%rsp)
        \\ syscall
        \\ movq (%%rsp), %%rcx
        \\ movq vm_exit_saved_rsp(%%rip), %%rsp
        : [v1] "={rax}" (ov1),
          [v2] "={rbx}" (ov2),
          [v3] "={rdx}" (ov3),
          [v4] "={rbp}" (ov4),
          [v5] "={rsi}" (ov5),
          [v6] "={rdi}" (ov6),
          [v7] "={r8}" (ov7),
          [v8] "={r9}" (ov8),
          [v9] "={r10}" (ov9),
          [v10] "={r12}" (ov10),
          [v11] "={r13}" (ov11),
          [v12] "={r14}" (ov12),
          [v13] "={r15}" (ov13),
          [oword] "={rcx}" (oword),
        : [word] "{rcx}" (word),
          [iv1] "{rax}" (@as(u64, port)),
          [iv2] "{rbx}" (@as(u64, 0)),
          [iv3] "{rdx}" (timeout_ns),
        : .{ .r11 = true, .memory = true });

    var result = RecvVmExitResult{
        .err = 0,
        .reply_handle_id = 0,
        .event_type = 0,
        .state = .{},
    };

    // §[recv] return word layout:
    //   bits 12-19: pair_count
    //   bits 20-31: tstart
    //   bits 32-43: reply_handle_id
    //   bits 44-48: event_type
    result.reply_handle_id = @truncate((oword >> 32) & 0xFFF);
    result.event_type = @truncate((oword >> 44) & 0x1F);

    // Distinguish "event delivered" from "syscall failed":
    // - event_type != 0: kernel delivered an event. vreg 1 = guest rax.
    // - event_type == 0: kernel hit a fast-failure (E_TIMEOUT etc.).
    //   vreg 1 = error code.
    if (result.event_type == 0) {
        result.err = ov1;
        return result;
    }

    // vregs 1..13 (register-backed)
    result.state.rax = ov1;
    result.state.rbx = ov2;
    result.state.rdx = ov3;
    result.state.rbp = ov4;
    result.state.rsi = ov5;
    result.state.rdi = ov6;
    result.state.r8 = ov7;
    result.state.r9 = ov8;
    result.state.r10 = ov9;
    result.state.r12 = ov10;
    result.state.r13 = ov11;
    result.state.r14 = ov12;
    result.state.r15 = ov13;

    // Stack-backed vregs (14..73) live in vm_exit_buf at indices
    // (N - 13) for vreg N: vreg 14 → buf[1], vreg 73 → buf[60].
    const buf = &vm_exit_buf;
    result.state.rip = buf[1];
    result.state.rflags = buf[2];
    result.state.rsp = buf[3];
    result.state.rcx = buf[4];
    result.state.r11 = buf[5];
    result.state.cr0 = buf[6];
    result.state.cr2 = buf[7];
    result.state.cr3 = buf[8];
    result.state.cr4 = buf[9];
    result.state.cr8 = buf[10];
    result.state.efer = buf[11];
    result.state.apic_base = buf[12];

    inline for (.{ &result.state.cs, &result.state.ds, &result.state.es, &result.state.fs, &result.state.gs, &result.state.ss, &result.state.tr, &result.state.ldtr }, 0..) |seg, i| {
        const base_idx = 13 + i * 2; // vreg (26 + 2i) → buf[13 + 2i]
        seg.base = buf[base_idx];
        const w = buf[base_idx + 1];
        seg.limit = @truncate(w);
        seg.selector = @truncate(w >> 32);
        seg.access_rights = @truncate(w >> 48);
    }

    result.state.gdtr_base = buf[29];
    result.state.gdtr_limit = buf[30];
    result.state.idtr_base = buf[31];
    result.state.idtr_limit = buf[32];

    result.state.star = buf[33];
    result.state.lstar = buf[34];
    result.state.cstar = buf[35];
    result.state.sfmask = buf[36];
    result.state.kernel_gs_base = buf[37];
    result.state.sysenter_cs = buf[38];
    result.state.sysenter_esp = buf[39];
    result.state.sysenter_eip = buf[40];
    result.state.pat = buf[41];
    result.state.tsc_aux = buf[42];

    result.state.dr0 = buf[43];
    result.state.dr1 = buf[44];
    result.state.dr2 = buf[45];
    result.state.dr3 = buf[46];
    result.state.dr6 = buf[47];
    result.state.dr7 = buf[48];

    result.state.vcpu_event_exception = buf[49];
    result.state.vcpu_event_exception_payload = buf[50];
    result.state.vcpu_event_intr_nmi = buf[51];
    result.state.vcpu_event_sipi_smi_triple = buf[52];

    result.state.interrupt_bitmap[0] = buf[53];
    result.state.interrupt_bitmap[1] = buf[54];
    result.state.interrupt_bitmap[2] = buf[55];
    result.state.interrupt_bitmap[3] = buf[56];

    result.state.exit_subcode = buf[57];
    result.state.exit_payload[0] = buf[58];
    result.state.exit_payload[1] = buf[59];
    result.state.exit_payload[2] = buf[60];

    return result;
}

/// Reply to a vm_exit event with `state` as the new guest state. Spec
/// §[reply]: reply_handle_id rides in syscall-word bits 12-23. The
/// receiver's vregs 1..73 are committed back to the vCPU's GuestState
/// (gated by `originating_write_cap` on the vCPU EC handle). Returns
/// the kernel's vreg 1 (`err` per §[error_codes]).
pub fn replyVmExit(reply_handle_id: u12, state: VmExitState) u64 {
    const word: u64 =
        (@as(u64, @intFromEnum(SyscallNum.reply)) & 0xFFF) |
        (@as(u64, reply_handle_id) << 12);

    // Serialize stack-backed vregs (14..73) into vm_exit_buf.
    const buf = &vm_exit_buf;
    buf[1] = state.rip;
    buf[2] = state.rflags;
    buf[3] = state.rsp;
    buf[4] = state.rcx;
    buf[5] = state.r11;
    buf[6] = state.cr0;
    buf[7] = state.cr2;
    buf[8] = state.cr3;
    buf[9] = state.cr4;
    buf[10] = state.cr8;
    buf[11] = state.efer;
    buf[12] = state.apic_base;

    inline for (.{ state.cs, state.ds, state.es, state.fs, state.gs, state.ss, state.tr, state.ldtr }, 0..) |seg, i| {
        const base_idx = 13 + i * 2;
        buf[base_idx] = seg.base;
        const w: u64 =
            @as(u64, seg.limit) |
            (@as(u64, seg.selector) << 32) |
            (@as(u64, seg.access_rights) << 48);
        buf[base_idx + 1] = w;
    }

    buf[29] = state.gdtr_base;
    buf[30] = state.gdtr_limit;
    buf[31] = state.idtr_base;
    buf[32] = state.idtr_limit;

    buf[33] = state.star;
    buf[34] = state.lstar;
    buf[35] = state.cstar;
    buf[36] = state.sfmask;
    buf[37] = state.kernel_gs_base;
    buf[38] = state.sysenter_cs;
    buf[39] = state.sysenter_esp;
    buf[40] = state.sysenter_eip;
    buf[41] = state.pat;
    buf[42] = state.tsc_aux;

    buf[43] = state.dr0;
    buf[44] = state.dr1;
    buf[45] = state.dr2;
    buf[46] = state.dr3;
    buf[47] = state.dr6;
    buf[48] = state.dr7;

    buf[49] = state.vcpu_event_exception;
    buf[50] = state.vcpu_event_exception_payload;
    buf[51] = state.vcpu_event_intr_nmi;
    buf[52] = state.vcpu_event_sipi_smi_triple;

    buf[53] = state.interrupt_bitmap[0];
    buf[54] = state.interrupt_bitmap[1];
    buf[55] = state.interrupt_bitmap[2];
    buf[56] = state.interrupt_bitmap[3];

    buf[57] = state.exit_subcode;
    buf[58] = state.exit_payload[0];
    buf[59] = state.exit_payload[1];
    buf[60] = state.exit_payload[2];

    var orax: u64 = undefined;
    asm volatile (
        \\ movq %%rsp, vm_exit_saved_rsp(%%rip)
        \\ leaq vm_exit_buf(%%rip), %%rsp
        \\ movq %%rcx, (%%rsp)
        \\ syscall
        \\ movq vm_exit_saved_rsp(%%rip), %%rsp
        : [v1] "={rax}" (orax),
        : [word] "{rcx}" (word),
          [iv1] "{rax}" (state.rax),
          [iv2] "{rbx}" (state.rbx),
          [iv3] "{rdx}" (state.rdx),
          [iv4] "{rbp}" (state.rbp),
          [iv5] "{rsi}" (state.rsi),
          [iv6] "{rdi}" (state.rdi),
          [iv7] "{r8}" (state.r8),
          [iv8] "{r9}" (state.r9),
          [iv9] "{r10}" (state.r10),
          [iv10] "{r12}" (state.r12),
          [iv11] "{r13}" (state.r13),
          [iv12] "{r14}" (state.r14),
          [iv13] "{r15}" (state.r15),
        : .{ .rbx = true, .rcx = true, .rdx = true, .rbp = true, .rsi = true, .rdi = true, .r8 = true, .r9 = true, .r10 = true, .r11 = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true, .memory = true });
    return orax;
}
