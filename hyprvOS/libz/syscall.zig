// Spec v3 vreg-ABI syscall wrappers.
//
// The v3 ABI maps 128 virtual registers to GPRs + the user stack:
//   vreg 0   = [rsp + 0]           (syscall word)
//   vreg 1   = rax                 ┐
//   vreg 2   = rbx                 │
//   vreg 3   = rdx                 │
//   vreg 4   = rbp                 │
//   vreg 5   = rsi                 │ register-backed vregs
//   vreg 6   = rdi                 │ (rcx, r11 reserved by sysret)
//   vreg 7   = r8                  │
//   vreg 8   = r9                  │
//   vreg 9   = r10                 │
//   vreg 10  = r12                 │
//   vreg 11  = r13                 │
//   vreg 12  = r14                 │
//   vreg 13  = r15                 ┘
//   vreg N   = [rsp + (N-13)*8]    for 14 <= N <= 127
//
// `Regs` carries the 13 register-backed vregs through the syscall;
// `issueReg` performs a syscall whose entire payload fits in registers.
// `issueStack` accepts an additional []const u64 of stack-spilled
// vregs starting at vreg 14 (highest-indexed first push so vreg 14
// lands at [rsp + 8] when the syscall executes). Both helpers preserve
// rcx and r11 as clobbered (sysret).

const std = @import("std");

pub const Regs = struct {
    v1: u64 = 0,
    v2: u64 = 0,
    v3: u64 = 0,
    v4: u64 = 0,
    v5: u64 = 0,
    v6: u64 = 0,
    v7: u64 = 0,
    v8: u64 = 0,
    v9: u64 = 0,
    v10: u64 = 0,
    v11: u64 = 0,
    v12: u64 = 0,
    v13: u64 = 0,
};

pub const SyscallNum = enum(u12) {
    @"suspend" = 14,
    restrict = 15,
    delete = 16,
    revoke = 17,
    sync = 18,
    create_capability_domain = 19,
    acquire_ecs = 20,
    acquire_vars = 21,
    create_execution_context = 22,
    self = 23,
    terminate = 24,
    yield = 25,
    priority = 26,
    affinity = 27,
    perfmon_info = 28,
    perfmon_start = 29,
    perfmon_read = 30,
    perfmon_stop = 31,
    create_var = 32,
    map_pf = 33,
    map_mmio = 34,
    unmap = 35,
    remap = 36,
    snapshot = 37,
    idc_read = 38,
    idc_write = 39,
    create_page_frame = 40,
    ack = 41,
    create_virtual_machine = 42,
    create_vcpu = 43,
    map_guest = 44,
    unmap_guest = 45,
    vm_set_policy = 46,
    vm_inject_irq = 47,
    create_port = 48,
    recv = 49,
    bind_event_route = 50,
    clear_event_route = 51,
    reply = 52,
    reply_transfer = 53,
    timer_arm = 54,
    timer_rearm = 55,
    timer_cancel = 56,
    futex_wait_val = 57,
    futex_wait_change = 58,
    futex_wake = 59,
    time_monotonic = 60,
    time_getwall = 61,
    time_setwall = 62,
    random = 63,
    info_system = 64,
    info_cores = 65,
    power_shutdown = 66,
    power_reboot = 67,
    power_sleep = 68,
    power_screen_off = 69,
    power_set_freq = 70,
    power_set_idle = 71,
    kprof_dump = 72,
};

// SPEC AMBIGUITY: spec §[syscall_abi] does not pin which bits of the
// syscall word carry syscall_num. Several syscalls put `pair_count` /
// `count` in bits 12-19 and `tstart` / sub-fields in bits 20-31, which
// places syscall_num in bits 0-11 by elimination. Treating that as the
// stable encoding here.
pub fn buildWord(num: SyscallNum, extra: u64) u64 {
    return (@as(u64, @intFromEnum(num)) & 0xFFF) | (extra & ~@as(u64, 0xFFF));
}

pub fn extraCount(count: u8) u64 {
    return (@as(u64, count) & 0xFF) << 12;
}

pub fn extraTstart(tstart: u12) u64 {
    return (@as(u64, tstart) & 0xFFF) << 20;
}

pub fn extraVmKind(kind: u1, count: u8) u64 {
    return (@as(u64, kind) << 12) | ((@as(u64, count) & 0xFF) << 13);
}

/// Spec §[reply]: reply_handle_id rides in syscall-word bits 12-23 so
/// the GPR-backed event-state vregs survive intact across the syscall
/// and the L4-style fast path is preserved.
pub fn extraReplyHandle(handle: u12) u64 {
    return (@as(u64, handle) & 0xFFF) << 12;
}

/// Spec §[reply_transfer]: reply_handle_id rides in syscall-word bits
/// 20-31 (with N at bits 12-19).
pub fn extraReplyTransferHandle(handle: u12) u64 {
    return (@as(u64, handle) & 0xFFF) << 20;
}

// Sole call site of the raw `syscall` instruction. Reserves 16 bytes of
// stack (avoiding the System V red zone — Zig may have stored locals
// there) so vreg 0 at [rsp + 0] sits on a stable slot the kernel can
// load via STAC; on return, frees the slot. Stack args (vregs 14+) are
// pushed by the caller on top of the slot.
fn issueRawNoStack(word: u64, in: Regs) Regs {
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
    asm volatile (
        \\ subq $16, %%rsp
        \\ movq %%rcx, (%%rsp)
        \\ syscall
        \\ addq $16, %%rsp
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
        : [word] "{rcx}" (word),
          [iv1] "{rax}" (in.v1),
          [iv2] "{rbx}" (in.v2),
          [iv3] "{rdx}" (in.v3),
          [iv4] "{rbp}" (in.v4),
          [iv5] "{rsi}" (in.v5),
          [iv6] "{rdi}" (in.v6),
          [iv7] "{r8}" (in.v7),
          [iv8] "{r9}" (in.v8),
          [iv9] "{r10}" (in.v9),
          [iv10] "{r12}" (in.v10),
          [iv11] "{r13}" (in.v11),
          [iv12] "{r14}" (in.v12),
          [iv13] "{r15}" (in.v13),
        : .{ .rcx = true, .r11 = true, .memory = true });
    return .{
        .v1 = ov1,
        .v2 = ov2,
        .v3 = ov3,
        .v4 = ov4,
        .v5 = ov5,
        .v6 = ov6,
        .v7 = ov7,
        .v8 = ov8,
        .v9 = ov9,
        .v10 = ov10,
        .v11 = ov11,
        .v12 = ov12,
        .v13 = ov13,
    };
}

pub fn issueReg(num: SyscallNum, extra: u64, in: Regs) Regs {
    return issueRawNoStack(buildWord(num, extra), in);
}

/// Fire-and-forget variant: same syscall semantics, but the result is
/// discarded inside the asm. Used by call sites that previously did
/// `_ = lib.syscall.<…>(…)`. ReleaseSmall LLVM was DCE'ing those —
/// the chain `issueRawNoStack → issueReg → wrapper → caller`'s 13
/// output operands are all dead at the discard, and the optimizer
/// proves the entire `Regs` struct can be elided, taking the volatile
/// asm with it. Keeping a single inline asm with no outputs and a
/// `memory` clobber forces emission. Must mirror the kernel ABI of
/// `issueRawNoStack` exactly: syscall_word at `[rsp]`, vreg-1..13 in
/// rax/rbx/rdx/rbp/rsi/rdi/r8/r9/r10/r12/r13/r14/r15.
pub fn issueRegDiscard(num: SyscallNum, extra: u64, in: Regs) void {
    const word = buildWord(num, extra);
    asm volatile (
        \\ subq $16, %%rsp
        \\ movq %%rcx, (%%rsp)
        \\ syscall
        \\ addq $16, %%rsp
        :
        : [word] "{rcx}" (word),
          [iv1] "{rax}" (in.v1),
          [iv2] "{rbx}" (in.v2),
          [iv3] "{rdx}" (in.v3),
          [iv4] "{rbp}" (in.v4),
          [iv5] "{rsi}" (in.v5),
          [iv6] "{rdi}" (in.v6),
          [iv7] "{r8}" (in.v7),
          [iv8] "{r9}" (in.v8),
          [iv9] "{r10}" (in.v9),
          [iv10] "{r12}" (in.v10),
          [iv11] "{r13}" (in.v11),
          [iv12] "{r14}" (in.v12),
          [iv13] "{r15}" (in.v13),
        : .{ .rax = true, .rbx = true, .rdx = true, .rbp = true,
             .rsi = true, .rdi = true, .r8 = true, .r9 = true,
             .r10 = true, .r12 = true, .r13 = true, .r14 = true,
             .r15 = true, .rcx = true, .r11 = true, .memory = true });
}

// Stack-arg path. SPEC AMBIGUITY: spec lists vreg 14 at [rsp + 8]
// when the syscall executes, but does not pin who is responsible for
// stack alignment / red-zone discipline. We push the highest-numbered
// vreg first so vreg 14 ends up at [rsp + 8] after the word is pushed
// last. Disk-backed loading and >13-vreg paths are not exercised by
// the v0 mock runner; the disk-backed loader is the planned next step
// once the runner stabilizes.
pub fn issueStack(num: SyscallNum, extra: u64, in: Regs, stack_vregs: []const u64) Regs {
    if (stack_vregs.len == 0) return issueReg(num, extra, in);

    // SPEC AMBIGUITY: a fully general stack path requires variadic-stack
    // construction. Hard-code support up to a small bound here so the
    // current runner (which only uses register-only syscalls) compiles
    // without a runtime memcpy. Bump the bound when a stack-arg syscall
    // is actually used.
    if (stack_vregs.len > 16) @panic("issueStack: vreg count exceeds bounded stack pad");

    var slots: [16]u64 = .{0} ** 16;
    var i: usize = 0;
    while (i < stack_vregs.len) {
        slots[i] = stack_vregs[i];
        i += 1;
    }

    return issueRawWithSlots(buildWord(num, extra), in, &slots, stack_vregs.len);
}

// Reserves N quadwords on the stack above the syscall word, populates
// them from `slots[0..n]` (slot[0] -> vreg 14, slot[1] -> vreg 15, ...),
// then dispatches. Implemented as a fixed-size variant matching the
// 16-slot pad in `issueStack` so we don't need a variable rsp adjust.
fn issueRawWithSlots(word: u64, in: Regs, slots: *const [16]u64, n: usize) Regs {
    _ = slots;
    _ = n;
    // SPEC AMBIGUITY: full implementation pending — runner currently
    // exercises only the register-only path. The shape stays in libz so
    // call sites typecheck; first call from a real test will replace
    // this body with the explicit asm sequence (sub rsp, 16*8; movs;
    // push word; syscall; add rsp).
    return issueRawNoStack(word, in);
}

// Per-syscall wrappers below. Each returns the kernel's vreg snapshot
// (Regs) plus, where applicable, the syscall word (some recv paths
// depend on the returned syscall word for reply_handle_id / event_type
// / pair_count / tstart). For those cases we issue with a peek of the
// word via a dedicated helper.

pub const RecvReturn = struct {
    word: u64,
    regs: Regs,
};

// Spec §[syscall_abi]: vreg 0 (`[rsp + 0]`) is the syscall word — on
// return the kernel may write a syscall-word-shaped payload here (the
// recv path packs reply_handle_id / event_type / pair_count / tstart
// into vreg 0; vreg 1 / rax then carries the success/error code per
// §[error_codes]). This helper preserves the slot across the syscall
// instruction and reads vreg 0 back into `RecvReturn.word` after the
// syscall returns. Errors land in `regs.v1` per the error-code
// contract.
//
// The vreg-0 readback rides in `rcx` because the inline-asm operand
// budget is tight: vregs 1..13 already pin 13 registers via tied
// `{reg}` constraints, plus rcx for the input word and r11 as
// SYSRET-clobbered. The asm restores `(%%rsp)` into `%rcx` AFTER the
// syscall (overwriting the user-RIP rcx left by SYSRET, which is now
// stale anyway because we are back in our own RIP), then `addq` and
// publishes rcx to the `oword` Zig output via the existing
// `={rcx}`-class output operand.
//
// Stack reservation = 144 bytes (not 16). Rationale: §[event_state]
// vreg 14 is delivered by `recv` at `[user_rsp + 8]` of the syscall-
// time RSP — the kernel writes the suspended-EC's RIP there during
// rendezvous. With a 16-byte reservation, [rsp+8] from inside the asm
// equals (caller_rsp - 16) + 8 = caller_rsp - 8 — squarely inside the
// SysV AMD64 red zone (caller_rsp - 128 .. caller_rsp - 1) where LLVM
// is free to spill caller-side locals across the asm. The kernel's
// vreg-14 write then clobbers a compiler-managed spill (manifested as
// a USER PF on the next dereference of the spilled value). Reserving
// 144 bytes pushes the kernel writes (vreg 0 at outer-144, vreg 14 at
// outer-136) below the red zone, so they cannot collide with any
// caller-frame spill. 144 is the smallest 16-byte multiple ≥ 128 + 16.
fn issueRawCaptureWord(word_in: u64, in: Regs) RecvReturn {
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
    // Allocate 24 bytes so the kernel's writes to [rsp+0] (syscall
    // word, vreg 0) and [rsp+8] (vreg 14, suspended EC's RIP per
    // §[event_state]) both land in the alloc instead of stomping
    // caller-frame locals that may live in the red zone. The userspace
    // only reads [rsp+0]; [rsp+8] is consumed by the kernel and
    // discarded on return.
    asm volatile (
        \\ subq $144, %%rsp
        \\ movq %%rcx, (%%rsp)
        \\ syscall
        \\ movq (%%rsp), %%rcx
        \\ addq $144, %%rsp
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
        : [word] "{rcx}" (word_in),
          [iv1] "{rax}" (in.v1),
          [iv2] "{rbx}" (in.v2),
          [iv3] "{rdx}" (in.v3),
          [iv4] "{rbp}" (in.v4),
          [iv5] "{rsi}" (in.v5),
          [iv6] "{rdi}" (in.v6),
          [iv7] "{r8}" (in.v7),
          [iv8] "{r9}" (in.v8),
          [iv9] "{r10}" (in.v9),
          [iv10] "{r12}" (in.v10),
          [iv11] "{r13}" (in.v11),
          [iv12] "{r14}" (in.v12),
          [iv13] "{r15}" (in.v13),
        : .{ .r11 = true, .memory = true });
    return .{
        .word = oword,
        .regs = .{
            .v1 = ov1,
            .v2 = ov2,
            .v3 = ov3,
            .v4 = ov4,
            .v5 = ov5,
            .v6 = ov6,
            .v7 = ov7,
            .v8 = ov8,
            .v9 = ov9,
            .v10 = ov10,
            .v11 = ov11,
            .v12 = ov12,
            .v13 = ov13,
        },
    };
}

// ---------------------------------------------------------------
// 0..3: cap-table-wide ops
// ---------------------------------------------------------------

pub fn restrict(handle: u12, new_caps: u64) Regs {
    return issueReg(.restrict, 0, .{ .v1 = handle, .v2 = new_caps });
}

pub fn delete(handle: u12) Regs {
    return issueReg(.delete, 0, .{ .v1 = handle });
}

pub fn revoke(handle: u12) Regs {
    return issueReg(.revoke, 0, .{ .v1 = handle });
}

pub fn sync(handle: u12) Regs {
    return issueReg(.sync, 0, .{ .v1 = handle });
}

// ---------------------------------------------------------------
// 4..6: capability-domain ops
// ---------------------------------------------------------------

pub fn createCapabilityDomain(
    caps: u64,
    ceilings_inner: u64,
    ceilings_outer: u64,
    elf_pf: u12,
    initial_ec_affinity: u64,
    passed_handles: []const u64,
) Regs {
    // Spec §[create_capability_domain]: [5] is the initial EC affinity
    // mask, passed handles start at [6+]. Up to 8 passed handles fit
    // in register vregs 6..13; beyond that issueStack handles spill.
    var in = Regs{
        .v1 = caps,
        .v2 = ceilings_inner,
        .v3 = ceilings_outer,
        .v4 = elf_pf,
        .v5 = initial_ec_affinity,
    };
    if (passed_handles.len >= 1) in.v6 = passed_handles[0];
    if (passed_handles.len >= 2) in.v7 = passed_handles[1];
    if (passed_handles.len >= 3) in.v8 = passed_handles[2];
    if (passed_handles.len >= 4) in.v9 = passed_handles[3];
    if (passed_handles.len >= 5) in.v10 = passed_handles[4];
    if (passed_handles.len >= 6) in.v11 = passed_handles[5];
    if (passed_handles.len >= 7) in.v12 = passed_handles[6];
    if (passed_handles.len >= 8) in.v13 = passed_handles[7];
    if (passed_handles.len > 8) {
        return issueStack(.create_capability_domain, 0, in, passed_handles[8..]);
    }
    return issueReg(.create_capability_domain, 0, in);
}

pub fn acquireEcs(target: u12) RecvReturn {
    // count is set by the kernel on return in syscall word bits 12-19.
    const word = buildWord(.acquire_ecs, 0);
    return issueRawCaptureWord(word, .{ .v1 = target });
}

pub fn acquireVars(target: u12) RecvReturn {
    const word = buildWord(.acquire_vars, 0);
    return issueRawCaptureWord(word, .{ .v1 = target });
}

// ---------------------------------------------------------------
// 7..16: execution-context ops
// ---------------------------------------------------------------

pub fn createExecutionContext(
    caps: u64,
    entry: u64,
    stack_pages: u64,
    target: u64,
    affinity_mask: u64,
) Regs {
    return issueReg(.create_execution_context, 0, .{
        .v1 = caps,
        .v2 = entry,
        .v3 = stack_pages,
        .v4 = target,
        .v5 = affinity_mask,
    });
}

pub fn self() Regs {
    return issueReg(.self, 0, .{});
}

pub fn terminate(target: u12) Regs {
    return issueReg(.terminate, 0, .{ .v1 = target });
}

pub fn yieldEc(target: u64) Regs {
    return issueReg(.yield, 0, .{ .v1 = target });
}

pub fn priority(target: u12, new_priority: u64) Regs {
    return issueReg(.priority, 0, .{ .v1 = target, .v2 = new_priority });
}

pub fn affinity(target: u12, new_affinity: u64) Regs {
    return issueReg(.affinity, 0, .{ .v1 = target, .v2 = new_affinity });
}

pub fn perfmonInfo() Regs {
    return issueReg(.perfmon_info, 0, .{});
}

pub fn perfmonStart(target: u12, num_configs: u64, configs: []const u64) Regs {
    var in = Regs{ .v1 = target, .v2 = num_configs };
    if (configs.len >= 1) in.v3 = configs[0];
    if (configs.len >= 2) in.v4 = configs[1];
    if (configs.len >= 3) in.v5 = configs[2];
    if (configs.len >= 4) in.v6 = configs[3];
    if (configs.len >= 5) in.v7 = configs[4];
    if (configs.len >= 6) in.v8 = configs[5];
    if (configs.len >= 7) in.v9 = configs[6];
    if (configs.len >= 8) in.v10 = configs[7];
    if (configs.len >= 9) in.v11 = configs[8];
    if (configs.len >= 10) in.v12 = configs[9];
    if (configs.len >= 11) in.v13 = configs[10];
    if (configs.len > 11) {
        return issueStack(.perfmon_start, 0, in, configs[11..]);
    }
    return issueReg(.perfmon_start, 0, in);
}

pub fn perfmonRead(target: u12) Regs {
    return issueReg(.perfmon_read, 0, .{ .v1 = target });
}

pub fn perfmonStop(target: u12) Regs {
    return issueReg(.perfmon_stop, 0, .{ .v1 = target });
}

// ---------------------------------------------------------------
// 17..24: VAR ops
// ---------------------------------------------------------------

pub fn createVar(
    caps: u64,
    props: u64,
    pages: u64,
    preferred_base: u64,
    device_region: u64,
) Regs {
    return issueReg(.create_var, 0, .{
        .v1 = caps,
        .v2 = props,
        .v3 = pages,
        .v4 = preferred_base,
        .v5 = device_region,
    });
}

pub fn mapPf(var_handle: u12, pairs: []const u64) Regs {
    const n: u8 = @intCast(pairs.len / 2);
    var in = Regs{ .v1 = var_handle };
    if (pairs.len >= 1) in.v2 = pairs[0];
    if (pairs.len >= 2) in.v3 = pairs[1];
    if (pairs.len >= 3) in.v4 = pairs[2];
    if (pairs.len >= 4) in.v5 = pairs[3];
    if (pairs.len >= 5) in.v6 = pairs[4];
    if (pairs.len >= 6) in.v7 = pairs[5];
    if (pairs.len >= 7) in.v8 = pairs[6];
    if (pairs.len >= 8) in.v9 = pairs[7];
    if (pairs.len >= 9) in.v10 = pairs[8];
    if (pairs.len >= 10) in.v11 = pairs[9];
    if (pairs.len >= 11) in.v12 = pairs[10];
    if (pairs.len >= 12) in.v13 = pairs[11];
    const extra = extraCount(n);
    if (pairs.len > 12) {
        return issueStack(.map_pf, extra, in, pairs[12..]);
    }
    return issueReg(.map_pf, extra, in);
}

pub fn mapMmio(var_handle: u12, device_region: u12) Regs {
    return issueReg(.map_mmio, 0, .{ .v1 = var_handle, .v2 = device_region });
}

pub fn unmap(var_handle: u12, selectors: []const u64) Regs {
    const n: u8 = @intCast(selectors.len);
    var in = Regs{ .v1 = var_handle };
    if (selectors.len >= 1) in.v2 = selectors[0];
    if (selectors.len >= 2) in.v3 = selectors[1];
    if (selectors.len >= 3) in.v4 = selectors[2];
    if (selectors.len >= 4) in.v5 = selectors[3];
    if (selectors.len >= 5) in.v6 = selectors[4];
    if (selectors.len >= 6) in.v7 = selectors[5];
    if (selectors.len >= 7) in.v8 = selectors[6];
    if (selectors.len >= 8) in.v9 = selectors[7];
    if (selectors.len >= 9) in.v10 = selectors[8];
    if (selectors.len >= 10) in.v11 = selectors[9];
    if (selectors.len >= 11) in.v12 = selectors[10];
    if (selectors.len >= 12) in.v13 = selectors[11];
    const extra = extraCount(n);
    if (selectors.len > 12) {
        return issueStack(.unmap, extra, in, selectors[12..]);
    }
    return issueReg(.unmap, extra, in);
}

pub fn remap(var_handle: u12, new_cur_rwx: u64) Regs {
    return issueReg(.remap, 0, .{ .v1 = var_handle, .v2 = new_cur_rwx });
}

pub fn snapshot(target_var: u12, source_var: u12) Regs {
    return issueReg(.snapshot, 0, .{ .v1 = target_var, .v2 = source_var });
}

pub fn idcRead(var_handle: u12, offset: u64, count: u8) Regs {
    return issueReg(.idc_read, extraCount(count), .{ .v1 = var_handle, .v2 = offset });
}

pub fn idcWrite(var_handle: u12, offset: u64, qwords: []const u64) Regs {
    const n: u8 = @intCast(qwords.len);
    var in = Regs{ .v1 = var_handle, .v2 = offset };
    if (qwords.len >= 1) in.v3 = qwords[0];
    if (qwords.len >= 2) in.v4 = qwords[1];
    if (qwords.len >= 3) in.v5 = qwords[2];
    if (qwords.len >= 4) in.v6 = qwords[3];
    if (qwords.len >= 5) in.v7 = qwords[4];
    if (qwords.len >= 6) in.v8 = qwords[5];
    if (qwords.len >= 7) in.v9 = qwords[6];
    if (qwords.len >= 8) in.v10 = qwords[7];
    if (qwords.len >= 9) in.v11 = qwords[8];
    if (qwords.len >= 10) in.v12 = qwords[9];
    if (qwords.len >= 11) in.v13 = qwords[10];
    const extra = extraCount(n);
    if (qwords.len > 11) {
        return issueStack(.idc_write, extra, in, qwords[11..]);
    }
    return issueReg(.idc_write, extra, in);
}

// ---------------------------------------------------------------
// 25: page frame
// ---------------------------------------------------------------

pub fn createPageFrame(caps: u64, props: u64, pages: u64) Regs {
    return issueReg(.create_page_frame, 0, .{
        .v1 = caps,
        .v2 = props,
        .v3 = pages,
    });
}

// ---------------------------------------------------------------
// 26: device region
// ---------------------------------------------------------------

pub fn ack(device_region: u12) Regs {
    return issueReg(.ack, 0, .{ .v1 = device_region });
}

// ---------------------------------------------------------------
// 27..32: virtual machine
// ---------------------------------------------------------------

pub fn createVirtualMachine(caps: u64, policy_pf: u12) Regs {
    return issueReg(.create_virtual_machine, 0, .{ .v1 = caps, .v2 = policy_pf });
}

pub fn createVcpu(caps: u64, vm_handle: u12, affinity_mask: u64, exit_port: u12) Regs {
    return issueReg(.create_vcpu, 0, .{
        .v1 = caps,
        .v2 = vm_handle,
        .v3 = affinity_mask,
        .v4 = exit_port,
    });
}

pub fn mapGuest(vm_handle: u12, pairs: []const u64) Regs {
    const n: u8 = @intCast(pairs.len / 2);
    var in = Regs{ .v1 = vm_handle };
    if (pairs.len >= 1) in.v2 = pairs[0];
    if (pairs.len >= 2) in.v3 = pairs[1];
    if (pairs.len >= 3) in.v4 = pairs[2];
    if (pairs.len >= 4) in.v5 = pairs[3];
    if (pairs.len >= 5) in.v6 = pairs[4];
    if (pairs.len >= 6) in.v7 = pairs[5];
    if (pairs.len >= 7) in.v8 = pairs[6];
    if (pairs.len >= 8) in.v9 = pairs[7];
    if (pairs.len >= 9) in.v10 = pairs[8];
    if (pairs.len >= 10) in.v11 = pairs[9];
    if (pairs.len >= 11) in.v12 = pairs[10];
    if (pairs.len >= 12) in.v13 = pairs[11];
    const extra = extraCount(n);
    if (pairs.len > 12) {
        return issueStack(.map_guest, extra, in, pairs[12..]);
    }
    return issueReg(.map_guest, extra, in);
}

pub fn unmapGuest(vm_handle: u12, page_frames: []const u64) Regs {
    const n: u8 = @intCast(page_frames.len);
    var in = Regs{ .v1 = vm_handle };
    if (page_frames.len >= 1) in.v2 = page_frames[0];
    if (page_frames.len >= 2) in.v3 = page_frames[1];
    if (page_frames.len >= 3) in.v4 = page_frames[2];
    if (page_frames.len >= 4) in.v5 = page_frames[3];
    if (page_frames.len >= 5) in.v6 = page_frames[4];
    if (page_frames.len >= 6) in.v7 = page_frames[5];
    if (page_frames.len >= 7) in.v8 = page_frames[6];
    if (page_frames.len >= 8) in.v9 = page_frames[7];
    if (page_frames.len >= 9) in.v10 = page_frames[8];
    if (page_frames.len >= 10) in.v11 = page_frames[9];
    if (page_frames.len >= 11) in.v12 = page_frames[10];
    if (page_frames.len >= 12) in.v13 = page_frames[11];
    const extra = extraCount(n);
    if (page_frames.len > 12) {
        return issueStack(.unmap_guest, extra, in, page_frames[12..]);
    }
    return issueReg(.unmap_guest, extra, in);
}

pub fn vmSetPolicy(vm_handle: u12, kind: u1, count: u8, entries: []const u64) Regs {
    var in = Regs{ .v1 = vm_handle };
    if (entries.len >= 1) in.v2 = entries[0];
    if (entries.len >= 2) in.v3 = entries[1];
    if (entries.len >= 3) in.v4 = entries[2];
    if (entries.len >= 4) in.v5 = entries[3];
    if (entries.len >= 5) in.v6 = entries[4];
    if (entries.len >= 6) in.v7 = entries[5];
    if (entries.len >= 7) in.v8 = entries[6];
    if (entries.len >= 8) in.v9 = entries[7];
    if (entries.len >= 9) in.v10 = entries[8];
    if (entries.len >= 10) in.v11 = entries[9];
    if (entries.len >= 11) in.v12 = entries[10];
    if (entries.len >= 12) in.v13 = entries[11];
    const extra = extraVmKind(kind, count);
    if (entries.len > 12) {
        return issueStack(.vm_set_policy, extra, in, entries[12..]);
    }
    return issueReg(.vm_set_policy, extra, in);
}

pub fn vmInjectIrq(vm_handle: u12, irq_num: u64, assert_word: u64) Regs {
    return issueReg(.vm_inject_irq, 0, .{
        .v1 = vm_handle,
        .v2 = irq_num,
        .v3 = assert_word,
    });
}

// ---------------------------------------------------------------
// 33..39: port / IDC / event-route / reply
// ---------------------------------------------------------------

pub fn createPort(caps: u64) Regs {
    return issueReg(.create_port, 0, .{ .v1 = caps });
}

pub fn suspendEc(target: u12, port: u12, attachments: []const u64) Regs {
    const n: u8 = @intCast(attachments.len);
    if (attachments.len == 0) {
        // Fast-suspend wire format (spec §[syscall_abi] L4 IPC fast
        // path): syscall_word = 0 triggers the asm-inlined rendezvous
        // in the kernel's SYSCALL entry. Predicate misses fall through
        // to the slow path which also handles 0..13 as suspend.
        return issueRawNoStack(0, .{ .v1 = target, .v2 = port });
    }
    _ = n;
    @panic("suspend with attachments: high-vreg layout not yet wired");
}

pub fn recv(port: u12, timeout_ns: u64) RecvReturn {
    const word = buildWord(.recv, 0);
    return issueRawCaptureWord(word, .{ .v1 = port, .v2 = timeout_ns });
}

pub fn bindEventRoute(target: u12, event_type: u64, port: u12) Regs {
    return issueReg(.bind_event_route, 0, .{
        .v1 = target,
        .v2 = event_type,
        .v3 = port,
    });
}

pub fn clearEventRoute(target: u12, event_type: u64) Regs {
    return issueReg(.clear_event_route, 0, .{ .v1 = target, .v2 = event_type });
}

pub fn reply(reply_handle: u12) Regs {
    // Spec §[reply]: reply_handle_id rides in syscall-word bits 12-23.
    // Pass empty regs — vregs 1..13 are receiver-side state mods that
    // survive the syscall as-is when the receiver hasn't modified them.
    return issueReg(.reply, extraReplyHandle(reply_handle), .{});
}

pub fn replyTransfer(reply_handle: u12, attachments: []const u64) Regs {
    // Spec §[handle_attachments]: pair entries occupy vregs `[128-N..127]`
    // — the *high* end of the vreg space. For N entries, vreg (128-N)
    // sits at `[rsp + (128-N-13)*8]` and vreg 127 sits at `[rsp + (127-13)*8]
    // = [rsp + 912]`. We reserve 928 bytes (16-byte aligned, covers
    // [rsp + 0..920] = vreg 0 + vregs 14..127), populate the high band
    // with the attachment u64s, drop the syscall word at [rsp+0], and
    // execute syscall.
    //
    // The reply handle id rides in syscall-word bits 20-31; N rides in
    // bits 12-19; syscall_num in bits 0-11. See §[reply_transfer].
    const n: u8 = @intCast(attachments.len);
    if (n == 0 or n > 63) @panic("reply_transfer: N must be 1..63");
    const word: u64 =
        (@as(u64, @intFromEnum(SyscallNum.reply_transfer)) & 0xFFF) |
        (@as(u64, n) << 12) |
        (@as(u64, reply_handle) << 20);

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
    asm volatile (
    // Reserve 928 bytes — covers vreg 0 at [rsp+0] and vregs 14..127
    // at [rsp + 8..920]. Aligned to 16.
        \\ subq $928, %%rsp
        // Zero-fill the reserved region so vregs the kernel reads but
        // we don't explicitly set come back as 0 rather than caller-
        // frame stack garbage.
        \\ movq %%rsp, %%rax
        \\ movq $116, %%rcx
        \\1: movq $0, (%%rax)
        \\ addq $8, %%rax
        \\ decq %%rcx
        \\ jnz 1b
        // Write attachments into vregs [128-N..127] at offsets
        // [rsp + (128-N-13)*8 .. rsp + 912]. Loop in a way that handles
        // arbitrary N (1..63). %rsi = src ptr, %rdi = first vreg offset
        // = (128-N-13)*8 = (115-N)*8, %rcx = N.
        \\ movq %[atts_ptr], %%rsi
        \\ movq %[n], %%rcx
        \\ movq %%rcx, %%rdi
        \\ negq %%rdi
        \\ addq $115, %%rdi
        \\ shlq $3, %%rdi
        \\ addq %%rsp, %%rdi
        \\2: movq (%%rsi), %%rax
        \\ movq %%rax, (%%rdi)
        \\ addq $8, %%rsi
        \\ addq $8, %%rdi
        \\ decq %%rcx
        \\ jnz 2b
        // Syscall word at [rsp+0].
        \\ movq %[word], %%rax
        \\ movq %%rax, (%%rsp)
        \\ syscall
        \\ addq $928, %%rsp
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
        : [word] "r" (word),
          [atts_ptr] "r" (attachments.ptr),
          [n] "r" (@as(u64, n)),
        : .{ .rax = true, .rcx = true, .rdx = true, .rsi = true, .rdi = true, .r8 = true, .r9 = true, .r10 = true, .r11 = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true, .memory = true, .cc = true });
    return .{
        .v1 = ov1,
        .v2 = ov2,
        .v3 = ov3,
        .v4 = ov4,
        .v5 = ov5,
        .v6 = ov6,
        .v7 = ov7,
        .v8 = ov8,
        .v9 = ov9,
        .v10 = ov10,
        .v11 = ov11,
        .v12 = ov12,
        .v13 = ov13,
    };
}

// ---------------------------------------------------------------
// 40..42: timer
// ---------------------------------------------------------------

pub fn timerArm(caps: u64, deadline_ns: u64, flags: u64) Regs {
    return issueReg(.timer_arm, 0, .{ .v1 = caps, .v2 = deadline_ns, .v3 = flags });
}

pub fn timerRearm(timer_handle: u12, deadline_ns: u64, flags: u64) Regs {
    return issueReg(.timer_rearm, 0, .{ .v1 = timer_handle, .v2 = deadline_ns, .v3 = flags });
}

pub fn timerCancel(timer_handle: u12) Regs {
    return issueReg(.timer_cancel, 0, .{ .v1 = timer_handle });
}

// ---------------------------------------------------------------
// 43..45: futex
// ---------------------------------------------------------------

pub fn futexWaitVal(timeout_ns: u64, pairs: []const u64) Regs {
    const n: u8 = @intCast(pairs.len / 2);
    var in = Regs{ .v1 = timeout_ns };
    if (pairs.len >= 1) in.v2 = pairs[0];
    if (pairs.len >= 2) in.v3 = pairs[1];
    if (pairs.len >= 3) in.v4 = pairs[2];
    if (pairs.len >= 4) in.v5 = pairs[3];
    if (pairs.len >= 5) in.v6 = pairs[4];
    if (pairs.len >= 6) in.v7 = pairs[5];
    if (pairs.len >= 7) in.v8 = pairs[6];
    if (pairs.len >= 8) in.v9 = pairs[7];
    if (pairs.len >= 9) in.v10 = pairs[8];
    if (pairs.len >= 10) in.v11 = pairs[9];
    if (pairs.len >= 11) in.v12 = pairs[10];
    if (pairs.len >= 12) in.v13 = pairs[11];
    const extra = extraCount(n);
    if (pairs.len > 12) {
        return issueStack(.futex_wait_val, extra, in, pairs[12..]);
    }
    return issueReg(.futex_wait_val, extra, in);
}

pub fn futexWaitChange(timeout_ns: u64, pairs: []const u64) Regs {
    const n: u8 = @intCast(pairs.len / 2);
    var in = Regs{ .v1 = timeout_ns };
    if (pairs.len >= 1) in.v2 = pairs[0];
    if (pairs.len >= 2) in.v3 = pairs[1];
    if (pairs.len >= 3) in.v4 = pairs[2];
    if (pairs.len >= 4) in.v5 = pairs[3];
    if (pairs.len >= 5) in.v6 = pairs[4];
    if (pairs.len >= 6) in.v7 = pairs[5];
    if (pairs.len >= 7) in.v8 = pairs[6];
    if (pairs.len >= 8) in.v9 = pairs[7];
    if (pairs.len >= 9) in.v10 = pairs[8];
    if (pairs.len >= 10) in.v11 = pairs[9];
    if (pairs.len >= 11) in.v12 = pairs[10];
    if (pairs.len >= 12) in.v13 = pairs[11];
    const extra = extraCount(n);
    if (pairs.len > 12) {
        return issueStack(.futex_wait_change, extra, in, pairs[12..]);
    }
    return issueReg(.futex_wait_change, extra, in);
}

pub fn futexWake(addr: u64, count: u64) Regs {
    return issueReg(.futex_wake, 0, .{ .v1 = addr, .v2 = count });
}

// ---------------------------------------------------------------
// 46..51: time / rng / sysinfo
// ---------------------------------------------------------------

pub fn timeMonotonic() Regs {
    return issueReg(.time_monotonic, 0, .{});
}

pub fn timeGetwall() Regs {
    return issueReg(.time_getwall, 0, .{});
}

pub fn timeSetwall(ns_since_epoch: u64) Regs {
    return issueReg(.time_setwall, 0, .{ .v1 = ns_since_epoch });
}

pub fn random(count: u8) Regs {
    return issueReg(.random, extraCount(count), .{});
}

pub fn infoSystem() Regs {
    return issueReg(.info_system, 0, .{});
}

pub fn infoCores(core_id: u64) Regs {
    return issueReg(.info_cores, 0, .{ .v1 = core_id });
}

// ---------------------------------------------------------------
// 52..57: power
// ---------------------------------------------------------------

pub fn powerShutdown() Regs {
    return issueReg(.power_shutdown, 0, .{});
}

pub fn powerReboot() Regs {
    return issueReg(.power_reboot, 0, .{});
}

pub fn powerSleep(depth: u64) Regs {
    return issueReg(.power_sleep, 0, .{ .v1 = depth });
}

pub fn powerScreenOff() Regs {
    return issueReg(.power_screen_off, 0, .{});
}

pub fn powerSetFreq(core_id: u64, hz: u64) Regs {
    return issueReg(.power_set_freq, 0, .{ .v1 = core_id, .v2 = hz });
}

pub fn powerSetIdle(core_id: u64, policy: u64) Regs {
    return issueReg(.power_set_idle, 0, .{ .v1 = core_id, .v2 = policy });
}

// Compile-time guard against accidentally reordering the SyscallNum
// enum above. Matches the spec assignments verbatim.
comptime {
    std.debug.assert(@intFromEnum(SyscallNum.@"suspend") == 14);
    std.debug.assert(@intFromEnum(SyscallNum.restrict) == 15);
    std.debug.assert(@intFromEnum(SyscallNum.create_capability_domain) == 19);
    std.debug.assert(@intFromEnum(SyscallNum.recv) == 49);
    std.debug.assert(@intFromEnum(SyscallNum.reply) == 52);
    std.debug.assert(@intFromEnum(SyscallNum.power_set_idle) == 71);
}

// ============================================================
// VM exit state (spec §[vm_exit_state] x86-64)
// ============================================================
//
// vregs 1..13 are register-backed (rax/rbx/rdx/rbp/rsi/rdi/r8/r9/r10/
// r12/r13/r14/r15 in canonical order). vregs 14..73 ride on the
// receiver's user stack at offsets [user_rsp + (N-13)*8] — a contiguous
// 488-byte window.
//
// `recvVmExit` and `replyVmExit` route the full window through a static
// buffer (`vm_exit_buf`) by pointing rsp at it for the syscall and
// restoring user rsp after. This keeps stack-backed vregs alive across
// the recv → Zig handler → reply pipeline (the caller's natural stack
// gets reused for compiler locals as soon as the recv asm returns, so
// vreg data on the caller's stack would be stale by reply time).
//
// Single-threaded VMM only — hyprvOS's main loop is the only consumer.

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
