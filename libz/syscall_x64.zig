// x86-64 backing implementation for the spec-v3 vreg ABI.
//
// vreg map (spec §[syscall_abi] x86-64):
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
// `Regs` (defined in syscall.zig) carries the 13 register-backed vregs
// through the syscall.

const syscall = @import("syscall.zig");

const Regs = syscall.Regs;
const RecvReturn = syscall.RecvReturn;
const SyscallNum = syscall.SyscallNum;

// Sole call site of the raw `syscall` instruction. Reserves 16 bytes of
// stack (avoiding the System V red zone — Zig may have stored locals
// there) so vreg 0 at [rsp + 0] sits on a stable slot the kernel can
// load via STAC; on return, frees the slot. Stack args (vregs 14+) are
// pushed by the caller on top of the slot.
pub fn issueRawNoStack(word: u64, in: Regs) Regs {
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
pub fn issueRegDiscard(word: u64, in: Regs) void {
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
pub fn issueRawCaptureWord(word_in: u64, in: Regs) RecvReturn {
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

// Stack-arg path. SPEC AMBIGUITY: spec lists vreg 14 at [rsp + 8]
// when the syscall executes. Disk-backed loading and >13-vreg paths
// are not exercised by the v0 mock runner; the disk-backed loader is
// the planned next step once the runner stabilizes. The current
// implementation falls through to issueRawNoStack so the call sites
// typecheck — first call from a real test will replace this with the
// explicit asm sequence (sub rsp, N*8; movs; push word; syscall; add).
pub fn issueRawWithSlots(word: u64, in: Regs, slots: *const [16]u64, n: usize) Regs {
    _ = slots;
    _ = n;
    return issueRawNoStack(word, in);
}

// Reply-transfer high-vreg path. Spec §[handle_attachments]: pair
// entries occupy vregs `[128-N..127]` — the *high* end of the vreg
// space. For N entries, vreg (128-N) sits at `[rsp + (128-N-13)*8]`
// and vreg 127 sits at `[rsp + (127-13)*8] = [rsp + 912]`. We reserve
// 928 bytes (16-byte aligned, covers [rsp + 0..920] = vreg 0 + vregs
// 14..127), populate the high band with the attachment u64s, drop the
// syscall word at [rsp+0], and execute syscall.
pub fn replyTransferAsm(word: u64, attachments_ptr: [*]const u64, n: u64) Regs {
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
          [atts_ptr] "r" (attachments_ptr),
          [n] "r" (n),
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
