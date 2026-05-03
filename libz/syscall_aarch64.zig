// aarch64 backing implementation for the spec-v3 vreg ABI.
//
// vreg map (spec §[syscall_abi] aarch64):
//   vreg 0      = [sp + 0]            (syscall word, on user stack)
//   vreg 1..31  = x0..x30             (in order — vreg 1 is x0)
//   vreg N      = [sp + (N - 31) * 8] for 32 <= N <= 127
//
// Syscall instruction is `svc #0`. Error code returns in vreg 1 = x0,
// per spec §[error_codes].
//
// libz's `Regs` only carries v1..v13 (the lowest 13 vregs), per the
// design note in syscall.zig — every existing test populates only
// these, and aarch64 happens to back them with x0..x12 directly. The
// remaining GPR-backed vregs (vregs 14..31 = x13..x30) are not exposed
// through the libz API; that band is reserved for future use and the
// inline asm preserves it via clobbers so no caller-frame value is
// trampled.
//
// AAPCS64 detail (relevant to the inline asm clobber lists):
//   - x0..x18 are caller-saved general-purpose registers.
//   - x19..x28 are callee-saved — the asm must NOT clobber these
//     without restoring them. We declare them clobbered in the
//     clobber list anyway (LLVM will spill/reload around the asm) so
//     the kernel is free to scribble vregs 20..29 without surprising
//     us. Same idea for x29 (FP) — Zig modules are compiled with
//     -fomit-frame-pointer, so x29 is just another scratch.
//   - x30 is LR; we must restore it (or treat it as clobbered, which
//     LLVM then handles around the call site).
//   - There is no AAPCS64 red zone — the stack pointer is the lowest
//     valid address — so the issueRawCaptureWord helper does not
//     need the 144-byte over-reservation that x86-64 requires.

const syscall = @import("syscall.zig");

const Regs = syscall.Regs;
const RecvReturn = syscall.RecvReturn;
const SyscallNum = syscall.SyscallNum;

// Issues an svc with the syscall word at [sp + 0] and vregs 1..13 in
// x0..x12. Returns updated v1..v13 (kernel writes back into the same
// registers). 16 bytes reserved to keep sp 16-aligned per AAPCS64.
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
        \\ sub sp, sp, #16
        \\ str %[word], [sp]
        \\ svc #0
        \\ add sp, sp, #16
        : [v1] "={x0}" (ov1),
          [v2] "={x1}" (ov2),
          [v3] "={x2}" (ov3),
          [v4] "={x3}" (ov4),
          [v5] "={x4}" (ov5),
          [v6] "={x5}" (ov6),
          [v7] "={x6}" (ov7),
          [v8] "={x7}" (ov8),
          [v9] "={x8}" (ov9),
          [v10] "={x9}" (ov10),
          [v11] "={x10}" (ov11),
          [v12] "={x11}" (ov12),
          [v13] "={x12}" (ov13),
        : [word] "r" (word),
          [iv1] "{x0}" (in.v1),
          [iv2] "{x1}" (in.v2),
          [iv3] "{x2}" (in.v3),
          [iv4] "{x3}" (in.v4),
          [iv5] "{x4}" (in.v5),
          [iv6] "{x5}" (in.v6),
          [iv7] "{x6}" (in.v7),
          [iv8] "{x7}" (in.v8),
          [iv9] "{x8}" (in.v9),
          [iv10] "{x9}" (in.v10),
          [iv11] "{x10}" (in.v11),
          [iv12] "{x11}" (in.v12),
          [iv13] "{x12}" (in.v13),
        : .{ .x13 = true, .x14 = true, .x15 = true, .x16 = true, .x17 = true,
             .x19 = true, .x20 = true, .x21 = true, .x22 = true, .x23 = true,
             .x24 = true, .x25 = true, .x26 = true, .x27 = true, .x28 = true,
             .x29 = true, .x30 = true, .memory = true });
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

/// Fire-and-forget variant — see syscall_x64.zig for the DCE rationale.
/// Same kernel ABI as `issueRawNoStack`; results are dropped inside the
/// asm so LLVM cannot prove the chain dead and elide it. The `memory`
/// clobber plus `volatile` keep emission required.
pub fn issueRegDiscard(word: u64, in: Regs) void {
    asm volatile (
        \\ sub sp, sp, #16
        \\ str %[word], [sp]
        \\ svc #0
        \\ add sp, sp, #16
        :
        : [word] "r" (word),
          [iv1] "{x0}" (in.v1),
          [iv2] "{x1}" (in.v2),
          [iv3] "{x2}" (in.v3),
          [iv4] "{x3}" (in.v4),
          [iv5] "{x4}" (in.v5),
          [iv6] "{x5}" (in.v6),
          [iv7] "{x6}" (in.v7),
          [iv8] "{x7}" (in.v8),
          [iv9] "{x8}" (in.v9),
          [iv10] "{x9}" (in.v10),
          [iv11] "{x10}" (in.v11),
          [iv12] "{x11}" (in.v12),
          [iv13] "{x12}" (in.v13),
        : .{ .x0 = true, .x1 = true, .x2 = true, .x3 = true, .x4 = true,
             .x5 = true, .x6 = true, .x7 = true, .x8 = true, .x9 = true,
             .x10 = true, .x11 = true, .x12 = true, .x13 = true, .x14 = true,
             .x15 = true, .x16 = true, .x17 = true, .x19 = true, .x20 = true,
             .x21 = true, .x22 = true, .x23 = true, .x24 = true, .x25 = true,
             .x26 = true, .x27 = true, .x28 = true, .x29 = true, .x30 = true,
             .memory = true });
}

// Mirrors issueRawNoStack but reads the post-syscall vreg-0 word back
// out of [sp + 0] into `RecvReturn.word`. The recv path packs
// reply_handle_id / event_type / pair_count / tstart there per the
// spec; vreg 1 / x0 carries the success/error code. No red zone on
// aarch64, so the 16-byte reservation suffices for the syscall word
// slot — the kernel may also write vreg 32 at [sp + 8] during a recv
// rendezvous (carrying the suspended EC's PC per §[event_state]),
// which still falls inside the reservation.
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
        \\ sub sp, sp, #16
        \\ str %[word], [sp]
        \\ svc #0
        \\ ldr %[oword], [sp]
        \\ add sp, sp, #16
        : [v1] "={x0}" (ov1),
          [v2] "={x1}" (ov2),
          [v3] "={x2}" (ov3),
          [v4] "={x3}" (ov4),
          [v5] "={x4}" (ov5),
          [v6] "={x5}" (ov6),
          [v7] "={x6}" (ov7),
          [v8] "={x7}" (ov8),
          [v9] "={x8}" (ov9),
          [v10] "={x9}" (ov10),
          [v11] "={x10}" (ov11),
          [v12] "={x11}" (ov12),
          [v13] "={x12}" (ov13),
          [oword] "=&r" (oword),
        : [word] "r" (word_in),
          [iv1] "{x0}" (in.v1),
          [iv2] "{x1}" (in.v2),
          [iv3] "{x2}" (in.v3),
          [iv4] "{x3}" (in.v4),
          [iv5] "{x4}" (in.v5),
          [iv6] "{x5}" (in.v6),
          [iv7] "{x6}" (in.v7),
          [iv8] "{x7}" (in.v8),
          [iv9] "{x8}" (in.v9),
          [iv10] "{x9}" (in.v10),
          [iv11] "{x10}" (in.v11),
          [iv12] "{x11}" (in.v12),
          [iv13] "{x12}" (in.v13),
        : .{ .x13 = true, .x14 = true, .x15 = true, .x16 = true, .x17 = true,
             .x19 = true, .x20 = true, .x21 = true, .x22 = true, .x23 = true,
             .x24 = true, .x25 = true, .x26 = true, .x27 = true, .x28 = true,
             .x29 = true, .x30 = true, .memory = true });
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

// Stack-arg path stub. Mirrors syscall_x64.zig: not exercised by the
// current runner; falls through to issueRawNoStack so call sites
// typecheck.
pub fn issueRawWithSlots(word: u64, in: Regs, slots: *const [16]u64, n: usize) Regs {
    _ = slots;
    _ = n;
    return issueRawNoStack(word, in);
}

// Reply-transfer high-vreg path. Spec §[handle_attachments]: pair
// entries occupy vregs `[128-N..127]`. On aarch64 vregs 32..127 sit
// at `[sp + (N-31)*8]`, so vreg 32 = [sp + 8] and vreg 127 = [sp + 768].
// We reserve 784 bytes (16-byte aligned, covers vreg 0 at [sp+0] and
// vregs 32..127 at [sp + 8..768]), zero it so the kernel reads 0 for
// vregs we don't explicitly set, write the attachment u64s into the
// high band, drop the syscall word at [sp+0], and `svc #0`.
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
    // Reserve 784 bytes: vreg 0 at [sp+0] and vregs 32..127 at
    // [sp + 8 .. sp + 768]. 16-byte aligned per AAPCS64.
        \\ sub sp, sp, #784
        // Zero-fill the 97 reserved slots (1 word + 96 high vregs) so
        // any vreg the kernel reads but we don't explicitly set comes
        // back as 0 instead of caller-frame stack garbage.
        \\ mov x13, sp
        \\ mov x14, #97
        \\1: str xzr, [x13]
        \\ add x13, x13, #8
        \\ subs x14, x14, #1
        \\ b.ne 1b
        // Write attachments into vregs [128-N..127] at offsets
        // [sp + (128-N-31)*8 .. sp + 768]. x15 = src ptr, x14 = N,
        // x13 = first dst offset = (97 - N) * 8 + sp.
        \\ mov x15, %[atts_ptr]
        \\ mov x14, %[n]
        \\ mov x13, #97
        \\ sub x13, x13, x14
        \\ lsl x13, x13, #3
        \\ add x13, x13, sp
        \\2: ldr x16, [x15]
        \\ str x16, [x13]
        \\ add x15, x15, #8
        \\ add x13, x13, #8
        \\ subs x14, x14, #1
        \\ b.ne 2b
        // Syscall word at [sp+0].
        \\ str %[word], [sp]
        \\ svc #0
        \\ add sp, sp, #784
        : [v1] "={x0}" (ov1),
          [v2] "={x1}" (ov2),
          [v3] "={x2}" (ov3),
          [v4] "={x3}" (ov4),
          [v5] "={x4}" (ov5),
          [v6] "={x5}" (ov6),
          [v7] "={x6}" (ov7),
          [v8] "={x7}" (ov8),
          [v9] "={x8}" (ov9),
          [v10] "={x9}" (ov10),
          [v11] "={x10}" (ov11),
          [v12] "={x11}" (ov12),
          [v13] "={x12}" (ov13),
        : [word] "r" (word),
          [atts_ptr] "r" (attachments_ptr),
          [n] "r" (n),
        : .{ .x13 = true, .x14 = true, .x15 = true, .x16 = true, .x17 = true,
             .x19 = true, .x20 = true, .x21 = true, .x22 = true, .x23 = true,
             .x24 = true, .x25 = true, .x26 = true, .x27 = true, .x28 = true,
             .x29 = true, .x30 = true, .memory = true, .cc = true });
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
