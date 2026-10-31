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
// through the libz API; x13..x17 are treated as scratch, x18 is saved
// around the trap, and the aarch64 exception path preserves x19..x30.
//
// AAPCS64 detail (relevant to the inline asm clobber lists):
//   - x0..x18 are caller-saved general-purpose registers. LLVM may keep
//     libz bootstrap state in x18 across these asm blocks, so the shim
//     preserves x18 around `svc` instead of listing it as clobbered; the
//     tied syscall operands otherwise exhaust the aarch64 allocator.
//   - x19..x28 are callee-saved, x29 is FP, and x30 is LR. Do not list
//     them as asm clobbers here: normal syscalls preserve that band, and
//     the high-output syscall wrappers otherwise exceed LLVM's available
//     aarch64 registers.
//   - There is no AAPCS64 red zone — the stack pointer is the lowest
//     valid address — so the issueRawCaptureWord helper does not
//     need the 144-byte over-reservation that x86-64 requires.

const syscall = @import("syscall_extern.zig");

const Regs = syscall.Regs;
const RecvReturn = syscall.RecvReturn;
const SyscallNum = syscall.SyscallNum;

// Issues an svc with the syscall word at [sp + 0] and vregs 1..13 in
// x0..x12. Returns updated v1..v13 (kernel writes back into the same
// registers). Reserves the 784-byte kernel slow-path arg window plus
// one private x18 save slot, so the collector can read vregs 32..127 at
// `[sp + (N-31)*8]` without walking past the upper guard page; sp stays
// 16-byte aligned per AAPCS64. Unread bytes in the kernel window are
// inert — the handler bound-checks count from the syscall word before
// consuming any vreg.
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
        \\ sub sp, sp, #800
        \\ str x18, [sp, #784]
        \\ str %[word], [sp]
        \\ svc #0
        \\ ldr x18, [sp, #784]
        \\ add sp, sp, #800
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
        : .{ .x13 = true, .x14 = true, .x15 = true, .x16 = true, .x17 = true, .memory = true });
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
        \\ sub sp, sp, #800
        \\ str x18, [sp, #784]
        \\ str %[word], [sp]
        \\ svc #0
        \\ ldr x18, [sp, #784]
        \\ add sp, sp, #800
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
        : .{ .x0 = true, .x1 = true, .x2 = true, .x3 = true, .x4 = true, .x5 = true, .x6 = true, .x7 = true, .x8 = true, .x9 = true, .x10 = true, .x11 = true, .x12 = true, .x13 = true, .x14 = true, .x15 = true, .x16 = true, .x17 = true, .memory = true });
}

// Mirrors issueRawNoStack but reads the post-syscall vreg-0 word back
// out of [sp + 0] into `RecvReturn.word`. The recv path packs
// reply_handle_id / event_type / pair_count / tstart there per the
// spec; vreg 1 / x0 carries the success/error code. No red zone on
// aarch64, so the 800-byte reservation covers the kernel-visible
// receive window (vreg 0 at [sp + 0], vregs 32..127 at [sp + 8..768])
// and keeps private x18 and x19..x30 saves outside that window.
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
        \\ sub sp, sp, #896
        \\ str x18, [sp, #784]
        \\ add x16, sp, #800
        \\ stp x19, x20, [x16, #0]
        \\ stp x21, x22, [x16, #16]
        \\ stp x23, x24, [x16, #32]
        \\ stp x25, x26, [x16, #48]
        \\ stp x27, x28, [x16, #64]
        \\ stp x29, x30, [x16, #80]
        \\ str %[word], [sp]
        \\ svc #0
        \\ ldr %[oword], [sp]
        \\ add x16, sp, #800
        \\ ldp x19, x20, [x16, #0]
        \\ ldp x21, x22, [x16, #16]
        \\ ldp x23, x24, [x16, #32]
        \\ ldp x25, x26, [x16, #48]
        \\ ldp x27, x28, [x16, #64]
        \\ ldp x29, x30, [x16, #80]
        \\ ldr x18, [sp, #784]
        \\ add sp, sp, #896
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
          [oword] "={x17}" (oword),
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
        : .{ .x13 = true, .x14 = true, .x15 = true, .x16 = true, .memory = true });
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

// Stack-arg path. Spec §[syscall_abi] aarch64: vreg N at `[sp + (N-31)*8]`
// for 32 <= N <= 127, with vreg 0 (the syscall word) at `[sp + 0]`.
//
// Reserve the kernel-visible vreg window on the caller stack for the
// svc instant. That keeps libz's shared image read-only in test
// processes; a process-global .bss scratch page would alias across every
// concurrently running child.
pub fn issueRawWithSlots(word: u64, in: Regs, slots: *const [16]u64, n: usize) Regs {
    var window: [97]u64 align(16) = .{0} ** 97;
    window[0] = word;
    var i: usize = 0;
    while (i < n and i < 16) : (i += 1) {
        window[1 + i] = slots[i];
    }

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
        \\ sub sp, sp, #800
        \\ str x18, [sp, #784]
        \\ mov x13, %[window_ptr]
        \\ mov x14, sp
        \\ mov x16, #97
        \\1: ldr x15, [x13]
        \\ str x15, [x14]
        \\ add x13, x13, #8
        \\ add x14, x14, #8
        \\ subs x16, x16, #1
        \\ b.ne 1b
        \\ svc #0
        \\ ldr x18, [sp, #784]
        \\ add sp, sp, #800
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
        : [window_ptr] "r" (&window),
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
        : .{ .x13 = true, .x14 = true, .x15 = true, .x16 = true, .x17 = true, .memory = true });
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

// Reply-transfer high-vreg path. Spec §[handle_attachments]: pair
// entries occupy vregs `[128-N..127]`. On aarch64 vregs 32..127 sit
// at `[sp + (N-31)*8]`, so vreg 32 = [sp + 8] and vreg 127 = [sp + 768].
// We reserve the 784-byte kernel window (vreg 0 at [sp+0] and vregs
// 32..127 at [sp + 8..768]) plus one private x18 save slot, zero the
// kernel window so unread vregs are 0, write attachment u64s into the
// high band, drop the syscall word at [sp+0], and `svc #0`.
// Reply path for vm_exit-typed replies (spec §[reply] / §[vm_exit_state]).
// On aarch64 the kernel reads vregs 32..127 from [sp + 8 .. sp + 776],
// so the buffer covers 97 u64 slots: vreg 0 at index 0, vregs 32..127
// at indices 1..96. Sub-code (vreg 117) lives at index 86 = (117-31).
// Pair entries at vregs [128-N..127] → indices [97-N..96].
export var vm_exit_reply_buf_arm: [128]u64 align(16) = .{0} ** 128;
export var vm_exit_reply_saved_sp: u64 align(8) = 0;

pub fn replyVmExitAsm(word: u64, subcode: u64) Regs {
    @memset(vm_exit_reply_buf_arm[0..97], 0);
    vm_exit_reply_buf_arm[0] = word;
    vm_exit_reply_buf_arm[86] = subcode;

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
        \\ adrp x13, vm_exit_reply_saved_sp
        \\ add x13, x13, :lo12:vm_exit_reply_saved_sp
        \\ mov x14, sp
        \\ str x14, [x13]
        \\ adrp x13, vm_exit_reply_buf_arm
        \\ add x13, x13, :lo12:vm_exit_reply_buf_arm
        \\ mov sp, x13
        \\ str x18, [sp, #784]
        \\ svc #0
        \\ ldr x18, [sp, #784]
        \\ adrp x13, vm_exit_reply_saved_sp
        \\ add x13, x13, :lo12:vm_exit_reply_saved_sp
        \\ ldr x14, [x13]
        \\ mov sp, x14
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
        :
        : .{ .x13 = true, .x14 = true, .memory = true });
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

// reply_transfer for vm_exit-typed replies. Combines the wide
// §[vm_exit_state] window write (sub-code at vreg 117) with attached
// handles in vregs [128-N..127] using the same buffer-pointed pattern.
pub fn replyTransferVmExitAsm(word: u64, attachments_ptr: [*]const u64, n: u64, subcode: u64) Regs {
    @memset(vm_exit_reply_buf_arm[0..97], 0);
    vm_exit_reply_buf_arm[0] = word;
    vm_exit_reply_buf_arm[86] = subcode;
    const k_first: usize = 97 - n;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        vm_exit_reply_buf_arm[k_first + i] = attachments_ptr[i];
    }

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
        \\ adrp x13, vm_exit_reply_saved_sp
        \\ add x13, x13, :lo12:vm_exit_reply_saved_sp
        \\ mov x14, sp
        \\ str x14, [x13]
        \\ adrp x13, vm_exit_reply_buf_arm
        \\ add x13, x13, :lo12:vm_exit_reply_buf_arm
        \\ mov sp, x13
        \\ str x18, [sp, #784]
        \\ svc #0
        \\ ldr x18, [sp, #784]
        \\ adrp x13, vm_exit_reply_saved_sp
        \\ add x13, x13, :lo12:vm_exit_reply_saved_sp
        \\ ldr x14, [x13]
        \\ mov sp, x14
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
        :
        : .{ .x13 = true, .x14 = true, .memory = true });
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

pub fn replyTransferRecvAsm(word: u64, attachments_ptr: [*]const u64, n: u64) RecvReturn {
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
        \\ sub sp, sp, #896
        \\ str x18, [sp, #784]
        \\ add x16, sp, #800
        \\ stp x19, x20, [x16, #0]
        \\ stp x21, x22, [x16, #16]
        \\ stp x23, x24, [x16, #32]
        \\ stp x25, x26, [x16, #48]
        \\ stp x27, x28, [x16, #64]
        \\ stp x29, x30, [x16, #80]
        \\ mov x13, sp
        \\ mov x14, #97
        \\1: str xzr, [x13]
        \\ add x13, x13, #8
        \\ subs x14, x14, #1
        \\ b.ne 1b
        \\ mov x15, %[atts_ptr]
        \\ mov x14, %[n]
        \\ mov x13, #97
        \\ sub x13, x13, x14
        \\ lsl x13, x13, #3
        \\ add x13, sp, x13
        \\2: ldr x16, [x15]
        \\ str x16, [x13]
        \\ add x15, x15, #8
        \\ add x13, x13, #8
        \\ subs x14, x14, #1
        \\ b.ne 2b
        \\ str %[word], [sp]
        \\ svc #0
        \\ ldr %[oword], [sp]
        \\ add x16, sp, #800
        \\ ldp x19, x20, [x16, #0]
        \\ ldp x21, x22, [x16, #16]
        \\ ldp x23, x24, [x16, #32]
        \\ ldp x25, x26, [x16, #48]
        \\ ldp x27, x28, [x16, #64]
        \\ ldp x29, x30, [x16, #80]
        \\ ldr x18, [sp, #784]
        \\ add sp, sp, #896
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
          [oword] "={x17}" (oword),
        : [word] "r" (word),
          [atts_ptr] "r" (attachments_ptr),
          [n] "r" (n),
        : .{ .x13 = true, .x14 = true, .x15 = true, .x16 = true, .memory = true });
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

pub fn replyTransferAsm(word: u64, attachments_ptr: [*]const u64, n: u64) Regs {
    const InputBlock = extern struct {
        word: u64,
        attachments_ptr: [*]const u64,
        n: u64,
    };
    var input_block: InputBlock = .{
        .word = word,
        .attachments_ptr = attachments_ptr,
        .n = n,
    };
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
    // Reserve the kernel-visible 784-byte window, one x18 save slot,
    // and three saved input words. Copy the compiler-assigned input
    // pointer out before reusing the scratch registers below; the input
    // must not be pinned to a register that is also declared clobbered.
        \\ sub sp, sp, #832
        \\ str x18, [sp, #784]
        \\ mov x13, %[input]
        \\ ldr x14, [x13]
        \\ str x14, [sp, #792]
        \\ ldr x14, [x13, #8]
        \\ str x14, [sp, #800]
        \\ ldr x14, [x13, #16]
        \\ str x14, [sp, #808]
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
        \\ ldr x15, [sp, #800]
        \\ ldr x14, [sp, #808]
        \\ mov x13, #97
        \\ sub x13, x13, x14
        \\ lsl x13, x13, #3
        \\ add x13, sp, x13
        \\2: ldr x16, [x15]
        \\ str x16, [x13]
        \\ add x15, x15, #8
        \\ add x13, x13, #8
        \\ subs x14, x14, #1
        \\ b.ne 2b
        // Syscall word at [sp+0].
        \\ ldr x13, [sp, #792]
        \\ str x13, [sp]
        \\ svc #0
        \\ ldr x18, [sp, #784]
        \\ add sp, sp, #832
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
        : [input] "r" (&input_block),
        : .{ .x13 = true, .x14 = true, .x15 = true, .x16 = true, .memory = true });
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
