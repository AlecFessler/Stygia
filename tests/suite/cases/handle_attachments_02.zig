// Spec §[handle_attachments] — test 02.
//
// "[test 02] returns E_BADCAP if any entry's source handle id is not
// valid in the suspending EC's domain."
//
// Strategy
//   The child capability domain's table at spawn time contains:
//     slot 0  → self
//     slot 1  → initial EC
//     slot 2  → self-IDC
//     slot 3  → result port (granted with `bind | xfer` by the runner)
//   By construction every other slot is empty. Slot 4095 — the
//   maximum 12-bit handle id — is therefore guaranteed to be invalid,
//   matching the shape used by restrict_01 / acquire_ecs_01.
//
//   The test issues `suspend([1] = SLOT_INITIAL_EC, [2] = port)` with
//   `pair_count = 1` and a single entry placed at vreg 127 per
//   §[handle_attachments]. The entry's source `id = 4095` (an empty
//   slot); other entry fields are zero (caps = 0, move = 0, no
//   reserved bits set), so the E_PERM (tests 03-05), E_INVAL
//   (test 06) and E_INVAL-duplicate (test 07) checks cannot fire and
//   E_PERM-on-port-xfer (test 01) cannot fire because the port was
//   granted with `xfer`. The kernel validates entries at suspend time
//   per the §[handle_attachments] prose, so the suspending EC sees
//   E_BADCAP returned in vreg 1 without actually suspending.
//
// Action
//   Build the syscall frame manually: reserve 920 bytes on the stack
//   so vreg 127 lands at `[rsp + (127-13)*8] = [rsp + 912]` and the
//   syscall word lands at `[rsp + 0]` per the v3 vreg ABI in
//   `libz/syscall.zig`. libz's `suspendEc` panics on a non-empty
//   attachments slice ("high-vreg layout not yet wired"), so the test
//   issues the syscall directly via inline asm.
//
// Assertion
//   v1 == E_BADCAP  (assertion id 1)

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const SUSPEND_NUM: u64 = @intFromEnum(syscall.SyscallNum.@"suspend");

const STACK_PAD_BYTES: u64 = 912;
const VREG127_PRE_PUSH_OFFSET: u64 = (127 - 14) * 8; // = 904

fn suspendWithOnePairAtV127X64(word: u64, target: u64, port: u64, entry: u64) syscall.Regs {
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
        \\ subq %[pad], %%rsp
        \\ movq %[entry], 904(%%rsp)
        \\ pushq %%rcx
        \\ syscall
        \\ addq $8, %%rsp
        \\ addq %[pad], %%rsp
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
          [pad] "i" (STACK_PAD_BYTES),
          [entry] "r" (entry),
          [iv1] "{rax}" (target),
          [iv2] "{rbx}" (port),
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

fn suspendWithOnePairAtV127Arm(word: u64, target: u64, port: u64, entry: u64) syscall.Regs {
    // aarch64: vreg 127 = [sp + (127-31)*8] = [sp + 768]. Reserve
    // 784 bytes (16-byte aligned) so [sp+0]=word and [sp+768]=vreg 127.
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
        \\ sub sp, sp, #784
        \\ str %[entry], [sp, #768]
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
          [entry] "r" (entry),
          [iv1] "{x0}" (target),
          [iv2] "{x1}" (port),
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

fn suspendWithOnePairAtV127(target: u12, port: u12, entry: u64) syscall.Regs {
    const word: u64 = (SUSPEND_NUM & 0xFFF) | (@as(u64, 1) << 12);
    return switch (builtin.cpu.arch) {
        .x86_64 => suspendWithOnePairAtV127X64(word, @as(u64, target), @as(u64, port), entry),
        .aarch64 => suspendWithOnePairAtV127Arm(word, @as(u64, target), @as(u64, port), entry),
        else => @compileError("unsupported arch"),
    };
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const empty_slot: u12 = caps.HANDLE_TABLE_MAX - 1;

    // Single pair entry referencing an invalid source handle. caps and
    // move are zero so no other §[handle_attachments] check applies;
    // reserved bits are clean. E_BADCAP is the only path that fits.
    const entry = (caps.PairEntry{
        .id = empty_slot,
        .caps = 0,
        .move = false,
    }).toU64();

    const result = suspendWithOnePairAtV127(
        caps.SLOT_INITIAL_EC,
        caps.SLOT_FIRST_PASSED,
        entry,
    );

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
