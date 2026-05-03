// Spec §[handle_attachments] handle_attachments — test 04.
//
// "[test 04] returns E_PERM if any entry with `move = 1` references
//  a source handle that lacks the `move` cap."
//
// Strategy
//   §[handle_attachments] places pair entries in the high vregs
//   `[128-N..127]`. With N=1 the lone entry occupies vreg 127, which
//   per §[syscall_abi] lives at `[rsp + (127-13)*8] = [rsp + 912]`
//   when the syscall executes. libz's `suspendEc` `@panic`s on N>0
//   because its general stack-arg dispatcher isn't wired through; we
//   open-code the syscall here with a fixed 920-byte stack pad that
//   lands the entry at the right offset (matching the pattern in
//   handle_attachments_02 and 03).
//
//   For the source handle we use the test child's initial EC at
//   slot 1. Per §[create_capability_domain] test 21 the initial EC's
//   caps equal the runner's `ec_inner_ceiling`, which the runner sets
//   to 0xFF — bits 0-7 of `EcCap`: {move, copy, saff, spri, term,
//   susp, read, write}. To set up the precondition for test 04 we
//   first `restrict` the initial-EC handle to clear the `move` bit
//   (bit 0). The handle keeps `copy` and the rest of bits 1-7.
//
//   With move cleared from the source, an entry with `move = 1`
//   targeting that source must trip test 04 (E_PERM). Other
//   §[handle_attachments] checks must NOT fire:
//     - test 01 (port lacks xfer): the runner grants `bind | xfer`
//       on the result port at `SLOT_FIRST_PASSED`, so xfer is held.
//     - test 02 (invalid source id): slot 1 is valid.
//     - test 03 (caps not a subset): we set entry.caps = 0, which is
//       a subset of any source caps.
//     - test 05 (move=0 lacking copy): fires only when move=0; here
//       move=1, so this branch is moot.
//     - test 06 (reserved bits): all reserved bits in the entry are
//       zero by construction.
//     - test 07 (duplicate ids): only one entry.
//   E_PERM via test 04 is therefore the unique remaining outcome.
//
// Action
//   1. restrict(SLOT_INITIAL_EC, ec_caps & ~move) — must succeed.
//      Confirm via cap-table read that `move` is now clear.
//   2. Construct a PairEntry with id=SLOT_INITIAL_EC, caps=0, move=1.
//   3. Issue suspend(target=SLOT_INITIAL_EC, port=SLOT_FIRST_PASSED)
//      with the entry placed at vreg 127.
//   4. Verify the returned vreg 1 equals E_PERM.
//
// Assertions
//   1: restrict on the initial EC handle did not return success.
//   2: the cap table still reports `move` set after restrict (the
//      precondition for test 04 was not actually established).
//   3: suspend with a move=1 entry referencing a source lacking
//      `move` returned a value other than E_PERM.

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const SUSPEND_NUM: u64 = @intFromEnum(syscall.SyscallNum.@"suspend");

const STACK_PAD_BYTES: u64 = 912;

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
    // Read the initial EC's current caps and clear the `move` bit
    // via restrict. Per §[capabilities]/restrict test 02 a strict
    // subset always succeeds when the handle is valid and reserved
    // bits are clean.
    const ec_before = caps.readCap(cap_table_base, caps.SLOT_INITIAL_EC);
    const ec_caps_before: u16 = ec_before.caps();

    const move_bit: u16 = (caps.EcCap{ .move = true }).toU16();
    const reduced_caps: u16 = ec_caps_before & ~move_bit;

    const restrict_result = syscall.restrict(
        caps.SLOT_INITIAL_EC,
        @as(u64, reduced_caps),
    );
    if (restrict_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    const ec_after = caps.readCap(cap_table_base, caps.SLOT_INITIAL_EC);
    if ((ec_after.caps() & move_bit) != 0) {
        testing.fail(2);
        return;
    }

    // Single pair entry referencing the initial EC with move=1. The
    // source now lacks `move`, so test 04 (E_PERM) is the unique
    // applicable check; entry.caps=0 is a subset of any source caps,
    // and move=1 sidesteps the move=0/copy check (test 05).
    const entry = (caps.PairEntry{
        .id = caps.SLOT_INITIAL_EC,
        .caps = 0,
        .move = true,
    }).toU64();

    const result = suspendWithOnePairAtV127(
        caps.SLOT_INITIAL_EC,
        caps.SLOT_FIRST_PASSED,
        entry,
    );

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
