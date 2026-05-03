// Spec §[handle_attachments] handle_attachments — test 06.
//
// "[test 06] returns E_INVAL if any reserved bits are set in an entry."
//
// Strategy
//   §[handle_attachments] defines the pair-entry layout as:
//     bits  0-11: source handle id
//     bits 12-15: _reserved        (low band, 4 bits)
//     bits 16-31: caps
//     bit     32: move
//     bits 33-63: _reserved        (high band, 31 bits)
//   The libz `PairEntry` packed struct mirrors this exactly
//   (`_reserved_lo: u4`, `_reserved_hi: u31`). To trigger test 06 we
//   build an otherwise-clean entry via `PairEntry.toU64()` and then
//   set a single bit in the `_reserved_lo` band — bit 12 — by ORing
//   `(1 << 12)` into the encoded word. Setting any reserved bit is
//   sufficient; bit 12 is the lowest reserved bit and keeps the rest
//   of the entry byte-identical to the test 05 baseline.
//
//   With every other §[handle_attachments] gate cleared, only test 06
//   can resolve the suspend with E_INVAL:
//     - test 01 (port lacks xfer): the runner mints the result port
//       at SLOT_FIRST_PASSED with `{xfer, bind}`.            cleared
//     - test 02 (BADCAP for invalid source): SLOT_INITIAL_EC is a
//       live, valid handle in this domain.                    cleared
//     - test 03 (entry caps ⊄ source caps): entry.caps = 0,
//       trivially a subset of any source caps.                cleared
//     - test 04 (move=1 with no move cap): we use move=0; test 04
//       only fires for move=1 entries.                        cleared
//     - test 05 (move=0 lacking copy): per §[create_capability_domain]
//       test 21 the initial-EC handle's caps equal the runner's
//       `ec_inner_ceiling` (0xFF), so bit 1 (`copy`) is set.   cleared
//     - test 07 (duplicate sources): N=1.                     cleared
//   Bit 12 of the entry is set → test 06 must fire → E_INVAL.
//
//   We also need the §[suspend] preludes to be inert so the syscall
//   reaches the §[handle_attachments] entry-validation step:
//     - §[suspend] test 03 (no `susp` on EC) — slot 1's caps = 0xFF
//       includes `susp` (bit 5).
//     - §[suspend] test 04 (no `bind` on port) — slot 3's caps include
//       `bind`.
//     - §[suspend] test 05 (reserved bits in syscall word/[1]/[2]) —
//       only the syscall_num and pair_count fields are populated.
//     - §[suspend] test 06 (vCPU target) — slot 1 is a plain EC.
//     - §[suspend] test 07 (already-suspended) — slot 1 is the
//       calling, running EC.
//
//   The §[handle_attachments] entry layout places pair entries in
//   vregs `[128-N..127]`. With N=1 the lone entry occupies vreg 127,
//   which per §[syscall_abi] lives at `[rsp + (127-13)*8] = [rsp + 912]`
//   when the syscall executes. libz's `suspendEc` panics on N>0
//   because its high-vreg path is unwired, so we issue the syscall
//   directly via inline asm with a 920-byte stack pad — matching the
//   shape used by handle_attachments_02/03/04/05.
//
// Action
//   1. Build a clean PairEntry { id = SLOT_INITIAL_EC, caps = 0,
//      move = false } and encode to u64.
//   2. OR `1 << 12` into the encoded word to set the lowest reserved
//      bit (`_reserved_lo` band, bit 12).
//   3. Build syscall word with num = .suspend and pair_count = 1.
//   4. subq $920,%rsp; movq entry,912(%rsp); pushq word; syscall;
//      restore rsp.
//   5. Read returned vreg 1 (rax) — must equal E_INVAL.
//
// Assertions
//   1: suspend with a reserved-bit-dirty entry returned a value other
//      than E_INVAL.

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
    _ = cap_table_base;

    // Build a clean entry that satisfies tests 01-05 and 07, then
    // pollute a single reserved bit in the `_reserved_lo` band so
    // test 06 is the unique applicable check.
    const clean_entry: u64 = (caps.PairEntry{
        .id = caps.SLOT_INITIAL_EC,
        .caps = 0,
        .move = false,
    }).toU64();
    const dirty_entry: u64 = clean_entry | (@as(u64, 1) << 12);

    const result = suspendWithOnePairAtV127(
        caps.SLOT_INITIAL_EC,
        caps.SLOT_FIRST_PASSED,
        dirty_entry,
    );

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
