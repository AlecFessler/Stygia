// Spec §[reply] reply — test 11.
//
// "[test 11] returns E_INVAL if any reserved bits are set in any pair
//  entry."
//
// Spec semantics
//   The reply error ladder for the pair-attachment band:
//     test 09  — reply handle missing `xfer` cap when N>0 → E_PERM
//     test 10  — pair_count > 63                          → E_INVAL
//     test 11  — pair entry reserved bits set             → E_INVAL
//     test 16  — duplicate pair entry sources             → E_INVAL
//     test 01  — reply_handle_id is not valid             → E_BADCAP
//   The ABI-layer syscall-word reserved-bit gate is exercised by the
//   bare reply test 02; this test pins the per-entry reserved-bit
//   check inside §[handle_attachments] entry validation.
//
// Strategy
//   Reserved bit in a pair entry.
//     §[handle_attachments] defines the pair-entry layout as:
//       bits  0-11: source handle id
//       bits 12-15: _reserved        (low band, 4 bits)
//       bits 16-31: caps
//       bit     32: move
//       bits 33-63: _reserved        (high band, 31 bits)
//     The libz `PairEntry` packed struct mirrors this exactly. Build an
//     otherwise-clean entry via `PairEntry.toU64()` (id = SLOT_SELF,
//     caps = 0, move = false) and OR `1 << 12` into the encoded word
//     to set the lowest reserved bit (`_reserved_lo` band, bit 12).
//     Matches the reference pattern in handle_attachments_06.
//
//     With every other §[handle_attachments] gate cleared, only the
//     pair-entry reserved-bit check can resolve the syscall with
//     E_INVAL. The pair-entry reserved-bit check fires before the
//     reply-handle resolve check, so we can use slot id 0 in bits 20-31
//     of the syscall word without minting a real reply handle.
//
//     With N = 1 the lone entry occupies vreg 127, which per
//     §[syscall_abi] lives at `[rsp + (127-13)*8] = [rsp + 912]` when
//     the syscall executes. The libz wrapper handles only the bare-reply
//     path, so the call is issued via inline asm with a 920-byte stack
//     pad matching the shape used by handle_attachments_02/03/04/05/06.
//
//   Neutralize sibling gates so test 11 is the unique applicable check:
//     - test 09 (xfer cap): reply handle is invalid; not consulted
//     - test 10 (pair_count > 63): N = 1 is in [1, 63]. cleared
//     - test 16 (duplicate sources): N = 1 has no peers. cleared
//     - tests 12-15 (per-entry source/cap checks): downstream of the
//       reserved-bit gate. cleared
//
// Action
//     subq $920,%rsp
//     movq word, (%rsp)              ; word = num | (N<<12) | (rid<<20)
//     movq dirty_entry, 912(%rsp)
//     syscall
//     addq $920, %rsp
//
// Assertions
//   1: pair entry with reserved bit 12 set returned something other
//      than E_INVAL.

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const REPLY_NUM: u64 = @intFromEnum(syscall.SyscallNum.reply);

// Issue reply with a hand-crafted syscall word and a single pair entry
// placed at vreg 127. Delivers a (clean-syscall-word) call that should
// trip on a malformed pair entry. The reply_handle_id is encoded into
// syscall-word bits 20-31 per §[reply]; vregs 1..13 are not used.
fn replyWithOnePairAtV127(reply_handle: u12, entry: u64) syscall.Regs {
    // Syscall word: bits 0-11 = syscall_num, bits 12-19 = pair_count = 1,
    // bits 20-31 = reply_handle_id.
    const word: u64 = (REPLY_NUM & 0xFFF) |
        (@as(u64, 1) << 12) |
        ((@as(u64, reply_handle) & 0xFFF) << 20);

    switch (builtin.cpu.arch) {
        .x86_64 => {
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
                \\ subq $920, %%rsp
                \\ movq %%rcx, (%%rsp)
                \\ movq %[entry], 912(%%rsp)
                \\ syscall
                \\ addq $920, %%rsp
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
                  [entry] "r" (entry),
                : .{ .rcx = true, .r11 = true, .memory = true });
            return .{
                .v1 = ov1, .v2 = ov2, .v3 = ov3, .v4 = ov4, .v5 = ov5,
                .v6 = ov6, .v7 = ov7, .v8 = ov8, .v9 = ov9, .v10 = ov10,
                .v11 = ov11, .v12 = ov12, .v13 = ov13,
            };
        },
        .aarch64 => {
            // aarch64 high-vreg layout: vreg N (32..127) lives at
            // [sp + (N-31)*8]. vreg 127 = [sp + 768]. Reserve 784 bytes
            // (16-byte aligned, covers vreg 0 at [sp+0] and vregs 32..127
            // at [sp+8..768]).
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
                \\ str %[word], [sp]
                \\ str %[entry], [sp, #768]
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
                : .{ .x13 = true, .x14 = true, .x15 = true, .x16 = true, .x17 = true,
                     .x19 = true, .x20 = true, .x21 = true, .x22 = true, .x23 = true,
                     .x24 = true, .x25 = true, .x26 = true, .x27 = true, .x28 = true,
                     .x29 = true, .x30 = true, .memory = true });
            return .{
                .v1 = ov1, .v2 = ov2, .v3 = ov3, .v4 = ov4, .v5 = ov5,
                .v6 = ov6, .v7 = ov7, .v8 = ov8, .v9 = ov9, .v10 = ov10,
                .v11 = ov11, .v12 = ov12, .v13 = ov13,
            };
        },
        else => @compileError("unsupported target architecture"),
    }
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Clean syscall word, dirty pair entry. Build a clean entry that
    // would satisfy tests 12-16 (id is a valid in-domain handle,
    // caps = 0, move = false, no duplicates) and pollute a single
    // reserved bit in the `_reserved_lo` band so test 11's pair-entry
    // gate is the unique applicable check. reply_handle_id = 0
    // (invalid) is fine because the pair-entry reserved-bit gate fires
    // first.
    const clean_entry: u64 = (caps.PairEntry{
        .id = caps.SLOT_SELF,
        .caps = 0,
        .move = false,
    }).toU64();
    const dirty_entry: u64 = clean_entry | (@as(u64, 1) << 12);

    const b = replyWithOnePairAtV127(0, dirty_entry);
    if (b.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
