// Spec §[reply_transfer] — test 04.
//
// "[test 04] returns E_INVAL if any reserved bits are set in the
//  syscall word or any pair entry."
//
// Spec semantics
//   The reply_transfer error ladder (per the reply_transfer_01 header
//   ladder note plus the test 03 N-range gate):
//     test 04a — syscall-word reserved bits set   → E_INVAL
//     test 03  — N == 0 or N > 63                 → E_INVAL
//     test 04b — pair entry reserved bits set     → E_INVAL
//     test 09  — duplicate pair entry sources     → E_INVAL
//     test 01  — reply_handle_id is not valid     → E_BADCAP
//   Test 04 has two firing points: the syscall-word reserved-bit check
//   (an ABI-layer gate per §[syscall_abi]: "Bits not assigned by the
//   invoked syscall must be zero on entry; the kernel returns E_INVAL
//   if a reserved bit is set"), and the per-entry reserved-bit check
//   inside §[handle_attachments] entry validation. Both paths must
//   surface E_INVAL, and both are exercised below.
//
// Strategy
//   Case A — reserved bit in the syscall word.
//     The reply_transfer syscall word carries:
//       bits  0-11: syscall_num (= 53)
//       bits 12-19: N
//       bits 20-31: reply_handle_id
//       bits 32-63: _reserved
//     Setting bit 63 of the syscall word mirrors the reference pattern
//     in reply_02 / ack_04 / sync_02 / delete_02 (reserved-bit dirties
//     well above any plausible future field). The reserved-bit gate is
//     ABI-layer and so fires before any handle/cap resolution, even
//     before the N-range check, so we can keep N = 1 in the syscall
//     word and leave the pair-entry vregs untouched (the gate trips
//     before the kernel reads any pair entry).
//
//     libz's `replyTransfer` wrapper @panics on N > 0, and the typed
//     `issueReg` helper masks reserved-bit-dirty syscall words via
//     `buildWord`. We dispatch a hand-crafted word via inline asm so
//     bit 63 of vreg 0 reaches the kernel verbatim.
//
//   Case B — reserved bit in a pair entry.
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
//     E_INVAL. The pair-entry reserved-bit check is documented to fire
//     before the reply-handle resolve check (per the reply_transfer_01
//     ladder note), so we can use slot id 0 in bits 20-31 of the
//     syscall word without minting a real reply handle: SLOT_SELF is
//     valid in this domain but is not a reply handle, and the dirty-
//     pair-entry gate trips first.
//
//     With N = 1 the lone entry occupies vreg 127, which per
//     §[syscall_abi] lives at `[rsp + (127-13)*8] = [rsp + 912]` when
//     the syscall executes. The libz wrapper @panics on this path, so
//     the call is issued via inline asm with a 920-byte stack pad
//     matching the shape used by handle_attachments_02/03/04/05/06.
//
//   Neutralize sibling gates so test 04 is the unique applicable check
//   in each case:
//     - test 03 (N range): N = 1 is in [1, 63]. cleared
//     - test 09 (duplicate sources): N = 1 has no peers. cleared
//     - test 01/02 (handle resolve / xfer cap): downstream of test 04
//       in both firing paths. cleared
//     - tests 05-08 (per-entry source/cap checks): downstream of the
//       reserved-bit gate. cleared
//
// Action
//   Case A:
//     issueRawReplyTransfer(
//       syscall_num | (1 << 12) | (1 << 63))   // N=1, dirty bit 63
//   Case B:
//     subq $920,%rsp
//     movq word, (%rsp)              ; word = num | (N<<12) | (rid<<20)
//     movq dirty_entry, 912(%rsp)
//     syscall
//     addq $920, %rsp
//
// Assertions
//   1: Case A — syscall word with reserved bit 63 set returned something
//      other than E_INVAL.
//   2: Case B — pair entry with reserved bit 12 set returned something
//      other than E_INVAL.

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const REPLY_TRANSFER_NUM: u64 = @intFromEnum(syscall.SyscallNum.reply_transfer);

// Issue reply_transfer with a hand-crafted syscall word and a single
// pair entry placed at vreg 127. Used by case B to deliver a valid
// (clean-syscall-word) call that should trip on a malformed pair
// entry. The reply_handle_id is encoded into syscall-word bits 20-31
// per the new ABI; vregs 1..13 are not used.
fn replyTransferWithOnePairAtV127(reply_handle: u12, entry: u64) syscall.Regs {
    // Syscall word: bits 0-11 = syscall_num, bits 12-19 = pair_count = 1,
    // bits 20-31 = reply_handle_id.
    const word: u64 = (REPLY_TRANSFER_NUM & 0xFFF) |
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

// Issue reply_transfer with a hand-crafted syscall word and no pair
// entries populated. Used by case A to deliver a malformed syscall
// word (reserved bit set) that should trip the ABI-layer reserved-bit
// gate before any pair-entry walk. Mirrors libz's `issueRawNoStack`
// shape but accepts an arbitrary `word` so the caller can pin every
// bit — including reserved bits the typed wrappers would never set.
fn issueRawReplyTransfer(word: u64) u64 {
    switch (builtin.cpu.arch) {
        .x86_64 => {
            var ov1: u64 = undefined;
            asm volatile (
                \\ subq $16, %%rsp
                \\ movq %%rcx, (%%rsp)
                \\ syscall
                \\ addq $16, %%rsp
                : [v1] "={rax}" (ov1),
                : [word] "{rcx}" (word),
                : .{ .rcx = true, .r11 = true, .memory = true });
            return ov1;
        },
        .aarch64 => {
            var ov1: u64 = undefined;
            asm volatile (
                \\ sub sp, sp, #16
                \\ str %[word], [sp]
                \\ svc #0
                \\ add sp, sp, #16
                : [v1] "={x0}" (ov1),
                : [word] "r" (word),
                : .{ .x1 = true, .x2 = true, .x3 = true, .x4 = true, .x5 = true,
                     .x6 = true, .x7 = true, .x8 = true, .x9 = true, .x10 = true,
                     .x11 = true, .x12 = true, .x13 = true, .x14 = true, .x15 = true,
                     .x16 = true, .x17 = true, .x19 = true, .x20 = true, .x21 = true,
                     .x22 = true, .x23 = true, .x24 = true, .x25 = true, .x26 = true,
                     .x27 = true, .x28 = true, .x29 = true, .x30 = true, .memory = true });
            return ov1;
        },
        else => @compileError("unsupported target architecture"),
    }
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Case A: reserved bit 63 of the syscall word set; N = 1 in bits
    // 12-19; reply_handle_id band (bits 20-31) zeroed. The ABI-layer
    // reserved-bit gate fires before N-range and before any handle
    // resolution, so the pair-entry vregs need not be populated.
    const dirty_word: u64 =
        (REPLY_TRANSFER_NUM & 0xFFF) |
        (@as(u64, 1) << 12) |
        (@as(u64, 1) << 63);
    const a_v1 = issueRawReplyTransfer(dirty_word);
    if (a_v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    // Case B: clean syscall word, dirty pair entry. Build a clean entry
    // that would satisfy tests 05-09 (id is a valid in-domain handle,
    // caps = 0, move = false, no duplicates) and pollute a single
    // reserved bit in the `_reserved_lo` band so test 04's pair-entry
    // gate is the unique applicable check. reply_handle_id = 0 (invalid)
    // is fine because the pair-entry reserved-bit gate fires first.
    const clean_entry: u64 = (caps.PairEntry{
        .id = caps.SLOT_SELF,
        .caps = 0,
        .move = false,
    }).toU64();
    const dirty_entry: u64 = clean_entry | (@as(u64, 1) << 12);

    const b = replyTransferWithOnePairAtV127(0, dirty_entry);
    if (b.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
