// Spec §[reply] reply — test 02.
//
// "[test 02] returns E_INVAL if any reserved bits are set in the syscall
//  word."
//
// Strategy
//   §[reply] pins the syscall-word layout for `reply` at:
//     bits  0-11: syscall_num   (must be 38 = reply)
//     bits 12-23: reply_handle_id (12 bits)
//     bits 24-63: _reserved
//
//   §[syscall_abi] pins the reserved-bit gate at the ABI layer: "Bits
//   not assigned by the invoked syscall must be zero on entry; the
//   kernel returns E_INVAL if a reserved bit is set." Because the gate
//   is ABI-layer it fires regardless of whether `reply_handle_id` would
//   otherwise resolve to a valid reply handle. Sibling tests (sync_02 /
//   delete_02 / ack_04) rely on the same shape.
//
//   To exercise the gate we craft a syscall word whose low 12 bits hold
//   syscall_num = 52, whose `reply_handle_id` band is zeroed, and whose
//   reserved band (bits 24-63) has bit 63 set. Bit 63 mirrors the
//   reference pattern in ack_04.zig — it sits well above any plausible
//   future field on the syscall word.
//
//   The libz `syscall.reply` wrapper packages the handle id into the
//   syscall word for us; it leaves no path for setting reserved bits.
//   We bypass the wrapper and emit a hand-crafted syscall via inline
//   asm, putting the malformed word directly in vreg 0. vregs
//   1..13 are now event-state mod inputs in the new ABI rather than
//   handle carriers, so they are left zeroed.
//
// Action
//   1. issueRawReply(syscall_num | (1 << 63)) — must return E_INVAL.
//      Reserved bit 63 of the syscall word is set; the handle-id band
//      is zero; syscall_num is 38.
//
// Assertions
//   1: reply with reserved bit 63 of the syscall word returned something
//      other than E_INVAL.

const builtin = @import("builtin");
const lib = @import("lib");

const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Issue `reply` with a hand-crafted syscall word. Mirrors libz's
// `issueRawNoStack` shape (16-byte stack pad, vreg 0 at [sp+0]) but
// lets the caller pin every bit of the word — including reserved bits
// the typed `syscall.reply` wrapper would never set.
fn issueRawReply(word: u64) u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => issueRawReplyX64(word),
        .aarch64 => issueRawReplyArm(word),
        else => @compileError("unsupported arch"),
    };
}

fn issueRawReplyX64(word: u64) u64 {
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
}

fn issueRawReplyArm(word: u64) u64 {
    var ov1: u64 = undefined;
    asm volatile (
        \\ sub sp, sp, #16
        \\ str %[word], [sp]
        \\ svc #0
        \\ mov %[v1], x0
        \\ add sp, sp, #16
        : [v1] "=r" (ov1),
        : [word] "r" (word),
        : .{ .x0 = true, .x1 = true, .x2 = true, .x3 = true, .x4 = true,
             .x5 = true, .x6 = true, .x7 = true, .x8 = true, .x9 = true,
             .x10 = true, .x11 = true, .x12 = true, .x13 = true, .x14 = true,
             .x15 = true, .x16 = true, .x17 = true, .x19 = true, .x20 = true,
             .x21 = true, .x22 = true, .x23 = true, .x24 = true, .x25 = true,
             .x26 = true, .x27 = true, .x28 = true, .x29 = true, .x30 = true,
             .memory = true });
    return ov1;
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // syscall_num = 52 in bits 0-11; bits 12-23 (reply_handle_id) = 0;
    // bit 63 of the reserved band set. The ABI-layer reserved-bit gate
    // must fire regardless of the empty handle-id band.
    const syscall_num: u64 = @intFromEnum(syscall.SyscallNum.reply);
    const word_with_reserved: u64 = syscall_num | (@as(u64, 1) << 63);

    const v1 = issueRawReply(word_with_reserved);
    if (v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
