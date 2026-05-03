// Spec §[handle_attachments] handle_attachments — test 03.
//
// "[test 03] returns E_PERM if any entry's caps are not a subset of
//  the source handle's current caps."
//
// Strategy
//   §[handle_attachments] places pair entries in the high vregs
//   `[128-N..127]`. With N=1 the lone entry occupies vreg 127, which
//   per §[syscall_abi] lives at `[rsp + (127-13)*8] = [rsp + 912]`
//   when the syscall executes. libz's `suspendEc` `@panic`s on N>0
//   because its general stack-arg dispatcher isn't wired through; we
//   open-code the syscall here with a fixed 920-byte stack pad that
//   lands the entry at the right offset.
//
//   For the source handle we use the test child's initial EC at
//   slot 1. Per §[create_capability_domain] test 21 the initial EC's
//   caps equal the runner's `ec_inner_ceiling`, which the runner sets
//   to 0xFF — bits 0-7 of `EcCap`: {move, copy, saff, spri, term,
//   susp, read, write}. Since `copy` is set, an entry with `move = 0`
//   does NOT trip test 05 (which fires only if move=0 AND the source
//   lacks copy). Setting `move = 0` likewise sidesteps test 04 (fires
//   only when move=1 AND source lacks move).
//
//   To violate test 03 we set entry.caps = source.caps | (1 << 10) —
//   `EcCap.bind` (bit 10), which is NOT in the source's 0xFF. The
//   resulting caps word is a strict superset of the source's caps,
//   so the kernel must return E_PERM.
//
//   The result port the runner passes us at `SLOT_FIRST_PASSED` has
//   the `xfer` cap (the runner grants `bind | xfer` to the child),
//   so test 01 ("returns E_PERM if N>0 and the port lacks xfer") is
//   not the failure source. The entry's id (slot 1) is valid in this
//   domain, so test 02 (E_BADCAP) does not fire either. Reserved
//   entry bits are zero (test 06 inactive), and there is only one
//   entry so test 07 (duplicate ids) is moot.
//
// Action
//   1. Read the initial EC's current caps from the cap table.
//   2. Construct a PairEntry with id=SLOT_INITIAL_EC, move=0,
//      caps = current | EcCap{ .bind = true } (a strict superset).
//   3. Issue suspend(target=SLOT_INITIAL_EC, port=SLOT_FIRST_PASSED)
//      with the entry placed at vreg 127.
//   4. Verify the returned vreg 1 equals E_PERM.
//
// Assertions
//   1: EC slot 1 caps don't match the runner's ec_inner_ceiling shape
//      we depend on (precondition for the superset construction).
//   2: suspend with a strict-superset caps entry returned a value
//      other than E_PERM.

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

fn suspendWith1AttachmentX64(word: u64, target: u64, port: u64, entry: u64) u64 {
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
        \\ subq $912, %%rsp
        \\ movq %[entry], 904(%%rsp)
        \\ pushq %%rcx
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
          [iv1] "{rax}" (target),
          [iv2] "{rbx}" (port),
          [entry] "r" (entry),
        : .{ .rcx = true, .r11 = true, .memory = true });
    return ov1;
}

fn suspendWith1AttachmentArm(word: u64, target: u64, port: u64, entry: u64) u64 {
    var ov1: u64 = undefined;
    asm volatile (
        \\ sub sp, sp, #784
        \\ str %[entry], [sp, #768]
        \\ str %[word], [sp]
        \\ svc #0
        \\ add sp, sp, #784
        : [v1] "={x0}" (ov1),
        : [word] "r" (word),
          [iv1] "{x0}" (target),
          [iv2] "{x1}" (port),
          [entry] "r" (entry),
        : .{ .x1 = true, .x2 = true, .x3 = true, .x4 = true, .x5 = true,
             .x6 = true, .x7 = true, .x8 = true, .x9 = true, .x10 = true,
             .x11 = true, .x12 = true, .x13 = true, .x14 = true, .x15 = true,
             .x16 = true, .x17 = true, .x19 = true, .x20 = true, .x21 = true,
             .x22 = true, .x23 = true, .x24 = true, .x25 = true, .x26 = true,
             .x27 = true, .x28 = true, .x29 = true, .x30 = true, .memory = true });
    return ov1;
}

fn suspendWith1Attachment(target: u12, port: u12, entry: u64) u64 {
    const word: u64 = @as(u64, @intFromEnum(syscall.SyscallNum.@"suspend")) |
        (@as(u64, 1) << 12);
    return switch (builtin.cpu.arch) {
        .x86_64 => suspendWith1AttachmentX64(word, @as(u64, target), @as(u64, port), entry),
        .aarch64 => suspendWith1AttachmentArm(word, @as(u64, target), @as(u64, port), entry),
        else => @compileError("unsupported arch"),
    };
}

pub fn main(cap_table_base: u64) void {
    const ec = caps.readCap(cap_table_base, caps.SLOT_INITIAL_EC);
    const ec_caps_now: u16 = ec.caps();

    // Sanity check: this test depends on the source EC having `copy`
    // (bit 1) set so move=0 doesn't trip test 05, and on the bind bit
    // (bit 10) being clear so the constructed caps is a strict
    // superset.
    const ec_copy_bit: u16 = (caps.EcCap{ .copy = true }).toU16();
    const ec_bind_bit: u16 = (caps.EcCap{ .bind = true }).toU16();
    if ((ec_caps_now & ec_copy_bit) == 0 or (ec_caps_now & ec_bind_bit) != 0) {
        testing.fail(1);
        return;
    }

    const superset_caps: u16 = ec_caps_now | ec_bind_bit;

    const entry = (caps.PairEntry{
        .id = caps.SLOT_INITIAL_EC,
        .caps = superset_caps,
        .move = false,
    }).toU64();

    const v1 = suspendWith1Attachment(
        caps.SLOT_INITIAL_EC,
        caps.SLOT_FIRST_PASSED,
        entry,
    );
    if (v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
