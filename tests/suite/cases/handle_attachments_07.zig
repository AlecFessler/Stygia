// Spec §[handle_attachments] — test 07.
//
// "[test 07] returns E_INVAL if two entries reference the same source
//  handle."
//
// Strategy
//   §[handle_attachments] places pair entries at vregs [128-N..127] —
//   the high end of the vreg space. libz's `suspendEc(.., attachments)`
//   panics for N>0 because the bounded stack helpers in libz only cover
//   vregs 14..29. We bypass libz with an inline-asm syscall that
//   reserves a 920-byte stack pad (8B for the syscall word at [rsp+0]
//   plus 912B = 114 quadwords for vregs 14..127) and writes the two
//   pair entries at [rsp+904] (vreg 126) and [rsp+912] (vreg 127).
//
//   To reach the duplicate-source check (test 07) we must clear every
//   prior gate in the spec's order:
//
//     - test 01 (port xfer): runner grants the result port at
//       SLOT_FIRST_PASSED with caps {xfer, bind}, so xfer is set.
//     - test 02 (valid source ids): we mint a fresh port with
//       caps {move, copy} via createPort and use its handle id in both
//       entries.
//     - test 03 (caps ⊆ source caps): each entry's caps = the source's
//       caps verbatim ({move, copy}), trivially a subset.
//     - test 04 (move=1 needs `move` cap): both entries set move=0, so
//       this gate does not fire.
//     - test 05 (move=0 needs `copy` cap): the source carries `copy`, so
//       this gate is satisfied.
//     - test 06 (no reserved bits): PairEntry's packed-struct layout
//       zeros every reserved field.
//
//   With every prior check cleared, the kernel must reach the
//   duplicate-source check and reject the suspend with E_INVAL before
//   the EC actually suspends — a successful suspend would never return
//   to userspace via the syscall return path here; it would return only
//   after the primary's reply, and then with vreg 1 = 0 (the spec
//   reserves vreg 1 for the resume status; on this synchronous error
//   path vreg 1 carries the error code).
//
// Action
//   Issue `suspend` with:
//     v1 = SLOT_INITIAL_EC          (the calling EC)
//     v2 = SLOT_FIRST_PASSED        (result port; has xfer)
//     syscall word: pair_count = 2
//     vreg 126 = PairEntry{ id = src, caps = {move,copy}, move = 0 }
//     vreg 127 = PairEntry{ id = src, caps = {move,copy}, move = 0 }
//
// Assertion
//   1: createPort failed (setup failure — cannot reach the suspend).
//   2: vreg 1 != E_INVAL after the suspend (kernel did not reject the
//      duplicate-source pair as required).

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const SUSPEND_NUM: u64 = 14;

fn buildSuspendWord(pair_count: u8) u64 {
    return SUSPEND_NUM | (@as(u64, pair_count) << 12);
}

fn suspendWithDupPairX64(word: u64, target: u64, port: u64, entry: u64) u64 {
    var ov1: u64 = undefined;
    var d_v2: u64 = undefined;
    var d_v3: u64 = undefined;
    var d_v4: u64 = undefined;
    var d_v5: u64 = undefined;
    var d_v6: u64 = undefined;
    var d_v7: u64 = undefined;
    var d_v8: u64 = undefined;
    var d_v9: u64 = undefined;
    var d_v10: u64 = undefined;
    var d_v11: u64 = undefined;
    var d_v12: u64 = undefined;
    var d_v13: u64 = undefined;
    asm volatile (
        \\ subq $920, %%rsp
        \\ movq %%rdx, 0(%%rsp)
        \\ movq %%rsi, 904(%%rsp)
        \\ movq %%rsi, 912(%%rsp)
        \\ syscall
        \\ addq $920, %%rsp
        : [v1] "={rax}" (ov1),
          [v2] "={rbx}" (d_v2),
          [v3] "={rdx}" (d_v3),
          [v4] "={rbp}" (d_v4),
          [v5] "={rsi}" (d_v5),
          [v6] "={rdi}" (d_v6),
          [v7] "={r8}" (d_v7),
          [v8] "={r9}" (d_v8),
          [v9] "={r10}" (d_v9),
          [v10] "={r12}" (d_v10),
          [v11] "={r13}" (d_v11),
          [v12] "={r14}" (d_v12),
          [v13] "={r15}" (d_v13),
        : [iv1] "{rax}" (target),
          [iv2] "{rbx}" (port),
          [word] "{rdx}" (word),
          [entry] "{rsi}" (entry),
        : .{ .rcx = true, .r11 = true, .memory = true });
    return ov1;
}

fn suspendWithDupPairArm(word: u64, target: u64, port: u64, entry: u64) u64 {
    // aarch64 high-vreg layout: vreg N at [sp + (N-31)*8] for 32 ≤ N ≤ 127.
    // vreg 126 = [sp + 760]; vreg 127 = [sp + 768]. Reserve 784 bytes
    // (16-byte aligned) covering [sp+0] (word) through [sp+776].
    var ov1: u64 = undefined;
    asm volatile (
        \\ sub sp, sp, #784
        \\ str %[entry], [sp, #760]
        \\ str %[entry], [sp, #768]
        \\ str %[word], [sp]
        \\ svc #0
        \\ add sp, sp, #784
        : [v1] "={x0}" (ov1),
        : [iv1] "{x0}" (target),
          [iv2] "{x1}" (port),
          [word] "r" (word),
          [entry] "r" (entry),
        : .{ .x1 = true, .x2 = true, .x3 = true, .x4 = true, .x5 = true,
             .x6 = true, .x7 = true, .x8 = true, .x9 = true, .x10 = true,
             .x11 = true, .x12 = true, .x13 = true, .x14 = true, .x15 = true,
             .x16 = true, .x17 = true, .x19 = true, .x20 = true, .x21 = true,
             .x22 = true, .x23 = true, .x24 = true, .x25 = true, .x26 = true,
             .x27 = true, .x28 = true, .x29 = true, .x30 = true, .memory = true });
    return ov1;
}

fn suspendWithDupPair(target: u12, port: u12, entry: u64) u64 {
    const word = buildSuspendWord(2);
    return switch (builtin.cpu.arch) {
        .x86_64 => suspendWithDupPairX64(word, @as(u64, target), @as(u64, port), entry),
        .aarch64 => suspendWithDupPairArm(word, @as(u64, target), @as(u64, port), entry),
        else => @compileError("unsupported arch"),
    };
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Mint a source port we control. caps = {move, copy} carry the
    // shape this test needs for its pair entries (move=0 satisfies
    // test 05's `copy` requirement; move=1 would also be valid). `recv`
    // and `bind` are added to satisfy create_port's structural rule
    // (must include `recv` and one of `{suspend, bind}`); the entry
    // caps subset check (test 03) still holds because entry.caps =
    // {move, copy} is a subset of {move, copy, recv, bind}.
    const src_caps = caps.PortCap{
        .move = true,
        .copy = true,
        .recv = true,
        .bind = true,
    };
    const cp = syscall.createPort(@as(u64, src_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const src_handle: caps.HandleId = @truncate(cp.v1 & 0xFFF);

    // Two entries that reference the same source handle id.
    const entry = (caps.PairEntry{
        .id = src_handle,
        .caps = src_caps.toU16(),
        .move = false,
    }).toU64();

    const v1 = suspendWithDupPair(
        caps.SLOT_INITIAL_EC,
        caps.SLOT_FIRST_PASSED,
        entry,
    );

    if (v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
