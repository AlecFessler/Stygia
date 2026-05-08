// Spec §[recv] — test 09.
//
// "[test 09] on success when the sender attached N handles, the syscall
//  word's pair_count = N and the next N table slots [tstart, tstart+N)
//  contain the inserted handles per §[handle_attachments]."
//
// Strategy
//   The shape mirrors terminate_07: this test EC owns both ends of the
//   pipeline. It mints a port P with {bind, recv, xfer} (xfer is
//   required because the suspend will attach a handle — §[suspend]:
//   "Additionally `xfer` if any handles are attached in the syscall
//   word's `pair_count`"). It mints a worker EC W with the `susp` cap
//   (target = self-domain), and a source handle S that will be the
//   attachment target. Then the test calls `suspend(W, P)` with
//   pair_count = 1 and a single pair entry encoding S in vreg 127.
//
//   `suspend` with [1] != self is non-blocking on the caller per
//   §[suspend] ("[1] may reference the calling EC; the syscall returns
//   after the calling EC is resumed" — when [1] is *not* the caller,
//   the call simply queues W as a suspended sender on P and returns
//   immediately to this test EC). With W queued and the test EC still
//   holding P's bind cap, recv on P returns immediately with a syscall
//   word whose pair_count, tstart, and reply_handle_id are populated.
//
//   For the source handle S we mint a fresh port and use a strict-
//   subset cap pattern in the pair entry. Picking a non-IDC source
//   keeps the post-condition simple: per §[handle_attachments],
//   "caps = entry.caps intersected with `idc_rx` for IDC handles, or
//   entry.caps verbatim for other handle types" — so the inserted
//   handle's caps must equal the entry caps verbatim. We use move = 0
//   (copy), which requires the source's `copy` cap (§[handle_attachments]
//   test 05); we mint S with `copy` set so that gate passes.
//
//   Pre-call gates the test must clear so no other failure path can
//   mask the assertion under test:
//     - §[create_port] test 01: runner self-handle has `crpt`.
//     - §[create_port] test 02: caps {bind,recv,xfer} = 0x1C ⊆
//       runner port_ceiling 0x1C.
//     - §[create_execution_context] test 01: runner self-handle has
//       `crec`. test 03/06/08/09/10: caps subset of ec_inner_ceiling,
//       priority 0, stack_pages 1, affinity 0, reserved bits clear.
//     - §[recv] test 01: P is valid. test 02: P has `recv`. test 03:
//       reserved bits clear in [1]. test 04: P has live bind-cap
//       holders (this test EC) and a queued event. test 06: the
//       caller's table has plenty of free slots (the runner-spawned
//       child gets a fresh table with effectively the full 4096-slot
//       range available; one reply + one attachment is well under the
//       limit).
//     - §[handle_attachments] tests 01-07 (suspend-time gates): the
//       port has `xfer`, the source handle id is valid in the
//       suspending EC's domain (W's domain == this test's domain since
//       W was created with target = self), entry.caps ⊆ source caps,
//       move=0 with source `copy` set, no reserved bits, only one
//       entry so no duplicate-source case.
//
//   Custom-suspend asm: §[handle_attachments] places pair entries at
//   vregs [128-N..127] — the *high* end of the vreg space. libz's
//   `suspendEc` panics on the attachments path; this test inlines the
//   syscall sequence to populate vreg 127. Per §[syscall_abi]:
//     vreg 0   = [rsp + 0]            (syscall word)
//     vreg N   = [rsp + (N-13)*8]     for 14 <= N <= 127
//   At syscall time vreg 127 lives at [rsp + (127-13)*8] = [rsp + 912].
//   The sequence reserves 920 bytes on the stack (114 stack-vreg slots
//   + 8 for the word push), writes the pair entry at the slot that
//   becomes [rsp + 912] after the push, pushes the syscall word, runs
//   `syscall`, and restores rsp.
//
//   Post-condition probe: §[recv] syscall word return layout puts
//   pair_count in bits 12-19 and tstart in bits 20-31. We extract both
//   and compare pair_count to 1 (assertion id 6) and verify
//   `tstart != 0` so we have a valid slot to read (assertion id 7).
//   Then `readCap(cap_table_base, tstart)` is authoritative for the
//   handle's static layout (caps in word0 bits 48-63, type tag in
//   bits 12-15) without `sync` (§[capabilities]: caps and type tag
//   live in the static layout, not the kernel-mutable field0/field1
//   snapshot — same pattern as create_var_18 and create_port_04). We
//   verify the inserted slot holds a port handle (assertion id 8) and
//   that its caps equal the entry.caps verbatim (assertion id 9).
//
// Action
//   1. create_port(caps={bind, recv, xfer})        — must succeed
//   2. create_port(caps={copy, recv})              — source S, must succeed
//   3. create_execution_context(target=self,
//        caps={susp, restart_policy=0})            — worker W, must succeed
//      (entry = dummyEntry; W never executes meaningfully — it is
//      suspended before scheduling matters)
//   4. suspend(W, P) with pair_count=1 and vreg127
//      = pair_entry(S, caps={recv}, move=0)        — must return OK
//   5. recv(P)                                     — must return OK
//   6. assert syscall word's pair_count == 1
//   7. assert syscall word's tstart is a valid slot id (non-zero —
//      slot 0 holds the test's self-handle)
//   8. readCap(tstart).handleType() == .port
//   9. readCap(tstart).caps() == {recv}
//
// Assertions
//   1: setup port P creation failed (createPort returned an error word)
//   2: setup port S creation failed (createPort returned an error word)
//   3: setup EC W creation failed (createExecutionContext returned an
//      error word)
//   4: suspend itself did not return OK
//   5: recv did not return OK
//   6: syscall word's pair_count != 1
//   7: syscall word's tstart was 0 (would collide with self-handle slot)
//   8: inserted slot is not a port handle
//   9: inserted slot's caps do not match the entry's caps verbatim

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// §[suspend] syscall_num = 14. Pair-count goes in bits 12-19 of the
// syscall word per §[handle_attachments]. With N = 1 and vreg 127
// being the only attachment, the asm sequence reserves stack space
// for vregs 14..127 (114 quadwords = 912 bytes) plus 8 bytes for the
// syscall-word push. Only vreg 127 is meaningful for this call; the
// kernel does not consume the lower stack-vreg slots for `suspend`.
//
// Layout invariant verified per spec §[syscall_abi]:
//   At syscall time, [rsp + (N-13)*8] = vreg N for 14 <= N <= 127.
//   For N = 127 that is [rsp + 912]. Pre-push rsp is +8 higher, so we
//   write vreg 127 at offset 904 from the pre-push rsp. The syscall
//   word (rcx) is then pushed at [rsp - 8], landing at [rsp + 0]
//   relative to the post-push rsp.
//
// Inputs are passed via register constraints rather than memory operands
// — `subq $920, %%rsp` would otherwise invalidate any RSP-relative
// memory operand the compiler chose to back the local input variables
// with. Pinning each input to a specific call-clobbered register that
// is NOT consumed by the syscall ABI (rax/rbx/rcx are reserved for
// v1/v2/word) keeps the values intact across the RSP move. Same fix
// pattern as `handle_attachments_10`.
// Portable no-op entry — local to this test so we don't depend on the
// libz testing.dummyEntry (which is x86-only `hlt`). W never executes
// past creation in this test (suspend lands before scheduling), so the
// entry pointer just needs to be a valid code address.
fn localDummyEntry() noreturn {
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfi"),
            else => @compileError("unsupported arch"),
        }
    }
}

fn suspendWithOneAttachmentX64(target: u12, port: u12, entry: u64) u64 {
    const SUSPEND_NUM: u64 = 14;
    const PAIR_COUNT_ONE: u64 = 1 << 12;
    const word: u64 = SUSPEND_NUM | PAIR_COUNT_ONE;
    var v1_out: u64 = undefined;
    asm volatile (
        \\ subq $920, %%rsp
        \\ movq %%r8, 904(%%rsp)
        \\ pushq %%rcx
        \\ syscall
        \\ addq $928, %%rsp
        : [v1] "={rax}" (v1_out),
        : [word] "{rcx}" (word),
          [iv1] "{rax}" (@as(u64, target)),
          [iv2] "{rbx}" (@as(u64, port)),
          [entry] "{r8}" (entry),
        : .{ .rcx = true, .r8 = true, .r11 = true, .memory = true });
    return v1_out;
}

// aarch64 ABI per spec §[syscall_abi]:
//   vreg 0   = [sp + 0]            (syscall word)
//   vreg 1..31 = x0..x30           (vreg 1 = x0, vreg 2 = x1, ...)
//   vreg N   = [sp + (N-31)*8]     for 32 <= N <= 127
// vreg 127 lives at [sp + 768]. We reserve 784 bytes (16-byte aligned)
// to cover the syscall word at [sp+0] and vreg 127 at [sp+768].
fn suspendWithOneAttachmentArm(target: u12, port: u12, entry: u64) u64 {
    const SUSPEND_NUM: u64 = 14;
    const PAIR_COUNT_ONE: u64 = 1 << 12;
    const word: u64 = SUSPEND_NUM | PAIR_COUNT_ONE;
    var x0_out: u64 = undefined;
    asm volatile (
        \\ sub sp, sp, #784
        \\ str %[entry], [sp, #768]
        \\ str %[word], [sp]
        \\ svc #0
        \\ add sp, sp, #784
        : [x0_out] "={x0}" (x0_out),
        : [word] "r" (word),
          [iv1] "{x0}" (@as(u64, target)),
          [iv2] "{x1}" (@as(u64, port)),
          [entry] "r" (entry),
        : .{ .x1 = true, .x2 = true, .x3 = true, .x4 = true, .x5 = true,
             .x6 = true, .x7 = true, .x8 = true, .x9 = true, .x10 = true,
             .x11 = true, .x12 = true, .x13 = true, .x14 = true, .x15 = true,
             .x16 = true, .x17 = true, .x19 = true, .x20 = true, .x21 = true,
             .x22 = true, .x23 = true, .x24 = true, .x25 = true, .x26 = true,
             .x27 = true, .x28 = true, .x29 = true, .x30 = true, .memory = true });
    return x0_out;
}

fn suspendWithOneAttachment(target: u12, port: u12, entry: u64) u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => suspendWithOneAttachmentX64(target, port, entry),
        .aarch64 => suspendWithOneAttachmentArm(target, port, entry),
        else => @compileError("unsupported arch"),
    };
}

pub fn main(cap_table_base: u64) void {
    // Step 1: mint the receive port P. xfer is required because the
    // subsequent suspend attaches a handle (§[suspend] / §[handle_attachments]
    // test 01).
    const port_p_caps = caps.PortCap{ .bind = true, .recv = true, .xfer = true, .@"suspend" = true };
    const cp_p = syscall.createPort(@as(u64, port_p_caps.toU16()));
    if (testing.isHandleError(cp_p.v1)) {
        testing.fail(1);
        return;
    }
    const port_p: u12 = @truncate(cp_p.v1 & 0xFFF);

    // Step 2: mint the source handle S. We pick a fresh port so the
    // post-condition (§[handle_attachments] test 08: "caps =
    // entry.caps verbatim for other handle types") applies cleanly
    // without involving idc_rx. S needs `copy` so the move=0 entry
    // can pass §[handle_attachments] test 05.
    const port_s_caps = caps.PortCap{ .copy = true, .recv = true };
    const cp_s = syscall.createPort(@as(u64, port_s_caps.toU16()));
    if (testing.isHandleError(cp_s.v1)) {
        testing.fail(2);
        return;
    }
    const port_s: u12 = @truncate(cp_s.v1 & 0xFFF);

    // Step 3: mint the worker EC W. susp lets us queue W onto the port
    // via suspend; restart_policy = 0 (kill) keeps the call inside the
    // runner-granted ceiling and prevents any restart fallback from
    // resurrecting W.
    const w_caps = caps.EcCap{
        .susp = true,
        .restart_policy = 0,
    };
    const ec_caps_word: u64 = @as(u64, w_caps.toU16());
    const w_entry: u64 = @intFromPtr(&localDummyEntry);
    const cec = syscall.createExecutionContext(
        ec_caps_word,
        w_entry,
        1, // stack_pages
        0, // target = self (W's domain == this test's domain)
        0, // affinity = any core
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(3);
        return;
    }
    const w_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // Step 4: suspend(W, P) with one attachment. The pair entry layout
    // per §[handle_attachments]:
    //   bits  0-11: source id     = port_s
    //   bits 12-15: _reserved     = 0
    //   bits 16-31: caps          = {recv}    (subset of S's caps)
    //   bit     32: move          = 0          (copy; requires S.copy)
    //   bits 33-63: _reserved     = 0
    const entry_caps = caps.PortCap{ .recv = true };
    const pair_entry = caps.PairEntry{
        .id = port_s,
        .caps = entry_caps.toU16(),
        .move = false,
    };
    const sus_v1 = suspendWithOneAttachment(w_handle, port_p, pair_entry.toU64());
    if (sus_v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }

    // Step 5: recv on P. P has the test EC as a live bind-cap holder
    // and W queued as a suspension event, so recv returns immediately
    // with the syscall word populated per §[recv].
    const got = syscall.recv(port_p, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(5);
        return;
    }

    // §[recv] syscall word return layout:
    //   bits 12-19: pair_count
    //   bits 20-31: tstart
    const pair_count: u64 = (got.word >> 12) & 0xFF;
    const tstart: u12 = @truncate((got.word >> 20) & 0xFFF);

    // Step 6: pair_count must be 1.
    if (pair_count != 1) {
        testing.fail(6);
        return;
    }

    // Step 7: tstart should be a valid slot id. Slot 0 is the test
    // domain's self-handle, which the kernel will not overwrite, so
    // tstart = 0 would indicate the kernel did not allocate a slot.
    if (tstart == 0) {
        testing.fail(7);
        return;
    }

    // Step 8: the inserted slot must hold a port handle (since S was a
    // port handle).
    const inserted = caps.readCap(cap_table_base, tstart);
    if (inserted.handleType() != caps.HandleType.port) {
        testing.fail(8);
        return;
    }

    // Step 9: per §[handle_attachments] test 08, for non-IDC handle
    // types the inserted handle's caps equal entry.caps verbatim.
    if (inserted.caps() != entry_caps.toU16()) {
        testing.fail(9);
        return;
    }

    testing.pass();
}
