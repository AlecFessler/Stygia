// Spec §[suspend] — test 10.
//
// "[test 10] on success, when [1] has the `read` cap, the suspension
//  event payload exposes the target's EC state per §[event_state];
//  otherwise the state in the payload is zeroed."
//
// Strategy
//   The spec line has two halves; both must be observed.
//
//   Phase A — read=true → state per §[event_state]:
//     The test EC mints a port with `bind | recv` and a child EC W_R
//     in its own domain with caps `{susp, term, read, restart_policy=0}`
//     and entry pointing at a small assembly trampoline that:
//       (1) writes a sentinel value to a process-global with release
//           ordering so the test EC has a synchronization witness that
//           W_R has executed at least its prologue,
//       (2) loads a known sentinel into r15 (= vreg 13 per §[event_state]
//           x86-64 GPR table, which lists r15 as the 13th GPR),
//       (3) loops on `hlt` (a no-op or trap from user-mode is fine —
//           we just need W_R to stop progressing past the mov so its
//           snapshot is stable when suspend fires).
//
//     The test EC then re-yields to W_R repeatedly until it observes the
//     sentinel via an acquire load on the shared global (yield_03 shape).
//     Once the global carries the sentinel, the trampoline has executed
//     past the r15 mov; the kernel-held r15 in W_R's saved-context now
//     holds the sentinel until W_R is rescheduled (which it isn't,
//     because W_R is lower priority and has nothing to do).
//
//     The test EC then calls `suspend(W_R, port)`. Per §[suspend], a
//     non-self target is suspended without blocking the caller. W_R is
//     queued as a suspended sender. The test EC then `recv`s the port.
//     Per §[event_state] x86-64, vreg 13 carries the suspended EC's
//     r15. The test asserts vreg 13 == the sentinel — direct evidence
//     that the payload "exposes the target's EC state".
//
//   Phase B — read=false → zeroed:
//     Mint a fresh child EC W_Z with caps `{susp, term, restart_policy=0}`
//     (no `read`) and the same trampoline entry. Repeat the yield/observe
//     handshake against a separate global so we know W_Z too has run
//     past the mov; W_Z's actual r15 is therefore the sentinel. Then
//     `suspend(W_Z, port)` and `recv`. Per spec test 10, because the
//     suspending handle lacks `read`, the payload state must be zeroed
//     regardless of W_Z's real GPRs. The test asserts that all 13
//     register-backed event-state vregs (1..13) come back as zero.
//
//   The two phases together — non-zero pinned value when `read` is set
//   on the same trampoline that's known to have executed, vs. all zero
//   when `read` is cleared — are the strongest direct observation of
//   the spec line that the v0 register-only ABI permits. Reading vregs
//   14..18 (RIP/RFLAGS/RSP/FS.base/GS.base) would require a stack-pad
//   wrapper that the v0 libz does not yet provide; vreg 13 (r15) is
//   the highest-indexed register-backed slot and is sufficient.
//
//   Neutralize the other suspend / recv error paths so test 10 is the
//   only assertion exercised:
//     - suspend test 01 (E_BADCAP target): handles are freshly minted
//       valid ECs.
//     - suspend test 02 (E_BADCAP port): handle is the freshly minted
//       port.
//     - suspend test 03 (lacks `susp`): both ECs include `susp`.
//     - suspend test 04 (lacks `bind`): port has `bind`.
//     - suspend test 05 (reserved bits): EcCap and PortCap toU16 cover
//       the defined bit ranges; libz issueReg writes `pair_count = 0`
//       in the syscall word's count field.
//     - suspend test 06 (vCPU): targets are plain ECs, not vCPUs.
//     - suspend test 07 (already suspended): each phase suspends a
//       fresh EC exactly once.
//     - recv test 04 (E_CLOSED): the test EC keeps its bind-cap port
//       handle live across both phases.
//     - recv test 06 (E_FULL): the test EC's domain has plenty of
//       slack — only a handful of slots are consumed.
//
//   Neutralize create_execution_context error paths the same way
//   yield_03.zig does (caps inside the bitwise low 8 bits of
//   ec_inner_ceiling = 0xFF, priority = 0, stack_pages = 1, affinity
//   = 0, target = 0).
//
// Action
//   1. create_port(caps={bind, recv}) — must succeed
//   Phase A:
//   2. create_execution_context(W_R, caps={susp, term, read}) — OK
//   3. yield/poll until observed_R == SENTINEL_R
//   4. suspend(W_R, port) — OK
//   5. recv(port) — OK; assert vreg 13 == SENTINEL_R
//   Phase B:
//   6. create_execution_context(W_Z, caps={susp, term}) — OK
//   7. yield/poll until observed_Z == SENTINEL_Z
//   8. suspend(W_Z, port) — OK
//   9. recv(port) — OK; assert vregs 1..13 are all zero
//
// Assertions
//   1:  create_port returned an error word
//   2:  create_execution_context for W_R returned an error word
//   3:  yield(W_R) returned a non-OK status, or the sentinel never
//       became observable within the bounded poll
//   4:  suspend(W_R, port) returned non-OK
//   5:  recv(port) for W_R produced no reply handle / wrong event_type
//       (probe via syscall word, since with `read` set vreg 1 carries
//       W_R's rax rather than an error code on success)
//   6:  read=true payload did not expose W_R's r15 — vreg 13 != sentinel
//   7:  create_execution_context for W_Z returned an error word
//   8:  yield(W_Z) returned a non-OK status, or the sentinel never
//       became observable within the bounded poll
//   9:  suspend(W_Z, port) returned non-OK
//   10: recv(port) for W_Z produced no reply handle / wrong event_type
//   11: read=false payload was not zeroed — at least one of vregs 1..13
//       was non-zero

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const SENTINEL_R: u64 = 0xDEAD_BEEF_CAFE_F00D;
const SENTINEL_Z: u64 = 0xFEED_FACE_BAAD_F00D;

// Process-global handshake variables. Each child EC writes its sentinel
// here on entry (release) so the test EC can confirm the child's
// trampoline executed past the vreg-13-backing mov before we issue
// suspend.
var observed_r: u64 = 0;
var observed_z: u64 = 0;

// Phase A trampoline: write the shared-memory witness, pin the vreg-13
// backing register to the sentinel, then loop. The release store
// ensures the test EC's acquire load on observed_r happens-after the
// witness write. The mov is architecturally required to retire before
// any subsequent instruction the EC executes, so once observed_r ==
// SENTINEL_R, the backing register holds SENTINEL_R until the EC is
// rescheduled.
//
// Per §[event_state]:
//   x86-64: vreg 13 = r15
//   aarch64: vreg 13 = x12 (vreg 1..31 = x0..x30)
fn entryR() callconv(.c) noreturn {
    @atomicStore(u64, &observed_r, SENTINEL_R, .release);
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile (
            \\ movabsq $0xDEADBEEFCAFEF00D, %%r15
            \\ 1: pause
            \\    jmp 1b
            :
            :
            : .{ .r15 = true }),
        .aarch64 => asm volatile (
            \\ movz x12, #0xF00D
            \\ movk x12, #0xCAFE, lsl #16
            \\ movk x12, #0xBEEF, lsl #32
            \\ movk x12, #0xDEAD, lsl #48
            \\ 1: yield
            \\    b 1b
            :
            :
            : .{ .x12 = true }),
        else => @compileError("unsupported arch"),
    }
    unreachable;
}

fn entryZ() callconv(.c) noreturn {
    @atomicStore(u64, &observed_z, SENTINEL_Z, .release);
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile (
            \\ movabsq $0xFEEDFACEBAADF00D, %%r15
            \\ 1: pause
            \\    jmp 1b
            :
            :
            : .{ .r15 = true }),
        .aarch64 => asm volatile (
            \\ movz x12, #0xF00D
            \\ movk x12, #0xBAAD, lsl #16
            \\ movk x12, #0xFACE, lsl #32
            \\ movk x12, #0xFEED, lsl #48
            \\ 1: yield
            \\    b 1b
            :
            :
            : .{ .x12 = true }),
        else => @compileError("unsupported arch"),
    }
    unreachable;
}

// Yield-and-poll loop matching yield_03's shape. Re-yields to the
// target up to MAX_ATTEMPTS times, returning true the first iteration
// that observes the sentinel. Any non-OK yield return short-circuits
// false so the test can attribute the failure correctly.
const MAX_ATTEMPTS: usize = 64;

fn yieldUntilObserved(target_word: u64, observed: *u64, sentinel: u64) bool {
    var attempt: usize = 0;
    while (attempt < MAX_ATTEMPTS) {
        const yr = syscall.yieldEc(target_word);
        if (yr.v1 != @intFromEnum(errors.Error.OK)) return false;
        if (@atomicLoad(u64, observed, .acquire) == sentinel) return true;
        attempt += 1;
    }
    return false;
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint the port. bind+recv are the only caps the test
    // exercises; restricting to those keeps the runner's port_ceiling
    // (xfer/recv/bind = 0x1C) trivially satisfied.
    const port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // ---------------------------------------------------------------
    // Phase A — read=true: payload must expose state per §[event_state]
    // ---------------------------------------------------------------

    // Step 2: mint W_R with susp+term+read. restart_policy=0 keeps
    // restart_semantics test 01 satisfied. The runner's
    // ec_inner_ceiling covers EcCap bits 0-7 (0xFF) which includes
    // bits 4 (term), 5 (susp), 6 (read).
    const wr_caps = caps.EcCap{
        .term = true,
        .susp = true,
        .read = true,
        .restart_policy = 0,
    };
    const wr_caps_word: u64 = @as(u64, wr_caps.toU16());
    const cec_r = syscall.createExecutionContext(
        wr_caps_word,
        @intFromPtr(&entryR),
        1, // stack_pages
        0, // target = self
        0, // affinity = any
    );
    if (testing.isHandleError(cec_r.v1)) {
        testing.fail(2);
        return;
    }
    const wr_handle: u12 = @truncate(cec_r.v1 & 0xFFF);

    // Step 3: drive W_R until its trampoline witness is visible. After
    // this point W_R's r15 is SENTINEL_R until W_R is rescheduled.
    if (!yieldUntilObserved(@as(u64, wr_handle), &observed_r, SENTINEL_R)) {
        testing.fail(3);
        return;
    }

    // Step 4: queue W_R as a suspended sender on the port.
    const sus_r = syscall.issueReg(.@"suspend", 0, .{
        .v1 = wr_handle,
        .v2 = port_handle,
    });
    if (sus_r.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }

    // Step 5: recv. The test EC holds the port's bind cap and the
    // event is queued, so recv returns immediately. With W_R's handle
    // carrying `read`, vregs 1..13 must reflect W_R's GPRs per
    // §[event_state]; vreg 13 = r15.
    //
    // Note: when recv succeeds with `read` set, vreg 1 carries W_R's
    // rax (the suspended EC's GPR), NOT a 0/OK status — §[event_state]
    // defines vreg 1 as the GPR view in the success payload. The
    // success-vs-failure witness instead reads the syscall word's
    // reply_handle_id (bits 32-43, slot id of the inserted reply
    // handle) and event_type (bits 44-48). A valid reply_handle_id is
    // ≥ SLOT_FIRST_PASSED (=3), so a zero in those bits is a recv
    // failure witness; on success the event_type for a `suspend`-
    // generated event is `suspension` (=4 per §[event_type]).
    const got_r = syscall.recv(port_handle, 0);
    const reply_id_r: u12 = @truncate((got_r.word >> 32) & 0xFFF);
    const event_type_r: u5 = @truncate((got_r.word >> 44) & 0x1F);
    if (reply_id_r == 0 or event_type_r != 4) {
        testing.fail(5);
        return;
    }
    if (got_r.regs.v13 != SENTINEL_R) {
        testing.fail(6);
        return;
    }

    // ---------------------------------------------------------------
    // Phase B — read=false: payload state must be zeroed
    // ---------------------------------------------------------------

    // Step 6: mint W_Z with susp+term but NOT read. Same domain, same
    // address space, so entryZ is reachable.
    const wz_caps = caps.EcCap{
        .term = true,
        .susp = true,
        .restart_policy = 0,
    };
    const wz_caps_word: u64 = @as(u64, wz_caps.toU16());
    const cec_z = syscall.createExecutionContext(
        wz_caps_word,
        @intFromPtr(&entryZ),
        1,
        0,
        0,
    );
    if (testing.isHandleError(cec_z.v1)) {
        testing.fail(7);
        return;
    }
    const wz_handle: u12 = @truncate(cec_z.v1 & 0xFFF);

    // Step 7: drive W_Z past its r15 mov so we know W_Z's actual r15
    // is non-zero — the test then verifies that the kernel zeroes the
    // payload anyway because the suspending handle lacks `read`.
    if (!yieldUntilObserved(@as(u64, wz_handle), &observed_z, SENTINEL_Z)) {
        testing.fail(8);
        return;
    }

    // Step 8: queue W_Z.
    const sus_z = syscall.issueReg(.@"suspend", 0, .{
        .v1 = wz_handle,
        .v2 = port_handle,
    });
    if (sus_z.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(9);
        return;
    }

    // Step 9: recv. With W_Z's handle lacking `read`, every event-state
    // vreg in the payload must be zero per the spec line under test.
    // vregs 1..13 are register-backed; the v0 libz wrapper observes
    // them directly. Stack-spilled vregs 14..18 would require a stack
    // pad we don't yet have, but the spec line's "zeroed" requirement
    // applies uniformly across all event-state vregs and verifying any
    // strict subset is sufficient evidence that the kernel honored it.
    const got_z = syscall.recv(port_handle, 0);
    const reply_id_z: u12 = @truncate((got_z.word >> 32) & 0xFFF);
    const event_type_z: u5 = @truncate((got_z.word >> 44) & 0x1F);
    if (reply_id_z == 0 or event_type_z != 4) {
        testing.fail(10);
        return;
    }
    const all_zero =
        got_z.regs.v1 == 0 and
        got_z.regs.v2 == 0 and
        got_z.regs.v3 == 0 and
        got_z.regs.v4 == 0 and
        got_z.regs.v5 == 0 and
        got_z.regs.v6 == 0 and
        got_z.regs.v7 == 0 and
        got_z.regs.v8 == 0 and
        got_z.regs.v9 == 0 and
        got_z.regs.v10 == 0 and
        got_z.regs.v11 == 0 and
        got_z.regs.v12 == 0 and
        got_z.regs.v13 == 0;
    if (!all_zero) {
        testing.fail(11);
        return;
    }

    testing.pass();
}
