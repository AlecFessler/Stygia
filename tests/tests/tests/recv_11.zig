// Spec §[recv] recv — test 11.
//
// "[test 11] on success when the suspending EC handle had the `read`
//  cap, the receiver's vregs reflect the suspended EC's state per
//  §[event_state] (or §[vm_exit_state] when event_type = vm_exit)."
//
// Strategy
//   The assertion needs a witness that the receiver-side vregs really
//   carry the suspended EC's architectural state, gated on the `read`
//   cap of the EC handle used at suspend. Per §[suspend] [test 10],
//   "when [1] has the `read` cap, the suspension event payload exposes
//   the target's EC state per §[event_state]" — so the suspending side
//   only needs to hold `read` on the EC handle for the receiver to see
//   live state.
//
//   Witness pick: vreg 14 is RIP per §[event_state] x86-64 layout
//   (vreg 1..13 = GPRs in the receiver's hardware registers; vreg 14 =
//   `[rsp + 8]` during syscall execution, i.e., on the receiver's
//   user stack). For a freshly-created EC W that has never executed —
//   entry = `&dummyEntry`, suspended via `suspend(W, port)` immediately
//   after creation — §[create_execution_context] guarantees the EC
//   "begins executing at `[2] entry` with the stack pointer set to the
//   top of the allocated stack." The kernel must therefore have
//   recorded W's saved RIP as the entry pointer we passed in. Reading
//   vreg 14 == &dummyEntry is a strong, deterministic witness that:
//     (a) the kernel populated the receiver's vreg layout from W's
//         saved state, and
//     (b) the data really is W's RIP and not zero or the calling EC's.
//   The `read=false` companion case is the subject of recv test 12;
//   this file establishes only the positive direction.
//
//   The libz `recv` wrapper (`issueRawCaptureWord`) only captures vregs
//   1..13 (the GPR-backed band) and the syscall word — it does not
//   reach vreg 14. The recv path here therefore inlines its own
//   syscall sequence so it can carve out a stack slot at exactly
//   `[rsp + 8]` (relative to the syscall-time rsp) and read it back
//   after the kernel writes it.
//
//   Setup parallels terminate_07.zig: the test EC owns both ends — it
//   mints the port (so `bind` cap stays live and recv won't return
//   E_CLOSED), mints W with `susp` + `read` (the susp cap to enqueue
//   it, `read` to satisfy the gate the spec line names), suspends W
//   onto the port, and recvs. `[1]` may reference a non-self EC and
//   the call returns immediately without blocking the caller per
//   §[suspend], so the test EC stays runnable through recv.
//
// Action
//   1. create_port(caps={bind, recv})         — must succeed
//   2. create_execution_context(target=self,
//        caps={susp, read, term, rp=0})       — must succeed
//      (entry = dummyEntry; W never executes — suspend fires before
//      it would be scheduled. term lets the test clean up if needed
//      but isn't required for the assertion.)
//   3. suspend(W, port)                       — must return OK
//      (non-blocking on the test EC since [1] != self)
//   4. recv_with_rip(port)                    — must return OK; the
//      syscall word carries reply_handle_id and event_type, vregs
//      1..13 carry W's GPRs, and the captured stack slot carries
//      W's RIP per §[event_state] vreg 14.
//   5. assert captured_rip == &dummyEntry      — the spec line
//
// Assertions
//   1: setup port creation failed (createPort returned an error word)
//   2: setup EC creation failed (createExecutionContext returned an
//      error word)
//   3: suspend itself did not return OK
//   4: recv did not return OK in vreg 1
//   5: vreg 14 (RIP) does not equal the entry point we passed —
//      either the kernel zeroed the state vregs (the test 12 path,
//      indicating `read` was not honored) or the kernel wrote the
//      wrong EC's state.

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Custom recv that also captures vreg 14 (`[rsp + 8]` during syscall).
// libz's `syscall.recv` only reaches the GPR-band vregs (1..13) and
// the syscall word; vreg 14 lives on the user stack per §[event_state]
// and is not part of the libz return shape. This helper carves out a
// dedicated stack slot above the syscall word so the kernel writes
// vreg 14 into a location we can read after `popq`.
//
// Layout during syscall:
//   [rsp + 0]  = syscall word            (vreg 0)
//   [rsp + 8]  = vreg 14 capture slot    (RIP — kernel writes here)
// The `subq $8` reservation runs BEFORE `pushq %rcx`, so the slot
// survives the popq that pairs with the push on return.
//
// Register accounting:
//   rax: input (port handle in, syscall return v1 out)
//   rcx: input (syscall word; clobbered by sysret)
//   rbx: output (RIP popped from the reserved slot)
//   r11: clobbered by sysret
//   rbx, rdx, rbp, rsi, rdi, r8-r10, r12-r15: kernel writes vregs
//     2..13 here. rbx is reused as the RIP output (after the kernel
//     has already returned and we no longer need W's rbx). The other
//     12 registers carry W's GPRs but we don't read them in this
//     test — they are listed as clobbers so the compiler doesn't
//     assume any prior value survives.
const RecvRip = struct { v1: u64, rip: u64 };

// Portable no-op entry — local to this test so we don't depend on the
// libz testing.dummyEntry (which is x86-only `hlt`). W never executes
// past creation: suspend lands before scheduling, and the test reads
// W's saved RIP — which the kernel set to this function's address — as
// the witness for §[event_state].
fn localDummyEntry() noreturn {
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfi"),
            else => @compileError("unsupported arch"),
        }
    }
}

fn recvCaptureRipX64(port: u12) RecvRip {
    const word: u64 = 49; // syscall_num for recv per §[recv]
    var v1_out: u64 = undefined;
    var rip_out: u64 = undefined;

    asm volatile (
        \\ subq $8, %%rsp        // reserve vreg-14 slot (will sit at [rsp+8] post-push)
        \\ pushq %%rcx           // store syscall word at [rsp+0]
        \\ syscall               // kernel writes vreg 14 to [rsp+8] = the reserved slot
        \\ popq %%rcx            // discard syscall-word slot (now at original rsp - 8)
        \\ popq %%rbx            // pull RIP from the reserved slot into rbx
        : [v1] "={rax}" (v1_out),
          [rip] "={rbx}" (rip_out),
        : [word] "{rcx}" (word),
          [iv1] "{rax}" (@as(u64, port)),
        : .{ .rcx = true, .r11 = true, .rdx = true, .rbp = true,
             .rsi = true, .rdi = true, .r8 = true, .r9 = true, .r10 = true,
             .r12 = true, .r13 = true, .r14 = true, .r15 = true,
             .memory = true });

    return .{ .v1 = v1_out, .rip = rip_out };
}

// aarch64 ABI per spec §[syscall_abi]:
//   vreg 0     = [sp + 0]            (syscall word)
//   vreg 1..31 = x0..x30             (vreg 1 = x0; vreg 14 = x13)
// Per §[event_state] the kernel writes the suspended EC's saved RIP into
// vreg 14, which on aarch64 is register-backed at x13. We reserve 16
// bytes (16-byte aligned) for the syscall word slot only and read x13
// directly out of the asm.
fn recvCaptureRipArm(port: u12) RecvRip {
    const word: u64 = 49; // syscall_num for recv per §[recv]
    var v1_out: u64 = undefined;
    var rip_out: u64 = undefined;

    asm volatile (
        \\ sub sp, sp, #16
        \\ str %[word], [sp]
        \\ svc #0
        \\ add sp, sp, #16
        : [v1] "={x0}" (v1_out),
          [rip] "={x13}" (rip_out),
        : [word] "r" (word),
          [iv1] "{x0}" (@as(u64, port)),
        : .{ .x1 = true, .x2 = true, .x3 = true, .x4 = true, .x5 = true,
             .x6 = true, .x7 = true, .x8 = true, .x9 = true, .x10 = true,
             .x11 = true, .x12 = true, .x14 = true, .x15 = true,
             .x16 = true, .x17 = true, .x19 = true, .x20 = true, .x21 = true,
             .x22 = true, .x23 = true, .x24 = true, .x25 = true, .x26 = true,
             .x27 = true, .x28 = true, .x29 = true, .x30 = true, .memory = true });

    return .{ .v1 = v1_out, .rip = rip_out };
}

fn recvCaptureRip(port: u12) RecvRip {
    return switch (builtin.cpu.arch) {
        .x86_64 => recvCaptureRipX64(port),
        .aarch64 => recvCaptureRipArm(port),
        else => @compileError("unsupported arch"),
    };
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint the port. bind keeps a live bind-cap holder so recv
    // does not return E_CLOSED on the bind path; recv lets us dequeue
    // the suspension event. xfer is unused — no handles attached.
    const port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: mint W. susp to queue it as a suspended sender; read so
    // the kernel exposes W's state to the receiver per the spec line
    // under test. term is held for completeness but not exercised
    // here. restart_policy = 0 (kill) avoids any restart-fallback
    // interference. EcCap bits 0-7 cover {move,copy,saff,spri,term,
    // susp,read,write} — all within the runner's ec_inner_ceiling =
    // 0xFF, so caps_subset checks pass.
    const w_caps = caps.EcCap{
        .term = true,
        .susp = true,
        .read = true,
        .restart_policy = 0,
    };
    // §[create_execution_context] caps word: caps in bits 0-15,
    // target_caps in 16-31 (ignored when target = self), priority in
    // 32-33. priority = 0 stays inside the runner pri ceiling.
    const ec_caps_word: u64 = @as(u64, w_caps.toU16());
    const entry: u64 = @intFromPtr(&localDummyEntry);
    const cec = syscall.createExecutionContext(
        ec_caps_word,
        entry,
        1,
        0,
        0,
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(2);
        return;
    }
    const w_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // Step 3: queue W as a suspended sender on the port. Per
    // §[suspend], `[1]` may reference a non-self EC; the call returns
    // immediately without blocking the caller. The kernel records W's
    // saved state, gated on this EC handle's `read`/`write` for what
    // the receiver may see/write.
    const sus = syscall.suspendEc(w_handle, port_handle, &.{});
    if (sus.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Step 4: recv with stack-slot capture for vreg 14. The port has
    // the test EC as a live bind-cap holder and W queued as a
    // suspension event, so recv returns immediately (no E_CLOSED, no
    // E_FULL — the test domain has plenty of free slots for the reply
    // handle). With `read` set on the EC handle used at suspend, the
    // kernel writes W's saved register state into the vreg layout in
    // §[event_state]; vreg 14 = `[rsp + 8]` is W's RIP.
    const got = recvCaptureRip(port_handle);
    if (got.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }

    // Step 5: probe vreg 14. W never executed past creation; per
    // §[create_execution_context] the kernel sets RIP to the entry we
    // passed. Any other value — most notably zero (the test 12
    // read-not-set path) — fails the assertion under test.
    if (got.rip != entry) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
