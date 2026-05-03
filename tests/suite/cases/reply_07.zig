// Spec §[reply] reply — test 07.
//
// "[test 07] on success, the suspended EC is resumed."
//
// Strategy
//   The assertion is a liveness witness: after `reply(reply_handle)`
//   succeeds, the EC that the reply handle named must transition from
//   "suspended on a port" back to "runnable" and actually execute.
//
//   To witness "actually execute" we need an observable side effect
//   the worker EC performs only after it is resumed. The yield_03 idiom
//   applies: spawn the worker in the test EC's own capability domain
//   (target = 0) so a process-global is shared memory between the two
//   ECs, and have the worker's entry point store a sentinel into that
//   global with release ordering. The test EC then loads it with
//   acquire ordering after `reply` returns.
//
//   The recv-side scaffolding is the same shape as terminate_07:
//     - mint a port with {bind, recv} caps so recv is callable and the
//       port has a live bind-cap holder for its full lifetime (no
//       E_CLOSED on the recv path),
//     - mint a worker EC W with {term, susp} caps, restart_policy = 0,
//     - suspend(W, port) — non-blocking on the test EC since [1] != self,
//       queues W on the port,
//     - recv(port) — returns immediately, handing back the reply handle
//       id in the syscall word per §[recv],
//     - reply(reply_handle_id) — the spec line under test.
//
//   `term` is included on W so any restart-side scaffolding that fires
//   on test exit can clean up cleanly (matching the terminate_07
//   blueprint); `susp` is what authorizes the suspend syscall in step 3.
//   The `write` cap is intentionally NOT minted because reply test 06
//   asserts that without `write`, modifications written between recv
//   and reply are discarded — and this test makes none, so the absence
//   of `write` keeps the test EC honest about which spec line it is
//   asserting (test 07 is about resumption, not state propagation).
//
//   Because W has not run yet at the moment of `suspend`, the kernel
//   queues it on the port before its initial entry-point gets to
//   execute. `reply` is therefore observably the only edge that lets W
//   reach its entry point and write the sentinel. Polling for the
//   sentinel with a bounded yield loop (matching yield_03) tolerates
//   schedulers that delay the wake target onto another core or after
//   one or more reschedules.
//
//   Neutralize other reply error paths so test 07 is the only spec
//   assertion exercised:
//     - test 01 (E_BADCAP for invalid reply handle): the reply handle id
//       is the one the kernel just minted via recv, so it is valid.
//     - test 02 (E_INVAL if reserved bits set in the syscall word):
//       the wrapper builds the syscall word from a u12 handle and the
//       syscall_num enum, leaving every reserved bit at zero.
//     - test 03 (E_TERM if W was terminated before reply): the test
//       does not terminate W between recv and reply.
//     - test 04 (handle consumed on success): not exercised here, but
//       does not affect this test's pass/fail.
//     - tests 05/06 (state propagation gated by `write`): no event-state
//       vregs are modified between recv and reply.
//
// Action
//   1. create_port(caps={bind,recv})        — must succeed
//   2. create_execution_context(target=self,
//        entry=&workerEntry, caps={term,susp}, restart_policy=0)
//                                            — must succeed
//   3. suspend(W, port)                      — must return OK
//      (W is queued as a suspended sender on the port)
//   4. recv(port)                            — must return OK and yield
//      a reply_handle_id in the syscall word per §[recv]
//   5. reply(reply_handle_id)                — must return OK
//      (the spec line under test)
//   6. bounded yield-and-load loop on the sentinel — must observe
//      SENTINEL before the bound is exhausted
//
// Assertions
//   1: setup port creation failed (createPort returned an error word)
//   2: setup EC creation failed (createExecutionContext returned an
//      error word)
//   3: suspend itself did not return OK
//   4: recv did not return OK
//   5: reply did not return OK
//   6: sentinel was not visible after the bounded yield-and-load loop
//      (W was not actually resumed)

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const SENTINEL: u64 = 0xA110_C0DE_5EE5_BEEF;

// Process-global shared between the test EC and the worker EC. Both
// run in the same capability domain (target = self at create time), so
// this global is the shared-memory witness of W's resumption.
var observed: u64 = 0;

fn workerEntry() callconv(.c) noreturn {
    @atomicStore(u64, &observed, SENTINEL, .release);
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfe"),
            else => @compileError("unsupported arch"),
        }
    }
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint the port with bind + recv. The test EC holds the
    // only bind-cap copy for the test's duration so recv on this port
    // never observes E_CLOSED on the no-binders fallback.
    const port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: mint W. susp authorizes the suspend syscall in step 3;
    // term is held for orderly teardown on test exit; restart_policy
    // = 0 keeps the call inside the runner-granted ec_inner_ceiling
    // and prevents any restart fallback. `write` is omitted on
    // purpose — see header for why.
    const w_caps = caps.EcCap{
        .term = true,
        .susp = true,
        .restart_policy = 0,
    };
    const ec_caps_word: u64 = @as(u64, w_caps.toU16());
    const entry: u64 = @intFromPtr(&workerEntry);
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

    // Step 3: queue W as a suspended sender on the port. Per §[suspend]
    // when [1] != self, the calling EC is not blocked; the kernel only
    // suspends the target.
    const sus = syscall.issueReg(.@"suspend", 0, .{
        .v1 = w_handle,
        .v2 = port_handle,
    });
    if (sus.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Step 4: recv. The test EC holds the port's recv cap and W is
    // queued, so recv returns immediately. The reply_handle_id is in
    // the syscall word's bits 32-43 per §[recv].
    const got = syscall.recv(port_handle, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }
    const reply_handle_id: u12 = @truncate((got.word >> 32) & 0xFFF);

    // Step 5: the spec line under test. reply must consume the handle
    // and resume W.
    const r = syscall.reply(reply_handle_id);
    if (r.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(5);
        return;
    }

    // Step 6: witness W's resumption. Re-yield to W on each iteration
    // (per yield_03) and load the sentinel with acquire ordering.
    // Any observation of SENTINEL before the bound is exhausted is a
    // pass.
    const MAX_ATTEMPTS: usize = 64;
    const target_word: u64 = @as(u64, w_handle);
    var attempt: usize = 0;
    while (attempt < MAX_ATTEMPTS) {
        _ = syscall.yieldEc(target_word);
        if (@atomicLoad(u64, &observed, .acquire) == SENTINEL) {
            testing.pass();
            return;
        }
        attempt += 1;
    }

    testing.fail(6);
}
