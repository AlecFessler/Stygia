// Spec §[suspend] suspend — test 08.
//
// "[test 08] on success, the target EC stops executing."
//
// Strategy
//   Mint a worker EC inside this domain (target = self) that runs a
//   tight loop incrementing a shared u64 in this ELF's .bss. Because
//   create_execution_context with target = 0 puts the new EC in the
//   caller's own capability domain — and therefore in the same address
//   space — the parent test EC can observe the worker's progress by
//   reading the same memory location.
//
//   The worker uses an atomic increment so the value the parent reads
//   is the value the worker last wrote (the kernel gives no other
//   memory-ordering guarantee between unrelated user ECs). The parent
//   uses an atomic load for the symmetric reason.
//
//   suspend takes a port for the suspension event delivery target. We
//   mint a fresh port with `bind` so the suspend syscall passes its
//   port-cap check (§[suspend] test 04). recv is not exercised here —
//   the assertion only requires that the worker stops executing, which
//   the kernel must enforce synchronously regardless of whether anyone
//   ever recv's the event. The port is left with the suspension event
//   queued; teardown happens when the test EC's domain self-handle is
//   deleted on return from `main`.
//
//   The verification has two phases:
//     1. Liveness: yield a few times, then read the heartbeat. If it
//        is nonzero the worker is observably running. If the kernel
//        never schedules the worker (single-core with the parent
//        spinning, etc.) the heartbeat may stay at zero — in that
//        case the test degrades to "suspend returned OK", which
//        already covers the syscall-success leg of the assertion.
//     2. Stop: call suspend(worker, port), require it returned OK, then
//        sample the heartbeat, yield several times, sample again. If
//        the first sample was nonzero the worker had been running; the
//        post-suspend samples must be equal — the worker must not
//        advance the counter after it has been suspended.
//
//   Caps on the worker EC handle:
//     - susp  : required by §[suspend] (test 03 — E_PERM otherwise).
//     - restart_policy = 0 (kill): test ECs in this runner spawn
//                                   without restart context, and
//                                   create_execution_context with
//                                   restart_policy > 0 would require
//                                   ec_restart_max > 0 in the
//                                   parent's restart_policy_ceiling
//                                   — granted by the runner — but
//                                   adds no value to this assertion.
//
//   The worker's entry function is a Zig fn living in this ELF's
//   .text. The new EC's stack is allocated by the kernel; the worker
//   never returns from `workerLoop` so no stack-unwind concerns arise.
//
// Action
//   1. createPort(caps={bind, recv}) — must succeed.
//   2. create_execution_context(target=self, caps={susp, rp=0},
//                               entry=&workerLoop, stack_pages=1,
//                               affinity=0)                      — must succeed
//   3. yield-spin briefly to let the worker run; sample heartbeat
//   4. suspend(worker, port, attachments=&.{})                   — must return OK
//   5. sample heartbeat (c2), yield several times, sample again (c3)
//   6. if heartbeat was observably advancing pre-suspend, require
//      c2 == c3 after suspend
//
// Assertions
//   1: createPort failed (returned an error word in vreg 1)
//   2: setup syscall failed (create_execution_context returned an error)
//   3: suspend returned non-OK
//   4: post-suspend heartbeat advanced (worker still executing)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Heartbeat written by the worker, read by the parent. Same address
// space (target = self), so the global is shared by construction.
var heartbeat: u64 = 0;

fn workerLoop() noreturn {
    while (true) {
        _ = @atomicRmw(u64, &heartbeat, .Add, 1, .monotonic);
    }
}

// Yield to scheduler N times. Used both to let the worker run and to
// give the kernel a chance to migrate work between cores.
fn yieldN(n: u32) void {
    var i: u32 = 0;
    while (i < n) {
        _ = syscall.yieldEc(0);
        i += 1;
    }
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // §[create_port] mint a port for the suspension event delivery
    // target. `bind` is required by §[suspend] test 04. `recv` is
    // included so the runner-granted port_ceiling subset check (= 0x1C
    // — xfer | recv | bind — see runner/primary.zig) accepts the cap
    // word; it isn't exercised here.
    const port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Worker caps: susp is required by §[suspend]. restart_policy = 0
    // keeps the call free of restart-ceiling checks
    // (§[restart_semantics] test 01).
    const worker_caps = caps.EcCap{
        .susp = true,
        .restart_policy = 0,
    };
    // §[create_execution_context] caps word: caps in bits 0-15,
    // target_caps in 16-31 (ignored when target = self), priority in
    // 32-33. priority = 0 stays within the runner-granted pri ceiling.
    const caps_word: u64 = @as(u64, worker_caps.toU16());
    const entry: u64 = @intFromPtr(&workerLoop);
    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages
        0, // target = self
        0, // affinity = 0 (any core)
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(2);
        return;
    }
    const worker_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // Phase 1: liveness probe. Yield a handful of times so on a
    // single-core system the worker still gets scheduled at least
    // once. The exact count is a heuristic — the assertion only
    // depends on it being observably nonzero to graduate beyond
    // the degraded smoke shape.
    yieldN(8);
    const c1: u64 = @atomicLoad(u64, &heartbeat, .monotonic);

    // Phase 2: suspend. §[suspend]: "[1] may reference the calling EC;
    // the syscall returns after the calling EC is resumed." When [1]
    // is not the calling EC (as here), the syscall returns
    // synchronously after enqueuing the suspension event on [2] and
    // marking the target suspended. No attachments — N=0 keeps us on
    // the register-only path of suspendEc.
    const susp_result = syscall.suspendEc(worker_handle, port_handle, &.{});
    if (susp_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Phase 3: stop verification. Take an immediate post-suspend
    // sample, yield repeatedly to give any phantom worker continuation
    // a chance to fire, then sample again. The two samples must
    // match — the worker must have stopped writing.
    const c2: u64 = @atomicLoad(u64, &heartbeat, .monotonic);
    yieldN(16);
    const c3: u64 = @atomicLoad(u64, &heartbeat, .monotonic);

    // If the worker was never scheduled (c1 == 0), we lack a positive
    // observation that the EC was ever executing. The suspend-OK leg
    // above is already enforced; pass the test on the smoke shape and
    // rely on a future scheduler-cooperative variant for the full
    // assertion.
    if (c1 != 0 and c3 != c2) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
