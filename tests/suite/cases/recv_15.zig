// Spec §[recv] recv — test 15.
//
// "[test 15] on success when [2] timeout_ns is nonzero and a sender
//  is delivered before the deadline, the deadline is cancelled and
//  no E_TIMEOUT is later observed."
//
// Strategy
//   The assertion has two halves and both can be witnessed from a
//   single test EC paired with a worker EC in the same capability
//   domain:
//     (a) recv with a finite, nonzero timeout returns success — not
//         E_TIMEOUT — when a sender is queued before the deadline.
//     (b) After the original deadline elapses, no spurious E_TIMEOUT
//         signal surfaces. The kernel must have cancelled the armed
//         deadline when recv consumed the queued sender; if it had
//         not, the timer would later fire on a recv slot the EC has
//         already returned from, producing either a stale E_TIMEOUT
//         poked into vreg 1, an unsolicited resume, or a kernel-side
//         crash. The test EC stays runnable past the deadline by
//         busy-polling time_monotonic and then issuing a follow-up
//         syscall whose return value verifies vreg 1 carries that
//         syscall's result rather than a stale E_TIMEOUT.
//
//   Setup mirrors recv_05 / recv_16: the test EC mints a port with
//   caps={bind, recv}, spawns a worker EC in the same domain, and
//   yields to it so the worker reaches its blocking suspend before
//   the test EC calls recv. The worker calls suspend(self, port) so
//   the queued event is a suspended-EC sender the test EC can recv.
//
//   For witness (a) the test EC calls recv(port, timeout_ns =
//   100_000_000) — 100ms. The worker's queued suspend ensures the
//   recv returns with vreg 1 = OK well before the deadline. The
//   timeout is intentionally short enough that, were the deadline
//   not cancelled, it would elapse during the witness-(b) wait
//   window below.
//
//   For witness (b) the test EC busy-polls time_monotonic until at
//   least 4 * timeout_ns has elapsed (400ms — well past the original
//   100ms deadline), then issues `time_monotonic` once more. A
//   well-behaved kernel returns the current monotonic ns in vreg 1.
//   A buggy kernel that left the deadline armed and let it fire on
//   the test EC's now-returned recv slot could plausibly clobber
//   vreg 1 with E_TIMEOUT (15) on the next syscall return path; we
//   guard against that exact corruption by checking the post-wait
//   time_monotonic return is not in the error-code range 1..15.
//
//   Failure-path neutralization for the recv call itself (test 14
//   E_TIMEOUT is the only spec failure that this test's success
//   path could be confused for):
//     - test 01 (E_BADCAP): the freshly-minted port slot id is used.
//     - test 02 (E_PERM no `recv`): port_caps.recv = true.
//     - test 03 (E_INVAL on reserved bits): the libz wrapper takes
//       u12 and zero-extends.
//     - test 04 (E_CLOSED no bind/route/queue): the test EC holds
//       the port handle with the bind cap and the worker queues a
//       suspension event before the test EC recvs.
//     - test 05 (E_CLOSED on blocked recv when bind drops): the
//       test EC never deletes the port handle.
//     - test 06 (E_FULL): the test domain has plenty of free slots
//       for the reply handle plus zero attached handles.
//
//   create_execution_context error paths neutralized for the worker
//   the same way recv_05 / recv_16 neutralize them (target = 0,
//   stack_pages = 1, priority = 0, affinity = 0, caps subset of the
//   runner's ec_inner_ceiling = 0xFF).
//
// Action
//   1. create_port(caps = {bind, recv})           — must succeed.
//   2. create_execution_context(target = self,
//        caps = {susp, term, restart_policy = 0},
//        entry = &workerEntry, stack_pages = 1,
//        affinity = 0)                             — must succeed.
//   3. yield(worker) so it reaches its blocking suspend on the port
//      before the test EC calls recv.
//   4. recv(port_handle, timeout_ns = 100_000_000) — must return OK
//      (a sender is queued well before the deadline).
//   5. busy-poll time_monotonic until elapsed >= 4 * timeout_ns
//      (well past the original deadline).
//   6. time_monotonic once more — its vreg 1 must NOT be in the
//      error-code range (E_TIMEOUT = 15 in particular).
//
// Assertions
//   1: setup port creation failed (createPort returned an error).
//   2: setup EC creation failed (createExecutionContext returned an
//      error).
//   3: pre-recv yield to the worker did not return OK.
//   4: recv did not return OK (witness-(a) failure: success path
//      did not fire — either E_TIMEOUT, or the kernel didn't dequeue
//      the sender).
//   5: post-deadline time_monotonic returned an error-coded value
//      (witness-(b) failure: a stale E_TIMEOUT artifact corrupted
//      a later syscall return path).

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Process-global side channels shared across the test EC and the
// worker EC — both run in the same capability domain so they share
// the address space and the handle table.
//   - worker_self_slot: slot id of the worker's own EC handle, used
//     by suspend(self, port).
//   - worker_port_slot: slot id of the test-minted port; the worker
//     suspends onto this port.
var worker_self_slot: u12 = 0;
var worker_port_slot: u12 = 0;

fn workerEntry() callconv(.c) noreturn {
    // Both slot ids are published by the test EC before
    // createExecutionContext returns, so the worker's first read
    // sees them. No synchronisation needed: createExecutionContext
    // happens-before the worker's first instruction.
    const self_slot = worker_self_slot;
    const port_slot = worker_port_slot;
    // suspend(self, port) queues the worker as a suspended sender on
    // the port. The libz wrapper is the safe path with N = 0.
    _ = syscall.suspendEc(self_slot, port_slot, &.{});
    // The worker is left waiting indefinitely after suspend resolves.
    // The test EC never replies on the minted reply handle and the
    // capability domain is torn down at test exit, so the worker is
    // not expected to observe a particular resolution — it just must
    // not race the test EC into surfacing an unrelated event.
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfi"),
            else => @compileError("unsupported arch"),
        }
    }
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint the port. bind keeps the bind refcount at 1 so
    // the recv call does not short-circuit through E_CLOSED before
    // the kernel arms the deadline; recv passes test 02's gate.
    const port_caps = caps.PortCap{ .bind = true, .recv = true, .@"suspend" = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);
    worker_port_slot = port_handle;

    // Step 2: mint the worker EC. susp lets the worker self-suspend
    // onto the port; term is held for symmetry with sibling tests.
    // restart_policy = 0 (kill) keeps the request inside the runner's
    // ec_inner_ceiling and prevents any restart fallback after this
    // test ends.
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
        1, // stack_pages
        0, // target = self (this domain)
        0, // affinity = any core
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(2);
        return;
    }
    const w_handle: u12 = @truncate(cec.v1 & 0xFFF);
    const w_target: u64 = @as(u64, w_handle);
    worker_self_slot = w_handle;

    // Step 3: yield to the worker so it reaches its blocking suspend
    // syscall before the test EC calls recv. On a uniprocessor this
    // serialises the path; on multi-core the worker may execute
    // concurrently and either ordering reaches the witness-(a) state
    // (worker queued on port by the time recv runs).
    const y1 = syscall.yieldEc(w_target);
    if (y1.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Step 4: recv with a finite, nonzero timeout. The worker is
    // queued as a sender, so the kernel's success path fires well
    // before the deadline and vreg 1 must be OK. A 100ms deadline is
    // long enough to absorb scheduling jitter and short enough that,
    // if the kernel failed to cancel it, the timer would fire during
    // the witness-(b) wait below.
    const timeout_ns: u64 = 100_000_000; // 100 ms
    const got = syscall.recv(port_handle, timeout_ns);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }

    // Step 5: busy-poll time_monotonic until at least 4 * timeout_ns
    // has elapsed (400 ms — well past the original 100 ms deadline).
    // This gives the kernel ample opportunity to fire the would-be
    // deadline if the cancel did not stick.
    const wait_ns: u64 = 4 * timeout_ns;
    const t0 = syscall.timeMonotonic();
    const start_ns: u64 = t0.v1;
    while (true) {
        const tn = syscall.timeMonotonic();
        const now_ns: u64 = tn.v1;
        const elapsed: u64 = if (now_ns >= start_ns) now_ns - start_ns else 0;
        if (elapsed >= wait_ns) break;
    }

    // Step 6: one more time_monotonic. Its return must not look like
    // an error code. The worry is a stale E_TIMEOUT from the
    // not-properly-cancelled deadline corrupting a later syscall
    // return path; this read catches that. time_monotonic itself has
    // no error-coded return for a self-handle that holds the implied
    // caps (the runner self-handle does), so a value in 1..15 here
    // would specifically indicate an artifact of the prior deadline
    // — exactly what the spec line under test forbids.
    const post = syscall.timeMonotonic();
    if (errors.isError(post.v1) and post.v1 < 16) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
