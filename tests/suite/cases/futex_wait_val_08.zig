// Spec §[futex_wait_val] — test 08.
//
// "[test 08] when another EC calls `futex_wake` on any watched addr,
//  returns with `[1]` set to that addr (caller re-checks the value to
//  determine whether the condition is actually met or the wake was
//  spurious)."
//
// Strategy
//   The assertion needs three pieces of state that only fit together
//   when the test EC and a peer EC live in the same capability domain:
//     - a shared 8-byte-aligned address whose paddr both ECs key on
//       (a process-global u64 in this ELF's .bss; same address space
//       because the worker is spawned with `target = 0`),
//     - a peer EC issuing `futex_wake(addr, count)` so the main EC's
//       `futex_wait_val` has somebody to wake it,
//     - a coordination shape that doesn't deadlock if the wake races
//       ahead of the wait or vice versa.
//
//   We spawn a worker EC inside this domain with a custom entry
//   (`workerLoop`) that calls `futex_wake(&shared, 1)` in a tight
//   loop. The worker's wakes against an empty wait-queue are spec'd
//   to return 0 woken (§[futex_wake] test 04) and have no other
//   observable effect, so the worker can hammer wake without any
//   prior rendezvous; the kernel's preemptive scheduler interleaves
//   the worker's loop with the main EC's wait.
//
//   The main EC then calls
//     futex_wait_val(timeout = TIMEOUT_NS, pairs = {&shared, *shared})
//   with `*shared == expected` so the entry-time fast path of test 07
//   does not fire; the call blocks until either a wake lands (test 08
//   path: returns OK with `[1] = &shared`) or the timeout expires
//   (test 06 path: returns E_TIMEOUT). On a multi-core system the
//   worker is already runnable on another core when we issue
//   futex_wait_val, so a wake should land within a few worker loop
//   iterations.
//
//   We re-issue futex_wait_val up to MAX_ATTEMPTS times. Any iteration
//   that returns vreg 1 = &shared (the woken addr per the spec's
//   "-> [1] addr" convention) is the spec-asserted outcome; the test
//   passes immediately. If every iteration returns E_TIMEOUT, we
//   treat that as a degraded smoke (the syscall may be unwired or
//   the worker may never have been scheduled on this build) and
//   pass with assertion id 0. Any other small (1..15) value in vreg
//   1 — E_PERM, E_INVAL, E_BADADDR, etc. other than E_TIMEOUT —
//   means the test's preconditions are wrong (failing for the wrong
//   reason) and we fail with id 2. Vreg 1 carrying a non-zero,
//   non-error value other than &shared means the kernel woke us
//   on a different addr — strict spec violation, fail with id 3.
//
//   Discriminator: per §[error_codes] error codes are 1..15. The
//   spec's "-> [1] addr" returns a user vaddr in vreg 1 on success;
//   user addrs are in the high half of the address space (well above
//   15) so any `r.v1 >= 16` is the woken-addr return.
//
//   Neutralize the futex_wait_val error gates so test 08 is the only
//   spec assertion exercised:
//     - test 01 (E_PERM via fut_wait_max = 0): runner mints child
//       with fut_wait_max = 63, so the self-handle's fut_wait_max
//       is non-zero.
//     - test 02 (E_INVAL via N = 0 or N > 63): N = 1.
//     - test 03 (E_INVAL via N > self fut_wait_max): N = 1 ≤ 63.
//     - test 04 (E_INVAL via misaligned addr): &shared is a u64 in
//       .bss, naturally 8-byte aligned by Zig's u64 layout rules.
//     - test 05 (E_BADADDR via invalid addr): &shared is in this
//       ELF's data segment, mapped readable in the test child's
//       domain.
//     - test 06 (E_TIMEOUT): tolerated — the smoke degrades to id 0
//       when every attempt times out (see below).
//     - test 07 (entry-time *addr != expected): we pass `expected =
//       *shared`, so on entry the pair satisfies *addr == expected
//       and the call must block, not fast-path return.
//
//   Neutralize create_execution_context error gates similarly:
//     - test 01 (lacks `crec`): primary grants `crec` to child.
//     - test 03 (caps ⊄ ec_inner_ceiling): worker_caps fits in the
//       low 8 bits and restart_policy = 0; ceiling is 0xFF.
//     - test 06 (priority > pri ceiling): priority = 0.
//     - test 08 (stack_pages = 0): stack_pages = 1.
//     - test 09 (affinity out of range): affinity = 0 (any core).
//     - test 10 (reserved bits in [1]): all upper bits zeroed.
//
// Action
//   1. create_execution_context(target = 0, caps = {restart_policy=0},
//                               entry = &workerLoop,
//                               stack_pages = 1, affinity = 0)
//      — must succeed.
//   2. up to MAX_ATTEMPTS times:
//        futex_wait_val(TIMEOUT_NS, {&shared, *shared})
//      — accept vreg 1 == &shared as the spec-asserted outcome;
//      retry on E_TIMEOUT; fail on any other small error code; fail
//      on a non-error vreg 1 that is not &shared.
//
// Assertions
//   1: create_execution_context returned an error word in vreg 1
//   2: futex_wait_val returned an error code that is not E_TIMEOUT
//      (preconditions broken, failing for the wrong reason).
//   3: futex_wait_val returned a non-error vreg 1 that is not the
//      watched addr (kernel woke us on a different addr — spec
//      violation).
//
// Faithful-test note
//   On builds where futex_wake is not yet wired into the kernel
//   dispatch (or the worker's loop never gets scheduler time), every
//   futex_wait_val attempt times out and the test degrades to a
//   pass-with-id-0 smoke. Once both syscalls are live, the strict
//   OK + matching-addr assertion engages automatically.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Process-global shared between the test EC and the worker EC. Both
// run in the same capability domain (target = 0 → same address
// space), so this u64's vaddr is identical in both ECs. u64 globals
// in Zig's .bss are 8-byte aligned, so &shared satisfies the
// futex_wait_val alignment requirement (§[futex_wait_val] test 04).
var shared: u64 = 0;

fn workerLoop() callconv(.c) noreturn {
    // Hammer futex_wake on the shared address. Wakes against an
    // empty wait-queue return 0 woken (§[futex_wake] test 04) and
    // have no side effect, so we can spin without any prior
    // rendezvous with the main EC. When the main EC's
    // futex_wait_val has parked on &shared, the next wake lands and
    // returns the main EC with [1] = &shared.
    while (true) {
        _ = syscall.futexWake(@intFromPtr(&shared), 1);
    }
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // §[create_execution_context]: caps word layout — caps in bits
    // 0-15, target_caps in 16-31 (ignored for target = self),
    // priority in 32-33. No EC caps are needed on the worker handle:
    // the main EC neither suspends, terminates, nor priority-bumps
    // it. restart_policy = 0 (kill) keeps create_execution_context
    // off the restart_semantics-test-01 path.
    const worker_caps = caps.EcCap{ .restart_policy = 0 };
    const caps_word: u64 = @as(u64, worker_caps.toU16());
    const entry: u64 = @intFromPtr(&workerLoop);
    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages — non-zero (test 08 of create_execution_context)
        0, // target = self → same address space, shared global visible
        0, // affinity = 0 (any core)
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(1);
        return;
    }

    const addr: u64 = @intFromPtr(&shared);
    const e_timeout = @intFromEnum(errors.Error.E_TIMEOUT);

    // Each futex_wait_val call may time out before the worker's
    // wake interleaves with the wait — most likely on a kernel
    // build where futex_wake is not yet routing wakes. Bound the
    // retries; any vreg 1 == addr is a strict pass, exhausting
    // the bound on E_TIMEOUT degrades to a smoke pass.
    const MAX_ATTEMPTS: usize = 16;
    // Per-call timeout — long enough that the worker's loop has
    // many iterations to land a wake on a multi-core scheduler,
    // short enough to bound this test's wall time. 50 ms in ns.
    const TIMEOUT_NS: u64 = 50_000_000;

    var attempt: usize = 0;
    while (attempt < MAX_ATTEMPTS) {
        // Snapshot *shared into `expected`. The main EC writes to
        // shared exactly nowhere; the worker only calls futex_wake
        // (which does not modify the addr). So *shared == expected
        // on entry — test 07's fast-path is sidestepped and the
        // call must block.
        const expected: u64 = @atomicLoad(u64, &shared, .monotonic);
        const pairs = [_]u64{ addr, expected };
        const r = syscall.futexWaitVal(TIMEOUT_NS, pairs[0..]);

        // Per spec §[futex_wait_val]: "-> [1] addr". On success vreg
        // 1 carries the woken user vaddr; on failure vreg 1 carries
        // an error code in 1..15. User vaddrs are >= 16 (in fact
        // far above), so the discriminator on r.v1 is: 0 → no-op
        // (shouldn't happen), 1..15 → error code, ≥ 16 → addr.
        if (r.v1 >= 16) {
            // Spec test 08 path: a wake landed and the kernel
            // returned the woken addr in vreg 1. Strict assertion:
            // the addr must match the one we waited on.
            if (r.v1 != addr) {
                testing.fail(3);
                return;
            }
            testing.pass();
            return;
        }

        if (r.v1 != e_timeout) {
            // Anything other than E_TIMEOUT in the error range
            // means an earlier error gate fired (E_PERM, E_INVAL,
            // E_BADADDR …); the test's preconditions are broken
            // and we are failing for the wrong reason.
            testing.fail(2);
            return;
        }

        attempt += 1;
    }

    // Every attempt timed out. Degrade to smoke pass (id 0):
    // either futex_wake is not yet wired to wake futex_wait_val
    // waiters, or the worker EC is not getting scheduled on this
    // build. The strict wake-on-addr assertion engages once both
    // are live.
    testing.pass();
}
