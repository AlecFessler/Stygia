// Spec §[futex_wait_change] — test 08.
//
// "[test 08] when another EC calls `futex_wake` on any watched addr,
//  returns with `[1]` set to that addr (caller re-checks the value to
//  determine whether the condition is actually met or the wake was
//  spurious)."
//
// Strategy
//   The full assertion compares two ECs: one blocked in
//   `futex_wait_change` on a watched addr, and a second EC that
//   issues `futex_wake` on that addr. The blocked EC must return
//   with vreg 1 = the watched addr regardless of whether the wake
//   actually changed the underlying value (the spec note about
//   spurious wakes).
//
//   The runner mints each test child capability domain with
//   `fut_wake = true` on the self-handle (runner/primary.zig line
//   184) and `fut_wait_max = 63` (line 167); the self-handle is
//   shared across every EC in the domain, so any EC the test spawns
//   inherits both rights for free. Same-domain spawn (target = 0 on
//   create_execution_context) keeps the child in this address space
//   so a process-global is shared memory between the two ECs — same
//   shape `yield_03` uses to verify visibility of a child write.
//
//   The blocking-then-wake handshake follows naturally from the
//   scheduler invariant: when the test EC blocks in
//   `futex_wait_change`, the kernel runs the next runnable EC; on a
//   single-core test host that is the just-created child. The child
//   calls `futex_wake(&watched, 1)` and halts. The kernel's
//   `futex_wake` implementation must wake any EC blocked in either
//   `futex_wait_val` or `futex_wait_change` keyed on that addr per
//   §[futex_wake]; the wake delivers vreg 1 = watched_addr to the
//   blocked test EC per the spec line under test.
//
//   Sentinel placement: `watched` lives in .bss (zero-initialised).
//   We pass `target = 1` so `*addr == target` is false on entry and
//   the entry-time fast path of test 07 does not fire — the kernel
//   has to actually park the EC and wait for the wake. The child
//   never writes `watched`; the wake is by definition spurious in
//   the spec sense (the value condition was not met). The spec
//   under test is explicit that a spurious wake also returns the
//   addr — so the assertion is identical either way.
//
//   Watched address alignment: `watched` is a u64 in .bss; the
//   linker aligns u64 to 8 bytes so test 04 (E_INVAL on misaligned
//   addr) cannot fire. The address is in the test ELF's loaded
//   image, mapped r/w into the child capability domain by
//   `create_capability_domain`, so test 05 (E_BADADDR) cannot fire.
//   N = 1 stays inside [1, 63] and inside the caller's
//   `fut_wait_max = 63`, so tests 02 / 03 cannot fire. The
//   `fut_wait_max = 63` minted on the self-handle leaves test 01
//   inert as well.
//
//   Timeout: 1 second is generous enough to cover the round trip
//   on a TCG/KVM test host without materially extending suite
//   runtime. If the kernel were to fail to deliver the wake, the
//   call would still terminate via E_TIMEOUT — the test fails
//   cleanly rather than hanging the runner. Any return that is
//   neither an error nor `&watched` also fails the test.
//
//   Other failure paths neutralised on `create_execution_context`:
//     - test 01 (lacks `crec`): runner grants `crec`.
//     - test 03 (caps ⊄ ec_inner_ceiling): caps = 0 (no bits set).
//     - test 06 (priority > pri ceiling): priority = 0.
//     - test 08 (stack_pages = 0): stack_pages = 1.
//     - test 09 (affinity out of range): affinity = 0 (any core).
//     - test 10 (reserved bits in [1]): all upper bits zeroed.
//     - tests 04/05/07 (target nonzero paths): target = 0.
//
// Action
//   1. create_execution_context(caps=0, &childEntry, 1, 0, 0)
//      — must succeed; child runs `futexWake(&watched, 1)` then
//      halts.
//   2. futex_wait_change(timeout = 1 s,
//                        pairs = { &watched, target = 1 })
//      — child wakes the parent on `&watched`; spec line under
//      test mandates vreg 1 = `&watched`.
//
// Assertions
//   1: create_execution_context returned an error word (no child
//      EC was created, so the spec assertion under test cannot be
//      exercised).
//   2: futex_wait_change returned an error in vreg 1 — the kernel
//      must surface the watched addr on a wake-leg return, not an
//      error code (E_TIMEOUT here would mean the child's
//      `futex_wake` never woke the test EC).
//   3: vreg 1 != &watched — the returned addr must equal the
//      watched address the wake fired on.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Process-global watched word, shared between the test EC and the
// child EC because both run in the same capability domain. Stays at
// 0 throughout the test — the child never writes it; only its
// futex_wake call reaches the parent. .bss alignment for u64
// guarantees 8-byte alignment per test 04.
var watched: u64 = 0;

fn childEntry() callconv(.c) noreturn {
    // §[futex_wake]: wake up to `count` ECs blocked in
    // futex_wait_val or futex_wait_change on the given address. The
    // self-handle carries `fut_wake` (runner/primary.zig line 184),
    // so test 01 cannot fire; `&watched` is 8-byte aligned (test
    // 02) and mapped r/w in this domain (test 03). Hammer the wake
    // continuously: if the child is scheduled before the parent
    // parks on the futex bucket, an early single-shot wake misses
    // and the parent times out. The continuous loop guarantees a
    // wake fires AFTER the parent's enqueue, regardless of which
    // EC the scheduler runs first. §[futex_wake] test 04 specifies
    // wakes against an empty wait-queue return 0 and have no other
    // side effect, so spinning here is safe.
    while (true) {
        _ = syscall.futexWake(@intFromPtr(&watched), 1);
    }
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Same-domain spawn: caps = 0 (the child needs no per-handle
    // caps for `futex_wake` — that gate lives on the self-handle,
    // shared across every EC in the domain). `restart_policy = 0`
    // dodges restart_semantics test 01.
    const ec_caps = caps.EcCap{ .restart_policy = 0 };
    const caps_word: u64 = @as(u64, ec_caps.toU16());
    const entry: u64 = @intFromPtr(&childEntry);

    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages
        0, // target = self
        0, // affinity = any core
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(1);
        return;
    }

    // §[futex_wait_change]: target = 1 ≠ *watched (0), so the
    // entry-time fast path of test 07 does not fire and the kernel
    // must park the EC. We retry with a short per-call timeout —
    // the child hammer-wakes, but the worker may take a few attempts
    // to interleave with the parent's enqueue on the futex bucket
    // depending on scheduler ordering. Any single attempt's strict
    // success (vreg 1 = watched_addr) is the spec assertion under
    // test; the bounded retry handles scheduler-ordering jitter
    // without papering over a real bug (E_TIMEOUT every attempt
    // surfaces below as a failure).
    const watched_addr: u64 = @intFromPtr(&watched);
    const target: u64 = 1;
    const pairs = [_]u64{ watched_addr, target };
    const MAX_ATTEMPTS: usize = 16;
    const TIMEOUT_NS: u64 = 50_000_000; // 50 ms per attempt
    const e_timeout = @intFromEnum(errors.Error.E_TIMEOUT);

    var attempt: usize = 0;
    while (attempt < MAX_ATTEMPTS) {
        const result = syscall.futexWaitChange(TIMEOUT_NS, &pairs);

        // r.v1 ≥ 16 = a real user vaddr per §[error_codes]; that's
        // the spec test 08 success path.
        if (result.v1 >= 16) {
            // Assertion 3: the returned addr must equal &watched.
            if (result.v1 != watched_addr) {
                testing.fail(3);
                return;
            }
            testing.pass();
            return;
        }

        // Bounded retry on E_TIMEOUT — the wake/wait race didn't
        // resolve in this slot.
        if (result.v1 != e_timeout) {
            // Any non-timeout error is a hard failure: the spec
            // path under test must surface a vaddr, not E_BADADDR /
            // E_PERM / etc.
            testing.fail(2);
            return;
        }

        attempt += 1;
    }

    // Exhausted retries with E_TIMEOUT every time — the wake never
    // landed on this parked wait, contradicting test 08's invariant.
    testing.fail(2);
}
