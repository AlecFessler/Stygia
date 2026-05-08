// Spec §[futex_wake] — test 04.
//
// "[test 04] on success, [1] is the number of ECs actually woken
//  (0..count)."
//
// Spec semantics
//   §[futex_wake]: "Wakes up to `count` ECs blocked in `futex_wait_val`
//   or `futex_wait_change` on the given address." The success
//   post-condition asserts that vreg [1] reports the exact number of
//   ECs actually woken, capped by the `count` argument and bounded
//   below by 0 when no ECs are parked on the address.
//
// Strategy
//   We exercise both endpoints of the spec's `0..count` range:
//
//   Leg A — empty-queue endpoint (woken == 0). `futex_wake(addr,
//   count=1)` against an address with no parked EC must return OK
//   with vreg 1 = 0. Catches a kernel that returns a non-zero count,
//   an error word, or any non-zero value when the wake had nothing
//   to drain.
//
//   Leg B — non-empty endpoint (woken == 1, capped by parked count).
//   Spawn a sibling EC that calls `futex_wait_val` on a shared
//   address with a long enough timeout to cover the wake handshake
//   below. Once the sibling is parked, primary issues
//   `futex_wake(addr, count=8)`. With exactly one sibling parked,
//   the spec mandates vreg 1 = 1 (woken count, capped below `count`
//   by the actual parked-EC count). Catches a kernel that returns
//   the `count` argument verbatim instead of the actual woken size,
//   or that fails to filter the wake set down to the parked
//   set's intersection with the addr's bucket.
//
//   Wake/park handshake: primary loops `futex_wake(addr_b, 8)` —
//   wakes against an empty queue return 0 (Leg A's invariant), so
//   spinning is safe and synchronisation-free. The first wake to
//   land on a sibling that has actually parked returns 1; primary
//   asserts on that value and exits. A bounded loop (MAX_WAKE_TRIES)
//   bounds the test wall time on a kernel that fails to park the
//   sibling at all.
//
//   Choice of addr_a: `cap_table_base` — page-aligned, valid in the
//   caller's domain, so test 02 / 03 cannot fire on Leg A.
//   Choice of addr_b: `&shared` — process-global u64 in .bss; the
//   sibling is spawned with `target = 0` so the same vaddr is valid
//   in both ECs' (shared) domain, satisfying test 02 / 03 for Leg B.
//
//   Self-handle: the runner mints children with `fut_wake = true`
//   and `fut_wait_max = 63` (runner/primary.zig), so test 01
//   (E_PERM) cannot fire on either leg, and test 02 (E_INVAL) of
//   futex_wait_val cannot fire on the sibling.
//
// Action
//   1. futex_wake(addr_a = cap_table_base, count = 1)
//      — must return OK with [1] = 0.
//   2. create_execution_context(target = 0, entry = &siblingEntry,
//                               stack_pages = 1, affinity = 0)
//      — must succeed; sibling parks in futex_wait_val on &shared.
//   3. up to MAX_WAKE_TRIES times:
//        futex_wake(addr_b = &shared, count = 8)
//      — first non-zero return must equal 1 (only one sibling
//      parked), bounded by `count` from above.
//
// Assertions
//   1: leg A — futex_wake returned non-OK on the empty-queue wake.
//   2: leg A — futex_wake returned a non-zero woken count even
//      though no EC was parked on the address.
//   3: create_execution_context returned an error, OR the sibling
//      never started executing (no spawn = no parked sibling = leg
//      B unreachable).
//   5: leg B — every wake attempt returned 0; the sibling never
//      parked (or wakes never reach parked waiters), so the spec
//      line under test was not exercised.
//   6: leg B — wake's woken count was in [2, count] when only one
//      sibling was parked; kernel reported a wake that did not
//      correspond to a parked EC.
//   7: leg B — wake's woken count was > count; kernel returned a
//      value outside the spec's 0..count range (e.g. an unhandled
//      error code or the count arg verbatim past the cap).

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Process-global shared between primary and sibling — both run in the
// same capability domain (target = 0), so &shared has the same vaddr
// in both. .bss u64 alignment satisfies the 8-byte requirement.
var shared: u64 = 0;
var sibling_alive: u64 = 0;

fn siblingEntry() callconv(.c) noreturn {
    // Mark that the sibling is actually executing — primary uses
    // this to gate the wake loop on a confirmed-running sibling.
    @atomicStore(u64, &sibling_alive, 1, .release);
    // Park in futex_wait_val on &shared with a long timeout. The
    // primary's wake leg is the only thing that wakes us; if it
    // never fires, the timeout bounds our wall time. *shared == 0
    // == expected, so the entry-time fast path of test 07 does not
    // fire and we actually park.
    const addr: u64 = @intFromPtr(&shared);
    const expected: u64 = 0;
    const pairs = [_]u64{ addr, expected };
    const TIMEOUT_NS: u64 = 5_000_000_000; // 5 s
    while (true) {
        _ = syscall.futexWaitVal(TIMEOUT_NS, pairs[0..]);
    }
}

pub fn main(cap_table_base: u64) void {
    // Pre-fault the page holding `shared` and `sibling_alive` from
    // the test EC so the kernel's syscall-time vaddr→paddr walk
    // (resolveCallerVa) doesn't surface E_BADADDR on a demand-
    // paged .bss page. Both a read and a (no-op) write to the
    // page guarantee the page is mapped before either EC issues
    // a futex syscall against it.
    @atomicStore(u64, &shared, 0, .release);
    _ = @atomicLoad(u64, &sibling_alive, .acquire);

    // ── Leg A: empty-queue endpoint ──────────────────────────────────
    {
        const addr: u64 = cap_table_base;
        const result = syscall.futexWake(addr, 1);
        if (errors.isError(result.v1)) {
            testing.fail(1);
            return;
        }
        if (result.v1 != 0) {
            testing.fail(2);
            return;
        }
    }

    // ── Leg B: non-empty endpoint ────────────────────────────────────
    // Spawn the sibling. caps = 0 (no per-handle caps needed — fut_wake
    // / fut_wait_max live on the shared self-handle). target = 0 keeps
    // the sibling in this address space so &shared is valid for both.
    const ec_caps = caps.EcCap{ .restart_policy = 0 };
    const caps_word: u64 = @as(u64, ec_caps.toU16());
    const entry: u64 = @intFromPtr(&siblingEntry);
    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages
        0, // target = self
        0, // affinity = any core
    );
    // The kernel returns either an E_* code (1..15) or a packed
    // Word0 carrying the freshly-installed handle's slot id.
    if (testing.isHandleError(cec.v1)) {
        testing.fail(3);
        return;
    }
    const sibling_handle: u12 = @truncate(cec.v1 & 0xFFF);
    const sibling_target: u64 = @as(u64, sibling_handle);

    // Direct-yield to the sibling repeatedly until it has both
    // started AND parked in futex_wait_val. On smp=4 with primary
    // already running, primary can otherwise saturate the wake-
    // syscall path before the sibling has been picked up by any
    // core's scheduler.
    //
    // We wait for `sibling_alive == 1`, which the sibling's first
    // instruction sets before it calls futex_wait_val. yieldEc
    // (target = sibling) is the §[yield] test 03 pattern that
    // forces the kernel to run the sibling.
    var alive_spin: usize = 0;
    while (@atomicLoad(u64, &sibling_alive, .acquire) == 0) {
        const yr = syscall.yieldEc(sibling_target);
        if (yr.v1 != @intFromEnum(errors.Error.OK)) {
            // yield itself errored — handle slot is wrong, or the
            // EC was destroyed before we could yield to it. Either
            // way leg B is unreachable.
            testing.fail(3);
            return;
        }
        alive_spin += 1;
        if (alive_spin > 1_000_000) {
            // Sibling never started — kernel scheduler bug or the
            // sibling's _start crashed. Either way leg B can't run.
            testing.fail(3);
            return;
        }
    }

    const addr_b: u64 = @intFromPtr(&shared);
    // count = 8 lets us catch a kernel that returns the `count` arg
    // verbatim — the actual parked-EC count is 1, so the spec
    // mandates vreg 1 = 1 here, not 8.
    const wake_count: u64 = 8;
    // Bounded spin: each iteration tries one wake. Wakes on an
    // empty queue return 0 (Leg A's invariant); the first wake to
    // land on a parked sibling returns 1. Yield between attempts
    // so the sibling EC actually gets scheduler time on its core
    // to enter futex_wait_val and park; without the yield primary
    // can saturate one core's runqueue ordering on smp=4 long
    // enough to flake the handshake.
    const MAX_WAKE_TRIES: usize = 4096;
    var tries: usize = 0;
    while (tries < MAX_WAKE_TRIES) : (tries += 1) {
        const r = syscall.futexWake(addr_b, wake_count);
        // Spec §[futex_wake]: vreg 1 = woken count (0..count) on
        // success, OR an E_* code in 1..15 on failure. The two
        // ranges overlap (1..min(count, 15)); to disambiguate the
        // test reaches success only via r.v1 == 1 (the actual
        // parked-EC count for this addr) and fails the only
        // codes that the spec lists as possible failures
        // (E_PERM = 12 from missing fut_wake, E_INVAL = 7 from
        // misaligned addr, E_BADADDR = 2 from unmapped addr) —
        // none of which can fire from a configuration we
        // already validated on Leg A above.
        if (r.v1 == 0) {
            // No wake yet — sibling not parked, or wake fired
            // before park. Yield and retry.
            _ = syscall.yieldEc(sibling_target);
            continue;
        }
        if (r.v1 == 1) {
            // Spec line under test confirmed: 1 sibling parked
            // and count = 8 → kernel returned woken = 1, capped
            // by the parked-EC count (not by count = 8).
            testing.pass();
            return;
        }
        if (r.v1 <= wake_count) {
            // 2..wake_count: kernel reported more wakes than
            // there were parked ECs. Spec violation.
            testing.fail(6);
            return;
        }
        // r.v1 > wake_count: a value outside the spec's 0..count
        // range. Either kernel returned the count arg verbatim
        // past the cap, or a non-spec'd error word.
        testing.fail(7);
        return;
    }

    // Exhausted retries with woken == 0 every iteration — the
    // sibling never parked on &shared, so the non-empty endpoint of
    // the spec's `0..count` range was not exercised.
    testing.fail(5);
}
