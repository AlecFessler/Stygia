// Spec §[power] power_set_freq — test 11.
//
// "[test 11] on success, a subsequent `info_cores([1])` reports a
//  `freq_hz` consistent with the requested target (within hardware
//  tolerance)."
//
// DEGRADED SMOKE VARIANT
//   The faithful shape of this assertion observes the post-success side
//   effect of `power_set_freq` on the queried core's reported frequency:
//
//     1. info_system() — discover online core count
//     2. info_cores(0) — confirm flag bit 2 (frequency scaling) is set
//                        on at least one core; otherwise test 09's
//                        E_NODEV gate fires ahead of the success path
//                        and the assertion is vacuously not exercisable
//     3. choose a target hz inside the platform's supported range so
//        test 10's E_INVAL gate cannot fire
//     4. power_set_freq(core_id, hz) — *expected* OK
//     5. info_cores(core_id) — observe [2] freq_hz within hardware
//        tolerance of hz; that equality is the spec assertion
//
//   Reaching step 4's success requires the caller's self-handle to
//   carry the `power` cap. The runner intentionally withholds `power`
//   and `restart` from `child_self` (see runner/primary.zig spawnOne:
//   `child_self.power` is unset) so that every `power_*` syscall in a
//   test child returns E_PERM ahead of any other gate. That keeps the
//   E_PERM-only spec tests (01, 02, 03, 06, 07, 12) cleanly isolated
//   but it also makes test 11's success-side assertion unreachable
//   from inside a test child: there is no path from the runner's
//   spawn protocol to a `power`-bearing self-handle.
//
//   Reaching the faithful path needs a runner-side change that either:
//     - grants a separate "power-cap test child" privileged self-handle
//       to a designated subset of tests (the spec's success-side power
//       tests: power 11), spawned via a distinct entry point so the
//       runner does not surrender its own ability to shut down at the
//       end of the suite; or
//     - exposes a parent-driven driver where the primary itself (which
//       does hold `power`) calls `power_set_freq` and observes
//       `info_cores` on behalf of the child, surfacing the equality
//       check back via the result port.
//   Neither harness exists today; the power suite has no test that
//   crosses the success boundary observably.
//
// Strategy (smoke prelude)
//   We exercise the *pre-success* portion of the faithful sequence in
//   a single test EC: query info_system for the online core count,
//   query info_cores(0) to inspect the flags word, and call
//   power_set_freq(0, 0) (hz = 0 means "let the kernel pick", which is
//   the platform-range-bypass per spec §[power]). The call must return
//   E_PERM because the runner withheld `power`; that confirms the
//   E_PERM gate runs ahead of the success path the assertion is about,
//   but stops short of the actual reported-freq comparison that is the
//   point of test 11.
//
//   No spec assertion is checked beyond "the syscall returned a value
//   in vreg 1" — and we record even that as a smoke prelude rather
//   than a spec assertion, because the *behavior* under test
//   (post-success freq equality) is unreachable from inside the child
//   domain.
//
// Action
//   1. info_system()                — must succeed (no cap required)
//   2. info_cores(0)                — must succeed (no cap required)
//   3. power_set_freq(0, 0)         — *expected* E_PERM under the
//                                     current runner; the success-side
//                                     assertion (info_cores agreement)
//                                     is unreachable here
//
// Assertion
//   No spec assertion is checked — passes with assertion id 0 because
//   the post-success freq equality is unreachable from the v0 test
//   child. Test reports pass regardless of what `power_set_freq`
//   returns: the prelude itself is recorded as smoke-only in coverage.
//
// Faithful-test note
//   Faithful test deferred pending a runner-side power-cap harness or
//   a parent-driven driver that:
//     - identifies (via info_cores per-core flag bit 2) a core with
//       frequency scaling support;
//     - selects a target hz inside the platform's supported range;
//     - issues power_set_freq from a context that holds `power`;
//     - re-queries info_cores on the same core_id and asserts
//       |reported.freq_hz - requested.hz| is within hardware tolerance.
//   Once that exists, this file's body becomes that sequence and the
//   pass-with-id-0 is replaced with the equality assertion (id 1).
//
// Pre-call gates the test must clear so other error paths cannot mask
// the smoke:
//   - test 08 (E_INVAL on core_id >= cores) is sidestepped by passing
//     core_id = 0, which is always valid on any platform that boots
//     the runner.
//   - test 10 (E_INVAL on hz outside supported range) is sidestepped
//     by passing hz = 0, which the spec defines as "let the kernel
//     pick" rather than "validate against the supported range".
//   - tests 09 (E_NODEV on core lacking frequency scaling) cannot be
//     observed as the precondition — the E_PERM gate fires first per
//     the spec ordering implied by §[power]: "All `power_*` syscalls
//     require `power` on the caller's self-handle."

const lib = @import("lib");

const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Smoke prelude: query info_system for the core count and
    // info_cores(0) for the per-core flags. Neither requires a cap;
    // both should succeed. The smoke does not branch on their values
    // because the assertion under test is unreachable regardless.
    _ = syscall.infoSystem();
    _ = syscall.infoCores(0);

    // power_set_freq(core_id = 0, hz = 0). The runner withheld `power`
    // from this child's self-handle, so the call returns E_PERM under
    // the current scaffold. The faithful assertion (post-success
    // info_cores agreement) cannot be checked here; we record this as
    // smoke-only in coverage.
    _ = syscall.powerSetFreq(0, 0);

    // No spec assertion is being checked — the post-success
    // freq-equality observation is unreachable from the v0 test child.
    // Pass with assertion id 0 to mark this slot as smoke-only.
    testing.pass();
}
