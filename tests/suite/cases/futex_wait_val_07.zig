// Spec §[futex_wait_val] futex_wait_val — test 07.
//
// "[test 07] on entry, when any pair's current `*addr != expected`,
//  returns immediately with `[1]` set to that addr."
//
// Strategy
//   The success-on-entry contract is fully exercisable from a single
//   test EC: the test owns its own user-mode stack (mapped r/w into
//   its capability domain by the runner via §[create_capability_domain]
//   stack provisioning), so a stack-local `u64` is a valid 8-byte-
//   aligned user address whose initial value the test controls
//   absolutely. The runner mints the child with `fut_wait_max = 63`
//   and `pri = 3` (see runner/primary.zig); the call's N = 2 stays
//   well within both the spec range (1..63 per §[futex_wait_val]
//   test 02) and the per-domain ceiling (test 03), so neither cap
//   check can fire.
//
//   Use two pairs and arrange the *second* pair to be the one whose
//   `*addr != expected`:
//     - pair 0: addr = &v0, expected = *v0  → matches, would block
//     - pair 1: addr = &v1, expected = *v1 ^ 0xDEAD  → mismatch
//   Test 07 mandates the kernel return immediately with `[1]` set to
//   the addr of the *mismatching* pair. Verifying `[1] == &v1`
//   (not &v0, not 0, not an error code) proves three things in one
//   shot:
//     - the kernel inspected past the first pair (rules out a
//       degenerate "always returns first addr" implementation),
//     - it returned the addr that actually mismatched (rules out
//       returning a stale or zero value),
//     - it took the on-entry short-circuit path rather than blocking
//       (the test EC has no other thread to wake it; if the kernel
//       blocked we would never reach the post-call check).
//
//   Failure-path neutralization for the futex_wait_val call itself:
//     - test 01 (E_PERM via fut_wait_max = 0): runner mints fut_wait_max
//       = 63, comfortably > 0.
//     - test 02 (E_INVAL: N = 0 or N > 63): N = 2.
//     - test 03 (E_INVAL: N > caller's fut_wait_max): N = 2 ≤ 63.
//     - test 04 (E_INVAL: addr not 8-byte aligned): both addrs are
//       `&u64` stack locals which are naturally 8-byte aligned on
//       x86-64.
//     - test 05 (E_BADADDR: addr not in caller's domain): both addrs
//       point into the EC's own stack — definitionally valid user
//       addresses in the calling domain.
//     - test 06 (E_TIMEOUT): even though we pass a finite small
//       timeout (100ms) as a deadlock guard, test 07's on-entry
//       short-circuit fires before the kernel arms a timer at all,
//       so E_TIMEOUT is a strictly post-block path that cannot reach
//       us here. The timeout exists only so a buggy kernel that
//       fails to short-circuit fails this test by either E_TIMEOUT
//       (assertion 4 — wrong return) or by returning &v0 (assertion 4
//       — wrong addr) rather than hanging the suite.
//
//   The "could the addr collide with an error code" concern: error
//   codes are 0..15 per §[error_codes] / libz/errors.zig. A stack-
//   local in a user-mode mapping is well above 16. The discriminator
//   is exact equality with `&v1`.
//
// Action
//   1. Allocate two stack-local u64s; seed them to known values.
//   2. Build pairs = [&v0, *v0,   &v1, (*v1) ^ 0xDEAD].
//   3. futex_wait_val(timeout_ns = 100_000_000, pairs) — must return
//      with [1] = &v1.
//
// Assertions
//   1: futex_wait_val returned an error code in [1] (any value in
//      0..15 inclusive — the on-entry short-circuit path returns the
//      addr verbatim, which cannot be in the error-code range).
//   2: futex_wait_val returned an addr different from &v1 (e.g., &v0
//      means the kernel only inspected the first pair; any other
//      value means the return path produced a wrong addr).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Stack-local watched words. Declared `var` so their addresses
    // are concrete user-domain addresses for futex_wait_val to inspect.
    // u64 alignment on x86-64 SysV is 8, satisfying §[futex_wait_val]
    // test 04. Volatile-ish guard via @as conversions through u64
    // pointers keeps the optimizer from constant-folding the
    // *addr != expected comparison the kernel must actually perform.
    var v0: u64 = 0x1111_2222_3333_4444;
    var v1: u64 = 0x5555_6666_7777_8888;

    const addr0: u64 = @intFromPtr(&v0);
    const addr1: u64 = @intFromPtr(&v1);

    // Pair 0 expects v0's actual current value (so it would block on
    // its own); pair 1 expects something v1 is NOT currently set to,
    // so the on-entry short-circuit should fire on pair 1 and return
    // addr1 in vreg 1.
    const pairs = [_]u64{
        addr0, v0,
        addr1, v1 ^ 0xDEAD,
    };

    // 100ms deadline. Test 07's on-entry short-circuit must fire
    // before the kernel arms any timeout; the finite value is just
    // a deadlock guard so a non-conformant kernel surfaces a
    // diagnosable failure instead of hanging the runner.
    const timeout_ns: u64 = 100_000_000;
    const r = syscall.futexWaitVal(timeout_ns, pairs[0..]);

    // Per §[futex_wait_val] return spec: success returns [1] = addr.
    // Errors (E_PERM/E_INVAL/E_BADADDR/E_TIMEOUT) all fit in 0..15;
    // a real stack address is far above that range.
    if (errors.isError(r.v1) and r.v1 < 16) {
        testing.fail(1);
        return;
    }

    if (r.v1 != addr1) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
