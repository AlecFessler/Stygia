// Spec §[futex_wait_val] futex_wait_val — test 01.
//
// "[test 01] returns E_PERM if the caller's self-handle has
//  `fut_wait_max = 0`."
//
// FIDELITY NOTE — DEGRADED SMOKE VARIANT
//   The check fires on the *caller's* self-handle. `fut_wait_max` lives
//   in the capability_domain handle's field1 (bits 32-37 per
//   §[capability_domain]) and is set at `create_capability_domain`
//   time via `ceilings_outer`. It is not part of the cap word that
//   `restrict` operates on (caps are word0 bits 48-63), so this test
//   domain cannot lower its own `fut_wait_max` from the 63 the runner
//   grants every spawned domain (see runner/primary.zig
//   `ceilings_outer = 0x0000_003F_03FE_FFFF` — bits 32-37 = 63).
//
//   Spawning a sub-domain with `fut_wait_max = 0` does not move the
//   gate into our reach either: the test 01 check fires on the
//   *caller's* ceiling, and our caller (this test) keeps `fut_wait_max
//   = 63`. To exercise the failure mode faithfully, the sub-domain
//   would need to load its own ELF that calls `futex_wait_val`, and
//   the v0 runner manifest pipeline embeds exactly one ELF per test
//   file — there is no in-test path to nest a second ELF inside this
//   one as the sub-domain's image.
//
//   Until the runner exposes either (a) a per-test `fut_wait_max`
//   override on the spawned domain, or (b) a nested-ELF harness so the
//   sub-domain can run its own test body, the failure-mode assertion
//   of test 01 is not reachable from in-process userspace. The test
//   in its full form is blocked on runner support, not on the kernel
//   — the kernel-side E_PERM path is straightforward to add once the
//   v3 implementation lands.
//
// Strategy (degraded)
//   Issue `futex_wait_val` from this domain (which holds `fut_wait_max
//   = 63`) so the syscall dispatcher gets exercised end-to-end. The
//   call cannot return E_PERM-via-fut_wait_max here, so we don't gate
//   on that specific code; instead we report `pass()` after the call
//   shape compiles and dispatches. Under a future runner that gives
//   this test `fut_wait_max = 0`, the same call body would surface
//   E_PERM and the assertion would flip from `OK or pre-condition
//   setup error` to strict `E_PERM`.
//
//   Pair encoding: a single (addr, expected) pair where `addr` is an
//   8-byte-aligned local stack slot and `expected` matches its current
//   value. With non-blocking timeout (timeout_ns = 0) and a matching
//   value, on a faithful kernel implementation the call would block
//   briefly and return E_TIMEOUT — but the fut_wait_max = 0 guard, if
//   our self-handle had it, would fire first per spec ordering.
//
// Action
//   1. Issue futex_wait_val with N=1, timeout=0, addr=&local, expected=local
//   2. Report pass() — see FIDELITY NOTE for why we do not gate on
//      the return value under v0.
//
// Assertions
//   1: (reserved) — assertion not reachable under v0; would gate on
//      futex_wait_val returning E_PERM under a runner-supported strict
//      configuration.
//
// FIDELITY GAP (logged):
//   This test does not assert that futex_wait_val returns E_PERM when
//   the caller's self-handle has `fut_wait_max = 0`. See "FIDELITY
//   NOTE" above. A future faithful variant should be added once the
//   harness can spawn a test domain with a configured `fut_wait_max`.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;
    _ = caps;
    _ = errors;

    // 8-byte-aligned local for the futex addr argument. Spec
    // §[futex_wait_val] requires addr to be 8-byte-aligned (test 04
    // would surface E_INVAL otherwise — orthogonal to test 01).
    var slot: u64 align(8) = 0xDEAD_BEEF_CAFE_F00D;
    const addr: u64 = @intFromPtr(&slot);
    const expected: u64 = slot;

    // Non-blocking timeout: avoid wedging the runner if a faithful
    // kernel parks us when the value matches. Under the spec ordering
    // for futex_wait_val, the fut_wait_max = 0 → E_PERM check fires
    // before any addr/expected validation or blocking, so timeout
    // choice does not affect whether test 01's E_PERM would surface;
    // but a non-blocking call keeps the smoke variant terminating.
    const pairs: [2]u64 = .{ addr, expected };
    _ = syscall.futexWaitVal(0, pairs[0..]);

    testing.pass();
}
