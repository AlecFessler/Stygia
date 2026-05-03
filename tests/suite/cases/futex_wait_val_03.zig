// Spec §[futex_wait_val] futex_wait_val — test 03.
//
// "[test 03] returns E_INVAL if N exceeds the caller's self-handle
//  `fut_wait_max`."
//
// Strategy
//   `fut_wait_max` lives in the self-handle's field1 bits 32-37 — a
//   6-bit field whose maximum representable value is 63. The runner
//   primary mints each test domain with `fut_wait_max = 63` (see
//   runner/primary.zig: ceilings_outer = 0x0000_003F_03FE_FFFF). The
//   futex_wait_val syscall encodes N in syscall-word bits 12-19 with
//   spec-mandated range 1..63, and §[futex_wait_val] test 02 catches
//   N = 0 or N > 63 with E_INVAL before the fut_wait_max check runs.
//
//   The strict-exceedance side this test names — N within 1..63 yet
//   greater than the caller's fut_wait_max — is therefore unreachable
//   from inside this test domain: the ceiling already saturates the
//   field width. The same constraint blocks create_capability_domain
//   test 08 (see tests/create_capability_domain_08.zig), which lives
//   in the manifest as a degraded smoke test for the same reason.
//
// Degraded smoke variant (gap documented):
//   1. Read the caller's `fut_wait_max` from slot-0 field1 bits 32-37.
//   2. Issue futex_wait_val with N = caller_fut_wait_max (the equality
//      / subset side of the ceiling rule, which the spec permits) and
//      with addresses crafted so the call cannot succeed but does not
//      hit the test 02 (N range), test 04 (alignment), or test 03
//      (fut_wait_max ceiling) failure modes.
//   3. Assert the returned vreg-1 error code is NOT E_INVAL. The
//      ceiling check must pass at equality; any subsequent error
//      (E_BADADDR from the unmapped addresses below, E_PERM from a
//      missing fut_wake on a paired wake we never issue, etc.) is
//      acceptable for this degraded variant only insofar as it isn't
//      the fut_wait_max E_INVAL the spec is interested in.
//
//   We use the unmapped null page as the watched addresses (8-byte
//   aligned to dodge test 04). On the v0 kernel the futex path will
//   surface E_BADADDR (test 05) before any fut_wait_max check could
//   contradict the equality side; on a working kernel that orders
//   fut_wait_max ahead of address validation the call would also pass
//   the ceiling check at equality. Both branches satisfy our NOT
//   E_INVAL assertion provided the implementation does not falsely
//   raise the ceiling test.
//
// GAP: this variant exercises the equality / subset side of the
//   ceiling rule rather than the strict-exceedance side the spec test
//   names. Reaching the strict-exceedance side requires either (a) a
//   parent runner that mints children with `fut_wait_max < 63`, or (b)
//   widening the field. Until either happens, this file lives in the
//   manifest as a smoke test.
//
// Action
//   1. Read caller fut_wait_max via caps.readCap(cap_table_base, 0).
//   2. Build a pairs array sized to N = min(fut_wait_max, 6). The
//      cap of 6 keeps the syscall on the register-only path
//      (timeout in v1 plus 6 pairs in v2..v13 = 13 vregs); libz's
//      stack-arg path is not yet implemented, so probing N up to 63
//      would panic in libz before reaching the kernel. N <= 6 still
//      lands on the "N <= caller_fut_wait_max" side of the ceiling
//      check, which is the side this degraded smoke test asserts.
//   3. Issue futex_wait_val(timeout = 0, pairs).
//
// Assertions
//   1: caller fut_wait_max read as 0; the spec's test-01 path
//      (fut_wait_max = 0 → E_PERM) would have applied instead and
//      this degraded variant cannot probe the ceiling.
//   2: returned error code equals E_INVAL (the v0 kernel raised the
//      ceiling check at or below the caller's fut_wait_max,
//      contrary to the spec).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    // §[capability_domain] self-handle field1 layout. fut_wait_max is
    // at bits 32-37 (a 6-bit field). Snapshot directly from the
    // cap-table slot — `sync` is unnecessary here because the field is
    // installed at create-time and is not kernel-mutated thereafter.
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    const caller_fut_wait_max: u64 = (self_cap.field1 >> 32) & 0x3F;
    if (caller_fut_wait_max == 0) {
        testing.fail(1);
        return;
    }

    // Build a pairs array sized to N = min(fut_wait_max, 6). Each
    // pair is { addr, expected } where addr is 8-byte aligned (so the
    // alignment check from test 04 cannot fire) and expected = 0. The
    // addresses point at the unmapped null page; the spec's test-05
    // path (E_BADADDR for non-mapped user addresses) is the natural
    // outcome on a kernel that orders ceiling ahead of address
    // validation, while a kernel that mistakenly raises ceiling at or
    // below caller_fut_wait_max would surface E_INVAL — which is
    // exactly what this degraded smoke test is here to flag.
    //
    // N is capped at 6 because libz's stack-vreg path is not yet wired
    // (issueStack panics for >16 stack vregs). With N <= 6, timeout in
    // v1 plus 2*N = 12 pair vregs stay within v2..v13 — the register-
    // only path. N <= caller_fut_wait_max still satisfies the spec
    // contract this degraded smoke test asserts.
    const REG_PAIR_CAP: u64 = 6;
    const n_pairs: u64 = if (caller_fut_wait_max < REG_PAIR_CAP) caller_fut_wait_max else REG_PAIR_CAP;
    var pairs_buf: [12]u64 = undefined; // 2 * REG_PAIR_CAP
    var i: usize = 0;
    while (i < n_pairs) {
        pairs_buf[2 * i] = (i + 1) * 8; // 8, 16, 24, ... — all 8-aligned, all in null page
        pairs_buf[2 * i + 1] = 0;
        i += 1;
    }
    const pairs = pairs_buf[0 .. 2 * n_pairs];

    const result = syscall.futexWaitVal(0, pairs);

    if (result.v1 == @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
