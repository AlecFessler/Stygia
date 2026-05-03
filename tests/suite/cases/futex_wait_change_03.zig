// Spec §[futex_wait_change] futex_wait_change — test 03.
//
// "[test 03] returns E_INVAL if N exceeds the caller's self-handle
//  `fut_wait_max`."
//
// Strategy
//   `fut_wait_max` lives in the caller's self-handle field1 at bits
//   32-37 (§[capability_domain] Self handle). The field is 6 bits wide,
//   so its maximum representable value is 63 — which is also the
//   syscall-word maximum for N (§[futex_wait_change]: bits 12-19, range
//   1..63 per test 02). The runner primary mints each test domain with
//   `fut_wait_max = 63` (see runner/primary.zig: ceilings_outer =
//   0x0000_003F_03FE_FFFF), saturating the field.
//
//   Constructing an N that *exceeds* the caller's `fut_wait_max` while
//   still being a "valid" N (1..63) is therefore unconstructible from
//   inside this test domain: any N ≤ 63 stays within the ceiling, and
//   any N > 63 trips the test-02 width check before the test-03 ceiling
//   check. Same shape as create_capability_domain_08, where the
//   degraded variant exercises the equality / subset side of the rule
//   rather than the strict-exceedance side.
//
//   GAP: reaching the strict-exceedance side requires either (a) the
//   runner minting this child with `fut_wait_max < 63`, or (b) widening
//   the `fut_wait_max` field. Until either lands, this file pins the
//   inverse boundary as a smoke.
//
//   Degraded smoke:
//     1. Read the caller's `fut_wait_max` from slot-0 field1 bits 32-37.
//     2. Assert it equals 63 (boundary saturation — strict exceedance
//        unreachable from inside).
//     3. Issue futex_wait_change with N = 1 (≤ fut_wait_max) and a valid
//        8-byte-aligned in-domain addr whose current value differs from
//        target, with timeout_ns = 0 (non-blocking). Assert the result
//        is NOT E_INVAL — confirming that the test-02 (N width) and
//        test-03 (ceiling) checks both pass for an N within the
//        ceiling. The expected return for this shape is E_TIMEOUT
//        (test 06), but this file only pins NOT E_INVAL; tests 06/07
//        own the E_TIMEOUT vs immediate-return discrimination.
//
// Action
//   1. caps.readCap(cap_table_base, SLOT_SELF) — pull the self-handle.
//   2. Extract field1 bits 32-37; assert == 63.
//   3. Allocate a u64 on the stack; pick a target value distinct from
//      its current contents.
//   4. syscall.futexWaitChange(0, &.{ addr, target }).
//   5. Assert v1 != E_INVAL.
//
// Assertions
//   1: slot 0 is not a capability_domain_self handle (sanity — the
//      kernel placed something other than the self-handle here).
//   2: caller's `fut_wait_max` is not 63 (runner invariant violated;
//      test scenario is no longer the intended boundary case).
//   3: futex_wait_change with N ≤ fut_wait_max returned E_INVAL,
//      meaning either the test-02 width check or the test-03 ceiling
//      check spuriously fired.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const self = caps.readCap(cap_table_base, caps.SLOT_SELF);
    if (self.handleType() != .capability_domain_self) {
        testing.fail(1);
        return;
    }

    // §[capability_domain] Self handle: ceilings_outer (field1) bits
    // 32-37 carry `fut_wait_max`. The field is install-time and not
    // kernel-mutated thereafter, so a direct snapshot is authoritative
    // without `sync`.
    const fut_wait_max: u64 = (self.field1 >> 32) & 0x3F;
    if (fut_wait_max != 63) {
        testing.fail(2);
        return;
    }

    // 8-byte-aligned in-domain address. Local var on the stack is part
    // of the caller's domain by construction. Pick a target value
    // distinct from the current contents so the entry-time
    // `*addr == target` short-circuit (test 07) does not fire — the
    // call should fall through to the timeout path (test 06) with
    // timeout_ns = 0 acting as non-blocking. Either way, the assertion
    // here only requires the result to be NOT E_INVAL.
    var slot: u64 align(8) = 0;
    const addr: u64 = @intFromPtr(&slot);
    const target: u64 = 0xDEAD_BEEF_CAFE_BABE;

    const result = syscall.futexWaitChange(0, &.{ addr, target });
    if (result.v1 == @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
