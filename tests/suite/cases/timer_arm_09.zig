// Spec §[timer_arm] — test 09.
//
// "[test 09] on each fire, every EC blocked in futex_wait_val keyed
//  on the paddr of any domain-local copy of [1].field0 returns from
//  the call with [1] = the corresponding domain-local vaddr of
//  field0."
//
// Strategy
//   The runner spawns this test as a single capability domain with
//   `self.timer = true` (runner/primary.zig sets timer in
//   `child_self`) and `fut_wait_max = 63` (bits 32-37 of
//   ceilings_outer = 0x3F). That gives the test EC standing to mint
//   a timer and to call `futex_wait_val` with N=1.
//
//   "every domain-local copy" reduces to "this EC's own copy" inside
//   a single child domain — the runner does not stand up sibling
//   domains holding `xfer`-copied views of this timer. With one copy,
//   the assertion collapses to: the calling EC's `futex_wait_val`
//   keyed on `&cap_table[timer_handle].field0` returns from the call
//   with vreg 1 set to that same address after the timer fires.
//
//   §[capabilities] places `field0` at offset 8 within each handle
//   slot (Cap = { word0: u64, field0: u64, field1: u64 }). The cap
//   table is mapped read-only into the holding domain at
//   `cap_table_base`, and the kernel keys futex waits by the paddr
//   that backs each domain-local vaddr (§[futex] preamble), so the
//   user-visible vaddr `cap_table_base + handle*sizeof(Cap) + 8` is
//   the address the spec test refers to.
//
//   Two return paths satisfy the spec assertion equivalently:
//     - On-entry mismatch (futex_wait_val test 07): if the timer has
//       already fired by the time the kernel checks the value at
//       call entry, `*field0 == 1 != expected (0)` and the call
//       returns immediately with vreg 1 = `&field0`.
//     - Wake (futex_wait_val test 08): if we register before the
//       fire, the kernel's wake on field0's paddr returns the call
//       with vreg 1 = `&field0`.
//
//   Either way the spec assertion under test — vreg 1 == vaddr of
//   field0 — is the value being checked. We give the timer a 10 ms
//   one-shot deadline and use a 1 s timeout on `futex_wait_val` so
//   neither path is starved.
//
//   Reserved bits in the `caps` and `flags` words must be clean
//   (timer_arm test 04). `restart_policy = 0` keeps caps within the
//   runner's `tm_restart_max = 1` ceiling unconditionally
//   (timer_arm test 02 negative path is exercised separately by
//   restart_semantics_08). `deadline_ns` is non-zero (test 03), and
//   `flags = 0` (one-shot) keeps the timer firing exactly once.
//
// Action
//   1. timer_arm(caps={arm,cancel}, deadline_ns=10_000_000, flags=0)
//      — must succeed; carries the timer handle.
//   2. addr = cap_table_base + timer_handle*sizeof(Cap) + 8
//      — vaddr of `field0` for the minted timer in this domain.
//   3. futex_wait_val(timeout_ns=1_000_000_000,
//                     pairs=[(addr, expected=0)])
//      — must return with vreg 1 == addr.
//
// Assertions
//   1: timer_arm returned an error word in vreg 1 (no timer handle
//      to test against; the timer-arm success precondition for
//      test 09 was not met).
//   2: futex_wait_val returned vreg 1 != &field0 — the wake/entry
//      path did not surface the field0 vaddr the spec requires.
//      Includes the E_TIMEOUT case (vreg 1 == 0 unless the kernel
//      conventionally sets it to the addr on timeout — spec only
//      pins the value on the wake/entry-mismatch paths).

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    // §[timer] timer_arm caps word: bits 0-15 caps, 16-63 reserved.
    // {arm, cancel} are useful follow-on caps; restart_policy = 0
    // sidesteps the test 02 ceiling check unconditionally.
    const timer_caps = caps.TimerCap{ .arm = true, .cancel = true };
    const caps_word: u64 = @as(u64, timer_caps.toU16());

    // 10 ms one-shot. Non-zero (timer_arm test 03), well under the
    // 1 s futex timeout chosen below. flags = 0 — periodic clear,
    // reserved bits clean (timer_arm test 04).
    const deadline_ns: u64 = 10_000_000;
    const flags: u64 = 0;

    const armed = syscall.timerArm(caps_word, deadline_ns, flags);
    if (testing.isHandleError(armed.v1)) {
        testing.fail(1);
        return;
    }
    const timer_handle: u12 = @truncate(armed.v1 & 0xFFF);

    // §[capabilities] handle layout: Cap = { word0, field0, field1 },
    // each u64. field0 sits at offset 8 within the handle's 24-byte
    // slot. The cap table is mapped read-only at `cap_table_base`,
    // so the vaddr the kernel keys this domain's futex waiter on is
    // the byte offset arithmetic below.
    const slot_offset: u64 = @as(u64, timer_handle) * @as(u64, caps.HANDLE_BYTES);
    const field0_addr: u64 = cap_table_base + slot_offset + @offsetOf(caps.Cap, "field0");

    // 1 second timeout — long enough to absorb the 10 ms deadline
    // plus scheduling latency, short enough that a regression in
    // the wake path surfaces as E_TIMEOUT rather than a hang.
    const timeout_ns: u64 = 1_000_000_000;
    const pairs = [_]u64{ field0_addr, 0 };
    const r = syscall.futexWaitVal(timeout_ns, pairs[0..]);

    if (r.v1 != field0_addr) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
