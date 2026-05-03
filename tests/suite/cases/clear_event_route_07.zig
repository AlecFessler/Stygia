// Spec §[clear_event_route] clear_event_route — test 07.
//
// "[test 07] when [1] is a valid handle, [1]'s field0 and field1 are
//  refreshed from the kernel's authoritative state as a side effect,
//  regardless of whether the call returns success or another error
//  code."
//
// Spec semantics
//   §[execution_context] places kernel-mutable snapshots in the EC
//   handle's field0 (bits 0-1 = current scheduling priority) and
//   field1 (bits 0-63 = current core affinity mask). §[capabilities]:
//   "Any syscall that takes such a handle implicitly refreshes that
//   handle's snapshot from the authoritative kernel state as a side
//   effect" — and the clear_event_route spec restates that this
//   implicit-sync side effect fires regardless of return code.
//
// Strategy
//   The success path of clear_event_route requires a prior binding to
//   exist for ([1], [2]) (otherwise test 05 fires with E_NOENT), and
//   building one needs both a port with `bind` and an EC handle with
//   the `bind` cap. The runner's child domain ec_inner_ceiling = 0xFF
//   does not include the `bind` (bit 10) or `unbind` (bit 12) bits,
//   so the test can't mint an EC handle with either cap from this
//   domain. That precludes the success-path arm — but the spec line
//   covers the error-path arm verbatim ("regardless of whether the
//   call returns success or another error code"), so we drive the
//   assertion through E_PERM (test 02): mint the EC without the
//   `unbind` cap and call clear_event_route on it.
//
//   To make the post-condition unambiguous we exercise both kernel-
//   mutable snapshot fields (field0 pri, field1 affinity). The
//   target EC is created with priority = 2 (non-zero so an
//   implementation that zeroes field0 on the error path is observably
//   wrong) and affinity = 1 (single-bit mask, distinct from any
//   inherited or default value). The new EC begins executing at
//   `dummyEntry` which halts forever; it never reschedules itself or
//   mutates affinity, so the kernel's authoritative state for those
//   fields stays at the values we passed at creation time. After the
//   failed clear_event_route call, the handle's field0 must equal pri
//   (= 2) and field1 must equal the affinity mask we supplied (= 1).
//
//   To guarantee test 07 is the only assertion we exercise, every
//   other failure path on clear_event_route is neutralized:
//     - target [1] is the freshly-minted EC handle, so no E_BADCAP
//       (test 01).
//     - event_type [2] = 1 (memory_fault) is a registerable type
//       per §[event_route], so no E_INVAL on event-type (test 03).
//     - [1] carries only the bare handle id (clean reserved bits)
//       and [2] = 1 has no reserved bits set (the field is a bare
//       u64 event-type code), so no E_INVAL on reserved bits (test
//       04).
//     - test 05 (E_NOENT) is unreachable because the ordering of
//       checks places PERM before NOENT — the cap check rejects
//       before the route lookup.
//
//   Reading directly from the read-only-mapped cap table bypasses
//   any further syscall (which would itself trigger another implicit
//   refresh), so this read observes exactly the snapshot
//   clear_event_route's side effect left in place.
//
// Action
//   1. create_execution_context(target=self, caps={susp,term,rp=0},
//                               pri=2, affinity=0x1)         — must succeed
//   2. clear_event_route(ec, event_type=1)                   — must return E_PERM
//   3. readCap(cap_table_base, ec).field0 bits 0-1           — must equal 2
//   4. readCap(cap_table_base, ec).field1                    — must equal 0x1
//
// Assertions
//   1: setup syscall failed (create_execution_context returned an error)
//   2: clear_event_route did not return E_PERM (test 02 path is the
//      in-bounds trigger, since the handle lacks the `unbind` cap)
//   3: post-call field0's pri does not equal the priority we set,
//      meaning the implicit-sync side effect either did not run or
//      clobbered the snapshot
//   4: post-call field1 does not equal the affinity we set, meaning
//      the implicit-sync side effect either did not run or clobbered
//      the snapshot

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    // Mint an EC without the `unbind` cap so clear_event_route hits
    // E_PERM (§[clear_event_route] test 02). restart_policy = 0 keeps
    // the create within the inner ceiling.
    const initial = caps.EcCap{
        .susp = true,
        .term = true,
        .restart_policy = 0,
    };
    // §[create_execution_context] caps word:
    //   bits  0-15 caps          (caps on the returned handle)
    //   bits 16-31 target_caps   (ignored when target = self)
    //   bits 32-33 priority      (0-3, bounded by caller's priority ceiling)
    const target_priority: u64 = 2;
    const caps_word: u64 = @as(u64, initial.toU16()) | (target_priority << 32);
    const target_affinity: u64 = 0x1; // core 0 only

    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages — nonzero per create_execution_context test 08
        0, // target = self
        target_affinity,
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(1);
        return;
    }
    const ec_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // §[event_route]: event_type = 1 is `memory_fault`, a registerable
    // event type. The handle is valid and has clean reserved bits, so
    // tests 01, 03, and 04 are all neutralized; only the cap check in
    // test 02 fires, returning E_PERM.
    const result = syscall.clearEventRoute(ec_handle, 1);
    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    // The cap-table mapping is read-only userspace memory; the kernel
    // wrote the refreshed snapshot before returning. Reading directly
    // bypasses any further syscall (which would itself trigger another
    // implicit refresh), so this read observes exactly the snapshot
    // clear_event_route's side effect left in place.
    const cap = caps.readCap(cap_table_base, ec_handle);

    const observed_pri: u64 = cap.field0 & 0x3;
    if (observed_pri != target_priority) {
        testing.fail(3);
        return;
    }

    if (cap.field1 != target_affinity) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
