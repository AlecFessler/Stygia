// Spec §[bind_event_route] bind_event_route — test 10.
//
// "[test 10] when [1] is a valid handle, [1]'s field0 and field1 are
//  refreshed from the kernel's authoritative state as a side effect,
//  regardless of whether the call returns success or another error
//  code."
//
// Strategy
//   §[execution_context] field layout:
//     field0 bits 0-1   = pri (current scheduling priority)
//     field1 bits 0-63  = affinity (current core mask)
//   Both are kernel-mutable snapshots; the implicit-sync side effect
//   on any syscall taking the handle is what this test validates.
//
//   The success path of `bind_event_route` requires `bind` (or
//   `rebind`) on the target EC handle. Per §[execution_context], those
//   caps live at bits 10-12 of the EC cap field. The runner mints test
//   domains with `ec_inner_ceiling = 0xFF` (low byte only — see
//   `runner/primary.zig` `ceilings_inner`), so any EC handle a child
//   can mint via `create_execution_context(target=self, ...)` is
//   restricted to caps that fit in bits 0-7. `bind`/`rebind`/`unbind`
//   are structurally unreachable for child-minted EC handles in the
//   current runner — meaning the success path is unreachable from
//   here. The spec line under test explicitly covers the error case
//   ("regardless of whether the call returns success or another error
//   code"), so we drive the refresh side effect through a well-defined
//   error path instead.
//
//   E_PERM via §[bind_event_route] test 06 is the cleanest such path:
//     - test 01 (E_BADCAP on [1]):  closed by minting a fresh EC.
//     - test 02 (E_BADCAP on [3]):  closed by minting a fresh port.
//     - test 03 (E_INVAL on event_type): closed by passing 1, which is
//       in the registerable set {1, 2, 3, 6}.
//     - test 04 (E_INVAL reserved bits): closed by libz wrappers
//       narrowing handles to u12; event_type is set to a small literal.
//     - test 05 (E_PERM on port lacking `bind`): closed by minting the
//       port with `bind = true`.
//     - test 06 (E_PERM on EC lacking `bind` when no prior route):
//       this is the path we drive. The fresh EC handle has no `bind`,
//       no `rebind`, and no prior route exists, so the call must
//       return E_PERM.
//
//   With a known-priority, known-affinity EC that begins executing at
//   `dummyEntry` (halts forever, never mutates its own pri/affinity),
//   the kernel's authoritative state for those fields stays at the
//   values we passed at creation time. After the failed
//   `bind_event_route` call, the handle's field0 must equal pri and
//   field1 must equal the affinity mask we supplied. Reading directly
//   from the read-only cap-table mapping (no intervening syscall)
//   observes exactly the snapshot the side effect left in place.
//
// Action
//   1. create_port(caps={bind})                              — must succeed
//   2. create_execution_context(target=self, caps={susp,rp=0},
//                               pri=2, affinity=0x1)         — must succeed
//   3. bind_event_route(ec, event_type=1, port)              — must return E_PERM
//   4. readCap(cap_table_base, ec).field0 bits 0-1           — must equal 2
//   5. readCap(cap_table_base, ec).field1                    — must equal 0x1
//
// Assertions
//   1: create_port returned an error word (setup failed)
//   2: create_execution_context returned an error word (setup failed)
//   3: bind_event_route did not return E_PERM (test 06 path is the
//      in-bounds trigger)
//   4: post-call field0's pri does not equal the priority we set
//   5: post-call field1 does not equal the affinity we set

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    // Mint a port with `bind` cap so §[bind_event_route] test 05
    // (E_PERM on port lacking `bind`) does not fire.
    const port_initial = caps.PortCap{ .bind = true };
    const cp = syscall.createPort(@as(u64, port_initial.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Mint a fresh EC without `bind`/`rebind`/`unbind`. Those bits
    // (10-12) are above the runner's child ec_inner_ceiling = 0xFF
    // anyway, so they cannot be granted on this path. The EC carries
    // `susp` only for shape parity with sibling field-refresh tests.
    // restart_policy = 0 keeps the create within the inner ceiling.
    const ec_initial = caps.EcCap{
        .susp = true,
        .restart_policy = 0,
    };
    // §[create_execution_context] caps word:
    //   bits  0-15 caps          (caps on the returned handle)
    //   bits 16-31 target_caps   (ignored when target = self)
    //   bits 32-33 priority      (0-3, bounded by caller's priority ceiling)
    const target_priority: u64 = 2;
    const caps_word: u64 = @as(u64, ec_initial.toU16()) | (target_priority << 32);
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
        testing.fail(2);
        return;
    }
    const ec_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // event_type = 1 is in the registerable set {1, 2, 3, 6} per
    // §[bind_event_route] test 03, so the E_INVAL branch does not
    // fire. With no prior route for ([1], [2]) and the EC lacking
    // `bind`, test 06 is the active failure mode → E_PERM.
    const result = syscall.bindEventRoute(ec_handle, 1, port_handle);
    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(3);
        return;
    }

    // The cap-table mapping is read-only userspace memory; the kernel
    // wrote the refreshed snapshot before returning. Reading directly
    // bypasses any further syscall (which would itself trigger another
    // implicit refresh), so this read observes exactly the snapshot
    // bind_event_route's side effect left in place.
    const cap = caps.readCap(cap_table_base, ec_handle);

    const observed_pri: u64 = cap.field0 & 0x3;
    if (observed_pri != target_priority) {
        testing.fail(4);
        return;
    }

    if (cap.field1 != target_affinity) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
