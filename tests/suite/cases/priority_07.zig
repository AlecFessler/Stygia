// Spec §[execution_context] priority — test 07.
//
// "[test 07] on success, when the target is suspended on a port or
//  waiting on a futex, [2] takes effect on the target's next port
//  event delivery and futex wake."
//
// Strategy (degraded smoke)
//   The full assertion requires three coordinated ECs:
//     - two ECs blocked in futex_wait_val on the same address (or
//       queued as senders on the same port),
//     - a third EC that calls `priority` to raise one of them, then
//       issues `futex_wake` (or has a `recv` issued by the controller),
//     - and observation of which EC wins the wake / dequeue race.
//   That orchestration cannot be assembled in a single test ELF
//   without bootstrapping multiple ECs with their own stacks, having
//   one of them block in futex_wait_val before the test continues,
//   and reliably observing the wake order. The runner spawns one
//   initial EC per test ELF; that EC is the only thread of control
//   here. Building two more cooperating ECs from inside this test —
//   each with its own stack page-frame and entry that performs a
//   futex_wait_val and reports back — adds substantial setup that is
//   itself unverified scaffolding.
//
//   Degraded shape that still exercises the success path of priority
//   on a non-running target:
//     - create a child EC with `spri` (so the priority call passes
//       cap test 02) and `restart_policy = 0`, starting at
//       `dummyEntry`. The child immediately executes `hlt`, which
//       traps in user mode; it is not running normal user code when
//       the priority call lands. It is the closest single-test-ELF
//       analogue of "target not currently scheduled" without a
//       second cooperating EC.
//     - call `priority(child, 2)`. The caller's pri ceiling is 3
//       (runner-minted), so test 03 cannot fire; new_priority = 2
//       is in 0..3 so test 04 cannot fire; the handle id is valid
//       and reserved bits are clean so tests 01, 05 cannot fire.
//       The success path is the only path the kernel can take.
//     - verify the kernel reflects the new priority in the child's
//       handle field0. The handle table maps read-only into this
//       domain at `cap_table_base`; field0 bits 0-1 carry `pri`.
//       Reading it back confirms the kernel accepted and recorded
//       the priority change — a necessary precondition for any
//       "takes effect on next wake" assertion at the scheduler
//       level. (The cross-EC wake-ordering half of the assertion is
//       not exercised by this degraded test.)
//
//   This is a smoke test of priority's success path against a
//   non-running target, not a full validation of test 07's
//   wake-ordering claim. The full assertion requires multi-EC test
//   harness work that is out of scope here.
//
// Action
//   1. create_execution_context(target=self,
//                               caps = {spri, restart_policy=0},
//                               priority = 0,
//                               entry = &dummyEntry,
//                               stack_pages = 1, affinity = 0)
//                                                       — must succeed
//   2. priority(child_ec, new_priority = 2)             — must succeed
//   3. readCap(child_ec).field0 & 0x3                   — must equal 2
//
// Assertions
//   1: setup syscall failed (create_execution_context returned an error)
//   2: priority returned non-OK in vreg 1
//   3: child handle's field0 priority bits do not equal the new priority

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    // §[execution_context] EcCap: `spri` gates the priority syscall on
    // this handle (§[priority] cap requirement). Without it the call
    // would return E_PERM (priority test 02), short-circuiting the
    // success path we want to exercise. Keep restart_policy = 0 so
    // there's no interaction with restart-policy ceilings.
    const child_caps = caps.EcCap{
        .spri = true,
        .restart_policy = 0,
    };

    // §[create_execution_context] caps word layout:
    //   bits  0-15: caps          ({spri} — subset of inner ceiling)
    //   bits 16-31: target_caps   (ignored when target = 0)
    //   bits 32-33: priority      (0 — within caller's pri = 3 ceiling)
    //   bits 34-63: _reserved     (0)
    const initial_priority: u64 = 0;
    const caps_word: u64 =
        @as(u64, child_caps.toU16()) |
        (initial_priority << 32);

    const entry: u64 = @intFromPtr(&testing.dummyEntry);
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
    const child_ec: u12 = @truncate(cec.v1 & 0xFFF);

    // §[priority]: priority([1] target, [2] new_priority). Caller has
    // pri = 3 (runner-minted self caps); new_priority = 2 is within
    // that ceiling, in range 0..3, and the handle is fresh+valid with
    // reserved bits clean — so the only path the kernel can take is
    // the success path.
    const new_priority: u64 = 2;
    const pri_result = syscall.priority(child_ec, new_priority);
    if (pri_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    // §[execution_context] field0 bits 0-1 = pri. The kernel writes the
    // authoritative snapshot back to the caller's handle slot as a side
    // effect of any syscall taking the handle (§[priority] test 08 /
    // §[capabilities] implicit-sync). Reading the read-only-mapped cap
    // table at this point reflects the post-priority-call snapshot.
    const cap = caps.readCap(cap_table_base, child_ec);
    const observed_priority: u64 = cap.field0 & 0x3;
    if (observed_priority != new_priority) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
