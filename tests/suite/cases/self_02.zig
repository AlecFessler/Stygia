// Spec §[self] self — test 02.
//
// "[test 02] on success, [1] is a handle in the caller's table whose
//  resolved capability references the calling thread."
//
// Strategy
//   §[self] is a pure lookup: no handle is inserted, minted, or
//   modified. The only spec-mandated failure path is E_NOENT (test 01)
//   when the caller's table contains no handle referencing the calling
//   thread. Per the runner setup in `runner/primary.zig`, every test ELF
//   spawns as a fresh capability domain whose initial thread handle lives
//   at slot 1 (caps.SLOT_INITIAL_THREAD). The test code itself runs on the
//   initial thread (start.zig calls app.main on that thread), so a handle
//   referencing the calling thread exists in the table — `self()` must
//   return success.
//
//   To assert the post-condition without leaking implementation detail,
//   we check three properties of the returned handle:
//     - The vreg-1 result is not an error word (per testing.isHandleError,
//       any value < 16 in the success bit pattern would be ambiguous;
//       the kernel's success path returns a handle word with type tag
//       bits 12-15 set non-zero for handles other than the slot-0
//       capability_domain_self, but for the thread self-handle the type tag
//       is `thread = 2`, which makes the word > 15 by the
//       caps high-bits or the type-tag mid-bits).
//     - The handle id (low 12 bits) is a slot whose Cap entry has
//       handleType == thread. By the §[self] at-most-one
//       invariant, only one such thread self-reference can exist; every
//       other thread handle in this fresh domain (none, in this test)
//       would also be type thread, but slot collisions are
//       impossible.
//     - The handle id matches the conventional initial-thread slot
//       (caps.SLOT_INITIAL_THREAD). The runner installs the initial thread at
//       slot 1, the test runs on that thread, so by at-most-one the
//       returned slot must be 1. This pins the lookup to the spec's
//       "references the calling thread" requirement: any other slot would
//       either be empty (E_NOENT path, contradicting success) or
//       reference a different object type (contradicting the spec's
//       "thread" wording).
//
//   The third check is the load-bearing one: a no-op kernel that
//   returned a fixed unrelated slot would fail it; a kernel that
//   inserted a fresh handle would also fail (spec says pure lookup,
//   and the only thread handle in the table at this point is slot 1).
//
// Action
//   1. self()                                   — must return success
//   2. inspect returned handle id               — must equal SLOT_INITIAL_THREAD
//   3. readCap at that slot                     — must be type thread
//
// Assertions
//   1: self() returned an error word (vreg 1 < 16) instead of a handle
//   2: returned handle id != caps.SLOT_INITIAL_THREAD
//   3: cap at that slot is not handleType.thread

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const result = syscall.self();
    if (testing.isHandleError(result.v1)) {
        testing.fail(1);
        return;
    }

    const handle_id: u12 = @truncate(result.v1 & 0xFFF);
    if (handle_id != caps.SLOT_INITIAL_THREAD) {
        testing.fail(2);
        return;
    }

    const cap = caps.readCap(cap_table_base, handle_id);
    if (cap.handleType() != caps.HandleType.thread) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
