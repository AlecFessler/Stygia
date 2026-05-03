// Spec §[execution_context] terminate — test 05.
//
// "[test 05] on success, syscalls invoked with any handle to the
//  terminated EC return E_TERM and remove that handle from the
//  caller's table on the same call."
//
// Strategy
//   The assertion has two halves the test must witness:
//     (a) a post-terminate syscall on the EC handle returns E_TERM,
//     (b) that same call removes the handle from the caller's table.
//   Witnessing (a) needs a side-effect-free EC syscall callable on
//   the stale handle. Witnessing (b) needs a follow-up call on the
//   same handle id that observes the slot is now empty — its result
//   must be E_BADCAP per §[error_codes] (stale-vs-empty are distinct
//   error codes: E_TERM for "EC terminated", E_BADCAP for "no
//   handle in this slot").
//
//   Mint a target EC inside the calling domain (target = self, so
//   no IDC is needed) with caps {term, spri, restart_policy = 0}:
//     - `term` lets the test EC actually terminate the target,
//     - `spri` lets the test invoke `priority` on the EC handle,
//     - `restart_policy = 0` (kill) keeps the target inside the
//       restart_policy ceiling and avoids any restart fallback that
//       could mask the post-termination state.
//   The target's entry is `dummyEntry` — it halts forever; it does
//   not matter for this test since the kernel destroys the EC at
//   terminate without waiting for it to consent.
//
//   priority is a clean follow-up choice: it gates on `spri` (which
//   the handle has when minted) and on the caller's pri ceiling
//   (the runner grants pri = 3, so new_priority = 0 is in bounds).
//   Therefore on a live handle priority would return OK; on a stale
//   handle the kernel returns E_TERM (per §[error_codes] entry 14)
//   and removes the slot; on an empty slot the kernel returns
//   E_BADCAP.
//
// Action
//   1. create_execution_context(target = self, caps = {term, spri,
//      rp = 0})                            — must succeed
//   2. terminate(ec_handle)                — must return OK
//   3. priority(ec_handle, 0)              — must return E_TERM
//      (witnesses half (a) of the assertion: stale-handle syscall
//      surfaces E_TERM)
//   4. priority(ec_handle, 0)              — must return E_BADCAP
//      (witnesses half (b): step 3 removed the slot, so the same
//      handle id now has no entry in the caller's table)
//
// Assertions
//   1: setup syscall failed (create_execution_context returned an
//      error word in vreg 1)
//   2: terminate itself did not return success in vreg 1
//   3: post-terminate priority returned something other than E_TERM
//   4: follow-up priority returned something other than E_BADCAP
//      (i.e. the slot was not removed by step 3, contradicting the
//      "remove that handle from the caller's table on the same
//      call" half of the spec line)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const initial = caps.EcCap{
        .term = true,
        .spri = true,
        .restart_policy = 0,
    };
    // §[create_execution_context] caps word: caps in bits 0-15,
    // target_caps in 16-31 (ignored when target = self), priority in
    // 32-33. priority = 0 stays within the runner-granted pri ceiling.
    const caps_word: u64 = @as(u64, initial.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1,
        0,
        0,
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(1);
        return;
    }
    const ec_handle: u12 = @truncate(cec.v1 & 0xFFF);

    const term_result = syscall.terminate(ec_handle);
    if (term_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    // First post-terminate use of the now-stale handle. Per the spec
    // line under test, the kernel must surface E_TERM on this call
    // and atomically remove the handle from the caller's table.
    const stale = syscall.priority(ec_handle, 0);
    if (stale.v1 != @intFromEnum(errors.Error.E_TERM)) {
        testing.fail(3);
        return;
    }

    // Second use on the same handle id. With the slot removed, the
    // call must surface E_BADCAP (handle id no longer references any
    // capability) — this is the witness for the "remove ... on the
    // same call" half of the assertion.
    const empty = syscall.priority(ec_handle, 0);
    if (empty.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
