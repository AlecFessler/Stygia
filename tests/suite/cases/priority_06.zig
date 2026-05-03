// Spec §[execution_context] priority — test 06.
//
// "[test 06] on success, when two ECs are blocked in `futex_wait_val`
//  on the same address and a `futex_wake` is issued, the EC whose
//  priority was last set higher via `priority` is woken first; the
//  same ordering applies to `recv` selection when the two ECs are
//  both queued senders on the same port."
//
// Strategy
//   The full assertion compares wake ordering between two ECs blocked
//   on a futex (or queued on a port). Faithfully exercising it
//   requires (1) two distinct worker ECs that each enter
//   `futex_wait_val` on the same shared address, (2) a stable
//   "they're both blocked" rendezvous before the test EC issues
//   `futex_wake`, and (3) a side-channel from the woken EC back to
//   the test EC that records *which* EC woke first. None of those
//   pieces are wired up in the v0 test harness:
//     - There is no in-test EC entry point that takes per-EC state
//       (`createExecutionContext` only takes a single entry pointer);
//       distinguishing the two workers requires either two distinct
//       entry symbols or a TLS-equivalent the harness does not
//       expose.
//     - The runner's child capability domain has no preconfigured
//       page_frame for shared memory between the test EC and worker
//       ECs; staging one in-test would compose `create_page_frame`,
//       `create_var`, `map_pf`, and per-EC stack-relative addressing
//       not yet validated end-to-end in the kernel.
//     - Kernel-side priority-ordered futex wake ordering is itself
//       unverified by any prior test in the suite.
//
//   Per the task brief's "degraded smoke OK with doc-comment if
//   blocked" provision, this test instead exercises the
//   priority-syscall happy path on a freshly-created EC that holds
//   the `spri` cap, with the new priority within the caller's
//   priority ceiling. A success return (vreg 1 == OK) demonstrates
//   that:
//     - the EC handle resolves and is recognized as an EC type
//     - the `spri` cap check passes
//     - the `[2] new_priority <= caller's pri ceiling` check passes
//     - the `[2] new_priority <= 3` check passes
//     - no reserved bits in [1] tripped E_INVAL
//
//   The full two-EC-wake-ordering assertion is intentionally not
//   attempted here; it should be revisited once the harness grows
//   shared-memory-and-multiple-workers helpers (likely alongside
//   priority test 07, which has the same shape).
//
//   Other failure paths neutralized for the priority call:
//     - test 01 (E_BADCAP): handle is the freshly-created EC.
//     - test 02 (E_PERM via missing spri): cap word includes spri.
//     - test 03 (E_PERM via priority > pri ceiling): caller's
//       self-handle pri ceiling = 3 (runner mints with pri = 3),
//       new_priority = 1 stays well within.
//     - test 04 (E_INVAL: new_priority > 3): new_priority = 1.
//     - test 05 (E_INVAL: reserved bits in [1]): use the typed
//       wrapper which takes u12 and zero-extends.
//
// Action
//   1. create_execution_context(caps={spri, susp, term},
//                               &dummyEntry, 1, 0, 0)
//      — must succeed, yielding an EC handle that carries `spri`.
//   2. priority(ec_handle, 1)
//      — must succeed (vreg 1 == OK).
//
// Assertions
//   1: create_execution_context returned an error word (no EC handle
//      to test against)
//   2: priority returned a non-OK error code

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Mint an EC that carries `spri` so the priority syscall's cap
    // check passes. `susp` and `term` are added so the handle's caps
    // are well within the child's `ec_inner_ceiling` (low 8 bits per
    // runner/primary.zig's ceilings_inner = 0xFF in field 0-7) and
    // restart_policy stays 0 to satisfy test 01 of restart_semantics.
    const ec_caps = caps.EcCap{
        .spri = true,
        .susp = true,
        .term = true,
        .restart_policy = 0,
    };
    // §[create_execution_context] caps word layout: caps in bits
    // 0-15, target_caps in 16-31 (ignored for target=self), priority
    // in 32-33. Set priority = 0 so the EC is born at the lowest
    // priority — well within the caller's ceiling of 3.
    const caps_word: u64 = @as(u64, ec_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages — non-zero (test 08 guard)
        0, // target = self (avoids tests 02/07)
        0, // affinity = any core (avoids test 09)
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(1);
        return;
    }
    const ec_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // priority(ec_handle, 1) — well within the caller's pri ceiling
    // of 3 and within the spec range [0, 3]. The typed wrapper takes
    // u12 so [1]'s reserved bits are zero by construction.
    const r = syscall.priority(ec_handle, 1);
    if (r.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
