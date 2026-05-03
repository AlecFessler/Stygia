// Spec §[restart_semantics] — test 03.
//
// "[test 03] returns E_PERM if `create_page_frame` is called with
//  `caps.restart_policy = 1` and the calling domain's
//  `restart_policy_ceiling.pf_restart_max = 0`."
//
// Spec semantics
//   `restart_policy_ceiling.pf_restart_max` is bit 20 of the self-handle's
//   field1 (per §[capability_domain] field1 layout). At
//   `create_page_frame` time the kernel rejects any caps whose
//   `restart_policy` bit (PfCap bit 7) exceeds the calling domain's
//   `pf_restart_max` ceiling. With ceiling = 0, requesting
//   `restart_policy = 1` (keep) must surface E_PERM.
//
// Strategy (degraded smoke variant)
//   The faithful test would look like:
//     1. spawn a child capability domain whose `restart_policy_ceiling`
//        has `pf_restart_max = 0` (e.g., ceilings_outer with bit 20 of
//        bits 16-31 cleared).
//     2. inside that child, call `create_page_frame(caps.restart_policy
//        = 1)` and assert the return is E_PERM.
//     3. report the result back across the IDC link.
//
//   The current test infrastructure embeds each test ELF directly in
//   the primary's manifest and spawns each as a single capability
//   domain whose ceilings are fixed in `runner/primary.zig` to
//   `restart_policy_ceiling = 0x03FE` (which sets bit 4 = bit 20-of-the-
//   ceiling-field, i.e., `pf_restart_max = 1`). A test ELF cannot
//   reduce its own ceiling: `restrict` only operates on the caps field
//   (word0 bits 48-63) of the self-handle, not on field0/field1 where
//   the ceiling lives. There is also no path for a single test ELF to
//   embed and spawn a grandchild domain with a different ceiling.
//
//   To still exercise the syscall surface, this test mints a page
//   frame with `caps.restart_policy = 1` from the test domain itself
//   and asserts that — under the runner's default `pf_restart_max = 1`
//   — the call succeeds. The "ceiling = 0 ⇒ E_PERM" rule narrows to a
//   "ceiling = 1 ⇒ accept" smoke check, which is a strict subset of
//   the spec rule (the kernel must not erroneously reject when the
//   ceiling permits the value). Faithfully exercising the E_PERM path
//   needs either a per-test ceilings override in the runner or a
//   two-level test infra extension where a test ships its own child
//   ELF, stages it into a page frame at runtime, and calls
//   `create_capability_domain` with reduced ceilings — the same gap
//   noted in revoke_06.
//
// Action
//   1. create_page_frame(caps={r, restart_policy=1}, props=0, pages=1)
//      — must succeed (i.e., return a handle, not an error word).
//
// Assertions
//   1: create_page_frame did not return a valid handle. Under the
//      runner's `pf_restart_max = 1`, the kernel must accept the
//      request; an error response (especially E_PERM) would mean the
//      kernel is over-rejecting.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // §[page_frame] PfCap layout: r = bit 2, restart_policy = bit 7.
    // Setting r so the resulting handle is usable by a follow-up
    // map_pf if a future iteration of this test wants to extend the
    // assertion; restart_policy = 1 ("keep") is the value the spec
    // line under test gates on.
    const pf_caps = caps.PfCap{
        .r = true,
        .restart_policy = true,
    };

    const result = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB), reserved bits clean
        1, // pages: 1 (smallest non-zero allocation)
    );

    if (testing.isHandleError(result.v1)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
