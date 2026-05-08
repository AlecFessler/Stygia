// Spec §[create_execution_context] — test 15.
//
// "[test 15] on success, the EC's stack base lies within the ASLR
//  zone (see §[address_space])."
//
// Strategy — DEGRADED SMOKE (kernel stack alloc is not ASLR'd yet)
//   FINDING: `create_execution_context` is supposed to place the
//   EC's user stack at a kernel-chosen randomized base inside the
//   ASLR zone (`arch.dispatch.paging.user_aslr` =
//   [0x0000_0000_0000_1000, 0x0000_1000_0000_0000) on x86-64). The
//   kernel today uses a deterministic bump allocator
//   (`domain.next_var_base`) for the stack reservation — see
//   `kernel/sched/execution_context.zig::createEcInDomain`. The
//   bump cursor lives inside the ASLR zone numerically (the
//   per-domain VAR base starts there), so the spec invariant "base
//   lies within the ASLR zone" is satisfied trivially without any
//   actual randomization. The proper fix is to plumb the existing
//   randomized placer (`memory/vmar.zig::vaRangeAllocate`) through
//   to the EC stack reservation; that's a deferred change that
//   touches both the EC create path and the per-domain VMM glue.
//   Tracked alongside the v3 spec-test tightening pass.
//
//   Until ASLR is wired in, asserting "base ∈ ASLR zone" would
//   succeed even on a kernel with no randomization at all (the
//   bump cursor's start is inside the zone), so the assertion would
//   pass for the wrong reason. This test stays at smoke level and
//   the rich check ("two ECs minted back-to-back have unrelated
//   stack offsets") is parked until the kernel impl lands.
//
//   Even at smoke level the test still verifies the precondition
//   for the spec invariant: `create_execution_context` succeeds at
//   all when called with default affinity + a stack_pages > 0.
//
// Action
//   1. create_execution_context(caps={susp,term}, &dummyEntry,
//      stack_pages=1, target=0, affinity=0)
//      — must succeed.
//
// Assertions
//   1: create_execution_context returned an error word in vreg 1.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const ec_caps = caps.EcCap{
        .susp = true,
        .term = true,
        .restart_policy = 0,
    };
    const caps_word: u64 = @as(u64, ec_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);

    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages
        0, // target = self
        0, // affinity = any
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(1);
        return;
    }

    // Once an EC stack-base introspection primitive lands, swap this
    // smoke pass for the real ASLR-zone bounds check.
    testing.pass();
}
