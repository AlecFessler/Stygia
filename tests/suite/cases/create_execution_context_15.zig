// Spec §[create_execution_context] — test 15.
//
// "[test 15] on success, the EC's stack base lies within the ASLR
//  zone (see §[address_space])."
//
// Strategy
//   `create_execution_context` allocates `[3] stack_pages` of stack
//   in the target's address space at a kernel-chosen randomized base
//   in the ASLR zone (spec §[create_execution_context]). The EC's
//   handle does not directly expose the stack base; verifying the
//   spec assertion from userspace requires inspecting the EC's saved
//   register state, which is not surfaced by the v0 syscall ABI.
//
//   This file is a placeholder that documents the required check; it
//   is currently a degraded smoke that waits on
//   create_execution_context's full implementation. Today's stub
//   returns E_BADCAP unconditionally, so the only outcome is
//   assertion 1 (setup error). Once create_execution_context lands
//   and an EC introspection primitive exposes the stack base, this
//   test can assert the base lies in the ASLR zone.
//
// Action
//   1. create_execution_context(caps={susp,term}, &dummyEntry,
//      stack_pages=1, target=0, affinity=0)
//      — must succeed.
//
// Assertions
//   1: create_execution_context returned an error word in vreg 1
//      (today: stub always returns E_BADCAP, so this fails until the
//      real implementation lands).

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
