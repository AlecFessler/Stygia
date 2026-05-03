// Spec §[create_execution_context] create_execution_context — test 13.
//
// "[test 13] on success, the EC's priority is set to `[1].priority`."
//
// Strategy
//   §[execution_context] handle ABI: word0 carries cap+id+type, field0
//   bits 0-1 hold the kernel-mutable scheduling priority `pri`. The
//   priority an EC starts with is taken from `[1].priority` (bits
//   32-33 of the caps word) at create_execution_context time.
//
//   To isolate the success-path priority assertion we must:
//     - have `crec` on the self-handle (granted by the runner; see
//       runner/primary.zig SelfCap)
//     - keep target = 0 (self) so the outer-ceiling and IDC paths are
//       all bypassed (tests 02, 04, 05, 07 cannot fire)
//     - keep caps a strict subset of `ec_inner_ceiling` (test 03 OK)
//     - keep priority within the caller's pri ceiling (test 06 OK).
//       The runner sets the child's self-handle `pri = 3`, so any
//       priority in 0..3 is admissible. We pick 2 — distinct from the
//       0 default a fresh field0 would naturally have, so an
//       implementation that simply zero-initializes pri would fail
//       this test.
//     - pass stack_pages = 1 so test 08 (E_INVAL on 0) cannot fire
//     - pass affinity = 0 (= "any core") so test 09 cannot fire
//     - clear all reserved bits in [1] (test 10 OK)
//
//   On success, the syscall returns the new EC's handle id in vreg 1.
//   We then read the cap entry directly out of the read-only-mapped
//   handle table and check field0's low 2 bits equal the requested
//   priority. The kernel writes the authoritative snapshot into the
//   caller's slot at create time, so a fresh `sync` is not required
//   for the read to be observable.
//
//   The new EC begins executing immediately at `dummyEntry`, which
//   halts forever; this test EC continues independently and reports
//   on its own initial EC's port without interference.
//
// Action
//   1. create_execution_context(
//        caps_word = caps={susp,term} | (priority=2 << 32),
//        entry     = &dummyEntry,
//        stack_pages = 1,
//        target    = 0,
//        affinity  = 0,
//      )
//      — must succeed.
//   2. readCap(cap_table_base, ec_handle).field0 & 0x3 == 2
//
// Assertions
//   1: create_execution_context returned an error word in vreg 1
//   2: handle's field0 priority bits do not equal the requested 2

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const ec_caps = caps.EcCap{
        .susp = true,
        .term = true,
    };
    // §[create_execution_context] caps word: caps in bits 0-15,
    // target_caps in 16-31 (ignored when target=self), priority in
    // 32-33. priority = 2 is non-zero (so a default-initialized field
    // would not coincidentally pass) and within the caller's pri = 3
    // ceiling (no E_PERM from test 06).
    const requested_priority: u64 = 2;
    const caps_word: u64 =
        @as(u64, ec_caps.toU16()) |
        (requested_priority << 32);

    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages
        0, // target = self
        0, // affinity = 0 (any core)
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(1);
        return;
    }
    const ec_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // §[execution_context] field0 bits 0-1 = pri. Read the cap entry
    // out of the read-only handle table mapped at cap_table_base.
    const cap = caps.readCap(cap_table_base, ec_handle);
    const observed_priority: u64 = cap.field0 & 0x3;
    if (observed_priority != requested_priority) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
