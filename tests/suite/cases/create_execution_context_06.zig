// Spec §[execution_context] create_execution_context — test 06.
//
// "[test 06] returns E_PERM if priority exceeds the caller's priority
//  ceiling."
//
// Strategy
//   The caller's priority ceiling lives in the self-handle's `pri`
//   field (§[capability_domain] field bits 14-15 of the SelfCap word).
//   The runner mints each child with `pri = 3` (the maximum), so a
//   create_execution_context call with priority in 0..3 cannot exceed
//   the ceiling out of the box. We first lower our own ceiling via
//   `restrict` on the self-handle.
//
//   `restrict` uses bitwise subset semantics for self-handle cap fields
//   (§[capabilities] restrict, "Most cap fields use bitwise subset
//   semantics"). pri = 3 has both bits set; pri = 1 has only bit 0
//   set, which is a strict subset, so restrict accepts it. We keep
//   `crec` set in the same restrict so the create_execution_context
//   call can still pass the test 01 `crec` check — that leaves the
//   priority comparison as the only spec-mandated failure path.
//
//   With pri-ceiling lowered to 1, calling create_execution_context
//   with priority = 2 (encoded in caps-word bits 32-33) must return
//   E_PERM by test 06. priority = 2 exceeds ceiling = 1 numerically;
//   the bitwise subset semantics that govern restrict do not apply
//   here, since the spec text for create_execution_context test 06
//   says "exceeds", a numeric comparison.
//
//   target = 0 (self), so the test 02 / test 04 / test 05 / test 07
//   target-side checks cannot fire. caps = {susp, term} is a subset of
//   the new domain's `ec_inner_ceiling = 0xFF` (set by the runner), so
//   test 03 cannot fire. stack_pages = 1, affinity = 0 (any core),
//   reserved bits clean, so tests 08, 09, 10 cannot fire. The
//   priority-ceiling check from test 06 is the only error path the
//   kernel can take.
//
// Action
//   1. restrict(SLOT_SELF, caps={crec, pri=1})    — must succeed
//      (strict subset of the runner-minted self caps; lowers ceiling)
//   2. create_execution_context(caps={susp, term, priority=2},
//                               entry=&dummyEntry, stack_pages=1,
//                               target=0, affinity=0)
//                                                  — must return E_PERM
//
// Assertions
//   1: restrict on the self-handle returned non-OK
//   2: create_execution_context returned something other than E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // §[capability_domain] SelfCap. Lower the priority ceiling from 3
    // (runner default) to 1 while keeping `crec` so the subsequent
    // create_execution_context still passes the test 01 cap check.
    const restricted_self = caps.SelfCap{
        .crec = true,
        .pri = 1,
    };
    const restrict_result = syscall.restrict(
        caps.SLOT_SELF,
        @as(u64, restricted_self.toU16()),
    );
    if (restrict_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    // §[create_execution_context] caps word layout:
    //   bits  0-15: caps          ({susp, term} — subset of inner ceiling)
    //   bits 16-31: target_caps   (ignored when target = 0)
    //   bits 32-33: priority      (2 — exceeds the ceiling we just set)
    //   bits 34-63: _reserved     (0)
    const ec_caps = caps.EcCap{ .susp = true, .term = true };
    const priority: u64 = 2;
    const caps_word: u64 = @as(u64, ec_caps.toU16()) | (priority << 32);

    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const result = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages
        0, // target = self
        0, // affinity = any core
    );

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
