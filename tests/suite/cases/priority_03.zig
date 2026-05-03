// Spec §[execution_context] priority — test 03.
//
// "[test 03] returns E_PERM if [2] exceeds the caller's self-handle `pri`."
//
// Strategy
//   The priority syscall checks `[2] new_priority` against the caller's
//   self-handle `pri` (§[capability_domain] field bits 14-15 of SelfCap).
//   The runner mints each child with `pri = 3` (the maximum), so any
//   `[2]` in 0..3 cannot exceed the ceiling out of the box. We first
//   lower our own pri ceiling via `restrict` on the self-handle.
//
//   `restrict` on the self-handle uses bitwise subset semantics —
//   §[capabilities] restrict notes the only fields with numeric
//   semantics are EC and VAR `restart_policy`. `pri = 3` has both bits
//   set; `pri = 1` has only bit 0 (i.e. SelfCap bit 14) set, which is
//   a strict subset, so restrict accepts it.
//
//   To isolate the priority-ceiling check, every other priority error
//   path must miss:
//     - test 01 (E_BADCAP): use the runner-installed initial EC at
//       SLOT_INITIAL_EC. Per §[create_capability_domain] test 21 the
//       initial EC carries caps = `ec_inner_ceiling` (0xFF in the
//       runner), which includes `spri` (EcCap bit 3), so the cap is
//       valid for the priority syscall.
//     - test 02 (E_PERM if no `spri`): same — initial EC has spri.
//     - test 04 (E_INVAL if [2] > 3): pick `new_priority = 2`, which
//       is <= 3 numerically.
//     - test 05 (E_INVAL on reserved bits in [1]): the libz wrapper
//       takes `u12` for the handle, so the high bits of the syscall
//       slot are zero by construction.
//   With pri-ceiling lowered to 1 and `new_priority = 2`, the spec
//   text "exceeds" (numeric comparison) puts test 03 as the only
//   spec-mandated failure path.
//
// Action
//   1. restrict(SLOT_SELF, caps={pri=1})              — must succeed
//      (strict subset of the runner-minted self caps; lowers ceiling
//       from 3 to 1)
//   2. priority(SLOT_INITIAL_EC, new_priority = 2)    — must return
//                                                       E_PERM
//
// Assertions
//   1: restrict on the self-handle returned non-OK
//   2: priority returned something other than E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // §[capability_domain] SelfCap. Lower the priority ceiling from 3
    // (runner default) to 1. Every other cap bit drops to 0; that is a
    // strict bitwise subset of the runner-minted self-handle, so
    // restrict accepts it.
    const restricted_self = caps.SelfCap{ .pri = 1 };
    const restrict_result = syscall.restrict(
        caps.SLOT_SELF,
        @as(u64, restricted_self.toU16()),
    );
    if (restrict_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    // new_priority = 2 exceeds the ceiling we just set (pri = 1) but
    // is still <= 3, so the kernel must reject with E_PERM (test 03)
    // rather than E_INVAL (test 04).
    const result = syscall.priority(caps.SLOT_INITIAL_EC, 2);
    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
