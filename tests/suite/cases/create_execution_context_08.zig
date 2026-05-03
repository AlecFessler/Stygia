// Spec §[create_execution_context] create_execution_context — test 08.
//
// "[test 08] returns E_INVAL if [3] stack_pages is 0."
//
// Strategy
//   To isolate the stack_pages=0 check we must neutralize every other
//   spec-mandated failure path:
//
//     - test 01 (E_PERM, missing crec on self): the runner-provided
//       self-handle has `crec` set (see runner/primary.zig:`child_self`),
//       so this cannot fire.
//     - tests 02, 04, 05, 07 (target-side checks when [4] != 0): use
//       `target = 0` (self) so none of the target-domain paths apply.
//     - test 03 (E_PERM, caps not subset of self's ec_inner_ceiling):
//       set caps = 0. The empty cap set is a subset of any ceiling.
//     - test 06 (E_PERM, priority exceeds ceiling): set priority = 0.
//       The runner grants the child `pri = 3`, so 0 is well within bounds.
//     - test 09 (E_INVAL, affinity bits outside system core count):
//       set affinity = 0. Per §[create_execution_context], 0 means
//       "kernel chooses" — no per-bit core check applies.
//     - test 10 (E_INVAL, reserved bits set in [1]): build the caps
//       word with only bits 0-15 (caps), 16-31 (target_caps), and
//       32-33 (priority) set. We use only caps=0, target_caps=0 (ignored
//       since target=self), priority=0 — the entire word is 0, so no
//       reserved bit can be set.
//
//   With all the other paths neutralized, the only spec-mandated
//   failure is the stack_pages=0 check, and the kernel must return
//   E_INVAL.
//
//   `entry` is set to a valid in-process function pointer
//   (`testing.dummyEntry`). The kernel's spec doesn't define an
//   "invalid entry" error path on this syscall, so any in-bounds value
//   works; using a real symbol is conservative against future tightening.
//
// Action
//   create_execution_context(
//     caps        = 0,
//     entry       = &dummyEntry,
//     stack_pages = 0,         <-- the trigger
//     target      = 0,         (self)
//     affinity    = 0,         (kernel chooses)
//   )
//   -> must return E_INVAL
//
// Assertion
//   result.v1 == E_INVAL  (assertion id 1)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const result = syscall.createExecutionContext(
        0, // caps word: caps=0, target_caps=0, priority=0, no reserved bits
        entry,
        0, // stack_pages = 0 — the trigger
        0, // target = self
        0, // affinity = 0 (kernel chooses)
    );

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
