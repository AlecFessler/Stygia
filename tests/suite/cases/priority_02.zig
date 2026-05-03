// Spec §[execution_context] priority — test 02.
//
// "[test 02] returns E_PERM if [1] does not have the `spri` cap."
//
// Strategy
//   Mint a fresh EC handle whose caps explicitly omit `spri`. Caps are
//   mintable a la carte at create time, so producing an spri-less EC
//   handle is direct. Then call `priority` on it.
//
//   Failure-path neutralization:
//     - E_BADCAP (test 01) — handle id comes from a successful
//       create_execution_context, so it's valid.
//     - E_PERM via priority-ceiling (test 03) — `[2] new_priority = 0`
//       cannot exceed any priority ceiling (the runner grants
//       `pri = 3`); the cap check therefore precedes/isolates from
//       the ceiling check.
//     - E_INVAL on [2] > 3 (test 04) — `[2] = 0` is in range.
//     - E_INVAL on [1] reserved bits (test 05) — the typed
//       `syscall.priority(u12, ...)` wrapper carries no reserved bits
//       in [1].
//   The cap check is therefore the only spec-mandated failure path
//   that applies, isolating E_PERM.
//
//   The new EC begins executing immediately at `dummyEntry`, which
//   halts forever (`hlt`). No synchronization is needed because the
//   `spri` cap check happens against the handle's caps field in our
//   domain's handle table; the running EC's state is irrelevant.
//
// Action
//   1. create_execution_context(target=self, caps={susp, spri=false})
//                                                    — must succeed
//   2. priority(ec, 0)                               — must return E_PERM
//
// Assertions
//   1: setup syscall failed (create_execution_context returned an error)
//   2: priority returned something other than E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // EcCap with no `spri` bit set. `susp` is included so the caps
    // word is non-zero — purely a defensive choice; nothing in the
    // spec requires a non-empty caps word and a fully-empty caps EC
    // would also be valid for this test.
    const initial = caps.EcCap{
        .susp = true,
        .spri = false,
        .restart_policy = 0,
    };
    // §[create_execution_context] caps word: caps in bits 0-15,
    // target_caps in 16-31 (ignored when target=self), priority in
    // 32-33. priority=0 keeps the call within the child's pri ceiling.
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

    const result = syscall.priority(ec_handle, 0);

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
