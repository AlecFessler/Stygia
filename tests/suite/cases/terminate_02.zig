// Spec §[thread] terminate — test 02.
//
// "[test 02] returns E_PERM if [1] does not have the `term` cap."
//
// Strategy
//   Mint a fresh thread handle whose caps explicitly omit `term`. Caps
//   are mintable a la carte at create time, so producing a term-less
//   thread handle is direct. Then call `terminate` on it.
//
//   Failure-path neutralization:
//     - E_BADCAP (test 01) — handle id comes from a successful
//       create_thread, so it's valid.
//     - E_INVAL (test 03) — the typed `syscall.terminate(u12)` wrapper
//       carries no reserved bits in [1].
//   The cap check is therefore the only spec-mandated failure path
//   that applies, isolating E_PERM.
//
//   The new thread begins executing immediately at `dummyEntry`, which
//   halts forever (`hlt`). No synchronization is needed because the
//   terminate cap check happens against the handle's caps field in
//   our domain's handle table; the running thread's state is irrelevant.
//
// Action
//   1. create_thread(target=self, caps={susp})  — must succeed
//   2. terminate(thread)                                       — must return E_PERM
//
// Assertions
//   1: setup syscall failed (create_thread returned an error)
//   2: terminate returned something other than E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // ThreadCap with no `term` bit set. `susp` is included so the caps
    // word is non-zero — purely a defensive choice; nothing in the
    // spec requires a non-empty caps word and a fully-empty caps thread
    // would also be valid for this test.
    const initial = caps.ThreadCap{
        .susp = true,
        .term = false,
        .restart_policy = 0,
    };
    // §[create_thread] caps word: caps in bits 0-15,
    // target_caps in 16-31 (ignored when target=self), priority in
    // 32-33. priority=0 keeps the call within the child's pri ceiling.
    const caps_word: u64 = @as(u64, initial.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createThread(
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
    const thread_handle: u12 = @truncate(cec.v1 & 0xFFF);

    const result = syscall.terminate(thread_handle);

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
