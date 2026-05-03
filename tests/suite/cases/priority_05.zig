// Spec §[execution_context] priority — test 05.
//
// "[test 05] returns E_INVAL if any reserved bits are set in [1]."
//
// Strategy
//   The [1] handle word carries the 12-bit handle id in bits 0-11
//   with bits 12-63 _reserved (§[handle_representation]). Setting
//   any bit outside the id field is a spec violation that must
//   surface E_INVAL at the syscall ABI layer (§[syscall_abi]).
//
//   To isolate the reserved-bit check we make every other check
//   pass. priority's failure paths are:
//     [test 01] E_BADCAP if [1] is not a valid EC handle.
//     [test 02] E_PERM   if [1] does not have the `spri` cap.
//     [test 03] E_PERM   if [2] exceeds the caller's self-handle `pri`.
//     [test 04] E_INVAL  if [2] is greater than 3.
//     [test 05] E_INVAL  if any reserved bits are set in [1].
//
//   So [1]'s low 12 bits must reference a valid EC handle that has
//   the `spri` cap, and [2] must be in 0..3 and must not exceed the
//   caller's self-handle `pri` ceiling. The runner gives the child
//   `self.pri = 3` (primary.zig), so [2] = 0 is safely within the
//   ceiling.
//
//   We mint a fresh EC via `create_execution_context(target=self,
//   caps={spri,susp,term,rp=0})` — same shape as terminate_03's setup
//   but with `spri` substituted in. The new EC begins executing at
//   `testing.dummyEntry`, which halts forever; the test EC continues
//   independently and the `priority` call targets the new EC's
//   handle slot in our table, not its running state.
//
//   We then dispatch priority with reserved bit 12 of [1] set while
//   the low 12 bits hold the valid EC slot id. The libz
//   `syscall.priority` wrapper takes `target: u12`, which cannot
//   carry reserved bits in [1]. We bypass that wrapper and dispatch
//   through `syscall.issueReg` directly so we can stuff bit 12 into
//   vreg 1.
//
//   We do NOT first invoke priority with the clean low bits — that
//   would actually retune the EC's priority and is irrelevant to
//   the assertion. The reserved-bit check fires at the ABI dispatch
//   layer before any priority side effect, so the target EC's
//   priority remains unchanged after this call.
//
// Action
//   1. create_execution_context(target=self, caps={spri,susp,term,rp=0})
//      — must succeed (yields a valid EC handle with `spri` cap)
//   2. priority(handle | (1 << 12), 0)
//      — must return E_INVAL (reserved bit 12 of [1] set;
//        low 12 bits hold the valid EC id; [2]=0 is in 0..3 and
//        within the caller's pri ceiling)
//
// Assertions
//   1: setup syscall failed (create_execution_context returned an
//      error word in v1)
//   2: priority with reserved bit 12 of [1] returned something
//      other than E_INVAL

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const initial = caps.EcCap{
        .spri = true,
        .susp = true,
        .term = true,
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

    // Reserved bit 12 of [1] set; low 12 bits hold the valid EC id.
    // Bypass the typed wrapper since it takes u12 and would truncate
    // the reserved bit before it reaches the kernel. [2]=0 is in
    // 0..3 and within the caller's pri ceiling so neither test 03
    // nor test 04 can fire.
    const handle_with_reserved: u64 = @as(u64, ec_handle) | (@as(u64, 1) << 12);
    const r = syscall.issueReg(.priority, 0, .{
        .v1 = handle_with_reserved,
        .v2 = 0,
    });
    if (r.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
