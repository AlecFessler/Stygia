// Spec §[clear_event_route] — test 04.
//
// "[test 04] returns E_INVAL if any reserved bits are set in [1] or [2]."
//
// Spec semantics
//   §[clear_event_route] takes [1] target (EC handle) and [2]
//   event_type (u64). [1] is a handle word: bits 0-11 hold the 12-bit
//   handle id and bits 12-63 are _reserved (§[handle_representation]).
//   [2] event_type must be one of the registerable types {1, 2, 3, 6}
//   (§[clear_event_route] test 03); the rest of the 64 bits are
//   _reserved. Setting any bit outside the defined fields must surface
//   E_INVAL at the syscall ABI layer (§[syscall_abi]) before any
//   cap-/handle-/state-dependent check fires.
//
// Strategy
//   The clear_event_route failure-path ordering is:
//     [test 01] E_BADCAP if [1] is not a valid EC handle.
//     [test 02] E_PERM   if [1] does not have the `unbind` cap.
//     [test 03] E_INVAL  if [2] is not a registerable event type.
//     [test 04] E_INVAL  if any reserved bits are set in [1] or [2].
//     [test 05] E_NOENT  if no binding exists for ([1], [2]).
//
//   To isolate the reserved-bit check we want [1]'s low 12 bits to
//   point at a real EC handle (so test 01 cannot fire) and [2] to be a
//   registerable event type (so test 03 cannot fire). With a valid
//   handle id and a registerable event_type, the only spec-mandated
//   failure for a reserved bit set on top is test 04. Reserved-bit
//   validation at the ABI layer fires ahead of cap (test 02) and
//   binding-state (test 05) checks, mirroring the precedent used by
//   affinity_04 / create_vcpu_07.
//
//   We mint a valid EC by calling create_execution_context with
//   target = self. The runner spawns the child with `crec` in
//   child_self and an ec_inner_ceiling = 0xFF (EcCap bits 0-7), so a
//   minimal caps word stays within the ceiling and the EC handle
//   appears in our table with a known slot id.
//
//   The libz `syscall.clearEventRoute` wrapper takes `target: u12`,
//   which cannot carry reserved bits in [1]. We bypass it via
//   `syscall.issueReg` to dispatch the syscall with bit 12 of [1] set
//   directly, mirroring the pattern in affinity_04.
//
// Action
//   1. create_execution_context(target=self, caps={term}) — must
//      succeed (yields a valid EC handle).
//   2. issueReg(.clear_event_route, [1] = handle | (1 << 12), [2] = 1)
//      — must return E_INVAL (reserved bit 12 of [1] set; low 12 bits
//        hold the valid EC id; [2] = 1 is a registerable event type).
//
// Assertions
//   1: setup — create_execution_context returned an error word.
//   2: clear_event_route with reserved bit 12 of [1] returned
//      something other than E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // §[create_execution_context] caps word: caps in bits 0-15,
    // target_caps in 16-31 (ignored when target=self), priority in
    // 32-33. priority=0 keeps the call within the child's pri ceiling;
    // EcCap{ .term = true } stays inside the runner-granted
    // ec_inner_ceiling = 0xFF (bits 0-7).
    const initial = caps.EcCap{ .term = true };
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
    // the reserved bit before it reaches the kernel. event_type = 1 is
    // a registerable type per §[clear_event_route] test 03's enumeration
    // {1, 2, 3, 6}, so the registerability check cannot fire ahead of
    // the reserved-bit check.
    const handle_with_reserved: u64 = @as(u64, ec_handle) | (@as(u64, 1) << 12);
    const r = syscall.issueReg(.clear_event_route, 0, .{
        .v1 = handle_with_reserved,
        .v2 = 1,
    });
    if (r.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
