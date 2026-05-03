// Spec §[capabilities] restrict — test 03.
//
// "[test 03] returns E_PERM if the handle is an EC handle and [2].caps'
//  restart_policy (bits 8-9) numeric value exceeds the handle's current
//  restart_policy."
//
// Strategy
//   restart_policy is a 2-bit enum (0=kill, 1=restart_at_entry,
//   2=persist) that uses NUMERIC monotonicity, not bitwise subset
//   semantics. Test 03 specifically asserts the EC-handle path of
//   that rule.
//
//   Mint a new EC with `restart_policy = 0`. Then call restrict,
//   keeping every other cap bit identical, but raising
//   restart_policy to 1. The new numeric value (1) exceeds the
//   current (0); the kernel must reject with E_PERM.
//
//   The new EC begins executing immediately at `dummyEntry`, which
//   halts forever; the test EC continues independently. No
//   synchronization is required because the restrict operation
//   touches the handle's caps slot in our domain's handle table —
//   not the running EC's state.
//
// Action
//   1. create_execution_context(target=self, caps={susp,term,rp=0})
//   2. restrict(ec, caps={susp,term,rp=1})
//
// Assertions
//   1: setup syscall failed (create_execution_context returned an error)
//   2: restrict returned something other than E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const initial = caps.EcCap{
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

    const expanded = caps.EcCap{
        .susp = true,
        .term = true,
        .restart_policy = 1,
    };
    const new_caps_word: u64 = @as(u64, expanded.toU16());
    const result = syscall.restrict(ec_handle, new_caps_word);

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
