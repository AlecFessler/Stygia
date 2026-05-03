// Spec §[create_execution_context] create_execution_context — test 01.
//
// "[test 01] returns E_PERM if the caller's self-handle lacks `crec`."
//
// Strategy
//   The primary spawns each test as its own child capability domain,
//   minting a self-handle with caps = {crcd, crec, crvr, crpf, crvm,
//   crpt, pmu, fut_wake, timer, pri=3} (see runner/primary.zig). To
//   exercise the missing-`crec` path we first reduce the self-handle's
//   caps via `restrict`, dropping just the `crec` bit while leaving
//   every other cap untouched. `restrict` per §[restrict] requires no
//   self-handle cap — reducing authority is unconditional — so this
//   step always succeeds.
//
//   With `crec` cleared, a subsequent `create_execution_context` with
//   target = self must trigger §[create_execution_context]'s self-cap
//   check: "Caller's self-handle must always have `crec`." That check
//   fires before any of the argument-validation paths (test 08 INVAL on
//   stack_pages = 0, test 10 INVAL on reserved bits in [1]), so we use
//   well-formed args (stack_pages = 1, no reserved bits, target = 0)
//   and isolate the E_PERM path.
//
//   We do not reduce any other caps — the runner-supplied self-handle
//   already lacks `power`, `restart`, `setwall`, `reply_policy`, and
//   the `_reserved` bit, so dropping `crec` alone is sufficient and
//   keeps the rest of the runner's environment intact for the tail of
//   the test.
//
// Action
//   1. restrict(SLOT_SELF, caps_without_crec)              — must succeed
//   2. create_execution_context(caps={...}, entry, 1, 0, 0) — must return E_PERM
//
// The `caps` word in step 2 has caps = {susp, term} and priority = 0,
// well within the child's `ec_inner_ceiling` and priority ceiling so
// neither test 03 (caps not subset of `ec_inner_ceiling`) nor test 06
// (priority exceeds caller's ceiling) can fire ahead of the `crec`
// check.
//
// Assertions
//   1: restrict() returned non-OK in vreg 1 (failed to drop crec)
//   2: create_execution_context returned something other than E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // §[capability_domain] self-handle caps minted by the runner
    // (see runner/primary.zig spawnOne), with `crec` cleared.
    const reduced_self = caps.SelfCap{
        .crcd = true,
        .crec = false, // drop just this bit
        .crvr = true,
        .crpf = true,
        .crvm = true,
        .crpt = true,
        .pmu = true,
        .fut_wake = true,
        .timer = true,
        .pri = 3,
    };
    const reduced_word: u64 = @as(u64, reduced_self.toU16());
    const r = syscall.restrict(caps.SLOT_SELF, reduced_word);
    if (r.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    // create_execution_context: caps = {susp, term}, priority = 0,
    // target = 0 (self), stack_pages = 1, affinity = 0 (any core).
    const ec_caps = caps.EcCap{
        .susp = true,
        .term = true,
    };
    const caps_word: u64 = @as(u64, ec_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const result = syscall.createExecutionContext(
        caps_word,
        entry,
        1,
        0,
        0,
    );

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
