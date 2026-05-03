// Spec §[restart_semantics] Restart Semantics — test 01.
//
// "[test 01] returns E_PERM if `create_execution_context` is called
//  with `caps.restart_policy` exceeding the calling domain's
//  `restart_policy_ceiling.ec_restart_max`."
//
// Strategy
//   `restart_policy` on an EC handle is a 2-bit numeric field
//   (0=kill / 1=restart_at_entry / 2=persist / 3=_reserved) bounded
//   at create time by the calling domain's `ec_restart_max` field
//   in `restart_policy_ceiling`. Test 01 specifically exercises the
//   create-time bound on `create_execution_context`.
//
//   The runner spawns each test in a child capability domain whose
//   `ceilings_outer` encodes `ec_restart_max = 2` (see
//   runner/primary.zig — restart_policy_ceiling = 0x03FE puts
//   ec_restart_max in bits 0-1 of the field = 0b10). Asking for
//   `caps.restart_policy = 3` therefore exceeds the ceiling and is
//   the value the spec test calls out.
//
//   Holding all other ceiling/check inputs valid:
//     - target = 0 (self) → no IDC-handle E_BADCAP path (test 07)
//       and no IDC-side `crec` E_PERM path (test 02)
//     - stack_pages = 1 → not zero (test 08)
//     - affinity = 0 → "any core" sentinel, no out-of-range bits
//       (test 09)
//     - caps without reserved bits set (test 10)
//     - caps subset of self's `ec_inner_ceiling` (test 03): the
//       child's self-handle was minted with crec etc., but EC
//       cap bits susp/term/restart_policy=3 are ec-only — the
//       child's ec_inner_ceiling = 0xFF (set by the runner) covers
//       the low 8 EC cap bits; restart_policy lives in bits 8-9
//       which are NOT in the inner ceiling field (bits 0-7) and
//       are gated separately by ec_restart_max
//     - priority = 0 (well within ceiling)
//
//   The only spec-mandated failure path that fits is E_PERM via
//   the restart_policy_ceiling check from §[restart_semantics].
//
// Action
//   1. create_execution_context(caps={restart_policy=3, susp,
//      term}, entry=&dummyEntry, stack_pages=1, target=self,
//      affinity=0)
//
// Assertion
//   1: create_execution_context returned something other than
//      E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // restart_policy = 3 exceeds the child domain's ec_restart_max
    // (= 2) supplied by the runner. Other cap bits are kept inside
    // the child's ec_inner_ceiling so they cannot trip a separate
    // E_PERM via test 03.
    const ec = caps.EcCap{
        .susp = true,
        .term = true,
        .restart_policy = 3,
    };
    // §[create_execution_context] caps word: caps in bits 0-15,
    // target_caps in 16-31 (ignored when target=self), priority in
    // bits 32-33. Keep priority = 0 to stay under the caller's
    // priority ceiling (no E_PERM via test 06).
    const caps_word: u64 = @as(u64, ec.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const result = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages — non-zero (test 08 guard)
        0, // target = self (avoids tests 02/07)
        0, // affinity = any (avoids test 09)
    );

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
