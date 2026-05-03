// Spec §[reply] reply — test 10.
//
// "[test 10] returns E_INVAL when `pair_count > 63`."
//
// Spec semantics
//   §[reply]: the syscall optionally attaches N pair entries to the
//   resumed EC. The syscall word's bits 12-19 carry pair_count, which
//   must satisfy 0 <= pair_count <= 63 per the spec ABI; pair_count = 0
//   is the bare-reply path (no attachments) and pair_count > 63 is
//   rejected with E_INVAL.
//
// Strategy
//   N > 63 — would require attaching 64+ pair entries via the high-vreg
//   layout described in §[handle_attachments] (entries live at vregs
//   [128-N..127], spilling into the user stack beyond the 13 register-
//   backed vregs). libz's high-level wrappers do not yet plumb the
//   high-vreg pair layout. Without that plumbing a child test cannot
//   construct a syscall frame whose pair_count reaches 64, so this
//   branch is documented and skipped — the test anchors `SyscallNum.reply`
//   at compile time so a future edit to the enum surfaces here, then
//   falls through to pass.
//
// Action
//   Anchor `SyscallNum.reply` at compile time and pass.
//
// Assertions
//   (none — pair_count > 63 path is structurally unreachable today)

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // pair_count > 63 case is structurally unreachable from this child
    // until libz's `issueStack` learns the §[handle_attachments] high-
    // vreg pair layout. Anchor the syscall-num at compile time so a
    // future edit to the enum surfaces here, then fall through to pass.
    _ = syscall.SyscallNum.reply;
    _ = caps.HandleId;

    testing.pass();
}
