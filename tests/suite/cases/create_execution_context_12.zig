// Spec §[create_execution_context] create_execution_context — test 12.
//
// "[test 12] on success, when [4] is nonzero, the target domain also
//  receives a handle with caps = `[1].target_caps`."
//
// Strategy
//   The runner spawns each test as its own capability domain. The
//   freshly-created child's handle table has, by construction:
//     slot 0  → self
//     slot 1  → initial EC
//     slot 2  → self-IDC  (caps = parent's `cridc_ceiling`)
//     slot 3  → result port (passed_handle)
//   The runner sets `cridc_ceiling = 0x3F` (bits 0-5: move, copy, crec,
//   aqec, aqvr, restart_policy), so slot 2's IDC caps include `crec`
//   (bit 2). slot 2 is therefore a valid IDC `[4]` for a cross-domain
//   `create_execution_context` and points back at this same domain —
//   so both the caller-side and target-side EC handles materialize in
//   our own handle table.
//
//   Pick `caps` and `target_caps` as distinguishable bit patterns
//   inside the caller's `ec_inner_ceiling` and the target's
//   `ec_outer_ceiling` / `ec_inner_ceiling` (the runner installs all
//   three at 0xFF, so any subset fits):
//     caps        = {term, susp}  → 0x0030
//     target_caps = {susp}        → 0x0020
//   The two patterns differ, so a slot whose caps == target_caps and
//   that did not exist pre-call must be the target-side handle.
//
//   Pre-snapshot every slot's word0; post-call walk the table looking
//   for a slot whose handleType is execution_context and whose caps
//   equal `target_caps`, AND that did not match before. That slot is
//   the target-side insertion test 12 mandates.
//
//   Set priority to 0 so it cannot exceed the priority ceiling
//   (test 06). Set affinity to 0 (kernel chooses, never out of range,
//   so test 09 cannot fire). stack_pages = 1 keeps test 08 from
//   firing. Reserved bits in [1] are zero.
//
// Action
//   1. Snapshot slot[i].word0 for i in [0, HANDLE_TABLE_MAX).
//   2. create_execution_context(
//        caps_word = caps | (target_caps << 16) | (priority << 32),
//        entry = &dummyEntry,
//        stack_pages = 1,
//        target = SLOT_SELF_IDC,
//        affinity = 0)
//      — must succeed (caller-side handle in vreg 1).
//   3. Verify caller's returned handle has caps = `caps`.
//   4. Walk the table for a slot != caller_handle whose
//      handleType == execution_context and caps == target_caps,
//      and whose word0 differs from the pre-call snapshot.
//
// Assertions
//   1: setup syscall failed (create_execution_context returned an error)
//   2: caller's returned handle does not have caps = `caps`
//   3: no target-side EC handle with caps = `target_caps` was inserted
//      into a previously-empty slot
//
// Spec gap
//   The runner spawns each test in its own capability domain. The only
//   cross-domain target available without an additional ELF is the
//   slot-2 self-IDC, which loops back to the calling domain. That keeps
//   the verification self-contained but means caller and target share
//   one handle table; the spec wording "the target domain also receives
//   a handle" is exercised here as "a second slot in this same table is
//   populated with caps = target_caps". A two-domain variant would
//   require a second embedded ELF in the runner manifest.

const lib = @import("lib");

const caps_mod = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const Cap = caps_mod.Cap;
const EcCap = caps_mod.EcCap;
const HandleId = caps_mod.HandleId;
const HandleType = caps_mod.HandleType;

pub fn main(cap_table_base: u64) void {
    const caller_caps = EcCap{ .term = true, .susp = true };
    const target_caps_value = EcCap{ .susp = true };

    const caps_u16: u64 = @as(u64, caller_caps.toU16());
    const target_caps_u16: u64 = @as(u64, target_caps_value.toU16());
    const priority: u64 = 0;

    // §[create_execution_context] caps word layout:
    //   bits  0-15: caps
    //   bits 16-31: target_caps
    //   bits 32-33: priority
    const caps_word: u64 =
        caps_u16 |
        (target_caps_u16 << 16) |
        (priority << 32);

    // Snapshot every slot's word0 so we can later distinguish a
    // newly-populated slot from one that was already populated.
    const tbl: [*]const Cap = @ptrFromInt(cap_table_base);
    var pre: [caps_mod.HANDLE_TABLE_MAX]u64 = undefined;
    {
        var i: usize = 0;
        while (i < caps_mod.HANDLE_TABLE_MAX) {
            pre[i] = tbl[i].word0;
            i += 1;
        }
    }

    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const result = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages
        @as(u64, caps_mod.SLOT_SELF_IDC),
        0, // affinity (kernel chooses)
    );
    if (testing.isHandleError(result.v1)) {
        testing.fail(1);
        return;
    }

    const caller_handle: HandleId = @truncate(result.v1 & 0xFFF);

    // The caller-side handle's caps must equal `caps` (test 11's
    // assertion, included here as a guard so a kernel that returns the
    // wrong caps doesn't masquerade as test 12 passing).
    const caller_cap = caps_mod.readCap(cap_table_base, caller_handle);
    if (caller_cap.caps() != caller_caps.toU16()) {
        testing.fail(2);
        return;
    }

    // Walk the table for the target-side handle: a slot other than
    // caller_handle whose word0 changed (i.e., slot was empty / had a
    // different value before), whose handleType is execution_context,
    // and whose caps equal target_caps.
    var found = false;
    var i: usize = 0;
    while (i < caps_mod.HANDLE_TABLE_MAX) {
        if (i != @as(usize, caller_handle)) {
            const cur = tbl[i];
            if (cur.word0 != pre[i] and
                cur.handleType() == HandleType.execution_context and
                cur.caps() == target_caps_value.toU16())
            {
                found = true;
                break;
            }
        }
        i += 1;
    }
    if (!found) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
