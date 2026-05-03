// Spec §[execution_context] create_execution_context — test 04.
//
// "[test 04] returns E_PERM if [4] is nonzero and caps is not a subset
//  of the target domain's `ec_outer_ceiling`."
//
// Strategy
//   The check fires only when [4] is a valid IDC handle with `crec`
//   that targets a domain whose `ec_outer_ceiling` does not cover the
//   caller's requested EC caps. Two ways to set that up:
//
//     a) Stand up a fresh child capability domain with
//        `ec_outer_ceiling` restricted, then invoke
//        `create_execution_context` against the IDC the parent gets
//        back. Faithful but heavy: it requires synthesizing a valid
//        ELF image in a page frame, which the v3 spec does not pin
//        down precisely (the loader contract beyond §[create_capability_domain]
//        test 15/16 isn't normative). SPEC AMBIGUITY.
//
//     b) Reuse the test's own self-IDC at `SLOT_SELF_IDC` (slot 2),
//        which references the calling domain. The runner
//        (`primary.zig`) sets the child's `ec_outer_ceiling` to 0xFF
//        — all 8 bits — and `cridc_ceiling` to 0x3F so the slot-2 IDC
//        carries `crec` (bit 2 of IDC caps). With those settings:
//          - test 01 (self-handle lacks crec) cannot fire — the child
//            self-handle has `crec` per primary.zig.
//          - test 02 ([4] lacks crec) cannot fire — slot-2 IDC has crec.
//          - test 03 ([4] = 0 path) cannot fire — [4] = 2 ≠ 0.
//          - test 05 (target_caps not subset of ec_inner_ceiling)
//            cannot fire — we leave `target_caps` as 0.
//          - test 06 (priority exceeds ceiling) cannot fire — priority
//            field is 0; the child's pri ceiling is 3.
//          - test 07 ([4] not a valid IDC) cannot fire — slot 2 is a
//            valid IDC.
//          - tests 08-10 (E_INVAL paths) cannot fire — stack_pages = 1,
//            affinity = 0, [1] reserved bits clean.
//        That leaves test 04 as the sole spec-mandated failure path
//        when caps carries any bit outside the 8-bit ec_outer_ceiling.
//
//   Path (b) is taken here. The test sets `caps = bind` (EC cap
//   bit 10), which sits outside the target domain's 8-bit
//   ec_outer_ceiling regardless of what value is encoded there:
//   `ec_outer_ceiling` is field1 bits 0-7, so any cap bit at index 8
//   or higher cannot be covered by it.
//
//   SPEC AMBIGUITY: §[capability_domain] field1 lays out
//   `ec_outer_ceiling` as 8 bits (0-7) but EC cap handles span 13
//   bits (0-12). The spec does not pin which non-overlap bits fall
//   under which check (some bits — `restart_policy` 8-9 — are
//   governed by `restart_policy_ceiling`; `bind`/`rebind`/`unbind`
//   bits 10-12 are gated only by ec_outer_ceiling). Setting `bind`
//   here keeps the failure attributable to test 04's check rather
//   than to the restart_policy_ceiling check.
//
// Action
//   1. create_execution_context(
//        caps={caps={bind}, target_caps=0, priority=0},
//        entry=&dummyEntry,
//        stack_pages=1,
//        target=SLOT_SELF_IDC,
//        affinity=0,
//      )
//      — must return E_PERM.
//
// Assertions
//   1: create_execution_context returned something other than E_PERM.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // EC caps with `bind` set (bit 10). The 8-bit ec_outer_ceiling
    // field cannot cover bits 8+, so this is guaranteed not a subset
    // of the target domain's ec_outer_ceiling regardless of the
    // ceiling's value in bits 0-7.
    const ec_caps = caps.EcCap{ .bind = true };

    // §[create_execution_context] caps word:
    //   bits  0-15: caps         — set to {bind}
    //   bits 16-31: target_caps  — 0 (kept clean to not collide with
    //                              test 05's check on ec_inner_ceiling)
    //   bits 32-33: priority     — 0 (within the child's pri ceiling)
    const caps_word: u64 = @as(u64, ec_caps.toU16());

    const entry: u64 = @intFromPtr(&testing.dummyEntry);

    const result = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages: nonzero so test 08 cannot fire
        @as(u64, caps.SLOT_SELF_IDC), // [4]: nonzero; valid IDC with crec
        0, // affinity: 0 = any core; passes test 09
    );

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
