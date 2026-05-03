// Spec §[create_execution_context] — test 11.
//
// "[test 11] on success, the caller receives an EC handle with caps =
//  `[1].caps`."
//
// Strategy
//   Build an in-bounds create_execution_context call with target = self
//   so the spec ceiling check that applies is `caps ⊆ self's
//   ec_inner_ceiling`. The runner primary configures the child domain's
//   `ec_inner_ceiling` to 0xFF (all 8 low bits) — see runner/primary.zig
//   `ceilings_inner`. The low 8 bits of the EC cap word cover the
//   bitwise-only fields {move, copy, saff, spri, term, susp, read,
//   write} (§[execution_context]). restart_policy lives at bits 8-9 and
//   uses numeric semantics; we keep it at 0 so the matching ceiling
//   check (`restart_policy_ceiling.ec_restart_max`) trivially passes.
//
//   Pick a multi-bit caps pattern so test 11 can fail meaningfully if
//   the kernel were to drop, mask, or substitute bits: {saff, spri,
//   term, susp, read, write}. Then verify after the call that the
//   handle's cap field equals exactly those bits.
//
//   Other failure paths neutralized:
//     - test 01 (self lacks crec): primary grants crec.
//     - test 03 (caps not ⊆ ec_inner_ceiling): caps fit in low 8 bits.
//     - test 06 (priority > pri ceiling): priority = 0.
//     - test 08 (stack_pages = 0): stack_pages = 1.
//     - test 09 (affinity has out-of-range bits): affinity = 0 (any).
//     - test 10 (reserved bits in [1]): all upper bits zeroed.
//     - tests 04/05/07 (target nonzero paths): target = 0.
//     - restart_semantics test 01: caps.restart_policy = 0.
//
//   Read the post-condition out of the read-only-mapped cap table.
//   The caps field is part of the static handle layout (word0 bits
//   48-63) — not a kernel-mutable snapshot — so a fresh `readCap` is
//   authoritative without calling `sync`.
//
//   The new EC starts at `dummyEntry`, which halts forever. The test
//   EC continues independently; no synchronization is required because
//   the cap-field read targets our domain's handle table, not the
//   running EC's state.
//
// Action
//   1. create_execution_context(caps_word, &dummyEntry, 1, 0, 0)
//      — must succeed and return a handle in vreg 1.
//   2. readCap(cap_table_base, ec_handle).caps() must equal the
//      requested caps bit pattern.
//
// Assertions
//   1: create_execution_context returned an error word in vreg 1
//   2: handle's caps field after creation does not equal the requested
//      caps pattern

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const requested = caps.EcCap{
        .saff = true,
        .spri = true,
        .term = true,
        .susp = true,
        .read = true,
        .write = true,
        .restart_policy = 0,
    };
    // §[create_execution_context] caps word: bits 0-15 hold caps,
    // bits 16-31 target_caps (ignored when target = self), bits 32-33
    // priority, bits 34-63 _reserved. Set caps only.
    const caps_word: u64 = @as(u64, requested.toU16());

    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages
        0, // target = self
        0, // affinity = any core
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(1);
        return;
    }
    const ec_handle: u12 = @truncate(cec.v1 & 0xFFF);

    const cap = caps.readCap(cap_table_base, ec_handle);
    if (cap.caps() != requested.toU16()) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
