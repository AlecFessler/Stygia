// Spec §[create_capability_domain] — test 28.
//
// "[test 28] on success, the new domain's `idc_rx` in field0 is set to
//  the value supplied in [1]."
//
// Strategy
//   The test ELF runs as the initial EC of a brand-new capability
//   domain that the runner (`runner/primary.zig`) created via
//   `create_capability_domain`. From this seat the test IS "the new
//   domain": its own self-handle at slot 0 of its read-only cap table
//   was minted by the kernel during the same create call whose
//   post-condition we are asserting.
//
//   Per §[capability_domain] Self handle, field0 lays idc_rx at bits
//   32-39:
//     bits  0-7   ec_inner_ceiling
//     bits  8-23  var_inner_ceiling
//     bits 24-31  cridc_ceiling
//     bits 32-39  idc_rx
//     bits 40-47  pf_ceiling
//     bits 48-55  vm_ceiling
//     bits 56-63  port_ceiling
//
//   Per §[create_capability_domain] [1] caps:
//     bits  0-15  self_caps
//     bits 16-23  idc_rx
//     bits 24-63  _reserved
//
//   The runner supplies `idc_rx` via the [1] caps word at child-spawn
//   time. The expected value is fixed by the runner contract — see
//   `runner/primary.zig` `caps_word` construction. Kept as an explicit
//   constant in this file so a runner change that drops/changes
//   idc_rx in [1] forces this test to be re-evaluated against the
//   actual contract rather than silently re-pinning to a moving
//   target.
//
//   `idc_rx` is part of the static handle layout — it is set at
//   create time and not a kernel-mutable snapshot — so a fresh
//   `readCap` of slot 0 is authoritative without calling `sync`
//   (cf. restrict_06.zig).
//
// Action
//   1. readCap(cap_table_base, SLOT_SELF)  — read this domain's own
//      self-handle from the read-only cap table.
//   2. Verify the slot is the `capability_domain_self` type tag.
//   3. Extract field0 bits 32-39 and compare against the value the
//      runner supplied in [1].
//
// Assertions
//   1: slot 0 is not a capability_domain_self handle (runner contract
//      drift or kernel mis-installed the self-handle).
//   2: field0[32:40] does not equal the runner-supplied idc_rx — the
//      spec post-condition this test guards.
//
// Coupling note
//   The runner currently passes [1].caps with `self_caps` populated
//   from `caps.SelfCap{...}.toU16()` and `idc_rx` left at zero (bits
//   16-23 of the caps word = 0). If/when the runner starts passing a
//   non-zero idc_rx, update `EXPECTED_IDC_RX` to match. The assertion
//   semantics (slot-0 idc_rx == runner-supplied value) are stable.

const lib = @import("lib");

const caps = lib.caps;
const testing = lib.testing;

// Runner-supplied idc_rx in the [1] caps word, bits 16-23. Mirrors
// `runner/primary.zig`'s `self_caps` construction, which packs
// `SelfCap.toU16()` into bits 0-15 and leaves bits 16-23 (idc_rx)
// zero. If the runner contract changes, update this constant.
const EXPECTED_IDC_RX: u8 = 0;

pub fn main(cap_table_base: u64) void {
    const cap = caps.readCap(cap_table_base, caps.SLOT_SELF);

    if (cap.handleType() != caps.HandleType.capability_domain_self) {
        testing.fail(1);
        return;
    }

    // field0 bits 32-39 = idc_rx.
    const idc_rx: u8 = @truncate((cap.field0 >> 32) & 0xFF);
    if (idc_rx != EXPECTED_IDC_RX) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
