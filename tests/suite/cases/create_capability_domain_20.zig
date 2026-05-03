// Spec §[create_capability_domain] create_capability_domain — test 20.
//
// "[test 20] on success, the new domain's handle table contains the
//  self-handle at slot 0 with caps = `self_caps`."
//
// Strategy
//   Each spec test ELF is itself spawned by the runner primary as the
//   initial EC of a freshly-minted capability domain. That spawn IS a
//   `create_capability_domain` call, with `self_caps` populated from
//   `runner/primary.zig`'s `child_self` SelfCap struct (crcd, crec,
//   crvr, crpf, crvm, crpt, pmu, fut_wake, timer all set, pri = 3).
//
//   The kernel maps the new domain's read-only cap table view at the
//   pointer passed in rdi (vreg 1) at entry — surfaced here as the
//   `cap_table_base` argument to main. Slot 0 of that view is — by the
//   spec line under test — the self-handle minted with the exact
//   `self_caps` the primary supplied.
//
//   Read slot 0 directly out of the cap table and confirm:
//     1. the type tag is `capability_domain_self` (sanity: the slot
//        actually holds the self-handle the spec says lives there),
//     2. the caps field equals the primary's `child_self.toU16()` —
//        i.e. the `self_caps` value that was passed in [1].
//
//   The caps field is part of the static handle layout (word0 bits
//   48-63 per §[capabilities]); it is not a kernel-mutable snapshot in
//   field0/field1, so a fresh `readCap` is authoritative without
//   calling `sync` first.
//
//   The assertion is degraded relative to a perfectly hermetic test
//   that would itself call `create_capability_domain` on a sub-child
//   and inspect that child's slot 0 — but the new domain's handle
//   table is mapped read-only into the new domain only, so the parent
//   has no way to read it. Asserting on the kernel's setup of OUR own
//   slot 0 exercises the same kernel code path with the same
//   post-condition.
//
// Coupling note
//   The expected caps value mirrors `runner/primary.zig`'s
//   `child_self` literal. If that literal changes, this test must be
//   updated in lock-step. The constant is recomputed below from the
//   same `caps.SelfCap` struct shape so a field flip in primary.zig
//   surfaces here as a structural mismatch rather than a silent skew.
//
// Action
//   1. readCap(cap_table_base, SLOT_SELF) — read slot 0 of our own
//      cap table.
//   2. Verify handleType == capability_domain_self.
//   3. Verify caps == expected_self_caps.
//
// Assertions
//   1: slot 0 is not tagged as capability_domain_self
//   2: slot 0's caps field does not equal the self_caps passed by the
//      primary at create_capability_domain time

const lib = @import("lib");

const caps = lib.caps;
const testing = lib.testing;

// Mirrors runner/primary.zig::spawnOne::child_self. Kept as a literal
// here (rather than imported) because tests are built as standalone
// ELFs with only `lib` and the test source on the import graph.
const expected_self = caps.SelfCap{
    .crcd = true,
    .crec = true,
    .crvr = true,
    .crpf = true,
    .crvm = true,
    .crpt = true,
    .pmu = true,
    .setwall = true,
    .fut_wake = true,
    .timer = true,
    .pri = 3,
};

pub fn main(cap_table_base: u64) void {
    const slot0 = caps.readCap(cap_table_base, caps.SLOT_SELF);

    if (slot0.handleType() != .capability_domain_self) {
        testing.fail(1);
        return;
    }

    if (slot0.caps() != expected_self.toU16()) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
