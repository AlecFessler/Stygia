// Fixture: symbol-anchored skip survives upstream line shifts.
//
// Reproduces the bd-na6c trap shape (in-source comment block shifts a
// downstream entity, would invalidate any SHA-pinned line-range skip
// entry) by placing a long doc comment between kEntry and the EndReason
// declaration. The fixture's skip.txt contains:
//   1. A symbol-anchored entry for EndReason.symbolHit — hash is over
//      the entity's normalized def-span (`symbolHit`); survives the
//      shift, so this variant is suppressed.
//   2. A legacy line-range entry for kEntry pointed at the wrong line
//      with a wrong hash — INVALIDATED on stderr; even when the SHA
//      pin matched, kEntry would be alive anyway (it's the entry
//      point), so this entry is purely there to confirm legacy parsing
//      still works without crashing the analyzer.
//   3. A symbol-anchored entry for EndReason.legacyDead with a
//      DELIBERATELY wrong hash to confirm the .invalidated path
//      reports a sensible diagnostic and does NOT suppress the
//      finding.
//
// Expected: legacyDead surfaces as UNUSED; symbolHit is suppressed.
//
// /////////////////////////////////////////////////////////////////
// Long doc comment to push EndReason past line ~30 — exactly the
// kind of upstream insert that broke line-pinned suppression in
// bd-mlpx, bd-kxa, and bd-o0y4.
//   - line a
//   - line b
//   - line c
//   - line d
//   - line e
//   - line f
//   - line g
// /////////////////////////////////////////////////////////////////

pub fn kEntry() void {
    accept(EndReason.alive);
}

fn accept(_: EndReason) void {}

const EndReason = enum {
    alive,
    symbolHit,
    legacyDead,
};
