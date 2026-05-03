// Spec §[capability_domain] create_capability_domain — test 27.
//
// "[test 27] on success, the new domain's `ec_outer_ceiling` and
//  `vmar_outer_ceiling` in field1 are set to the values supplied in [3]."
//
// Strategy
//   This test runs *inside* a freshly-created capability domain — it
//   IS the new domain that test 27 talks about. The runner/primary
//   spawned it via `create_capability_domain` and passed a known
//   `ceilings_outer` word as syscall arg [3]. Per §[capability_domain]
//   Self handle, the new domain's self-handle field1 carries
//   ec_outer_ceiling at bits 0-7 and vmar_outer_ceiling at bits 8-15.
//   That self-handle lives at slot 0 of our own handle table and is
//   visible read-only via `cap_table_base` (the entry-point arg).
//
//   So the post-condition for test 27 reduces to: read slot 0, mask
//   off field1[0:16], and assert it equals the runner-supplied value.
//
//   The runner's `ceilings_outer` is documented in `runner/primary.zig`
//   `spawnOne` as `0x0000_003F_03FE_FFFF`, which gives:
//     ec_outer_ceiling  (bits  0-7)  = 0xFF
//     vmar_outer_ceiling (bits  8-15) = 0xFF
//   The full low-16-bit slice is therefore 0xFFFF. We compare against
//   that exact slice rather than reconstructing per-field to keep the
//   assertion tight against [3]'s low bytes verbatim.
//
//   Field1 carries `restart_policy_ceiling` (bits 16-31) and
//   `fut_wait_max` (bits 32-37) above the two outer ceilings. Test 27
//   only governs ec_outer_ceiling and vmar_outer_ceiling, so we mask
//   field1 to its low 16 bits before the equality check; the higher
//   fields are out of scope here and exercised by other tests in this
//   section.
//
// Action
//   1. readCap(cap_table_base, SLOT_SELF) — pull the self-handle.
//   2. field1 & 0xFFFF — extract ec_outer_ceiling || vmar_outer_ceiling.
//   3. compare against EXPECTED_OUTER_CEILINGS_LOW16 (mirrors the
//      runner's documented `ceilings_outer` low bytes).
//
// Assertions
//   1: slot 0 is not a capability_domain_self handle (sanity — the
//      kernel placed something other than the self-handle here).
//   2: field1 bits 0-15 do not equal the supplied ec_outer/var_outer
//      values from the runner's ceilings_outer.
//
// Spec status: faithful. The kernel is unimplemented at this branch
// point; this test only needs to compile and link. Once the kernel
// honours `ceilings_outer`, the assertions exercise the post-condition
// directly without needing a sync — field1 of the self-handle is
// kernel-mutable, but ceilings are write-once at create time so the
// initial snapshot is authoritative.

const lib = @import("lib");

const caps = lib.caps;
const testing = lib.testing;

// Mirrors `ceilings_outer` in tests/suite/runner/primary.zig:spawnOne.
//   bits  0-7  ec_outer_ceiling  = 0xFF
//   bits  8-15 vmar_outer_ceiling = 0xFF
// If the runner's value is ever retuned, update both sites in lockstep.
const EXPECTED_OUTER_CEILINGS_LOW16: u64 = 0xFFFF;

pub fn main(cap_table_base: u64) void {
    const self = caps.readCap(cap_table_base, caps.SLOT_SELF);

    if (self.handleType() != .capability_domain_self) {
        testing.fail(1);
        return;
    }

    const outer_low16: u64 = self.field1 & 0xFFFF;
    if (outer_low16 != EXPECTED_OUTER_CEILINGS_LOW16) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
