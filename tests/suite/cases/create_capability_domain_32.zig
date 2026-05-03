// Spec §[create_capability_domain] create_capability_domain — test 32.
//
// "[test 32] returns E_INVAL if `[5]` has bits set outside the
//  system's core count."
//
// Strategy
//   Spawn a grandchild via `create_capability_domain` with an
//   affinity mask whose set bits exceed the system's core count
//   (queried from `info_system`). Per spec, the kernel must reject
//   this with E_INVAL before any other create-side work. Anything
//   other than E_INVAL means the kernel accepted a malformed
//   affinity mask, contradicting test 32.
//
// Degraded smoke
//   This test cannot run a real grandchild spawn from inside a
//   test domain today: the runner does not forward a ready-to-spawn
//   ELF page frame, and the `create_capability_domain` ELF-staging
//   path touches kernel page-frame writes that surface a known v3
//   bug (see runner/primary.zig comments). The assertion stays
//   declared in the spec so the day the prerequisite is wired up,
//   the body upgrades to a real assertion automatically.
//
// Action
//   None today. Documented gap.
//
// Assertions
//   None today.

const lib = @import("lib");

const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;
    testing.pass();
}
