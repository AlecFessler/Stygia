// Spec §[create_capability_domain] — test 13.
//
// "[test 13] returns E_BADCAP if `elf_page_frame` is not a valid page
// frame handle."
//
// Strategy
//   The child capability domain's table is populated by the kernel at
//   `create_capability_domain` time:
//     slot 0  → self
//     slot 1  → initial EC
//     slot 2  → self-IDC
//     slot 3+ → passed_handles (here: just the result port at slot 3)
//   By construction every other slot is empty. Slot 4095 — the maximum
//   12-bit handle id — is therefore guaranteed to be invalid.
//
//   To reach the [test 13] BADCAP path we have to pass the earlier
//   E_PERM checks ([test 01]-[test 12]) and the reserved-bit E_INVAL
//   ([test 17]). The simplest construction that does so is:
//     - caps           = 0  (subset of any caller self-handle caps;
//                            no reserved bits)
//     - ceilings_inner = 0  (every per-type ceiling field zeroed; each
//                            is trivially a subset of the caller's)
//     - ceilings_outer = 0  (likewise for outer ceilings, restart
//                            policy ceiling, fut_wait_max)
//     - passed_handles = empty slice (no test 14 BADCAP path engages)
//   The caller (this test domain) has `crcd` on its self-handle by
//   construction in the runner's spawnOne, so [test 01] does not fire.
//   The only remaining error-input is elf_page_frame, which we set to
//   the guaranteed-invalid empty slot, leaving E_BADCAP as the
//   sole applicable failure path.
//
// Action
//   create_capability_domain(0, 0, 0, invalid_handle, &.{}).
//
// Assertion
//   result.v1 == E_BADCAP  (assertion id 1)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const empty_slot: u12 = caps.HANDLE_TABLE_MAX - 1;

    const result = syscall.createCapabilityDomain(
        0, // caps: zero — trivial subset of caller's self caps
        0, // ceilings_inner: every field zeroed
        0, // ceilings_outer: every field zeroed
        empty_slot, // elf_page_frame: invalid handle id
        0, // initial_ec_affinity
        &.{}, // passed_handles: empty
    );

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
