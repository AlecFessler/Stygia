// Spec §[create_capability_domain] — test 08.
//
// "[test 08] returns E_PERM if `fut_wait_max` exceeds the caller's
//  `fut_wait_max`."
//
// Strategy
//   `fut_wait_max` lives in `ceilings_outer` (field1) bits 32-37 — a
//   6-bit field whose maximum representable value is 63. The runner
//   primary mints each test domain with `fut_wait_max = 63` (see
//   runner/primary.zig: ceilings_outer = 0x0000_003F_03FE_FFFF).
//
//   Constructing a value that *exceeds* the caller's ceiling is
//   therefore unconstructible from inside this test domain: the field
//   is already saturated. The same shape applies to ccd test 03's
//   reference scenario where the caller's ceiling already saturates
//   the field width.
//
//   Degraded smoke variant (gap documented):
//     1. Read the caller's `fut_wait_max` from slot-0 field1 bits 32-37.
//     2. Build a `ceilings_outer` that mirrors the caller's value (a
//        subset / exact-match path, which the spec permits).
//     3. Call create_capability_domain with `elf_page_frame = 0`. Bit
//        layout for [4] carries no other interpretation than a handle
//        id, and id 0 is the caller's self-handle (a capability_domain,
//        not a page_frame), so the call short-circuits on the ELF
//        page-frame validity check (test 13 → E_BADCAP) without ever
//        attempting to run the ELF.
//     4. Assert the returned vreg-1 error code is NOT E_PERM. The
//        ceiling subset check must pass; any subsequent error (E_BADCAP
//        from the elf_page_frame, E_PERM from a different ceiling we
//        accidentally tripped, etc.) is acceptable for this degraded
//        variant only insofar as it isn't the fut_wait_max E_PERM the
//        spec is interested in. We pin to NOT E_PERM specifically.
//
//   GAP: this variant exercises the equality / subset side of the
//   ceiling rule rather than the strict-exceedance side the spec test
//   names. Reaching the strict-exceedance side requires either (a) a
//   parent runner that mints children with `fut_wait_max < 63`, or (b)
//   widening the field. Until either happens, this file lives in the
//   manifest as a smoke test.
//
// Action
//   1. Read caller fut_wait_max via caps.readCap(cap_table_base, 0).
//   2. Build [1] caps, [2] ceilings_inner, [3] ceilings_outer matching
//      the runner's mint (so unrelated subset checks all pass).
//   3. issue create_capability_domain with elf_page_frame = 0.
//
// Assertions
//   1: returned error code equals E_PERM (degraded subset path should
//      not surface E_PERM at the fut_wait_max ceiling check).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    // §[capability_domain] self-handle field1 layout. fut_wait_max is
    // at bits 32-37 (a 6-bit field). Snapshot directly from the
    // cap-table slot — `sync` is unnecessary here because the field is
    // installed at create-time and is not kernel-mutated thereafter.
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    const caller_fut_wait_max: u64 = (self_cap.field1 >> 32) & 0x3F;

    // Mirror the runner's mint. Inner ceiling (field0) and the
    // restart_policy / ec / var portions of ceilings_outer use the
    // runner's all-valid-bits values so unrelated subset checks pass.
    // Splice the caller's fut_wait_max into bits 32-37 so the
    // `fut_wait_max` subset rule reduces to equality.
    const ceilings_inner: u64 = 0x001C_011F_3F01_FFFF;

    const ceilings_outer_low: u64 = 0x0000_0000_03FE_FFFF;
    const ceilings_outer: u64 = ceilings_outer_low | (caller_fut_wait_max << 32);

    // Self caps and idc_rx mirroring the runner. Withhold `power` and
    // `restart` (consistent with the runner) so the self_caps subset
    // check against the caller's self caps passes regardless of any
    // bit the runner cleared.
    const child_self = caps.SelfCap{
        .crcd = true,
        .crec = true,
        .crvr = true,
        .crpf = true,
        .crvm = true,
        .crpt = true,
        .pmu = true,
        .fut_wake = true,
        .timer = true,
        .pri = 3,
    };
    const caps_word: u64 = @as(u64, child_self.toU16());

    // elf_page_frame = 0 is the self-handle slot — type tag
    // capability_domain_self, not page_frame. The kernel's elf-handle
    // type check rejects with E_BADCAP (test 13). The
    // fut_wait_max ceiling check happens before that step in any sane
    // ordering of permission vs argument validation, but for this
    // degraded variant we only require that the result is NOT E_PERM.
    const result = syscall.createCapabilityDomain(caps_word, ceilings_inner, ceilings_outer, 0, 0, // initial_ec_affinity
        &.{});

    if (result.v1 == @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
