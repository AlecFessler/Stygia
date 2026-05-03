// Spec §[create_var] — test 20.
//
// "[test 20] on success, field1 contains `[2].props` together with
//  `[3]` pages."
//
// Strategy
//   Mint a regular VAR (mmio=0, dma=0) along the same prelude every
//   other "success-path" create_var test uses (see create_var_05 and
//   acquire_vars_06): caps={r,w}, props.cur_rwx=0b011, props.sz=0
//   (4 KiB), props.cch=0 (wb), pages=4, preferred_base=0,
//   device_region=0. None of the E_PERM / E_INVAL / E_BADCAP rejection
//   paths fire, so the kernel must take the success branch.
//
//   Then read the new handle's slot out of the read-only-mapped cap
//   table (§[capabilities]) and verify field1's bit layout matches the
//   §[var] field1 layout for the props we passed and the page count we
//   asked for. Per spec:
//
//     field1 bits 0-31  : page_count        (32 bits)
//     field1 bits 32-33 : sz                (2 bits, immutable)
//     field1 bits 34-35 : cch               (2 bits, immutable)
//     field1 bits 36-38 : cur_rwx           (3 bits)
//     field1 bits 39-40 : map               (2 bits; 0 = unmapped)
//     field1 bits 41-52 : device            (12 bits; 0 unless dma=1)
//     field1 bits 53-63 : _reserved
//
//   For a fresh non-DMA VAR with no `map_pf` / `map_mmio` yet, both
//   `map` and `device` must be 0 (per §[map_pf] test 11 the map field
//   begins at 0 and only flips to 1 when a page_frame is installed).
//   So we can compare the entire field1 word against the expected
//   encoding bit-for-bit.
//
//   Expected field1 = (cur_rwx << 36) | (cch << 34) | (sz << 32) | pages
//                   = (0b011  << 36) | (0    << 34) | (0  << 32) | 4
//                   = (3 << 36) | 4
//
//   The test header documents the props -> field1 remap because the
//   props word and field1 use different bit positions for the same
//   fields. props (the syscall arg) packs cur_rwx in bits 0-2, sz in
//   bits 3-4, cch in bits 5-6; field1 packs them at bits 36-38, 32-33,
//   34-35 respectively.
//
// Action
//   1. createVar(caps={r,w}, props={cur_rwx=0b011, sz=0, cch=0},
//                pages=4, preferred_base=0, device_region=0)
//      — must return a VAR handle in vreg 1.
//   2. readCap(cap_table_base, returned_handle_id) — read field1.
//   3. Compare field1 against the expected packed encoding.
//
// Assertions
//   1: createVar returned an error code in vreg 1 (success path
//      precondition broken — we cannot proceed to verify field1).
//   2: the returned slot's handleType is not virtual_address_range
//      (kernel installed something other than a VAR — also kills the
//      precondition).
//   3: field1 did not equal the expected (cur_rwx << 36) | pages
//      packed encoding (the spec assertion under test).

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

const PAGES: u64 = 4;
const CUR_RWX: u64 = 0b011; // r|w
const SZ: u64 = 0; // 4 KiB
const CCH: u64 = 0; // wb

pub fn main(cap_table_base: u64) void {
    const var_caps = caps.VarCap{ .r = true, .w = true };
    const props: u64 = (CCH << 5) | (SZ << 3) | CUR_RWX;

    const cv = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        PAGES,
        0, // preferred_base — kernel chooses
        0, // device_region — ignored when caps.dma = 0
    );
    if (testing.isHandleError(cv.v1)) {
        testing.fail(1);
        return;
    }

    const handle_id: u12 = @truncate(cv.v1 & 0xFFF);
    const cap = caps.readCap(cap_table_base, handle_id);

    if (cap.handleType() != caps.HandleType.virtual_address_range) {
        testing.fail(2);
        return;
    }

    // §[var] field1 layout: page_count[0..31] | sz[32..33] | cch[34..35]
    // | cur_rwx[36..38] | map[39..40] | device[41..52]. For a fresh
    // non-DMA VAR with no installations: map = 0, device = 0.
    const expected_field1: u64 =
        (CUR_RWX << 36) |
        (CCH << 34) |
        (SZ << 32) |
        PAGES;

    if (cap.field1 != expected_field1) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
