// Spec §[create_page_frame] — test 10.
//
// "[test 10] on success, field0 contains `[3]` pages and `[2].props.sz`."
//
// Strategy
//   Mint a page frame along the same prelude that create_page_frame_02
//   uses for its success-path smoke variant: caps.r/w set (within
//   ceiling's max_rwx = 0b111), caps.max_sz = 0 (4 KiB; within
//   ceiling's max_sz = 3 and not reserved), props.sz = 0 (≤ caps.max_sz
//   and not reserved), pages = 2 (non-zero, satisfies test 04). All
//   reserved bits in caps and props are zero (test 08). Self-handle
//   `crpf` is granted by the runner. None of the rejection paths fire,
//   so the kernel must take the success branch.
//
//   Then read the new handle's slot out of the read-only-mapped cap
//   table (§[capabilities]) and verify field0's bit layout matches the
//   §[page_frame] field0 layout for the pages and sz we passed. Per
//   spec:
//
//     field0 bits 0-31  : page_count        (32 bits)
//     field0 bits 32-33 : sz                (2 bits, immutable)
//     field0 bits 34-63 : _reserved
//
//   Expected field0 = (sz << 32) | pages
//                   = (0 << 32) | 2
//                   = 2
//
//   The test header documents the props -> field0 remap because props
//   (the syscall arg) packs sz in bits 0-1, while field0 packs sz in
//   bits 32-33.
//
// Action
//   1. createPageFrame(caps={r,w}, props={sz=0}, pages=2) — must
//      return a page_frame handle in vreg 1.
//   2. readCap(cap_table_base, returned_handle_id) — read field0.
//   3. Compare field0 against the expected packed encoding.
//
// Assertions
//   1: createPageFrame returned an error code in vreg 1 (success-path
//      precondition broken — we cannot proceed to verify field0).
//   2: the returned slot's handleType is not page_frame (kernel
//      installed something other than a page_frame — also kills the
//      precondition).
//   3: field0 did not equal the expected (sz << 32) | pages packed
//      encoding (the spec assertion under test).

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

const PAGES: u64 = 2;
const SZ: u64 = 0; // 4 KiB

pub fn main(cap_table_base: u64) void {
    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const props: u64 = SZ; // props.sz at bits 0-1; reserved bits zero

    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        props,
        PAGES,
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }

    const handle_id: u12 = @truncate(cpf.v1 & 0xFFF);
    const cap = caps.readCap(cap_table_base, handle_id);

    if (cap.handleType() != caps.HandleType.page_frame) {
        testing.fail(2);
        return;
    }

    // §[page_frame] field0 layout: page_count[0..31] | sz[32..33].
    // For a freshly-created page_frame the upper bits are reserved (0).
    const expected_field0: u64 =
        (SZ << 32) |
        PAGES;

    if (cap.field0 != expected_field0) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
