// Spec §[create_page_frame] — test 09.
//
// "[test 09] on success, the caller receives a page frame handle with
//  caps = `[1].caps`."
//
// Strategy
//   Drive create_page_frame down its success path under the runner's
//   default ceilings (tests/suite/runner/primary.zig grants `crpf` on
//   the self-handle and pf_ceiling = 0x1F, i.e. max_rwx = 0b111 and
//   max_sz = 3). With caps.max_sz = 0 (4 KiB), props.sz = 0, pages = 1,
//   and no reserved bits set, every prior gate (tests 01-08) passes,
//   so the kernel must mint a page_frame handle and the only
//   observable post-condition this test asserts is the caps readback.
//
//   Use multi-bit caps {r, w} so the assertion exercises a non-trivial
//   bit pattern and is sensitive to either bit being dropped or any
//   stray bit being set on the way through the kernel.
//
//   The caps field of a handle lives in word0 bits 48-63 of the cap
//   table entry — part of the static handle layout, not a kernel-
//   mutable field0/field1 snapshot — so a fresh `readCap` against the
//   read-only-mapped table is authoritative without `sync` (same
//   pattern as create_var_18).
//
// Action
//   1. createPageFrame(caps={r, w, max_sz=0}, props={sz=0}, pages=1)
//      — must succeed.
//   2. readCap(cap_table_base, returned_handle) — verify caps == {r,w}.
//
// Assertions
//   1: createPageFrame returned an error word in vreg 1 (success path
//      failed).
//   2: returned handle's caps field does not equal the requested caps.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const requested = caps.PfCap{ .r = true, .w = true };
    const props: u64 = 0; // sz = 0 (4 KiB)

    const cpf = syscall.createPageFrame(
        @as(u64, requested.toU16()),
        props,
        1, // pages
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const pf_handle: u12 = @truncate(cpf.v1 & 0xFFF);

    const cap = caps.readCap(cap_table_base, pf_handle);
    if (cap.caps() != requested.toU16()) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
