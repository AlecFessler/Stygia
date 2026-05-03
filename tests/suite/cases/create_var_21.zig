// Spec §[create_var] — test 21.
//
// "[test 21] on success, when [4] preferred_base is nonzero and the
//  range is available, the assigned base address equals `[4]`."
//
// Strategy
//   Drive the same regular-VAR success prelude every other create_var
//   success test uses (caps={r,w}, props.cur_rwx=0b011, props.sz=0,
//   pages=1) but with a nonzero preferred_base. On success the kernel
//   returns the assigned base in vreg 2; the spec assertion is that
//   when the preferred range is free, that base equals `[4]`.
//
//   "Range is available" is a runtime fact, not a static one: a stray
//   start-up mapping (cap table, primary stack, embedded ELF region,
//   etc.) anywhere in user vaddr space could in principle collide with
//   any candidate we pick. Spec §[create_var] doesn't pin the kernel's
//   layout, so test 21 only commits the kernel to honoring `[4]` *if*
//   the range is free — if every candidate we try collides, the kernel
//   has the latitude to assign a different base and we cannot isolate
//   test 21 from the spec ambiguity around runtime layout.
//
//   Spec §[address_space] also requires preferred_base to lie wholly
//   within the static zone (spec test 23) — a request outside it
//   returns E_INVAL. Candidates are picked at the bottom of the
//   x86-64 static zone (0x0000_1000_0000_0000) so they satisfy both
//   the static-zone constraint and the page-alignment requirement.
//
// Action
//   For each preferred_base in the candidate list:
//     1. createVar(caps={r,w}, props={cur_rwx=0b011, sz=0, cch=0},
//                  pages=1, preferred_base=<candidate>, device_region=0)
//     2. If success, check cv.v2 == candidate. If yes, pass.
//        Otherwise try the next candidate.
//   If every candidate either errored or returned a different base,
//   fail with assertion 2.
//
// Assertions
//   1: a createVar call returned an unexpected error word in vreg 1
//      (preferred_base in user vaddr space + page-aligned shouldn't
//      hit the spec's E_PERM/E_INVAL/E_BADCAP gates, so any error here
//      is a setup break, not the spec assertion).
//   2: every candidate succeeded but none returned a base matching the
//      requested preferred_base — runtime layout collided with all
//      candidates and we couldn't isolate the test 21 assertion.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

const PAGES: u64 = 1;
const CUR_RWX: u64 = 0b011; // r|w
const SZ: u64 = 0; // 4 KiB
const CCH: u64 = 0; // wb

// preferred_base must lie wholly within the static zone (spec
// §[address_space] / §[create_var] test 23). On x86-64 the static
// zone starts at 0x0000_1000_0000_0000.
const candidates = [_]u64{
    0x0000_1000_0000_0000,
    0x0000_1000_0001_0000,
    0x0000_1000_0010_0000,
};

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const var_caps = caps.VarCap{ .r = true, .w = true };
    const props: u64 = (CCH << 5) | (SZ << 3) | CUR_RWX;

    for (candidates) |preferred_base| {
        const cv = syscall.createVar(
            @as(u64, var_caps.toU16()),
            props,
            PAGES,
            preferred_base,
            0,
        );
        if (testing.isHandleError(cv.v1)) {
            testing.fail(1);
            return;
        }
        if (cv.v2 == preferred_base) {
            testing.pass();
            return;
        }
        // Otherwise the kernel chose a different base for this candidate
        // (range not available); fall through to the next candidate.
    }

    testing.fail(2);
}
