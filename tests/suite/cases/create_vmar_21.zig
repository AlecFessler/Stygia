// Spec §[create_vmar] — test 21.
//
// "[test 21] on success, when [4] preferred_base is nonzero and the
//  range is available, the assigned base address equals `[4]`."
//
// Strategy
//   Drive the same regular-VMAR success prelude every other create_vmar
//   success test uses (caps={r,w}, props.cur_rwx=0b011, props.sz=0,
//   pages=1) but with a nonzero preferred_base. On success the kernel
//   returns the assigned base in vreg 2; the spec assertion is that
//   when the preferred range is free, that base equals `[4]`.
//
//   "Range is available" is a runtime fact: a stray boot-time mapping
//   (cap table, primary stack, embedded ELF region) could collide with
//   any specific candidate. The spec test surfaces a binary signal —
//   either createVmar returns success with cv.v2 == preferred_base
//   (range was free and the kernel honoured the request), or it
//   returns an error indicating the range was unavailable (E_NOSPC for
//   "no room", or another well-defined refusal). What the kernel must
//   NOT do is silently relocate the VMAR to a different base while
//   reporting success — that breaks the spec contract for test 21
//   regardless of whether the user-supplied address happened to
//   collide. We probe a small candidate list to dodge a single
//   unlucky collision and fail loudly the first time the kernel
//   succeeds with a base != preferred_base.
//
//   Spec §[address_space] requires preferred_base to lie wholly within
//   the static zone (spec test 23). Candidates are picked at the
//   bottom of the x86-64 static zone (0x0000_1000_0000_0000) so they
//   satisfy both the static-zone constraint and the page-alignment
//   requirement.
//
// Action
//   For each preferred_base in the candidate list:
//     1. createVmar(caps={r,w}, props={cur_rwx=0b011, sz=0, cch=0},
//                  pages=1, preferred_base=<candidate>, device_region=0).
//     2. On success: assert cv.v2 == preferred_base. If equal, pass;
//        if not, fail with assertion 2 — the kernel violated test 21.
//     3. On error: try the next candidate (range was unavailable).
//   If every candidate erred without a single success, the kernel
//   never reached the test-21 success arm; fail with assertion 3 to
//   distinguish that from a real test-21 violation.
//
// Assertions
//   1: createVmar returned an unexpected error word — not E_NOSPC and
//      not the success path. preferred_base in user vaddr + page-
//      aligned shouldn't hit E_PERM/E_INVAL/E_BADCAP, so any other
//      error is a setup break.
//   2: createVmar reported success with cv.v2 != preferred_base. This
//      is the spec test-21 violation: the kernel must either honour
//      the requested base on success or refuse the call.
//   3: every candidate failed with E_NOSPC; we never observed a
//      success leg, so test 21's invariant is vacuously satisfied
//      but not actually exercised.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const PAGES: u64 = 1;
const CUR_RWX: u64 = 0b011; // r|w
const SZ: u64 = 0; // 4 KiB
const CCH: u64 = 0; // wb

// preferred_base must lie wholly within the static zone (spec
// §[address_space] / §[create_vmar] test 23). On x86-64 the static
// zone starts at 0x0000_1000_0000_0000.
const candidates = [_]u64{
    0x0000_1000_0000_0000,
    0x0000_1000_0001_0000,
    0x0000_1000_0010_0000,
};

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const vmar_caps = caps.VmarCap{ .r = true, .w = true };
    const props: u64 = (CCH << 5) | (SZ << 3) | CUR_RWX;

    var saw_unavailable = false;
    for (candidates) |preferred_base| {
        const cv = syscall.createVmar(
            @as(u64, vmar_caps.toU16()),
            props,
            PAGES,
            preferred_base,
            0,
        );
        if (testing.isHandleError(cv.v1)) {
            // Range unavailable is the only spec-allowed refusal here;
            // anything else is a setup break.
            if (cv.v1 == @intFromEnum(errors.Error.E_NOSPC)) {
                saw_unavailable = true;
                continue;
            }
            testing.fail(1);
            return;
        }
        // Success arm: spec test 21 demands cv.v2 == preferred_base.
        // Anything else is a kernel violation — silently relocating
        // the VMAR while reporting success defeats the contract.
        if (cv.v2 == preferred_base) {
            testing.pass();
            return;
        }
        testing.fail(2);
        return;
    }

    if (saw_unavailable) {
        // Every candidate's range was occupied; we never reached the
        // success arm so test 21's invariant wasn't observably tested.
        testing.fail(3);
        return;
    }
    testing.fail(1);
}
