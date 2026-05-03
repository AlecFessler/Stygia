// Spec §[idc_write] — test 06.
//
// "[test 06] returns E_INVAL if any reserved bits are set in [1] or [2]."
//
// Strategy
//   §[idc_write] takes a VAR handle in [1], a byte offset in [2], and
//   the qwords to write in [3..2+count]:
//
//     idc_write([1] var, [2] offset, [3..2+count] qwords) -> void
//
//   Per §[handle_layout], a handle argument carries only the 12-bit
//   handle id in bits 0-11; bits 12-63 are _reserved. Setting any bit
//   in that reserved range on [1] must surface E_INVAL at the syscall
//   ABI layer regardless of whether the rest of the call would
//   otherwise have succeeded (§[syscall_abi]). Setting bit 63 of the
//   [2] offset likewise violates a structural constraint — it is a
//   high bit beyond any possible byte offset within a VAR — and must
//   surface E_INVAL.
//
//   To isolate the reserved-bit check we drive every other §[idc_write]
//   prelude check past inert:
//     - test 01 (VAR is invalid)        — pass a freshly-minted VAR.
//     - test 02 (no `w` cap)            — VAR is created with w = true.
//     - test 03 (offset not 8-aligned)  — for case A (reserved on [1])
//                                          we use offset = 0; for case
//                                          B we set bit 63 of [2] only,
//                                          keeping bits 0-2 clear so
//                                          alignment passes.
//     - test 04 (count = 0 or > 125)    — count = 1 in both cases.
//     - test 05 (offset+count*8 > size) — for case A, offset = 0 with
//                                          count = 1 fits in a 1-page
//                                          VAR. Case B's bit-63 offset
//                                          would also trip test 05;
//                                          either way E_INVAL fires,
//                                          which is what test 06
//                                          observably asserts.
//
//   The libz `syscall.idcWrite` wrapper takes `var_handle: u12` which
//   would truncate the reserved bits on [1] before they reach the
//   kernel. We bypass the wrapper via `syscall.issueReg` directly so
//   reserved bits in v1/v2 reach the ABI gate verbatim. The single
//   payload qword for count=1 lives in v3.
//
// Action
//   1. createVar(caps={w}, props={cur_rwx=w, sz=0, cch=0}, pages=1)
//      — must succeed, gives a regular VAR with the `w` cap so the
//      §[idc_write] test 02 (E_PERM) gate stays inert.
//   2. issueReg(.idc_write, count=1, .{ v1 = handle | (1 << 63),
//                                        v2 = 0,
//                                        v3 = 0 })
//      — must return E_INVAL.
//   3. issueReg(.idc_write, count=1, .{ v1 = handle,
//                                        v2 = (1 << 63),
//                                        v3 = 0 })
//      — must return E_INVAL.
//
// Assertions
//   1: reserved bit set in [1] did not return E_INVAL.
//   2: reserved bit set in [2] did not return E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: regular VAR with `w` cap so the test 02 (E_PERM) gate
    // cannot preempt the reserved-bit check. cur_rwx = w matches caps.w,
    // sz = 0 (4 KiB), pages = 1 — a valid 4 KiB VAR for offset = 0,
    // count = 1.
    const var_caps = caps.VarCap{ .w = true };
    const props: u64 = 0b010; // cur_rwx = w; sz = 0 (4 KiB); cch = 0
    const cv = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        1, // pages = 1
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cv.v1)) {
        // Prelude broke; we cannot exercise the reserved-bit gate
        // without a valid VAR. Surface as test 1 failure.
        testing.fail(1);
        return;
    }
    const var_handle: caps.HandleId = @truncate(cv.v1 & 0xFFF);

    // Case A: reserved bit 63 of [1] set on top of a valid var id.
    // Bypass the typed wrapper since it takes u12 and would truncate
    // the reserved bit before it reaches the kernel. count = 1 in the
    // syscall word avoids test 04; v2 = 0 is 8-byte aligned and within
    // the VAR's size, keeping tests 03 and 05 inert. v3 holds the
    // single payload qword that count=1 demands.
    const handle_with_reserved: u64 = @as(u64, var_handle) | (@as(u64, 1) << 63);
    const a = syscall.issueReg(.idc_write, syscall.extraCount(1), .{
        .v1 = handle_with_reserved,
        .v2 = 0,
        .v3 = 0,
    });
    if (a.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    // Case B: [1] clean and valid, reserved bit 63 of [2] set. Bits
    // 0-2 of [2] stay clear so test 03 alignment passes. count = 1
    // keeps test 04 inert.
    const offset_with_reserved: u64 = @as(u64, 1) << 63;
    const b = syscall.issueReg(.idc_write, syscall.extraCount(1), .{
        .v1 = @as(u64, var_handle),
        .v2 = offset_with_reserved,
        .v3 = 0,
    });
    if (b.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
