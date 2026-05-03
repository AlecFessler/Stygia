// Spec §[remap] — test 06.
//
// "[test 06] returns E_INVAL if any reserved bits are set in [2]."
//
// Strategy
//   §[remap] pins the layout of [2] new_cur_rwx as a u64 packed as:
//     bits 0-2:  new r/w/x
//     bits 3-63: _reserved
//   Setting any bit in that reserved range must surface E_INVAL at
//   the syscall ABI layer regardless of whether the rest of the call
//   would otherwise have succeeded (§[syscall_abi]).
//
//   To isolate the reserved-bit check we drive every other remap
//   prelude check past inert:
//     - test 01 (VAR is invalid)        — pass a freshly-minted VAR.
//     - test 02 (`map` ∈ {0, 2})        — install a page_frame so
//                                         map transitions 0 → 1.
//     - test 03 (rwx not subset of caps)— use cur_rwx = 0b011 (r|w),
//                                         which equals VAR.caps r|w.
//     - test 04 (rwx not subset of pf
//                intersection)          — pf was minted with caps r|w
//                                         too, so cur_rwx ⊆ pf caps.
//     - test 05 (caps.dma & x bit)      — caps.dma = 0 here, so this
//                                         gate cannot fire.
//   We then dial in a single reserved bit on top of an otherwise-
//   valid new_cur_rwx. Bit 63 sits at the top of the bits 3-63
//   reserved range and cannot be mistaken for any defined field.
//
//   The libz `syscall.remap` wrapper takes u64 args, so it does not
//   strip upper bits — the reserved bit reaches the kernel verbatim
//   on v2 (rbx). The ABI gate must reject it as E_INVAL.
//
// Action
//   1. createPageFrame(caps={r, w}, props=0, pages=1) — must succeed,
//      provides the page_frame for the map_pf prelude.
//   2. createVar(caps={r, w}, props={cur_rwx=r|w, sz=0, cch=0},
//                pages=1, preferred_base=0, device_region=0) —
//      must succeed; gives a regular VAR in `map = 0`.
//   3. mapPf(var, &.{ 0, pf }) — must succeed (transitions map 0 → 1
//      per §[map_pf] test 11) so the §[remap] test 02 gate cannot
//      preempt the reserved-bit check.
//   4. remap(var, valid_rwx | (1 << 63)) — must return E_INVAL.
//
// Assertion
//   1: reserved bit set in [2] did not return E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: real page_frame so map_pf has a backing frame and the
    // VAR can transition to map = 1 ahead of the remap call.
    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // pages = 1
    );
    if (testing.isHandleError(cpf.v1)) {
        // Prelude broke; we cannot exercise the reserved-bit gate
        // without a valid pf to install. Fail under the same id —
        // the runner will surface it as the spec assertion failing.
        testing.fail(1);
        return;
    }
    const pf_handle: u64 = @as(u64, cpf.v1 & 0xFFF);

    // Step 2: regular VAR in `map = 0`. caps.dma = 0 keeps test 05
    // from firing on the reserved-bit call below.
    const var_caps = caps.VarCap{ .r = true, .w = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0
    const cvar = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        1, // pages = 1
        0, // preferred_base = kernel chooses
        0, // device_region = unused
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(1);
        return;
    }
    const var_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);

    // Step 3: transition map 0 -> 1 so test 02 (map ∈ {0, 2}) cannot
    // preempt the reserved-bit gate. mapPf must succeed.
    const mp = syscall.mapPf(var_handle, &.{ 0, pf_handle });
    if (testing.isHandleError(mp.v1)) {
        testing.fail(1);
        return;
    }

    // Step 4: remap with bit 63 of [2] set — sits in the bits 3-63
    // _reserved range of new_cur_rwx. Low 3 bits are r|w (= 0b011),
    // a subset of VAR.caps and pf.caps so tests 03/04 don't fire.
    const valid_rwx: u64 = 0b011;
    const rwx_with_reserved: u64 = valid_rwx | (@as(u64, 1) << 63);
    const result = syscall.remap(var_handle, rwx_with_reserved);

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
