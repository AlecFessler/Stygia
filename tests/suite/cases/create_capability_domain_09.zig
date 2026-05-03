// Spec §[create_capability_domain] — test 09.
//
// "[test 09] returns E_PERM if `cridc_ceiling` is not a subset of the
//  caller's `cridc_ceiling`."
//
// Strategy
//   `cridc_ceiling` is the 8-bit field at bits 24-31 of the self-handle
//   field0 (= ceilings_inner). Only bits 0-5 are valid IDC cap bits
//   (move/copy/crec/aqec/aqvr/restart_policy); bits 6-7 are reserved
//   and trip the reserved-bits rule (test 17), so they cannot be used
//   to construct a superset for this test.
//
//   The runner mints each child with `cridc_ceiling = 0x3F` (full 6
//   valid bits set — see runner/primary.zig `ceilings_inner`). When the
//   caller already holds the full set there is no valid superset to
//   pass, so a faithful E_PERM probe of test 09 is impossible from this
//   child.
//
//   This is the degraded smoke variant the brief authorises: read the
//   caller's `cridc_ceiling` and, if any of bits 0-5 is unset, build a
//   true superset and assert E_PERM. Otherwise (caller has 0x3F),
//   submit a request with `cridc_ceiling = caller_value` (an equal-set,
//   which is a subset by definition) and assert the kernel does not
//   return E_PERM — proving the subset rule does not fire on a non-
//   superset value. `elf_page_frame = 0` keeps the call from succeeding
//   (page-frame handle 0 is the self-handle, not a page frame), so the
//   kernel will short-circuit on E_BADCAP for elf_page_frame (test 13)
//   instead. That is acceptable: the assertion only excludes E_PERM.
//
// Action — faithful path
//   1. create_capability_domain(... ceilings_inner with cridc bits =
//      caller_cridc | missing_bit ...) — must return E_PERM
//
// Action — degraded path (caller already at 0x3F)
//   1. create_capability_domain(... ceilings_inner with cridc bits =
//      caller_cridc ...) — must return anything except E_PERM
//
// Assertions
//   1: faithful path — kernel returned something other than E_PERM
//   2: degraded path — kernel returned E_PERM despite an equal-set
//      cridc_ceiling (the subset check must accept equal sets)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Bit layouts. The self-handle field0 and the [2] ceilings_inner
// argument are NOT the same shape: field0 inserts `idc_rx` at bits
// 32-39 and shifts pf/vm/port up by 8 bits, while ceilings_inner
// packs pf/vm/port at bits 32-55 with no idc_rx slot. See
// §[capability_domain] Self handle vs §[create_capability_domain] [2].
// `ec_inner`, `var_inner`, and `cridc_ceiling` (bits 0-31) are the
// only sub-fields that share an offset between the two.
const CRIDC_SHIFT: u6 = 24;

// Self-handle field0 sub-field offsets (per §[capability_domain]).
const FIELD0_PF_SHIFT: u6 = 40;
const FIELD0_VM_SHIFT: u6 = 48;
const FIELD0_PORT_SHIFT: u6 = 56;

// ceilings_inner sub-field offsets (per §[create_capability_domain] [2]).
const INNER_PF_SHIFT: u6 = 32;
const INNER_VM_SHIFT: u6 = 40;
const INNER_PORT_SHIFT: u6 = 48;

pub fn main(cap_table_base: u64) void {
    // Read the caller's self-handle. cridc_ceiling lives at field0
    // bits 24-31 — see §[capability_domain] Self handle.
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    const caller_cridc: u8 = @truncate((self_cap.field0 >> CRIDC_SHIFT) & 0xFF);

    // Translate the caller's field0 sub-fields into the ceilings_inner
    // packing so the request mirrors the caller exactly on every
    // sub-field except `cridc_ceiling`. Without this translation,
    // pf/vm/port sub-fields land at the wrong offsets and trip
    // tests 10/11/12 before the test 09 cridc check fires.
    const caller_ec_inner: u64 = self_cap.field0 & 0xFF;
    const caller_var_inner: u64 = (self_cap.field0 >> 8) & 0xFFFF;
    const caller_pf: u64 = (self_cap.field0 >> FIELD0_PF_SHIFT) & 0xFF;
    const caller_vm: u64 = (self_cap.field0 >> FIELD0_VM_SHIFT) & 0xFF;
    const caller_port: u64 = (self_cap.field0 >> FIELD0_PORT_SHIFT) & 0xFF;
    const base_inner: u64 =
        caller_ec_inner |
        (caller_var_inner << 8) |
        (caller_pf << INNER_PF_SHIFT) |
        (caller_vm << INNER_VM_SHIFT) |
        (caller_port << INNER_PORT_SHIFT);
    const ceilings_outer: u64 = self_cap.field1;

    // self_caps and elf_page_frame don't influence the cridc check;
    // pass values that match the runner's own grant set so the kernel
    // does not bail on a different rule before reaching the cridc
    // subset check. The kernel evaluates ceiling subset checks in the
    // order they appear in the spec; tests 02-08 appear before test
    // 09 and use fields we leave unchanged from the caller's view.
    const self_caps_word: u64 = self_cap.word0 >> 48; // caps live in bits 48-63 of word0.

    // Find a missing valid bit in caller_cridc (bits 0-5).
    var missing_bit: u8 = 0;
    var found_missing: bool = false;
    var i: u3 = 0;
    while (i < 6) {
        const bit: u8 = @as(u8, 1) << i;
        if ((caller_cridc & bit) == 0) {
            missing_bit = bit;
            found_missing = true;
            break;
        }
        if (i == 5) break;
        i += 1;
    }

    if (found_missing) {
        // Faithful path: superset by setting a bit the caller lacks.
        const new_cridc: u8 = caller_cridc | missing_bit;
        const ceilings_inner: u64 =
            base_inner | (@as(u64, new_cridc) << CRIDC_SHIFT);

        const result = syscall.createCapabilityDomain(
            self_caps_word,
            ceilings_inner,
            ceilings_outer,
            0, // elf_page_frame: bogus on purpose — irrelevant if E_PERM fires first.
            0, // initial_ec_affinity
            &.{},
        );
        if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
            testing.fail(1);
            return;
        }
        testing.pass();
        return;
    }

    // Degraded path: caller already holds full 0x3F, so no valid
    // superset exists. Submit an equal-set value (a subset by
    // definition) and assert the kernel does NOT return E_PERM —
    // proving the subset check does not misfire on equal sets.
    const equal_cridc: u8 = caller_cridc;
    const ceilings_inner: u64 =
        base_inner | (@as(u64, equal_cridc) << CRIDC_SHIFT);

    const result = syscall.createCapabilityDomain(
        self_caps_word,
        ceilings_inner,
        ceilings_outer,
        0, // elf_page_frame: bogus on purpose; expect E_BADCAP, not E_PERM.
        0, // initial_ec_affinity
        &.{},
    );
    if (result.v1 == @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }
    testing.pass();
}
