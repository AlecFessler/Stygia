// Spec §[execution_context] create_execution_context — test 05.
//
// "[test 05] returns E_PERM if [4] is nonzero and target_caps is not a
//  subset of the target domain's `ec_inner_ceiling`."
//
// Strategy
//   The caps word for create_execution_context packs both the caller's
//   EC handle caps (bits 0-15) and `target_caps` for the EC handle
//   inserted into the target domain's table (bits 16-31). When [4]
//   names an IDC handle to a target domain, the kernel separately
//   bounds:
//     - caps         <= target's ec_outer_ceiling   (test 04)
//     - target_caps  <= target's ec_inner_ceiling   (test 05)
//   ec_outer_ceiling and ec_inner_ceiling are 8-bit fields covering
//   EcCap bits 0-7 (move/copy/saff/spri/term/susp/read/write). Bits
//   >= 8 — restart_policy (8-9), bind (10), rebind (11), unbind (12)
//   — are unconditionally outside both ceilings.
//
//   Re-use the same target shape as create_execution_context_02: the
//   test child's slot-2 IDC (SLOT_SELF_IDC) references the test's
//   own domain and is minted with cridc_ceiling = 0x3F (every IDC
//   cap, including `crec`). Since slot 2's target is our own domain,
//   ec_inner_ceiling = 0xFF (set by the runner). target_caps must
//   therefore be a value that is a subset of 0xFF on bits 0-7 but
//   has at least one of the >=8 bits set — bind (bit 10) is the
//   minimal choice already proven to sit outside ec_inner_ceiling
//   (see create_execution_context_03's strategy note).
//
//   Choices that keep the call off the other reject paths:
//     - caller's self-handle holds `crec` (runner spawn config) —
//       avoids test 01.
//     - target = SLOT_SELF_IDC, which holds `crec` by default —
//       avoids test 02.
//     - target nonzero so tests 03 (target=self caps) does not apply.
//     - caps (bits 0-15) = 0 — vacuously a subset of any
//       ec_outer_ceiling, so test 04 cannot fire ahead of test 05.
//     - priority (bits 32-33) = 0 — within the runner's `pri = 3`
//       ceiling; test 06 cannot fire.
//     - SLOT_SELF_IDC is a valid IDC handle by construction — test
//       07 cannot fire.
//     - stack_pages = 1 — nonzero (test 08).
//     - affinity = 0 — "any core"; no out-of-range bits (test 09).
//     - reserved bits in [1] are clear (test 10).
//
//   With caps = 0 satisfying test 04 and target_caps.bind = 1
//   exceeding ec_inner_ceiling = 0xFF, the only spec-mandated failure
//   path that fits is test 05.
//
// SPEC AMBIGUITY
//   The libz `createExecutionContext` wrapper places affinity in vreg
//   5, but spec §[execution_context] lists `[5] vm_handle` and
//   `[6] affinity`. Bypass the wrapper and dispatch via `issueReg`
//   with the spec-correct vreg layout, matching create_execution_context_02.
//
// Action
//   1. create_execution_context(caps_word with target_caps=bind,
//                               entry, 1, SLOT_SELF_IDC, vm=0, aff=0)
//      — must return E_PERM.
//
// Assertions
//   1: create_execution_context returned something other than E_PERM.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // target_caps occupies bits 16-31 of the caps word (§[create_execution_context]
    // [1] layout). EcCap.bind is bit 10 within the per-handle caps,
    // so it lands at bit 26 of the full caps word. Every other field
    // — caps (bits 0-15), priority (bits 32-33), reserved (34-63) —
    // is left zero so this is the only ceiling violation that can
    // match.
    const target_ec = caps.EcCap{ .bind = true };
    const caps_word: u64 = @as(u64, target_ec.toU16()) << 16;

    // [2] entry: never reached. Use dummyEntry as a defensively-shaped
    // pointer in case the kernel sanity-checks it before the cap
    // check — nothing in the spec mandates that, but it costs nothing.
    const entry_addr: u64 = @intFromPtr(&testing.dummyEntry);

    // Spec §[execution_context] vreg layout for create_execution_context:
    //   v1 = caps word
    //   v2 = entry
    //   v3 = stack_pages
    //   v4 = target (IDC handle)
    //   v5 = vm_handle
    //   v6 = affinity mask
    const result = syscall.issueReg(.create_execution_context, 0, .{
        .v1 = caps_word,
        .v2 = entry_addr,
        .v3 = 1, // stack_pages — nonzero (test 08 guard)
        .v4 = caps.SLOT_SELF_IDC, // valid IDC; has crec; targets our own domain
        .v5 = 0, // vm_handle — none
        .v6 = 0, // affinity — any core
    });

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
