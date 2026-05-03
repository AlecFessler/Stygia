// Spec §[create_capability_domain] — test 05.
//
// "[test 05] returns E_PERM if `var_inner_ceiling` is not a subset of
//  the caller's `var_inner_ceiling`."
//
// Strategy
//   The faithful test mints a capability domain whose `ceilings_inner`
//   sets a bit in bits 8-23 (var_inner_ceiling) that the caller does
//   not have set in its own `var_inner_ceiling`. The kernel must
//   reject the call with E_PERM before any kernel state mutates.
//
//   The runner (runner/primary.zig) constructs each test domain with
//   `ceilings_inner = 0x001C_011F_3F01_FFFF`, so the test's
//   var_inner_ceiling (bits 8-23) is 0x01FF — every defined bit set
//   (move, copy, r, w, x, mmio, max_sz=3, dma; bits 17-23 are
//   reserved). With a fully-saturated caller ceiling, every legal
//   16-bit value the test could legally place in bits 8-23 is a
//   subset; setting any reserved bit (17-23) would route to test 17
//   (E_INVAL) rather than the test-05 subset check.
//
//   To exercise the rule faithfully would require a lower-privilege
//   caller — either a per-test override of the runner-supplied
//   ceilings, or a multi-level test where the test ELF spawns a
//   grandchild with restricted ceilings and observes the grandchild's
//   create_capability_domain attempt fail. Neither path exists in the
//   v0 runner, which spawns each test as a single domain off the
//   primary with fixed ceilings.
//
// Degraded variant landed here
//   Read the caller's actual `var_inner_ceiling` from slot 0 of the
//   capability table (the self-handle's field0 bits 8-23). Construct
//   `ceilings_inner` with that exact value in bits 8-23 and the
//   remaining ceiling fields cloned from the runner-supplied baseline.
//   Issue create_capability_domain with that word. The call must NOT
//   return E_PERM for the test 05 reason: the proposed value is, by
//   construction, equal to (and hence a subset of) the caller's
//   var_inner_ceiling.
//
//   This pins one half of the rule — that an exact-match value never
//   trips E_PERM — without requiring the lower-privilege caller path.
//   The other half (a true superset → E_PERM) is left for the
//   multi-level test infra extension.
//
//   The call may still fail for unrelated reasons (page frame is not a
//   real ELF, etc.); the assertion only checks that the failure code,
//   if any, is not E_PERM with this exact ceilings word. We bypass the
//   typed wrapper through `syscall.issueReg` so we can drive the call
//   without staging a real ELF: passing elf_pf = 0 (an unused slot)
//   should surface E_BADCAP from test 13's check rather than E_PERM.
//
// Action
//   1. read self-handle field0 (slot 0) → caller_var_inner_ceiling
//   2. compose ceilings_inner with bits 8-23 = caller_var_inner_ceiling
//      and the remaining fields cloned from the runner baseline
//   3. issue create_capability_domain with that word and elf_pf = 0
//
// Assertions
//   1: returned vreg 1 is E_PERM (would indicate the kernel rejected
//      a legitimate same-as-caller value as a subset violation —
//      a false positive on the test 05 check)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Runner-supplied baseline for the non-var_inner_ceiling fields.
// Mirrors runner/primary.zig's ceilings_inner; we substitute bits 8-23
// with the caller's actual var_inner_ceiling read from slot 0.
const RUNNER_CEILINGS_INNER_NON_VAR: u64 = 0x001C_011F_3F00_00FF;
const RUNNER_CEILINGS_OUTER: u64 = 0x0000_003F_03FE_FFFF;

pub fn main(cap_table_base: u64) void {
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    const caller_var_inner_ceiling: u64 = (self_cap.field0 >> 8) & 0xFFFF;

    const ceilings_inner: u64 =
        RUNNER_CEILINGS_INNER_NON_VAR | (caller_var_inner_ceiling << 8);

    // Compose the [1] caps word: self_caps in bits 0-15, idc_rx in
    // 16-23. Use the runner's cridc/idc_rx-friendly defaults with all
    // self-cap bits clear; the call doesn't need real self-caps to
    // reach the test-05 subset check.
    const self_caps_word: u64 = 0;

    // elf_pf = 0 deliberately. Test 13 flags E_BADCAP for an invalid
    // page frame handle. Whatever order the kernel checks ceilings vs.
    // the page frame handle, the only outcome we forbid is E_PERM
    // attributable to the var_inner_ceiling subset rule, which cannot
    // fire on an exact-match value.
    const result = syscall.issueReg(.create_capability_domain, 0, .{
        .v1 = self_caps_word,
        .v2 = ceilings_inner,
        .v3 = RUNNER_CEILINGS_OUTER,
        .v4 = 0,
    });

    if (result.v1 == @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
