// Spec §[futex_wait_change] — test 07.
//
// "[test 07] on entry, when any pair's current `*addr == target`,
//  returns immediately with `[1]` set to that addr."
//
// Strategy
//   §[futex_wait_change] specifies blocking iff every pair satisfies
//   `*addr != target`. The test 07 fast path is the negation of that
//   precondition: at least one pair already satisfies `*addr == target`
//   on entry. The kernel must skip the blocking path entirely and
//   return that pair's addr in vreg 1.
//
//   To exercise the fast path the test needs writable user memory
//   whose qword content the kernel will read. The test child cannot
//   touch arbitrary VAs — only ranges installed by the kernel into
//   the test domain's page tables are valid u-mode addresses
//   (E_BADADDR otherwise per test 05). The minimal construction is:
//
//     create_page_frame(caps={r,w}, sz=0, pages=1)   — backing 4 KiB
//     create_var(caps={r,w}, cur_rwx=r|w, pages=1)   — reserves vaddr
//     map_pf(var, &.{ 0, pf })                       — maps base→pf
//
//   After map_pf the VAR's `map` is 1 (pf-installed) per §[map_pf]
//   test 11; CPU stores at VAR.base land in the page_frame and
//   subsequent kernel reads of those qwords observe the same bytes
//   (same model that idc_read_07 uses for cross-mode visibility).
//
//   With base in hand, we plant two qwords:
//     base[0] = 0                  — pair-A current value
//     base[1] = TARGET_HIT         — pair-B current value
//
//   And call:
//     futex_wait_change(
//       timeout_ns = 1_000_000_000,
//       pairs = &.{
//         base + 0,  TARGET_PAIR_A,  // *addr=0, target=TARGET_PAIR_A: NOT met
//         base + 8,  TARGET_HIT,     // *addr == target: MET
//       },
//     )
//
//   TARGET_PAIR_A is chosen distinct from base[0]'s planted value (0)
//   so pair A is unambiguously not satisfied. Pair B satisfies
//   `*addr == target` on entry — the spec mandates immediate return
//   with vreg 1 = base + 8.
//
//   The timeout is set to a generous but finite 1 second. If the
//   kernel were to (incorrectly) block, the test would still
//   complete — but vreg 1 would be the addr that woke or timeout
//   would fire; neither matches the test 07 expectation that the
//   match-on-entry pair's addr is returned synchronously.
//
//   Volatile qword stores (same idiom as idc_read_07) defeat
//   ReleaseSmall constant-folding: the kernel must observe the
//   bytes we wrote, not whatever the optimizer would have left in
//   the page.
//
//   Self-handle preconditions: the runner mints every test child
//   with `fut_wait_max = 63` (runner/primary.zig line 167), so
//   N = 2 ≤ fut_wait_max satisfies §[futex_wait_change] line 2402.
//   `crpf`, `crvr` are also granted, enabling the construction
//   prelude. No `fut_wake` is needed — test 07 exercises the
//   fast-path return, not the wake leg.
//
// Action
//   1. createPageFrame(caps={r,w}, props={sz=0}, pages=1)
//   2. createVar(caps={r,w}, props={cur_rwx=r|w, sz=0}, pages=1)
//   3. mapPf(var, &.{ 0, pf })
//   4. plant base[0] = 0, base[1] = TARGET_HIT (volatile stores)
//   5. futexWaitChange(timeout=1s, &.{ base+0, TARGET_PAIR_A,
//                                     base+8, TARGET_HIT })
//
// Assertions
//   1: a setup syscall (createPageFrame / createVar / mapPf)
//      returned an error word — prelude broke before the spec
//      assertion under test could be exercised.
//   2: futex_wait_change returned an error in vreg 1 — the fast
//      path must not surface an error code when a pair already
//      satisfies its target on entry.
//   3: vreg 1 != base + 8 — the returned addr must be the matched
//      pair's addr (base + 8), not the unmatched pair's addr nor
//      anything else.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Distinct sentinel values: pair A's target intentionally differs
// from base[0]'s planted value (0) so the pair is unambiguously
// unsatisfied; pair B's planted value equals its target so the
// fast path fires on it.
const TARGET_PAIR_A: u64 = 0xAAAA_AAAA_AAAA_AAAA;
const TARGET_HIT: u64 = 0xDEAD_BEEF_CAFE_BABE;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: 4 KiB page_frame with r|w. Effective perms after the
    // map_pf intersect with the VAR's cur_rwx = r|w yield r|w on the
    // mapped range, so CPU writes succeed.
    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // pages = 1
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const pf_handle: u64 = @as(u64, cpf.v1 & 0xFFF);

    // Step 2: regular VAR sized to 1 page with caps={r,w} and
    // cur_rwx = r|w. The kernel chooses the base; field0 (cvar.v2)
    // reports it per §[create_var] test 19.
    const var_caps = caps.VarCap{ .r = true, .w = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0
    const cvar = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        1, // pages = 1
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(1);
        return;
    }
    const var_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);
    const var_base: u64 = cvar.v2;

    // Step 3: install the page_frame at offset 0 — drives `map`
    // 0 -> 1 per §[map_pf] test 11. After this, CPU stores at
    // var_base land in the page_frame and the kernel can observe
    // them through its own mapping when it reads the futex addr.
    const mr = syscall.mapPf(var_handle, &.{ 0, pf_handle });
    if (errors.isError(mr.v1)) {
        testing.fail(1);
        return;
    }

    // Step 4: plant the watched qwords. Volatile defeats
    // ReleaseSmall constant-folding — the kernel must read what we
    // actually stored. Both addresses are 8-byte aligned (base is
    // 4 KiB-aligned; +0 and +8 keep alignment), so test 04
    // (E_INVAL on misaligned addr) cannot fire.
    const qword_ptr: [*]volatile u64 = @ptrFromInt(var_base);
    qword_ptr[0] = 0; // pair-A's *addr — distinct from TARGET_PAIR_A
    qword_ptr[1] = TARGET_HIT; // pair-B's *addr — equals TARGET_HIT

    // Step 5: futex_wait_change with two pairs. Pair A is
    // unsatisfied (0 != TARGET_PAIR_A); pair B is satisfied
    // (TARGET_HIT == TARGET_HIT). Per §[futex_wait_change] test
    // 07, the kernel must detect the entry-time match and return
    // immediately with vreg 1 = pair B's addr (= var_base + 8).
    //
    // The 1-second timeout is a safety net: if the kernel were to
    // erroneously block, the call still terminates and the test
    // reports a meaningful failure (vreg 1 = the woken addr or
    // E_TIMEOUT) rather than hanging the runner.
    const addr_a: u64 = var_base + 0;
    const addr_b: u64 = var_base + 8;
    const result = syscall.futexWaitChange(
        1_000_000_000, // timeout = 1 s (kernel must not actually block)
        &.{
            addr_a, TARGET_PAIR_A,
            addr_b, TARGET_HIT,
        },
    );

    // Assertion 2: the fast path is success-coded; vreg 1 carries
    // the matched addr, never an error code. Spec §[error_codes]
    // confines error codes to 1..15, so a real user vaddr is
    // unambiguously not an error word.
    if (errors.isError(result.v1) and result.v1 < 16) {
        testing.fail(2);
        return;
    }

    // Assertion 3: the returned addr must equal the matched pair's
    // addr (var_base + 8), not the unmatched pair's addr and not
    // any other value.
    if (result.v1 != addr_b) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
