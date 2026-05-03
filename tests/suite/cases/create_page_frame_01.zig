// Spec §[create_page_frame] — test 01.
//
// "[test 01] returns E_PERM if the caller's self-handle lacks `crpf`."
//
// Spec semantics
//   §[create_page_frame]: "Self-handle cap required: `crpf`."
//   §[restrict]: "Reduces the caps on a handle in place. The new caps
//   must be a subset of the current caps. No self-handle cap is
//   required — reducing authority never requires authority." Restrict
//   on the self-handle is therefore a legal way for a domain to drop
//   bits from its own SelfCap without spawning a child domain.
//
// Strategy
//   The runner mints each test's child capability domain with a
//   SelfCap that includes `crpf` (see runner/primary.zig — the child
//   needs crpf to stage page frames for its own subordinate domains
//   and to construct the page-frame handles tested elsewhere in the
//   suite). To exercise the missing-`crpf` failure path, the test
//   itself must drop `crpf` from its self-handle before calling
//   create_page_frame.
//
//   `restrict` lets a domain reduce its own SelfCap caps in place.
//   The new caps must be a bitwise subset of the current caps, so we
//   compute the reduced SelfCap by copying the runner's grant and
//   clearing only the `crpf` bit. All other bits remain set, so the
//   subset check passes and the only behavioural change is `crpf`
//   becoming 0. After the restrict succeeds, create_page_frame must
//   return E_PERM per the cap-required rule.
//
// Action
//   1. restrict(SLOT_SELF, runner_caps_minus_crpf) — must succeed.
//   2. create_page_frame(caps=PfCap{r,w}, props=0, pages=1)
//      — must return E_PERM.
//
// Assertions
//   1: restrict returned a non-zero error word (failed to drop crpf).
//   2: create_page_frame returned something other than E_PERM.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Mirror runner/primary.zig's child_self grant exactly, with
    // `crpf` cleared. Every other bit must stay set so the bitwise
    // subset check in `restrict` (§[restrict] test 02) accepts the
    // reduction. `pri` is a 2-bit numeric field on SelfCap; restrict's
    // bitwise subset rule applies to it as well, so we keep pri = 3
    // (matching the runner).
    const reduced = caps.SelfCap{
        .crcd = true,
        .crec = true,
        .crvr = true,
        .crpf = false, // <-- the bit under test
        .crvm = true,
        .crpt = true,
        .pmu = true,
        .fut_wake = true,
        .timer = true,
        .pri = 3,
    };

    const restrict_result = syscall.restrict(
        caps.SLOT_SELF,
        @as(u64, reduced.toU16()),
    );
    if (restrict_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    // §[page_frame] PfCap layout: r = bit 2, w = bit 3. Reserved bits
    // clean; max_sz = 0; restart_policy = 0. props = 0 (sz = 4 KiB,
    // reserved bits clean). pages = 1 (smallest non-zero allocation).
    // None of the per-arg validation paths apply, so the only error
    // the kernel can return is the missing-`crpf` E_PERM under test.
    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const result = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0,
        1,
    );

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
