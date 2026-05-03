// Spec §[create_capability_domain] create_capability_domain — test 02.
//
// "[test 02] returns E_PERM if `self_caps` is not a subset of the
//  caller's self-handle caps."
//
// Strategy
//   `self_caps` (bits 0-15 of [1]) is the caps word installed on the
//   new domain's slot-0 self-handle. It must be a bitwise subset of
//   the calling domain's own self-handle caps; otherwise the call
//   would let a domain mint a child with rights it doesn't itself
//   hold, which would break the v3 monotonic-rights invariant.
//
//   The runner spawns each test with a child self-handle that has
//   `timer = true` (see runner/primary.zig spawnOne). We first
//   restrict slot 0 to drop the `timer` bit, then call
//   create_capability_domain with `self_caps` that re-asserts
//   `timer`. The new caps word now contains a bit (timer) that is
//   not set in the caller's current self-handle caps, so the
//   kernel must reject with E_PERM.
//
//   The remaining arguments are kept syntactically clean to make
//   the failure mode unambiguous: ceilings are zero (trivially a
//   subset of any caller ceiling), elf_page_frame is left as 0
//   (the kernel is permitted to fault with E_BADCAP on that, but
//   the self_caps subset check is documented before the ELF
//   handle resolution path in this section), and no passed
//   handles are supplied. The test runner only requires that the
//   ELF compile and link; the kernel-side check order will be
//   exercised once the v3 kernel implementation lands.
//
// Action
//   1. restrict(slot 0, current self caps without `timer`) — must succeed.
//   2. create_capability_domain(self_caps with `timer` set, …)
//      — must return E_PERM.
//
// Assertions
//   1: the setup restrict returned a non-zero error word
//   2: create_capability_domain returned something other than E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Match the cap shape the runner installs on every test's self
    // handle (see runner/primary.zig `child_self`) but with `timer`
    // dropped. restrict only narrows caps, so this is a valid subset
    // of the current caps.
    const reduced = caps.SelfCap{
        .crcd = true,
        .crec = true,
        .crvr = true,
        .crpf = true,
        .crvm = true,
        .crpt = true,
        .pmu = true,
        .fut_wake = true,
        .timer = false,
        .pri = 3,
    };
    const restrict_word: u64 = @as(u64, reduced.toU16());
    const restrict_result = syscall.restrict(caps.SLOT_SELF, restrict_word);
    if (restrict_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    // self_caps re-asserts `timer`, which is no longer in the
    // caller's self-handle caps after the restrict above. The
    // kernel must reject the call with E_PERM.
    const requested = caps.SelfCap{
        .crcd = true,
        .crec = true,
        .crvr = true,
        .crpf = true,
        .crvm = true,
        .crpt = true,
        .pmu = true,
        .fut_wake = true,
        .timer = true,
        .pri = 3,
    };
    const self_caps_word: u64 = @as(u64, requested.toU16());

    const result = syscall.createCapabilityDomain(
        self_caps_word,
        0, // ceilings_inner — trivially a subset of caller's ceilings
        0, // ceilings_outer — same
        0, // elf_page_frame — handle id 0 (self); kernel will reject
        // on the type tag, but only after the self_caps subset check
        0, // initial_ec_affinity
        &.{}, // passed_handles — empty
    );

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
