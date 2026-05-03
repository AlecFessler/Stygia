// Spec §[create_capability_domain] create_capability_domain — test 01.
//
// "[test 01] returns E_PERM if the caller's self-handle lacks `crcd`."
//
// Strategy
//   The runner spawns this test's domain with `crcd = true` on the
//   slot-0 self-handle (see runner/primary.zig `child_self`). To
//   exercise the no-crcd path we must clear that bit on our own
//   self-handle before invoking create_capability_domain.
//
//   Read the current self caps from slot 0, clear only the `crcd` bit
//   (preserving every other bool and the `pri` numeric field), then
//   `restrict` the self-handle to the reduced cap word. Restrict
//   accepts the call because the new caps are a subset of the current
//   caps for every bitwise field, and `pri` is unchanged.
//
//   The arguments to create_capability_domain itself are deliberately
//   minimal — a zero ELF page-frame handle, zero ceilings, no passed
//   handles. The crcd check fires before any argument validation per
//   the spec ordering of [test 01]: "returns E_PERM if the caller's
//   self-handle lacks `crcd`." So the call must return E_PERM
//   regardless of how broken the rest of the inputs are.
//
// Action
//   1. read self cap at slot 0; build new caps = current with crcd=0
//   2. restrict(slot 0, new caps) — must succeed
//   3. create_capability_domain(...) — must return E_PERM
//
// Assertions
//   1: restrict to drop crcd returned a non-OK error word
//   2: create_capability_domain returned something other than E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    const cur_caps_u16: u16 = self_cap.caps();
    const cur_self: caps.SelfCap = @bitCast(cur_caps_u16);

    var reduced = cur_self;
    reduced.crcd = false;
    const new_caps_word: u64 = @as(u64, reduced.toU16());

    const restrict_result = syscall.restrict(caps.SLOT_SELF, new_caps_word);
    if (restrict_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    // Arbitrary args. crcd-check fires before any cap subset, ELF, or
    // reserved-bit validation, so all-zero inputs still trigger E_PERM.
    const passed: [0]u64 = .{};
    const result = syscall.createCapabilityDomain(
        0, // caps
        0, // ceilings_inner
        0, // ceilings_outer
        0, // elf_page_frame
        0, // initial_ec_affinity
        passed[0..],
    );

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
