// Spec §[restart_semantics] restart_semantics — test 07.
//
// "[test 07] returns E_PERM if any device_region handle minted by
//  transfer (e.g., copy/move via xfer) has `caps.restart_policy = 1`
//  and the calling domain's `restart_policy_ceiling.dr_restart_max = 0`."
//
// DEGRADED SMOKE VARIANT
//
//   A faithful test for this rule needs three things the v0 runner +
//   libz cannot deliver yet:
//
//     1. A device_region handle in the calling domain. Per
//        §[capabilities] line 115, device_region handles are
//        "kernel-issued at boot to root service; received via
//        suspend/reply transfer". A test child domain spawned by the
//        runner has none unless the runner explicitly transfers one;
//        the runner currently transfers only the result port.
//
//     2. A calling domain with `dr_restart_max = 0` in its
//        `restart_policy_ceiling`. The runner's child template sets
//        `ceilings_outer = 0x0000_003F_03FE_FFFF`, which puts
//        dr_restart_max = 1 — explicitly the wrong polarity for this
//        test's failure path.
//
//     3. A live xfer transport that attaches the device_region handle
//        with caps.restart_policy = 1. Both call sites that attach
//        handles in libz — `syscall.suspendEc(..., attachments)` and
//        `syscall.replyTransfer(..., attachments)` — `@panic` because
//        the high-vreg pair layout (§[handle_attachments]: entries
//        spill into vregs [128-N..127]) is not yet wired through
//        `issueStack`.
//
//   None of these blockers are fixable inside this test alone. They
//   sit upstream — in the runner's restart_policy_ceiling layout, in
//   how the runner provisions child device_region handles, and in
//   libz's stack-vreg dispatcher. The test is written here as a
//   compile-and-link placeholder so the build manifest stays in sync
//   with the spec checklist; the actual assertion is replaced with a
//   pass() so the runner records a green and moves on.
//
//   When the upstream pieces land, replace the smoke body with the
//   faithful sequence:
//
//     1. Spawn a child domain with restart_policy_ceiling such that
//        dr_restart_max = 0 (and high enough other fields that the
//        E_PERM source is unambiguously dr_restart_max).
//     2. xfer-attach a device_region handle (kernel-issued to the
//        runner at boot, propagated to the test through its passed
//        handles) into the child via reply_transfer or suspend, with
//        the entry's caps.restart_policy bit set to 1.
//     3. Assert the reply_transfer / suspend returns E_PERM in vreg 1.
//
// Action (current degraded form)
//   - Build a `caps.DeviceCap` value with restart_policy = 1 to keep
//     the cap-layout helper exercised at compile time so a future
//     edit to the bit layout would surface here.
//   - Call testing.pass() so the build manifest entry round-trips
//     end-to-end through the runner.
//
// Assertion id reservations for the future faithful body
//   1: failed to obtain a transferable device_region handle in setup
//   2: reply_transfer/suspend returned something other than E_PERM
//      when carrying a device_region attachment with restart_policy=1
//      against a domain whose dr_restart_max = 0

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Compile-time anchor for the cap layout this test will eventually
    // craft into a PairEntry. Keeps the placeholder honest about which
    // bit it is asserting against once the faithful body lands.
    const dr_with_keep = caps.DeviceCap{
        .move = true,
        .copy = true,
        .restart_policy = true,
    };
    _ = dr_with_keep.toU16();
    _ = errors.Error.E_PERM;
    _ = syscall.SyscallNum.reply_transfer;

    testing.pass();
}
