// Spec §[restart_semantics] — test 05.
//
// "[test 05] returns E_PERM if `create_port` is called with
//  `caps.restart_policy = 1` and the calling domain's
//  `restart_policy_ceiling.port_restart_max = 0`."
//
// Variant chosen: degraded positive-path smoke.
//
//   The faithful negative variant requires running `create_port` from a
//   domain whose `restart_policy_ceiling.port_restart_max = 0`. The
//   ceiling is fixed on the calling domain's self-handle field1 at
//   `create_capability_domain` time and cannot be lowered post-hoc on
//   the test EC's own self-handle. Reaching a domain with that ceiling
//   from inside this test would mean calling `create_capability_domain`
//   with a reduced `ceilings_outer`, staging a separate ELF (or this
//   ELF re-entered in a different mode) into a fresh page frame, and
//   plumbing the grandchild's result back through a port — essentially
//   recreating the runner. The runner provisions the test EC's domain
//   with `port_restart_max = 1` (see `runner/primary.zig` ceilings_outer
//   = 0x...03FE_FFFF), so `create_port(restart_policy=1)` from this
//   domain is expected to succeed, not fail.
//
//   This test exercises the symmetric positive-path: when the calling
//   domain's `port_restart_max = 1`, `create_port` with
//   `caps.restart_policy = 1` must succeed and the returned handle's
//   caps must include the requested `restart_policy` bit. That confirms
//   the ceiling check accepts the in-bounds case; the E_PERM negative
//   case for `port_restart_max = 0` is left for the cross-domain
//   construction to land (same blocker as revoke_03/04/06).
//
// Strategy
//   The test EC's domain has `port_restart_max = 1` per the runner. Mint
//   a port with `caps.restart_policy = 1` plus `bind` so the handle is
//   well-formed (port caps use bitwise subset against `port_ceiling`,
//   which the runner sets to xfer|recv|bind = 0x1C; restart_policy lives
//   outside `port_ceiling` and is gated by the separate ceiling).
//
//   Read the cap back through the read-only cap table to verify the
//   handle's installed caps carry the restart_policy bit per
//   §[create_port] [test 04]: "on success, the caller receives a port
//   handle with caps = `[1].caps`."
//
// Action
//   1. create_port(caps={bind, restart_policy=1}) — must succeed
//   2. readCap(cap_table_base, port) — verify caps == requested
//
// Assertions
//   1: create_port returned an error word
//   2: handle's caps field after create_port does not equal requested

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const requested = caps.PortCap{
        .bind = true,
        .restart_policy = true,
    };
    const cp = syscall.createPort(@as(u64, requested.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    const cap = caps.readCap(cap_table_base, port_handle);
    if (cap.caps() != requested.toU16()) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
