// Spec §[create_port] — test 02.
//
// "[test 02] returns E_PERM if caps is not a subset of the caller's
//  `port_ceiling`."
//
// Faithful test rationale (and why this is a degraded smoke variant)
//   The runner (tests/suite/runner/primary.zig) mints every spec-test
//   domain with `ceilings_inner = 0x001C_011F_3F01_FFFF`. Bits 56-63
//   of that word are the `port_ceiling` byte, which carries the value
//   0x1C: bits 2-4 = `xfer | recv | bind` per §[capability_domain]
//   field0 (port_ceiling at bits 56-63 with `xfer` at field-bit 2,
//   `recv` at field-bit 3, `bind` at field-bit 4 — equivalently bits
//   58/59/60 of field0 as the spec describes).
//
//   A faithful "caps not a subset of port_ceiling" test would set at
//   least one of caps.xfer / caps.recv / caps.bind while the
//   corresponding bit in port_ceiling is clear. The runner's
//   port_ceiling already permits all three bits, so under the
//   runner-provided ceiling no choice of caps.{xfer, recv, bind} can
//   violate the subset relation: the kernel must accept every
//   combination.
//
//   The runner ceiling is shared across the entire test manifest and
//   cannot be narrowed for one test, and there is currently no
//   exposed syscall that lets a child domain restrict its own
//   port_ceiling below 0x1C before invoking create_port. Until such
//   a ceiling-restriction syscall lands, the faithful E_PERM path
//   for test 02 is unreachable from a userspace test domain. This
//   mirrors create_page_frame_02's degraded-smoke rationale for the
//   pf_ceiling.max_rwx analogue.
//
//   This file lands a degraded *smoke* variant in place of the
//   faithful test: it issues a create_port with caps =
//   `xfer | recv | bind` (the maximal subset of port_ceiling), which
//   is exactly equal to the ceiling and therefore a subset of it. The
//   kernel must accept the call and return a port handle; any error
//   would indicate the kernel rejected a port-cap combination that
//   the runner ceiling permits.
//
//   When a ceiling-restriction syscall is added, this test should be
//   rewritten to: (a) narrow the calling domain's port_ceiling so at
//   least one of xfer/recv/bind is clear, then (b) invoke create_port
//   with that bit set and assert E_PERM.
//
// Strategy (degraded smoke variant)
//   To keep the call on the success path under the runner ceiling we
//   make every prior check pass:
//     - caller self-handle has `crpt` (test 01): the runner grants
//       it on every spawned test domain.
//     - caps.{xfer, recv, bind} = 1, which is ⊆ port_ceiling = 0x1C
//       (this test's gate).
//     - all reserved bits zero (test 03): bits 16-63 of [1] are 0
//       by construction (we only set the low 16 caps bits).
//
// Action
//   create_port(caps={xfer, recv, bind}) must return success
//   (vreg 1 not an error code).
//
// Assertion
//   1: create_port returned an error (degraded variant — kernel
//      rejected a port-cap combination that the runner-provided
//      ceiling permits).

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const port_caps = caps.PortCap{
        .xfer = true,
        .recv = true,
        .bind = true,
    };

    const result = syscall.createPort(@as(u64, port_caps.toU16()));

    if (testing.isHandleError(result.v1)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
