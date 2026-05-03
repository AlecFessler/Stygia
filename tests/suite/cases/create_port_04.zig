// Spec §[create_port] — test 04.
//
// "[test 04] on success, the caller receives a port handle with caps
//  = `[1].caps`."
//
// Strategy
//   Drive create_port down its success path under the runner's default
//   ceilings (tests/suite/runner/primary.zig grants `crpt` on the
//   self-handle and port_ceiling = 0x1C, i.e. xfer | recv | bind). With
//   no reserved bits set and caps a subset of the ceiling, every prior
//   gate (tests 01-03) passes, so the kernel must mint a port handle
//   and the only observable post-condition this test asserts is the
//   caps readback.
//
//   Use multi-bit caps {xfer, recv, bind} so the assertion exercises a
//   non-trivial bit pattern and is sensitive to either bit being
//   dropped or any stray bit being set on the way through the kernel.
//
//   The caps field of a handle lives in word0 bits 48-63 of the cap
//   table entry — part of the static handle layout, not a kernel-
//   mutable field0/field1 snapshot — so a fresh `readCap` against the
//   read-only-mapped table is authoritative without `sync` (same
//   pattern as create_var_18 / create_page_frame_09).
//
// Action
//   1. createPort(caps={xfer, recv, bind}) — must succeed.
//   2. readCap(cap_table_base, returned_handle) — verify
//      caps == {xfer, recv, bind}.
//
// Assertions
//   1: createPort returned an error word in vreg 1 (success path failed).
//   2: returned handle's caps field does not equal the requested caps.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const requested = caps.PortCap{ .bind = true, .recv = true, .xfer = true };

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
