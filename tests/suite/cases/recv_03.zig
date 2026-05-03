// Spec §[recv] recv — test 03.
//
// "[test 03] returns E_INVAL if any reserved bits are set in [1]."
//
// Strategy
//   The [1] port handle word carries the 12-bit handle id in bits
//   0-11; bits 12-63 are _reserved per §[recv]. Setting any bit in
//   the reserved range while the low 12 bits hold a valid port handle
//   id (with `recv` cap) is the minimum setup that isolates the
//   reserved-bit gate from the BADCAP gate (test 01) and the PERM
//   gate (test 02).
//
//   The runner's `port_ceiling` per primary.zig is 0x1C (xfer | recv
//   | bind), so a `recv | bind` request on create_port satisfies
//   create_port's ceiling and reserved-bit gates and returns a port
//   handle whose caps include `recv`.
//
//   The libz `syscall.recv` wrapper takes `port: u12`, which cannot
//   carry reserved bits in [1]. We bypass that wrapper and dispatch
//   through `syscall.issueReg` directly so we can stuff bit 12 into
//   vreg 1 alongside the valid port id.
//
// Action
//   1. createPort(caps={recv, bind}) — must succeed, returning a port
//      handle that satisfies the BADCAP and PERM gates.
//   2. recv(port_handle | (1 << 12)) — must return E_INVAL because
//      bit 12 of [1] is a reserved bit.
//
// Assertions
//   1: createPort returned an error word in vreg 1 (setup failed).
//   2: recv with reserved bit 12 of [1] set returned something other
//      than E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Port handle with recv+bind. recv is required so the cap-gate
    // (test 02) passes; bind has no effect on the recv reserved-bit
    // gate but is harmless and inside the runner's port_ceiling.
    const port_caps = caps.PortCap{
        .bind = true,
        .recv = true,
    };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Reserved bit 12 of [1] set, low 12 bits hold the valid port
    // handle id. Bypass the typed wrapper since `syscall.recv` takes
    // u12 and would truncate the reserved bit before it reaches the
    // kernel.
    const handle_with_reserved: u64 =
        @as(u64, port_handle) | (@as(u64, 1) << 12);
    const result = syscall.issueReg(.recv, 0, .{
        .v1 = handle_with_reserved,
    });

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
