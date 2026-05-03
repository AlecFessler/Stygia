// Spec §[recv] recv — test 02.
//
// "[test 02] returns E_PERM if [1] does not have the `recv` cap."
//
// Strategy
//   Mint a fresh port via `create_port` with caps that omit `recv`
//   (bind | xfer here — exact cap mix doesn't matter as long as `recv`
//   is clear). The handle is otherwise structurally valid: the type
//   tag in the table entry is `port`, no reserved bits in the slot id,
//   and the slot is populated. The §[recv] cap-gate must therefore
//   reject the call with E_PERM rather than reaching any other gate.
//
//   The runner's port_ceiling (per primary.zig) is 0x1C = xfer | recv |
//   bind, so a `bind | xfer` request is a valid subset of the ceiling
//   and create_port's gates (tests 01-03) all pass. crpt is granted on
//   the child's self-handle by the runner.
//
// Action
//   1. createPort(caps={bind, xfer}) — must succeed, returning a port
//      handle whose caps explicitly lack `recv`.
//   2. recv(port_handle) — must return E_PERM because the handle's
//      caps lack `recv`.
//
// Assertions
//   1: createPort returned an error word in vreg 1 (setup failed).
//   2: recv returned something other than E_PERM.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Port handle with bind+xfer but no recv. The §[recv] gate order
    // checks the cap before any port-state checks, so this is the
    // minimum setup needed to observe E_PERM.
    const port_caps = caps.PortCap{
        .bind = true,
        .xfer = true,
    };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    const result = syscall.recv(port_handle, 0);

    if (result.regs.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
