// Spec §[suspend] suspend — test 05.
//
// "[test 05] returns E_INVAL if any reserved bits are set."
//
// Strategy
//   §[suspend] takes [1] target (EC handle) and [2] port (port handle).
//   Per §[handle_representation], a handle argument carries only the
//   12-bit handle id in bits 0-11; bits 12-63 are _reserved. Setting
//   any bit in that reserved range on either [1] or [2] must surface
//   E_INVAL at the syscall ABI layer regardless of whether the rest of
//   the call would otherwise have succeeded (§[syscall_abi]).
//
//   To isolate the reserved-bit check we drive every other §[suspend]
//   prelude check past inert:
//     - test 01 ([1] not a valid EC) — pass a freshly-minted EC.
//     - test 02 ([2] not a valid port) — pass a freshly-minted port.
//     - test 03 ([1] lacks `susp`)    — mint the EC with caps.susp = 1.
//     - test 04 ([2] lacks `bind`)    — mint the port with caps.bind = 1.
//     - test 06 ([1] is a vCPU)       — the EC we mint is a plain EC,
//                                       not a vCPU.
//     - test 07 ([1] already suspended) — the freshly-minted EC starts
//                                         runnable at dummyEntry; it has
//                                         not yet been suspended.
//   We then dial in a single reserved bit on top of an otherwise-valid
//   handle id. Bit 63 sits at the top of the bits 12-63 reserved range
//   and cannot be mistaken for any defined field.
//
//   The libz `syscall.suspendEc` wrapper takes `target: u12` and
//   `port: u12`, which cannot carry reserved bits. We bypass that
//   wrapper via `syscall.issueReg` directly so we can stuff bit 63 into
//   vreg 1 (case A) or vreg 2 (case B).
//
//   We target a fresh EC, not the calling EC, so that if the reserved-
//   bit check were to (incorrectly) not fire and the call were to fall
//   through to the success path, the suspension would land on the
//   helper EC rather than the running test EC. This keeps the test's
//   own pass()-via-suspend reporting path independent of the asserted
//   call's outcome.
//
// Action
//   1. createPort(caps={bind, recv, xfer}) — must succeed; the port
//      carries `bind` so test 04 stays inert. We add `recv` and `xfer`
//      simply because they are within the runner's port_ceiling
//      (0x1C) and form the maximal valid PortCap; only `bind` is
//      load-bearing for this test.
//   2. createExecutionContext(caps={susp,term,rp=0}, target=self,
//      affinity=0)                                — must succeed; the
//      EC carries `susp` so test 03 stays inert.
//   3. suspend(ec_handle | (1 << 63), port_handle) — must return
//      E_INVAL (reserved bit 63 of [1] set; low 12 bits hold a valid
//      EC id; [2] is a valid port handle with `bind`).
//   4. suspend(ec_handle, port_handle | (1 << 63)) — must return
//      E_INVAL (reserved bit 63 of [2] set; low 12 bits hold a valid
//      port id; [1] is a valid EC handle with `susp`).
//
// Assertions
//   1: setup syscall failed (createPort returned an error word in v1)
//   2: setup syscall failed (createExecutionContext returned an error
//      word in v1)
//   3: suspend with reserved bit 63 of [1] returned something other
//      than E_INVAL
//   4: suspend with reserved bit 63 of [2] returned something other
//      than E_INVAL

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: port with `bind` so suspend's [2] cap check stays inert.
    // recv and xfer round out the maximal subset of the runner's
    // port_ceiling (0x1C); they are not load-bearing for this test.
    const port_caps = caps.PortCap{
        .bind = true,
        .recv = true,
        .xfer = true,
    };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: caps.HandleId = @truncate(cp.v1 & 0xFFF);

    // Step 2: a fresh self-domain EC carrying `susp` so suspend's [1]
    // cap check stays inert. `term` is included for shape parity with
    // other EC-targeted tests; `restart_policy = 0` keeps the call
    // within the runner's restart_policy_ceiling. The new EC begins
    // executing at dummyEntry (an infinite hlt) — it never advances and
    // never suspends itself, so test 07 ("already suspended") stays
    // inert when we reference its handle.
    const ec_caps = caps.EcCap{
        .susp = true,
        .term = true,
        .restart_policy = 0,
    };
    // §[create_execution_context] caps word: caps in bits 0-15,
    // target_caps in 16-31 (ignored when target=self), priority in
    // 32-33. priority=0 keeps the call within the child's pri ceiling.
    const caps_word: u64 = @as(u64, ec_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1,
        0,
        0,
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(2);
        return;
    }
    const ec_handle: caps.HandleId = @truncate(cec.v1 & 0xFFF);

    // Case A: reserved bit 63 of [1] set on top of a valid EC id.
    // Bypass the typed wrapper since it takes u12 and would truncate
    // the reserved bit before it reaches the kernel. [2] is a valid
    // port handle with the `bind` cap, so test 04 cannot fire.
    const ec_with_reserved: u64 = @as(u64, ec_handle) | (@as(u64, 1) << 63);
    const a = syscall.issueReg(.@"suspend", 0, .{
        .v1 = ec_with_reserved,
        .v2 = @as(u64, port_handle),
    });
    if (a.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(3);
        return;
    }

    // Case B: [1] clean and valid, reserved bit 63 of [2] set on top
    // of a valid port id.
    const port_with_reserved: u64 = @as(u64, port_handle) | (@as(u64, 1) << 63);
    const b = syscall.issueReg(.@"suspend", 0, .{
        .v1 = @as(u64, ec_handle),
        .v2 = port_with_reserved,
    });
    if (b.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
