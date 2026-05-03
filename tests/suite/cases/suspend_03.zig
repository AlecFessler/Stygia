// Spec §[port] suspend — test 03.
//
// "[test 03] returns E_PERM if [1] does not have the `susp` cap."
//
// Strategy
//   Mint a fresh EC handle whose caps explicitly omit `susp`, mint a
//   port handle with `bind` (so the port-side cap check passes), and
//   call `suspend(ec, port)`. The EC-handle `susp` check is the only
//   spec-mandated failure path that applies, isolating E_PERM.
//
//   Failure-path neutralization (§[port] suspend tests 01..07):
//     - test 01 (E_BADCAP on [1]) — handle id comes from a successful
//       create_execution_context, so it's valid.
//     - test 02 (E_BADCAP on [2]) — handle id comes from a successful
//       create_port, so it's valid.
//     - test 04 (E_PERM on port `bind`) — port is minted with `bind`.
//     - test 05 (E_INVAL reserved bits) — typed `syscall.suspendEc`
//       wrapper packs target / port through u12, no reserved bits set
//       in vreg 1 / vreg 2; pair_count = 0 so no high-vreg pair entry
//       reserved bits to worry about.
//     - test 06 (E_INVAL vCPU) — EC is a regular EC, not a vCPU.
//     - test 07 (E_INVAL already suspended) — fresh EC starts running
//       at `dummyEntry` and has not been suspended.
//
//   The new EC begins executing at `dummyEntry`, which halts forever
//   (§[testing] dummyEntry: `hlt` loop). The suspend cap check fires
//   against the EC handle's caps field in the caller's domain table
//   before any state change to the running EC; the running state is
//   irrelevant.
//
// Action
//   1. create_execution_context(target=self, caps={term, restart_policy=0})
//      — must succeed (yields valid EC handle without `susp`)
//   2. create_port(caps={bind}) — must succeed (yields valid port
//      handle with `bind`)
//   3. suspend(ec, port) — must return E_PERM
//
// Assertions
//   1: setup syscall failed (create_execution_context returned error)
//   2: setup syscall failed (create_port returned error)
//   3: suspend returned something other than E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // EcCap with no `susp` bit set. `term` is included so the caps
    // word is non-zero — purely a defensive choice; nothing in the
    // spec requires a non-empty caps word.
    const ec_caps = caps.EcCap{
        .term = true,
        .susp = false,
        .restart_policy = 0,
    };
    // §[create_execution_context] caps word: caps in bits 0-15,
    // target_caps in 16-31 (ignored when target=self), priority in
    // 32-33. priority=0 keeps the call within the caller's pri ceiling.
    const ec_caps_word: u64 = @as(u64, ec_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createExecutionContext(
        ec_caps_word,
        entry,
        1,
        0,
        0,
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(1);
        return;
    }
    const ec_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // PortCap with `bind` so the port-side cap check (test 04) passes
    // and we isolate the EC-handle `susp` cap check.
    const port_caps = caps.PortCap{ .bind = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(2);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    const result = syscall.suspendEc(ec_handle, port_handle, &.{});

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
