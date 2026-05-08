// Spec §[suspend] suspend — test 04.
//
// "[test 04] returns E_PERM if [2] does not have the `suspend` cap."
//
// (Spec text in docs/kernel/specv3.md still names the older `bind` cap
// here; the kernel's port-bind / port-suspend cap split moved the
// suspend-syscall gate to a dedicated `suspend` cap. The kernel
// implementation in kernel/syscall/port.zig is authoritative — the
// gate now checks `suspend`, not `bind`.)
//
// Strategy
//   Mint a fresh port handle whose caps explicitly omit `suspend`.
//   Include `recv` and `bind` so create_port's structural rule
//   (must include `recv` and one of `{suspend, bind}`) is satisfied
//   while still leaving the suspend-syscall gate violated. Then mint
//   a fresh EC handle with the `susp` cap so test 03 (E_PERM if [1]
//   lacks `susp`) is neutralized, and call `suspend(ec, port, &.{})`.
//
//   Failure-path neutralization:
//     - test 01 (E_BADCAP if [1] not a valid EC handle): handle id
//       comes from a successful create_execution_context.
//     - test 02 (E_BADCAP if [2] not a valid port handle): handle id
//       comes from a successful create_port.
//     - test 03 (E_PERM if [1] lacks `susp`): EC is minted with `susp`.
//     - test 05 (E_INVAL reserved bits): the typed `syscall.suspendEc`
//       wrapper carries no reserved bits in [1] or [2].
//     - test 06 (E_INVAL if [1] is a vCPU): we use a regular EC.
//     - test 07 (E_INVAL if [1] already suspended): the EC was just
//       created and starts running at `dummyEntry`; it has not been
//       suspended.
//   The suspend-cap check is therefore the only spec-mandated failure
//   path that applies, isolating E_PERM.
//
//   The new EC begins executing immediately at `dummyEntry`, which
//   halts forever (`hlt`). No synchronization is needed because the
//   suspend-cap check happens against the port handle's caps field in
//   our domain's handle table; the running EC's state is irrelevant.
//
// Action
//   1. create_port(caps={recv, bind})                             — must succeed
//   2. create_execution_context(target=self, caps={susp})         — must succeed
//   3. suspend(ec, port, no_attachments)                          — must return E_PERM
//
// Assertions
//   1: setup syscall failed (create_port returned an error word)
//   2: setup syscall failed (create_execution_context returned an error word)
//   3: suspend returned something other than E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Port with no `suspend` bit. `recv` and `bind` are included so
    // create_port's structural rule (must include `recv` and one of
    // `{suspend, bind}`) is satisfied while the suspend-syscall gate
    // (which checks the dedicated `suspend` cap) still fails.
    const port_caps = caps.PortCap{
        .recv = true,
        .bind = true,
    };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // EcCap with `susp` so test 03 is neutralized.
    const ec_caps = caps.EcCap{
        .susp = true,
        .restart_policy = 0,
    };
    // §[create_execution_context] caps word: caps in bits 0-15,
    // target_caps in 16-31 (ignored when target=self), priority in
    // 32-33. priority=0 keeps the call within the child's pri ceiling.
    const ec_caps_word: u64 = @as(u64, ec_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createExecutionContext(
        ec_caps_word,
        entry,
        1, // stack_pages
        0, // target = self
        0, // affinity = any core
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(2);
        return;
    }
    const ec_handle: u12 = @truncate(cec.v1 & 0xFFF);

    const result = syscall.suspendEc(ec_handle, port_handle, &.{});

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
