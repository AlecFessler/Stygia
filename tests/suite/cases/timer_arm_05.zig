// Spec §[timer_arm] — test 05.
//
// "[test 05] on success, the caller receives a timer handle with caps
//  = [1].caps."
//
// Spec semantics
//   §[timer_arm]: "Mints a new timer handle ... -> [1] handle". The
//   returned handle's caps field (word0 bits 48-63 of the cap table
//   entry) must equal the caps requested in [1].caps (bits 0-15 of
//   the input word).
//
// Strategy
//   The runner mints each test's child capability domain with a
//   SelfCap that includes `timer` and a `restart_policy_ceiling` that
//   permits `tm_restart_max = 1` (see runner/primary.zig and the
//   commentary in timer_arm_02). All other prior gates (tests 01-04)
//   pass when we feed a non-zero deadline_ns and clean reserved bits,
//   so the kernel must mint a timer handle and we can read it back.
//
//   Use a multi-bit cap pattern {arm, cancel, restart_policy} to make
//   the assertion sensitive to either a missing bit or a stray bit
//   sneaking in via the kernel mint path. restart_policy = 1 is
//   permitted under the runner's `tm_restart_max = 1` ceiling (the
//   shape used by timer_arm_02), and `arm` / `cancel` are the bits a
//   production caller would request to make the handle structurally
//   useful.
//
//   The caps field of a handle lives in word0 bits 48-63 of the cap
//   table entry — part of the static handle layout, not a kernel-
//   mutable field0/field1 snapshot — so a fresh `readCap` against the
//   read-only-mapped table is authoritative without `sync` (same
//   pattern as create_port_04 / create_var_18 / create_page_frame_09).
//
// Action
//   1. timerArm(caps={arm, cancel, restart_policy=1}, deadline_ns=1,
//               flags=0) — must succeed (return a handle, not an
//               error word).
//   2. readCap(cap_table_base, returned_handle) — verify
//      caps == {arm, cancel, restart_policy=1}.
//
// Assertions
//   1: timer_arm did not return a valid handle.
//   2: returned handle's caps field does not equal the requested caps.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    // §[timer] TimerCap layout: arm = bit 2, cancel = bit 3,
    // restart_policy = bit 4. Multi-bit pattern catches bit-drop or
    // bit-add bugs in the kernel mint path.
    const requested = caps.TimerCap{
        .arm = true,
        .cancel = true,
        .restart_policy = true,
    };

    const result = syscall.timerArm(
        @as(u64, requested.toU16()),
        1, // deadline_ns: 1 ns (smallest non-zero; satisfies test 03)
        0, // flags: periodic = 0, all reserved bits clean
    );
    if (testing.isHandleError(result.v1)) {
        testing.fail(1);
        return;
    }
    const timer_handle: u12 = @truncate(result.v1 & 0xFFF);

    const cap = caps.readCap(cap_table_base, timer_handle);
    if (cap.caps() != requested.toU16()) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
