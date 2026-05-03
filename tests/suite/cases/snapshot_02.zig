// Spec §[snapshot] snapshot — test 02.
//
// "[test 02] returns E_BADCAP if [2] is not a valid VAR handle."
//
// Strategy
//   The child capability domain's table is populated by the kernel at
//   `create_capability_domain` time:
//     slot 0  → self
//     slot 1  → initial EC
//     slot 2  → self-IDC
//     slot 3+ → passed_handles (here: just the result port at slot 3)
//   By construction every other slot is empty. Slot 4095 — the
//   maximum 12-bit handle id — is therefore guaranteed to be invalid
//   as a VAR handle, so feeding it as [2] exercises the §[snapshot]
//   test 02 BADCAP gate on the source argument.
//
//   To isolate that gate from the §[snapshot] test 01 BADCAP gate on
//   [1], we must create [1] as a valid VAR handle. Per
//   §[restart_semantics], the calling domain's
//   `restart_policy_ceiling.var_restart_max` bounds `caps.restart_policy`
//   on `create_var`. The runner's primary.zig grants the child
//   `var_restart_max = 3` (full snapshot policy), so a VAR may be
//   minted with `caps.restart_policy = 3` (snapshot) here.
//
//   §[var] cap layout: bits 9-10 hold `restart_policy`; setting
//   `restart_policy = 3` is required by §[snapshot] for the [1]
//   target argument. The §[snapshot] gate order rejects an invalid
//   [2] before any policy check on [1], but matching [1]'s
//   precondition keeps the test focused on the [2] gate without
//   relying on incidental gate ordering.
//
// Action
//   1. createVar(caps={r,w,restart_policy=3}, props=0b011, pages=1) —
//      must return a VAR handle in vreg 1 (assertion 2 guards this
//      precondition).
//   2. snapshot(valid_var_handle, empty_slot=4095) — must return
//      E_BADCAP because [2] is not a valid VAR handle.
//
// Assertions
//   1: snapshot returned something other than E_BADCAP.
//   2: createVar failed — the success-path precondition is broken so
//      we cannot proceed to verify the snapshot E_BADCAP path.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const var_caps = caps.VarCap{
        .r = true,
        .w = true,
        .restart_policy = 3, // snapshot
    };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0

    const cv = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        1, // pages = 1
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cv.v1)) {
        testing.fail(2);
        return;
    }

    const target_var: caps.HandleId = @truncate(cv.v1 & 0xFFF);

    // Slot 4095 is guaranteed empty by the create_capability_domain
    // table layout. The §[snapshot] test 02 BADCAP gate on [2] must
    // fire because no VAR lives at this slot.
    const empty_slot: caps.HandleId = caps.HANDLE_TABLE_MAX - 1;

    const result = syscall.snapshot(target_var, empty_slot);

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
