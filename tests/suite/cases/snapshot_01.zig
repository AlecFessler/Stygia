// Spec §[snapshot] snapshot — test 01.
//
// "[test 01] returns E_BADCAP if [1] is not a valid VMAR handle."
//
// Strategy
//   The child capability domain's table is populated by the kernel at
//   `create_capability_domain` time:
//     slot 0  → self
//     slot 1  → initial thread
//     slot 2  → self-IDC
//     slot 3+ → passed_handles (here: just the result port at slot 3)
//   By construction every other slot is empty. Slot 4095 — the
//   maximum 12-bit handle id — is therefore guaranteed to be invalid
//   as a VMAR handle.
//
//   To isolate the §[snapshot] test 01 BADCAP gate on [1], [2] must
//   be a valid source VMAR handle. Per §[snapshot], the source VMAR
//   carries `caps.restart_policy = 2` (preserve). Per
//   §[restart_semantics], the calling domain's
//   `restart_policy_ceiling.vmar_restart_max` bounds
//   `caps.restart_policy` on `create_vmar`; the runner's primary.zig
//   grants the child `vmar_restart_max = 3`, so a VMAR may be minted
//   with restart_policy 2 here.
//
// Action
//   1. createVmar(caps={r,w,restart_policy=2}, props=0b011, pages=1) —
//      must return a VMAR handle in vreg 1 (assertion 2 guards this
//      precondition).
//   2. snapshot(empty_slot=4095, valid_source_vmar) — must return
//      E_BADCAP because [1] (the target VMAR slot) is empty.
//
// Assertions
//   1: snapshot returned something other than E_BADCAP.
//   2: createVmar failed — the success-path precondition is broken so
//      we cannot proceed to verify the snapshot E_BADCAP path.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const source_caps = caps.VmarCap{
        .r = true,
        .w = true,
        .restart_policy = 2, // preserve
    };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0

    const csource = syscall.createVmar(
        @as(u64, source_caps.toU16()),
        props,
        1, // pages = 1
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(csource.v1)) {
        testing.fail(2);
        return;
    }
    const source_vmar: caps.HandleId = @truncate(csource.v1 & 0xFFF);

    // Slot 4095 is guaranteed empty by the create_capability_domain
    // table layout. [2] is a valid preserve-policy source VMAR, so the
    // only remaining expected failure cause is the invalid [1] target.
    const empty_slot: caps.HandleId = caps.HANDLE_TABLE_MAX - 1;

    const result = syscall.snapshot(empty_slot, source_vmar);

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
