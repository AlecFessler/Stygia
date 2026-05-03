// Spec §[map_pf] map_pf — test 01.
//
// "[test 01] returns E_BADCAP if [1] is not a valid VAR handle."
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
//   as a VAR handle.
//
//   §[map_pf] test 04 says E_INVAL fires if N == 0, so passing an
//   empty pairs slice could mask the BADCAP signal. To exercise the
//   BADCAP gate with no risk of E_INVAL preempting it, mint a real
//   page_frame and pass a single (offset, page_frame) pair so N == 1.
//   The BADCAP gate must fire before the pages list is dereferenced;
//   the validity of the pair is irrelevant once [1] is rejected.
//
// Action
//   1. create_page_frame(caps={r,w}, props=0, pages=1) — must succeed,
//      provides a real page_frame handle for the pairs argument.
//   2. map_pf(invalid_var_slot, &.{ 0, pf_handle }) — must return
//      E_BADCAP because the VAR slot is empty.
//
// Assertions
//   1: setup syscall create_page_frame returned an error.
//   2: map_pf returned something other than E_BADCAP.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: real page_frame to fill the pairs slice. This ensures
    // N >= 1 so §[map_pf] test 04's E_INVAL N == 0 path cannot fire
    // ahead of the BADCAP gate we're exercising.
    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // pages
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const pf_handle: u64 = @as(u64, cpf.v1 & 0xFFF);

    // Step 2: invalid VAR handle. Slot 4095 is guaranteed empty by
    // the create_capability_domain table layout. The BADCAP gate on
    // [1] must fire before any validation of the (offset, page_frame)
    // pairs.
    const empty_slot: u12 = caps.HANDLE_TABLE_MAX - 1;

    const result = syscall.mapPf(empty_slot, &.{ 0, pf_handle });

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
