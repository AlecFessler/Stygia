// Spec §[map_pf] — test 02.
//
// "[test 02] returns E_BADCAP if any [2 + 2i + 1] is not a valid
//  page_frame handle."
//
// Strategy
//   To isolate the page_frame BADCAP check we need [1] to be a valid
//   VAR handle so map_pf clears the §[map_pf] test 01 path, and we
//   need every other rejection path that could fire ahead of the
//   per-pair page_frame validity check to be inert. With a single
//   pair (N = 1):
//     - test 01 (VAR is invalid) — pass a freshly-minted regular VAR
//       handle.
//     - test 03 (caps.mmio set) — caps = {r,w}, mmio = 0.
//     - test 04 (N == 0) — N = 1.
//     - test 05 (offset misaligned to VAR sz) — offset = 0 is aligned
//       to any sz, including the VAR's sz = 0 (4 KiB).
//     - test 10 (VAR.map ∈ {2,3}) — fresh VAR has map = 0.
//   Tests 06-09 all dereference the page_frame, so they cannot fire
//   ahead of the BADCAP check on the page_frame handle itself; they
//   would surface only after that check passes.
//
//   The child capability domain's table is populated by the kernel at
//   `create_capability_domain` time:
//     slot 0 → self
//     slot 1 → initial EC
//     slot 2 → self-IDC
//     slot 3 → result port (the only passed_handle from the runner)
//   plus the freshly-minted VAR slot. Slot 4095 — the maximum 12-bit
//   handle id — is therefore guaranteed to be empty (see restrict_01
//   for the same construction).
//
// Action
//   1. createVar(caps={r,w}, props=0b011, pages=1) — must return a
//      VAR handle in vreg 1 (assertion 1 guards this precondition).
//   2. mapPf(var_handle, &.{ 0, 4095 }) — offset 0 is aligned, but
//      page_frame_handle = slot 4095 is empty by construction, so
//      the kernel must return E_BADCAP per §[map_pf] test 02.
//
// Assertions
//   1: vreg 1 was not E_BADCAP (the spec assertion under test).
//   2: createVar returned an error code in vreg 1 — the success-path
//      precondition is broken so we cannot proceed to verify the
//      map_pf BADCAP path.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const var_caps = caps.VarCap{ .r = true, .w = true };
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

    const var_handle: caps.HandleId = @truncate(cv.v1 & 0xFFF);
    const empty_slot: u12 = caps.HANDLE_TABLE_MAX - 1;

    const result = syscall.mapPf(var_handle, &.{ 0, empty_slot });

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
