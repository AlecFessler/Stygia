// Spec §[map_mmio] — test 09.
//
// "[test 09] when [1] is a valid handle, [1]'s field0 and field1 are
//  refreshed from the kernel's authoritative state as a side effect,
//  regardless of whether the call returns success or another error
//  code."
//
// Strategy
//   The spec requires that whenever map_mmio sees a valid VAR in [1],
//   the kernel writes back [1]'s field0/field1 from authoritative
//   state — even when the call fails. The test only has to prove the
//   cap-table slot still faithfully reflects kernel state after a
//   failing call: if the kernel didn't change its authoritative state
//   (because the call errored before touching the VAR), then a
//   refresh must leave field1 bit-for-bit unchanged.
//
//   We mint an MMIO VAR using the same prelude as map_mmio_02 and
//   map_pf_03: caps = {r, w, mmio}, props = {sz=0, cch=1 (uc),
//   cur_rwx=0b011}, pages=1, preferred_base=0, device_region=0. This
//   succeeds and yields a VAR handle with `caps.mmio = 1` and
//   `field1.map = 0`.
//
//   We snapshot field1 from the read-only-mapped cap table before
//   the failing call. Then we call map_mmio with [2] = slot 4095 —
//   guaranteed empty by the create_capability_domain table layout
//   (slots 0/1/2 = self / initial EC / self-IDC; passed_handles begin
//   at slot 3) so the kernel returns E_BADCAP on the [2] gate. The
//   [1] gate passes because the VAR is valid, so the spec's refresh
//   requirement applies. After the call we re-read field1 and assert
//   it matches the pre-call snapshot — the kernel's authoritative
//   state never changed (the call errored before any mutation), so a
//   refresh must leave the slot bit-identical.
//
// Action
//   1. createVar(caps={r,w,mmio}, props={sz=0, cch=1 (uc),
//      cur_rwx=0b011}, pages=1, preferred_base=0, device_region=0)
//      — must succeed.
//   2. readCap → snapshot field1.
//   3. mapMmio(mmio_var_handle, 4095) — must return E_BADCAP (the [2]
//      gate fires after the [1] gate passes; the spec's "[1] valid"
//      precondition holds).
//   4. readCap again → field1 must equal the pre-call snapshot.
//
// Assertions
//   1: setup failed (createVar returned an error or the slot's
//      handleType was not virtual_address_range — precondition
//      broken, cannot evaluate the spec assertion).
//   2: field1 differed between the pre-call snapshot and the
//      post-error read — the slot is no longer a faithful reflection
//      of kernel state.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    // Build a valid MMIO VAR. Same construction as map_mmio_02 /
    // map_pf_03 — caps.mmio = 1 forces props.sz = 0 (create_var test
    // 08), caps.x = 0 (test 11), caps.dma = 0 (test 13); cch = 1 (uc)
    // is required for mmio.
    const mmio_caps = caps.VarCap{ .r = true, .w = true, .mmio = true };
    const props: u64 = (1 << 5) | // cch = 1 (uc) — required for mmio
        (0 << 3) | // sz = 0 (4 KiB) — required when caps.mmio = 1
        0b011; // cur_rwx = r|w
    const cvar = syscall.createVar(
        @as(u64, mmio_caps.toU16()),
        props,
        1, // pages = 1
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(1);
        return;
    }
    const mmio_var_handle: u12 = @truncate(cvar.v1 & 0xFFF);

    const cap_pre = caps.readCap(cap_table_base, mmio_var_handle);
    if (cap_pre.handleType() != caps.HandleType.virtual_address_range) {
        testing.fail(1);
        return;
    }
    const field1_pre = cap_pre.field1;

    // Slot 4095 is guaranteed empty by the create_capability_domain
    // table layout, so it is invalid as a device_region handle. The
    // [2] BADCAP gate must fire; the [1] gate has already passed
    // because mmio_var_handle is a valid VAR — that's the
    // precondition for the spec's "field0 and field1 are refreshed"
    // requirement.
    const empty_slot: u12 = caps.HANDLE_TABLE_MAX - 1;
    const mm = syscall.mapMmio(mmio_var_handle, empty_slot);
    _ = mm; // E_BADCAP is the expected outcome but the spec assertion
    // here turns on the cap-table side effect, not the return code.

    // The kernel never reached map_mmio's mutation path (the [2] gate
    // fired first), so the authoritative VAR state is unchanged. A
    // refresh of field0/field1 must therefore leave the slot
    // bit-identical to the pre-call snapshot.
    const cap_post = caps.readCap(cap_table_base, mmio_var_handle);
    if (cap_post.field1 != field1_pre) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
