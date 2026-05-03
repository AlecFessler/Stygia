// Spec §[create_var] — test 19.
//
// "[test 19] on success, field0 contains the assigned base address."
//
// Strategy
//   Replicate runner/serial.zig's success path: caps={r,w} (no mmio
//   so we steer clear of the device ceilings/sizing rules), props.sz
//   = 0 (4 KiB), props.cur_rwx = 0b011 (r|w, subset of caps.r/w),
//   pages = 1, preferred_base = 0 (kernel chooses), device_region =
//   0 (caps.dma = 0 so unused). All of test 02..test 17's E_PERM
//   and E_INVAL gates are dodged, so the syscall succeeds.
//
//   On success the wrapper returns v1 = caps_word|handle_id and
//   v2 = the assigned base address. The handle's field0 is defined
//   by §[create_var] test 19 to hold that base. To assert this we
//   read the cap directly out of the read-only-mapped cap table —
//   field0 is set as part of the kernel's atomic install of the
//   handle, so the snapshot is authoritative without `sync`.
//
// Action
//   1. createVar(caps={r,w}, props={sz=0, cch=0, cur_rwx=0b011},
//                pages=1, preferred_base=0, device_region=0)
//      — must succeed; v2 = base.
//   2. readCap(cap_table_base, handle_id) — verify field0 == v2.
//
// Assertions
//   1: createVar returned an error word in v1 (setup failed).
//   2: cap.field0 != v2 (base address not stored in field0).

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const var_caps = caps.VarCap{ .r = true, .w = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0

    const cv = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
        1,
        0,
        0,
    );
    if (testing.isHandleError(cv.v1)) {
        testing.fail(1);
        return;
    }

    const var_handle: u12 = @truncate(cv.v1 & 0xFFF);
    const base: u64 = cv.v2;

    const cap = caps.readCap(cap_table_base, var_handle);
    if (cap.field0 != base) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
