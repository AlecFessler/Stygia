// Spec §[create_var] — test 17.
//
// "[test 17] returns E_INVAL if any reserved bits are set in [1] or [2]."
//
// Strategy
//   §[create_var] pins the layout of [1] and [2] explicitly:
//     [1] caps:  bits  0-15 = caps; bits 16-63 = _reserved.
//     [2] props: bits  0-2  = cur_rwx; 3-4 = sz; 5-6 = cch;
//                bits  7-63 = _reserved.
//   Setting any bit in those reserved ranges must surface E_INVAL at
//   the syscall ABI layer regardless of whether the rest of the call
//   would otherwise have succeeded (§[syscall_abi]).
//
//   To isolate the reserved-bit check we make every other create_var
//   prelude check pass — same shape as create_var_05 — and then dial
//   in a single reserved bit on top of an otherwise-valid caps word.
//   We use bit 63 of [1] (the top of the 48-bit reserved range) which
//   sits well above the `max_sz` field (bits 6-7) and the `dma`/
//   `restart_policy` fields, so it cannot be mistaken for a real cap
//   that the kernel would reject for a different reason. A second
//   sub-test sets bit 63 of [2] for the same reason: it is well above
//   props' last live bit (bit 6) and cannot collide with any defined
//   field.
//
//   The libz `syscall.createVar` wrapper takes u64 args, so it does
//   not strip upper bits. We still bypass it via `syscall.issueReg`
//   to mirror the affinity_04 reference pattern and keep the call
//   shape explicit at the ABI layer.
//
// Action
//   1. createVar with caps = (valid_caps | (1<<63)), valid props
//      — must return E_INVAL.
//   2. createVar with valid caps, props = (valid_props | (1<<63))
//      — must return E_INVAL.
//
// Assertions
//   1: reserved bit set in [1] did not return E_INVAL.
//   2: reserved bit set in [2] did not return E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Same valid-create_var setup as create_var_05: caps={r,w},
    // props.cur_rwx=r|w, sz/cch/max_sz/mmio/dma all 0, pages=1,
    // preferred_base=0 (kernel chooses), device_region=0.
    const var_caps = caps.VarCap{ .r = true, .w = true };
    const valid_caps: u64 = @as(u64, var_caps.toU16());
    const valid_props: u64 = 0b011; // cur_rwx = r|w; sz = 0; cch = 0

    // Case 1: bit 63 of [1] set — sits in the bits 16-63 _reserved
    // range of the caps word.
    const caps_with_reserved: u64 = valid_caps | (@as(u64, 1) << 63);
    const r1 = syscall.issueReg(.create_var, 0, .{
        .v1 = caps_with_reserved,
        .v2 = valid_props,
        .v3 = 1,
        .v4 = 0,
        .v5 = 0,
    });
    if (r1.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    // Case 2: bit 63 of [2] set — sits in the bits 7-63 _reserved
    // range of the props word.
    const props_with_reserved: u64 = valid_props | (@as(u64, 1) << 63);
    const r2 = syscall.issueReg(.create_var, 0, .{
        .v1 = valid_caps,
        .v2 = props_with_reserved,
        .v3 = 1,
        .v4 = 0,
        .v5 = 0,
    });
    if (r2.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
