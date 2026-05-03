// Spec §[create_port] — test 03.
//
// "[test 03] returns E_INVAL if any reserved bits are set in [1]."
//
// Strategy
//   §[create_port] pins the layout of [1] explicitly:
//     [1] caps:  bits  0-15 = caps; bits 16-63 = _reserved.
//   Setting any bit in that reserved range must surface E_INVAL at
//   the syscall ABI layer regardless of whether the rest of the call
//   would otherwise have succeeded (§[syscall_abi]).
//
//   To isolate the reserved-bit check we make every other create_port
//   prelude check pass and then dial in a single reserved bit on top
//   of an otherwise-valid word:
//     - caller self-handle has `crpt` (test 01): the runner grants it
//       on every spawned test domain.
//     - caps' live bits are a subset of the runner's port_ceiling
//       (test 02): port_ceiling = 0x1C carries xfer/recv/bind, so we
//       set bind only — strictly within the ceiling.
//     - all reserved bits zero except the single bit under test.
//
//   Two sub-cases probe the boundary of the reserved range. Bit 16 is
//   the lowest reserved bit (one past the 0-15 caps field), and bit 63
//   is the highest. Both must produce E_INVAL.
//
//   The libz `syscall.createPort` wrapper takes a u64 caps argument so
//   it does not strip upper bits. We still bypass it via
//   `syscall.issueReg` to mirror the create_page_frame_08 reference
//   pattern and keep the call shape explicit at the ABI layer.
//
// Action
//   1. create_port with caps = (valid_caps | (1<<16)) — must return
//      E_INVAL.
//   2. create_port with caps = (valid_caps | (1<<63)) — must return
//      E_INVAL.
//
// Assertions
//   1: low reserved bit (16) set in [1] did not return E_INVAL.
//   2: high reserved bit (63) set in [1] did not return E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Valid caps within the runner's port_ceiling (xfer/recv/bind).
    // Use `bind` only — minimally sufficient for a successful mint —
    // so the only thing that can fail this call is the reserved-bit
    // check itself.
    const port_caps = caps.PortCap{ .bind = true };
    const valid_caps: u64 = @as(u64, port_caps.toU16());

    // Case 1: bit 16 set — the lowest bit of the [1] bits 16-63
    // _reserved range.
    const caps_low_reserved: u64 = valid_caps | (@as(u64, 1) << 16);
    const r1 = syscall.issueReg(.create_port, 0, .{ .v1 = caps_low_reserved });
    if (r1.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(1);
        return;
    }

    // Case 2: bit 63 set — the top of the [1] bits 16-63 _reserved
    // range, well above any defined cap field.
    const caps_high_reserved: u64 = valid_caps | (@as(u64, 1) << 63);
    const r2 = syscall.issueReg(.create_port, 0, .{ .v1 = caps_high_reserved });
    if (r2.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
