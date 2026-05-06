// serial_client — stateless client library for the serial protocol.
//
// One IPC round-trip per call. The shared scratch page_frame is the
// data plane; both this library and the serial_server alias the same
// page_frame at their own virtual address. The caller hands `scratch_va`
// (its mapped base) and a recv-port handle to every call.

const lib = @import("lib");
const serial = @import("serial");

const caps = lib.caps;
const syscall = lib.syscall;

const HandleId = caps.HandleId;

pub const Status = serial.Status;

pub const SerialError = error{
    BadOp,
    TooBig,
    Fail,
};

pub fn statusErr(s: Status) SerialError!void {
    return switch (s) {
        .ok => {},
        .bad_op => SerialError.BadOp,
        .too_big => SerialError.TooBig,
        else => SerialError.Fail,
    };
}

/// Print `bytes` to the serial sink owned by `serial_server`. Splits
/// nothing — payloads larger than `serial.SCRATCH_BYTES` come back as
/// `SerialError.TooBig`; chunk client-side.
pub fn print(port: HandleId, scratch_va: u64, bytes: []const u8) SerialError!void {
    if (bytes.len > serial.SCRATCH_BYTES) return SerialError.TooBig;
    const dst: [*]u8 = @ptrFromInt(scratch_va);
    @memcpy(dst[0..bytes.len], bytes);
    const r = syscall.issueReg(
        .@"suspend",
        0,
        .{
            .v1 = @as(u64, caps.SLOT_INITIAL_EC),
            .v2 = @as(u64, port),
            .v3 = @intFromEnum(serial.Op.print),
            .v4 = bytes.len,
        },
    );
    try statusErr(@enumFromInt(r.v1));
}
