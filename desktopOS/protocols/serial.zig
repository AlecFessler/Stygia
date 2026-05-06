// Serial server wire protocol.
//
// One op: print N bytes from offset 0 of the shared scratch page_frame.
// Server is `serial_server`; clients hold an xfer-side port handle plus
// the same scratch page_frame the server holds, mapped on each side.
//
// vreg layout (rides spec-v3 suspend/recv):
//
//   v3 = op (Op)
//   v4 = byte_count
//
// Reply:
//
//   v1 = status (Status)
//
// Bytes are read from scratch[0..byte_count]. Messages bigger than the
// scratch must be split client-side.

pub const SCRATCH_PAGES: u64 = 1;
pub const SCRATCH_BYTES: u64 = SCRATCH_PAGES * 4096;

pub const Op = enum(u64) {
    print = 1,
    _,
};

pub const Status = enum(u64) {
    ok = 0,
    bad_op = 1,
    too_big = 2,
    _,
};
