// Block-device port protocol — wire format between the filesystem
// service and whatever speaks the back end (block_device today, the
// real NVMe driver once IOMMU mapping lands).
//
// Wire shape (v3 vreg ABI):
//
//   Request (sender → port via suspend):
//     v1 = op            // 0 = read, 1 = write
//     v2 = lba           // starting logical-block address
//     v3 = count         // number of 512-byte sectors
//     v4 = buf_offset    // byte offset into the scratch buffer
//
//   Reply (server → sender via reply):
//     v1 = status        // 0 = ok; non-zero per Status below
//
// The data path is a shared page_frame ("scratch") mapped into both
// the fs and the block_device service. For reads, the server writes
// `count * 512` bytes into scratch starting at `buf_offset`. For
// writes, the client populates scratch first; the server reads from
// it and commits to its backing store.
//
// LBA size is fixed at 512 for now (matches both QEMU NVMe defaults
// and the page_frame-backed interim block_device's chosen format).

pub const BLOCK_SIZE: u64 = 512;

pub const Op = enum(u64) {
    read = 0,
    write = 1,
    _,
};

pub const Status = enum(u64) {
    ok = 0,
    bad_op = 1,
    out_of_range = 2,
    fail = 3,
    _,
};
