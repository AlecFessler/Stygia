// Stateless filesystem wire protocol.
//
// fs is the server (recv side); any client speaking this protocol
// holds an xfer-side port handle plus a shared io_scratch page_frame
// mapped at agreed addresses on each side.
//
// Every op is self-contained: paths, data buffers, and pagination
// cookies all live in `io_scratch`. The server keeps NO per-client
// state — each request carries (path, offset, length, …) in full.
//
// vreg layout (rides spec-v3 suspend/recv):
//
//   v3 = op (Op)
//   v4..v7 = op-specific small ints (offsets, lengths, modes, …)
//
// Reply:
//
//   v1 = status (Status)
//   v2..v5 = op-specific results (returned bytes, new size, …)
//
// io_scratch layout per op is documented next to each Op below.

pub const SCRATCH_PAGES: u64 = 16;
pub const SCRATCH_BYTES: u64 = SCRATCH_PAGES * 4096;

/// Maximum file path length (POSIX-typical PATH_MAX).
pub const PATH_MAX: usize = 4096;

/// Maximum file/directory name component length.
pub const NAME_MAX: usize = 255;

pub const Op = enum(u64) {
    // path at scratch[0..path_len]; v4=path_len.
    // reply: v1=status, v2=inode, v3=kind (Kind), v4=size, v5=mtime
    lookup = 1,

    // path at scratch[0..path_len]; v4=path_len.
    // reply: v1=status, v2=inode, v3=kind, v4=size, v5=mtime,
    //        v6=mode, v7=link_count, v8=ctime, v9=atime
    stat = 2,

    // path at scratch[0..path_len]; v4=path_len, v5=offset, v6=max_len.
    // reply: v1=status, v2=bytes_read, v3=data_off (in scratch).
    // server places data at scratch[data_off..data_off+bytes_read].
    pread = 3,

    // path at scratch[0..path_len]; data at scratch[v6..v6+v7].
    // v4=path_len, v5=offset, v6=data_off, v7=data_len.
    // reply: v1=status, v2=bytes_written, v3=new_size.
    pwrite = 4,

    // path at scratch[0..path_len]; v4=path_len, v5=new_size.
    // reply: v1=status.
    truncate = 5,

    // path at scratch[0..path_len]; v4=path_len, v5=mode.
    // reply: v1=status, v2=inode.
    create_file = 6,

    // path at scratch[0..path_len]; v4=path_len.
    // reply: v1=status.
    unlink = 7,

    // path at scratch[0..path_len]; v4=path_len, v5=mode.
    // reply: v1=status, v2=inode.
    mkdir = 8,

    // path at scratch[0..path_len]; v4=path_len.
    // reply: v1=status.
    rmdir = 9,

    // old at scratch[0..old_len]; new at scratch[old_len+1..old_len+1+new_len].
    // v4=old_len, v5=new_len.
    // reply: v1=status.
    rename = 10,

    // path at scratch[0..path_len]; target at scratch[path_len+1..path_len+1+target_len].
    // v4=path_len, v5=target_len.
    // reply: v1=status, v2=inode.
    symlink = 11,

    // path at scratch[0..path_len]; v4=path_len.
    // reply: v1=status, v2=target_len. target at scratch[0..target_len].
    readlink = 12,

    // path at scratch[0..path_len]; cookie at scratch[path_len+1..path_len+1+cookie_len].
    // v4=path_len, v5=cookie_len, v6=max_entries.
    // reply: v1=status, v2=entry_count, v3=entries_off, v4=entries_bytes,
    //        v5=next_cookie_off, v6=next_cookie_len.
    // entries layout (packed) at scratch[entries_off..entries_off+entries_bytes]:
    //   per record:
    //     u64 inode
    //     u8  kind
    //     u8  name_len
    //     [6 bytes pad]
    //     [name_len bytes name]
    //     pad to 8-byte boundary
    // next_cookie (the last name returned, for resume) at
    //   scratch[next_cookie_off..next_cookie_off+next_cookie_len].
    // next_cookie_len == 0 means "end of directory".
    readdir = 13,

    // no inputs.
    // reply: v1=status. flushes journal + asks back-end to flush.
    sync = 14,

    _,
};

pub const Kind = enum(u64) {
    file = 0,
    dir = 1,
    symlink = 2,
    _,
};

pub const Status = enum(u64) {
    ok = 0,
    not_found = 1,
    not_a_directory = 2,
    is_a_directory = 3,
    name_too_long = 4,
    path_too_long = 5,
    no_space = 6,
    exists = 7,
    not_empty = 8,
    bad_op = 9,
    invalid = 10,
    io_error = 11,
    bad_path = 12,
    too_many_links = 13,
    fail = 14,
    _,
};

/// One entry in a READDIR reply. Bit-for-bit layout in `io_scratch`.
pub const DirRec = extern struct {
    inode: u64,
    kind: u8,
    name_len: u8,
    _pad: [6]u8 = .{ 0, 0, 0, 0, 0, 0 },
    // followed inline by `name_len` name bytes + zero pad to 8-byte boundary.
};

pub const DIR_REC_HDR_BYTES: usize = @sizeOf(DirRec);

pub fn alignUp8(x: usize) usize {
    return (x + 7) & ~@as(usize, 7);
}
