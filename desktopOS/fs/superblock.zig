// fs superblock — 512 bytes pinned to LBA 0 of the backing volume.
//
// Lets fs service distinguish first-boot ("format the volume") from
// subsequent boots ("a SQLite DB already lives at LBA 1+"). Stores the
// logical_size snapshot so the in-memory VFS can advertise it to
// sqlite3_open_v2 before SQLite reads any pages.
//
// Layout is bit-for-bit on disk. Future additions go in the reserved
// tail and bump VERSION; readers refuse a higher version than they
// understand.

pub const MAGIC: u64 = 0x5A41_4746_535F_5642; // "ZAGFS_VB"
pub const VERSION: u32 = 1;
pub const SIZE_BYTES: usize = 512; // matches blockdev BLOCK_SIZE

pub const Superblock = extern struct {
    magic: u64,
    version: u32,
    _reserved0: u32,
    logical_size: u64,
    _reserved_tail: [SIZE_BYTES - 24]u8,

    pub fn fresh() Superblock {
        return .{
            .magic = MAGIC,
            .version = VERSION,
            ._reserved0 = 0,
            .logical_size = 0,
            ._reserved_tail = [_]u8{0} ** (SIZE_BYTES - 24),
        };
    }

    pub fn isValid(self: *const Superblock) bool {
        return self.magic == MAGIC and self.version == VERSION;
    }
};

comptime {
    if (@sizeOf(Superblock) != SIZE_BYTES) @compileError("Superblock must be 512 bytes");
}
