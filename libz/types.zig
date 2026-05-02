// libz_c/types.zig — C-ABI value types for libz_c.elf.
//
// Mirror of libz/syscall.zig's Regs / RecvReturn but declared as
// `extern struct` so they're allowed to flow through callconv(.c)
// function parameters and returns. Field layout is identical to the
// libz/ versions (all u64), so the C-ABI bridges in abi.zig can
// convert between them with a field-by-field copy.

pub const Regs = extern struct {
    v1: u64 = 0,
    v2: u64 = 0,
    v3: u64 = 0,
    v4: u64 = 0,
    v5: u64 = 0,
    v6: u64 = 0,
    v7: u64 = 0,
    v8: u64 = 0,
    v9: u64 = 0,
    v10: u64 = 0,
    v11: u64 = 0,
    v12: u64 = 0,
    v13: u64 = 0,
};

pub const RecvReturn = extern struct {
    word: u64,
    regs: Regs,
};
