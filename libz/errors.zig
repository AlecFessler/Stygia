// Spec v3 §[error_codes]. Errors are returned in vreg 1 by syscalls
// that fail; zero = success. Names spelled exactly as the spec
// spells them.

pub const Error = enum(u64) {
    OK = 0,
    E_ABANDONED = 1,
    E_BADADDR = 2,
    E_BADCAP = 3,
    E_BUSY = 4,
    E_CLOSED = 5,
    E_FULL = 6,
    E_INVAL = 7,
    E_NODEV = 8,
    E_NOENT = 9,
    E_NOMEM = 10,
    E_NOSPC = 11,
    E_PERM = 12,
    E_REFUSED = 13,
    E_TERM = 14,
    E_TIMEOUT = 15,
    _,
};

pub fn fromRaw(raw: u64) Error {
    return @enumFromInt(raw);
}

pub fn isError(raw: u64) bool {
    return raw != 0;
}
