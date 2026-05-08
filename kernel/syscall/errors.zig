// Spec v3 §[error_codes]. Returned in vreg 1 by syscalls that fail.
// Zero = success. Values match the table in docs/kernel/specv3.md
// verbatim — userspace compares directly against these numeric codes.
//
// All values are positive: the v3 ABI does not use sign as a success
// discriminator. For syscalls that return a handle word on success,
// userspace distinguishes errors via the value-range check (the small
// positive error codes 1..15 cannot be confused with a real handle
// word, which always carries a non-zero type tag in bits 12-15 making
// the value >= 0x1000). Internal helpers that distinguish success
// from failure must use `!= 0`, never `< 0`.

pub const OK: i64 = 0;
pub const E_ABANDONED: i64 = 1;
pub const E_BADADDR: i64 = 2;
pub const E_BADCAP: i64 = 3;
pub const E_BUSY: i64 = 4;
pub const E_CLOSED: i64 = 5;
pub const E_FULL: i64 = 6;
pub const E_INVAL: i64 = 7;
pub const E_NODEV: i64 = 8;
pub const E_NOENT: i64 = 9;
pub const E_NOMEM: i64 = 10;
pub const E_NOSPC: i64 = 11;
pub const E_PERM: i64 = 12;
pub const E_REFUSED: i64 = 13;
pub const E_TERM: i64 = 14;
pub const E_TIMEOUT: i64 = 15;
// E_AGAIN is kernel-internal — not a spec error code, used in the
// futex fast path to signal value-mismatch retry. Higher than the
// spec range so it cannot collide with a spec-defined error returned
// directly to userspace.
pub const E_AGAIN: i64 = 16;
