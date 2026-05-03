// Spec §[futex_wake] — test 03.
//
// "[test 03] returns E_BADADDR if [1] addr is not a valid user
// address in the caller's domain."
//
// Spec semantics
//   §[error_codes] (table row for E_BADADDR): "a user address
//   argument is not a valid mapped address in the caller's domain".
//   §[futex_wake]: "[1] addr: 8-byte-aligned user address in the
//   caller's domain". The address-validity gate is observably
//   distinct from:
//     - test 01 (E_PERM)  — runner mints the child with `fut_wake`
//                            true, so this test does not touch its
//                            self-handle caps.
//     - test 02 (E_INVAL) — alignment failure. Both witnesses below
//                            are 8-byte aligned, so alignment cannot
//                            preempt the address check.
//
// Strategy
//   To exercise the address-validity gate we need an 8-byte-aligned
//   address that is not part of any mapping in the caller's domain.
//   Two distinct witnesses pin the kernel to a real validity check
//   rather than e.g. only filtering one canonical-half:
//
//     1. Low witness: 0x10. The first page (the NULL page) is never
//        mapped in a user domain. 0x10 is 8-byte aligned, well below
//        any code/data/stack mapping the runner installs.
//     2. High witness: 0xFFFF_FFFF_FFFF_FF00. This sits in the
//        x86-64 high-half (kernel range) and is never part of a
//        user-domain mapping. It is 16-byte (and thus 8-byte)
//        aligned.
//
//   `syscall.futexWake` takes `addr: u64`, so both values flow
//   through verbatim — no need to bypass via `issueReg`.
//
// Action
//   1. futex_wake(addr=0x10, count=1) — must return E_BADADDR.
//   2. futex_wake(addr=0xFFFF_FFFF_FFFF_FF00, count=1) — must
//      return E_BADADDR.
//
// Assertions
//   1: low never-mapped addr did not return E_BADADDR.
//   2: high kernel-half addr did not return E_BADADDR.

const lib = @import("lib");

const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Low witness: 8-byte aligned, in the never-mapped NULL page.
    const r1 = syscall.futexWake(0x10, 1);
    if (r1.v1 != @intFromEnum(errors.Error.E_BADADDR)) {
        testing.fail(1);
        return;
    }

    // High witness: 8-byte aligned, kernel-half address that is
    // never part of a user-domain mapping.
    const r2 = syscall.futexWake(0xFFFF_FFFF_FFFF_FF00, 1);
    if (r2.v1 != @intFromEnum(errors.Error.E_BADADDR)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
