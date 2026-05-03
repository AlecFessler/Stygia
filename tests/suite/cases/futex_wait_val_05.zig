// Spec §[futex_wait_val] futex_wait_val — test 05.
//
// "[test 05] returns E_BADADDR if any addr is not a valid user
//  address in the caller's domain."
//
// Strategy
//   The runner gives every test domain a self-handle with
//   `fut_wait_max = 63` (see runner/primary.zig ceilings_outer), so
//   test 01's E_PERM (fut_wait_max = 0) and test 03's E_INVAL
//   (N > fut_wait_max) cannot fire. Picking N = 1 keeps us inside
//   test 02's [1, 63] range. Choosing an 8-byte-aligned address keeps
//   us out of test 04's E_INVAL.
//
//   The remaining filter to satisfy is the "valid user address in
//   the caller's domain" requirement. Per arch/dispatch/paging.zig
//   the x86_64 user partition is `[0, 0xFFFF_8000_0000_0000)`; any
//   address with bit 63 set is in the kernel half and cannot be a
//   valid user mapping in any capability domain. `0xFFFF_8000_0000_0000`
//   is the first kernel-half address, is 8-byte aligned, and is
//   guaranteed unmapped from the test domain's user-side page
//   tables — `resolveVaddr` returns null and the syscall must
//   produce E_BADADDR.
//
//   timeout_ns = 0 forces the non-blocking entry path so the test
//   never hits the scheduler; the address-check is performed during
//   argument validation, before any wait. The expected value paired
//   with the bad address is irrelevant — the kernel rejects on the
//   address before reading `*addr` — but we set it to 0 to keep the
//   call deterministic.
//
// Action
//   1. futex_wait_val(timeout_ns = 0,
//                     pairs = .{ 0xFFFF_8000_0000_0000, 0 })
//      — must return E_BADADDR.
//
// Assertions
//   1: futex_wait_val returned something other than E_BADADDR.

const lib = @import("lib");

const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // First kernel-half address on x86_64; 8-byte aligned; never a
    // valid user mapping. Pair the expected value 0 — never read,
    // since the kernel rejects on the address before dereferencing.
    const bad_addr: u64 = 0xFFFF_8000_0000_0000;
    const pairs = [_]u64{ bad_addr, 0 };

    const result = syscall.futexWaitVal(0, pairs[0..]);
    if (result.v1 != @intFromEnum(errors.Error.E_BADADDR)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
