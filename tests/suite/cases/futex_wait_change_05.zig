// Spec §[futex_wait_change] — test 05.
//
// "[test 05] returns E_BADADDR if any addr is not a valid user address
//  in the caller's domain."
//
// Strategy
//   Per kernel/syscall/futex.zig the order of checks for
//   `futex_wait_change` is:
//     1. pairs.len > 0 and even, and N in [1, 63]               (E_INVAL)
//     2. self-handle `fut_wait_max >= 1`                        (E_PERM)
//     3. N <= self-handle `fut_wait_max`                        (E_INVAL)
//     4. for each pair: addr is 8-byte aligned                  (E_INVAL)
//     5. for each pair: resolveCallerVa(addr) succeeds          (E_BADADDR)
//
//   The runner mints each child capability domain with
//   `fut_wait_max = 63` and a non-zero `fut_wake` cap (see
//   runner/primary.zig). To isolate the BADADDR rejection we must
//   pass:
//     - timeout_ns = 0 (non-blocking; even if BADADDR did not fire we
//       would not hang waiting on a target value).
//     - exactly N = 1 pair (well within [1, 63] and <= fut_wait_max).
//     - addr that is 8-byte aligned (so the alignment gate clears).
//     - addr that is not mapped in the caller's domain (so
//       resolveCallerVa returns null and the syscall returns
//       E_BADADDR).
//
//   The test ELF is linked at virtual base 0 and the kernel relocates
//   it into the child's address space alongside its stack and the
//   read-only cap-table view. None of those mappings reach into the
//   high user-half PML4 entries, so an address far above the loaded
//   image — well below the canonical user/kernel split at
//   0xFFFF_8000_0000_0000 — has no PML4 entry installed and walks to
//   null on the kernel's resolveVaddr. We use 0x4000_0000_0000
//   (64 TiB), 8-byte aligned, deep into unmapped user space.
//
// Action
//   1. futexWaitChange(timeout_ns=0,
//                      pairs=&.{ 0x4000_0000_0000, 0 }) — must
//      return E_BADADDR. The target value 0 is irrelevant; the
//      address-resolution gate fires before the per-pair compare.
//
// Assertions
//   1: vreg 1 was not E_BADADDR after the futex_wait_change call (the
//      spec assertion under test).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // 0x4000_0000_0000 = 64 TiB. 8-byte aligned. Deep in the canonical
    // user half (below the 0xFFFF_8000_0000_0000 user/kernel split) but
    // well above any address the loader / stack / cap-table view of
    // this child capability domain occupies. The PML4 entry covering
    // it is unset, so the kernel's page-table walk for resolveVaddr
    // returns null and the syscall must surface E_BADADDR.
    const unmapped_addr: u64 = 0x4000_0000_0000;
    const target: u64 = 0;
    const pairs = [_]u64{ unmapped_addr, target };

    const result = syscall.futexWaitChange(0, pairs[0..]);

    if (result.v1 != @intFromEnum(errors.Error.E_BADADDR)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
