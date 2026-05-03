// Spec §[create_var] — test 01.
//
// "[test 01] returns E_PERM if the caller's self-handle lacks `crvr`."
//
// Strategy
//   The runner's primary gives every test domain a self-handle with
//   `crvr = true`. To force the create_var E_PERM path we must drop
//   the `crvr` bit on the self-handle before invoking the syscall.
//
//   §[restrict] is the right primitive: it reduces caps in place on
//   any handle and requires no self-handle cap of its own. For the
//   self-handle we read the current caps verbatim out of the read-
//   only-mapped cap table, clear bit 2 (`crvr`), and write that
//   reduced word back. Every other bit stays identical, so neither
//   the bitwise subset check nor any reserved-bit rejection can
//   fire — restrict must succeed, and the only spec-mandated
//   outcome of the subsequent create_var call is E_PERM.
//
// Action
//   1. read self-handle caps from slot 0 of the cap table
//   2. restrict(self, caps & ~crvr) — must succeed
//   3. create_var(...)              — must return E_PERM
//
// Assertions
//   1: self-handle did not actually carry `crvr` (runner contract
//      broken; the precondition this test relies on is gone)
//   2: restrict failed when dropping the crvr bit
//   3: create_var returned something other than E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const CRVR_BIT: u16 = 1 << 2;

pub fn main(cap_table_base: u64) void {
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    const cur_caps: u16 = self_cap.caps();

    if ((cur_caps & CRVR_BIT) == 0) {
        testing.fail(1);
        return;
    }

    const reduced_caps: u16 = cur_caps & ~CRVR_BIT;
    const restrict_result = syscall.restrict(caps.SLOT_SELF, @as(u64, reduced_caps));
    if (restrict_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    // create_var args: caps with r/w set, props.sz=0, pages=1, base=0, dev=0.
    // VarCap r=bit2, w=bit3.
    const var_caps: u64 = (1 << 2) | (1 << 3);
    const props: u64 = 0;
    const pages: u64 = 1;
    const result = syscall.createVar(var_caps, props, pages, 0, 0);
    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
