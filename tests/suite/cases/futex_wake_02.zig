// Spec §[futex] futex_wake — test 02.
//
// "[test 02] returns E_INVAL if [1] addr is not 8-byte aligned."
//
// Strategy
//   §[futex] futex_wake takes a single 8-byte-aligned user address in
//   [1] and a count in [2]:
//
//     futex_wake([1] addr, [2] count) -> [1] woken
//
//   Per the §[futex_wake] gate order in the spec:
//     test 01 — E_PERM if self-handle lacks `fut_wake`
//     test 02 — E_INVAL if [1] is not 8-byte aligned
//     test 03 — E_BADADDR if [1] is not valid in the caller's domain
//     test 04 — success
//
//   The runner's primary spawns the test with `fut_wake = true` on its
//   self-handle (see runner/primary.zig: child_self.fut_wake = true), so
//   the test 01 (E_PERM) gate stays inert.
//
//   To keep the test 03 (E_BADADDR) gate from masking the alignment
//   check, we feed a misaligned address that lies inside a valid
//   user-mapped page in the caller's domain. We construct that by
//   creating a VAR backed by a fresh page frame, then offsetting the
//   VAR's base vaddr by 1 byte. The result is a real, mapped, R/W
//   user address that is unambiguously not 8-byte aligned. Whatever
//   gate ordering the kernel uses, the only error path that can fire
//   on this input is E_INVAL.
//
//   count = 0 is a valid value for futex_wake ("wake at most 0 ECs"),
//   so it does not synthesize a separate failure.
//
// Action
//   1. createPageFrame(caps={r,w}, props=0 [4 KiB], pages=1)
//      — must succeed; gives a backing PF.
//   2. createVar(caps={r,w}, props={cur_rwx=r|w, sz=0, cch=0}, pages=1)
//      — must succeed; gives a 1-page user VAR with a base vaddr.
//   3. mapPf(var_handle, .{ 0, pf_handle })
//      — binds page 0 of the VAR to the PF so the vaddr is actually
//      mapped in the caller's domain.
//   4. futexWake(var_base + 1, 0)
//      — must return E_INVAL because var_base + 1 is not 8-byte
//      aligned.
//
// Assertions
//   1: prelude (PF / VAR creation) failed; cannot exercise the gate.
//   2: futexWake on a misaligned-but-mapped address did not return
//      E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: backing page frame, 1 page (sz = 0 means 4 KiB).
    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // pages = 1
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const pf_handle: caps.HandleId = @truncate(cpf.v1 & 0xFFF);

    // Step 2: VAR with cur_rwx = r|w, 1 page, kernel-chosen base.
    const var_caps = caps.VarCap{ .r = true, .w = true };
    const cvar = syscall.createVar(
        @as(u64, var_caps.toU16()),
        0b011, // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0
        1, // pages = 1
        0, // preferred_base = kernel chooses
        0, // device_region = unused (caps.dma = 0)
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(1);
        return;
    }
    const var_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);
    const var_base: u64 = cvar.v2;

    // Step 3: bind page 0 of the VAR to the PF so var_base is mapped.
    _ = syscall.mapPf(var_handle, &.{ 0, pf_handle });

    // VAR bases are page-aligned by construction; +1 byte is therefore
    // unambiguously misaligned (any of the low three bits being set
    // violates 8-byte alignment).
    const misaligned_addr: u64 = var_base + 1;

    const result = syscall.futexWake(misaligned_addr, 0);

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
