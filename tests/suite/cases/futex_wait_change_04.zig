// Spec §[futex_wait_change] futex_wait_change — test 04.
//
// "[test 04] returns E_INVAL if any addr is not 8-byte aligned."
//
// Strategy
//   The check under test is the per-pair addr alignment gate: every
//   addr in the pairs list must be a multiple of 8. To isolate this
//   gate from the other E_PERM / E_INVAL paths in futex_wait_change,
//   every other precondition must be satisfied:
//     - the caller's self-handle must have `fut_wait_max >= 1` so
//       test 01 (E_PERM, fut_wait_max = 0) cannot fire,
//     - N must be in [1, 63] and N must not exceed `fut_wait_max` so
//       tests 02 and 03 cannot fire,
//     - the addr we pass must resolve to a valid user mapping in the
//       caller's domain so test 05 (E_BADADDR) cannot fire if a
//       future implementation evaluates that gate before alignment.
//
//   The test runs in the root capability domain, whose self-handle
//   carries the full ceiling — `fut_wait_max` is therefore non-zero,
//   so tests 01/03 cannot trigger. We pass a single (addr, target)
//   pair (N = 1), so test 02 cannot trigger either.
//
//   Setup:
//     1. createPageFrame(caps={r,w}, props=0, pages=1) — backing
//        storage so the VAR has live, mapped bytes.
//     2. createVar(caps={r,w}, props={cur_rwx=r|w, sz=0, cch=0},
//        pages=1, preferred_base=0, device_region=0) — regular VAR
//        whose base vaddr is reported in field0 (cvar.v2). With
//        cur_rwx = r|w the kernel can resolve the vaddr to a paddr
//        once we install a page_frame, defeating any future test 05
//        ordering surprise.
//     3. mapPf(var, &.{ 0, pf }) — install the page_frame at offset
//        0 of the VAR; map transitions 0 -> 1.
//
//   Action:
//     futexWaitChange(timeout_ns = 0, pairs = .{ var_base + 1, 0 }).
//     The addr `var_base + 1` is one past an aligned base, so its
//     low 3 bits are nonzero (`var_base` is page-aligned, hence
//     8-byte aligned). Per §[futex_wait_change] test 04 the kernel
//     must return E_INVAL. timeout_ns = 0 (non-blocking) keeps the
//     call from suspending if the alignment gate were skipped.
//
// Assertions
//   1: a setup syscall returned an error (createPageFrame, createVar,
//      or mapPf) — the precondition for the assertion is broken so we
//      cannot proceed.
//   2: futex_wait_change did not return E_INVAL after passing a
//      misaligned addr (the spec assertion under test).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: page_frame with caps = r|w. Provides backing storage
    // for the VAR so the addr we later pass resolves to a real paddr.
    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1, // pages
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const pf_handle: u64 = @as(u64, cpf.v1 & 0xFFF);

    // Step 2: regular VAR with caps = r|w and cur_rwx = r|w. The
    // kernel chooses the base; field0 (cvar.v2) reports it. The base
    // is page-aligned (4 KiB), hence 8-byte aligned, so adding 1
    // produces a guaranteed-misaligned addr.
    const var_caps = caps.VarCap{ .r = true, .w = true };
    const props: u64 = 0b011; // cur_rwx = r|w; sz = 0 (4 KiB); cch = 0
    const cvar = syscall.createVar(
        @as(u64, var_caps.toU16()),
        props,
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

    // Step 3: install the page_frame at offset 0. After this, CPU
    // accesses to VAR.base[0..4096] hit the page_frame and the
    // kernel can resolve vaddrs in that range to a paddr.
    const mr = syscall.mapPf(var_handle, &.{ 0, pf_handle });
    if (errors.isError(mr.v1)) {
        testing.fail(1);
        return;
    }

    // Step 4: futex_wait_change with a single pair whose addr is
    // var_base + 1 — a valid user address but not 8-byte aligned.
    // timeout_ns = 0 (non-blocking) keeps the call from suspending
    // if the alignment gate were skipped. Per §[futex_wait_change]
    // test 04, the kernel must return E_INVAL.
    const misaligned_addr: u64 = var_base + 1;
    const result = syscall.futexWaitChange(0, &.{ misaligned_addr, 0 });

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
