// Spec §[execution_context] create_execution_context — test 02.
//
// "[test 02] returns E_PERM if [4] is nonzero and [4] lacks `crec`."
//
// Strategy
//   The kernel populates slot 2 of every fresh capability domain with
//   an IDC handle to the domain itself (§[capability_domain] /
//   §[create_capability_domain] test 22). The primary builds the test
//   child with `cridc_ceiling = 0x3F` (all six IDC cap bits set,
//   including `crec` at bit 2), so slot 2 starts with `crec`.
//
//   To isolate the test 02 failure path we drop `crec` from the
//   self-IDC via `restrict`, leaving every other IDC bit intact. After
//   the restrict, slot 2 is a structurally valid IDC handle that
//   resolves to a real domain (so test 07's E_BADCAP check cannot
//   fire) but lacks the cap that test 02 requires.
//
//   With the IDC handle prepared, call create_execution_context with:
//     - caps = 0                — vacuously a subset of any ceiling
//                                  (so tests 03/04/05 do not fire);
//                                  reserved bits are zero (test 10);
//                                  priority field is 0 (test 06);
//                                  restart_policy is 0
//     - entry = arbitrary       — never executed; we expect E_PERM
//     - stack_pages = 1         — nonzero (test 08)
//     - target = SLOT_SELF_IDC  — nonzero, valid IDC, missing `crec`
//     - vm_handle = 0           — no VM
//     - affinity = 0            — any core (test 09)
//   The caller's self-handle holds `crec` (the runner mints it on
//   spawn — see runner/primary.zig `child_self.crec = true`), so test
//   01's E_PERM check cannot fire either. The only spec-mandated
//   error path that fits is test 02.
//
// SPEC AMBIGUITY
//   The libz `createExecutionContext` wrapper places affinity in vreg
//   5, but spec §[execution_context] lists `[5] vm_handle` and
//   `[6] affinity`. Bypass the wrapper and dispatch via `issueReg`
//   with the spec-correct vreg layout so the test does not depend on
//   the wrapper bug.
//
// Action
//   1. restrict(SLOT_SELF_IDC, idc_caps_without_crec)  — must succeed
//   2. create_execution_context(target = SLOT_SELF_IDC) — must return
//      E_PERM
//
// Assertions
//   1: setup restrict failed (returned non-success)
//   2: create_execution_context returned something other than E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Drop `crec` from the self-IDC. Keep every other bit set so the
    // handle stays a fully-formed IDC reference — only the cap test 02
    // checks is missing. `restart_policy` is a single bool field on
    // IdcCap; clearing it would force the bit to 0, so leave it set
    // here to keep behavior change isolated to `crec`.
    const reduced_idc = caps.IdcCap{
        .move = true,
        .copy = true,
        .crec = false,
        .aqec = true,
        .aqvr = true,
        .restart_policy = true,
    };
    const restrict_result = syscall.restrict(
        caps.SLOT_SELF_IDC,
        @as(u64, reduced_idc.toU16()),
    );
    if (restrict_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    // [1] caps word: zero. With all bit-fields zero, reserved bits are
    // zero, priority is 0 (within any ceiling), restart_policy is 0,
    // and target_caps is 0 (vacuous subset of any ec_inner_ceiling).
    const caps_word: u64 = 0;

    // [2] entry: address never reached. Use the libz dummyEntry as a
    // valid-shaped pointer in case the kernel sanity-checks it before
    // the cap check — nothing in the spec mandates that, but it costs
    // nothing to be defensive.
    const entry_addr: u64 = @intFromPtr(&testing.dummyEntry);

    // Spec §[execution_context] vreg layout for create_execution_context:
    //   v1 = caps word
    //   v2 = entry
    //   v3 = stack_pages
    //   v4 = target (IDC handle)
    //   v5 = vm_handle
    //   v6 = affinity mask
    const result = syscall.issueReg(.create_execution_context, 0, .{
        .v1 = caps_word,
        .v2 = entry_addr,
        .v3 = 1,
        .v4 = caps.SLOT_SELF_IDC,
        .v5 = 0,
        .v6 = 0,
    });

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
