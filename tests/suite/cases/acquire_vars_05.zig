// Spec §[capability_domain] acquire_vars — test 05.
//
// "[test 05] on success, the syscall word's count field equals the
//  number of `map=1` and `map=3` VARs bound to the target domain."
//
// Strategy
//   The IDC at slot 2 of the test's own handle table — the self-IDC,
//   minted by the kernel at create_capability_domain time per
//   §[capability_domain]/§[create_capability_domain] test 22 — is the
//   only IDC handle the test can use to introspect a domain whose
//   VAR set the test fully controls: its own. acquire_vars on this
//   handle returns handles to the test's own pf and demand-mapped
//   VARs.
//
//   The runner hands the test self-IDC caps from the new domain's
//   `cridc_ceiling` passed in §[create_capability_domain] [2].
//   primary.zig sets `cridc_ceiling = 0x3F` (all six IDC cap bits),
//   so `aqvr` (bit 4) is set on the slot-2 self-IDC. No restrict is
//   needed before the call.
//
//   The exact baseline VAR count for the freshly-spawned test domain
//   depends on how the kernel materializes ELF segments, the EC's
//   stack, and any kernel-allocated VARs at create_capability_domain
//   time — none of which the spec pins. To stay independent of that
//   detail we measure the count delta around a controlled mutation:
//
//     1. Call acquire_vars(self_idc) — record N0 (baseline).
//     2. Create K = 2 new VARs, each backed by a page frame and
//        map_pf'd at offset 0 to drive `map` from 0 to 1. Per §[var]
//        a VAR with `map = 1` is included in acquire_vars's reply.
//     3. Call acquire_vars(self_idc) — record N1.
//     4. Assert N1 == N0 + K.
//
//   This isolates the count-counting behavior from the baseline
//   composition of the test domain. The K = 2 choice rules out an
//   off-by-one masquerading as correct.
//
//   We pick map=1 (pf-installed) rather than map=3 (demand-faulted)
//   because driving a demand fault from a test EC requires touching
//   the VAR's base address, which would mutate the test EC's data
//   segment and risk crashing the test before it reports. map_pf
//   gives us a deterministic state transition into the counted set.
//
//   The syscall word's count field lives in bits 12-19 per
//   §[acquire_vars] (and §[acquire_ecs] uses the same encoding). The
//   libz `syscall.acquireVars` wrapper returns a `RecvReturn` with
//   the post-syscall word in `.word`, so we shift-and-mask out the
//   count.
//
// Action
//   1. acquire_vars(SLOT_SELF_IDC)                 — record baseline N0
//   2. for i in 0..K:
//        create_page_frame(1 page, r|w)
//        create_var(1 page, caps.r|w, props.cur_rwx=r|w)
//        map_pf(var, offset=0, pf)
//   3. acquire_vars(SLOT_SELF_IDC)                 — record N1
//   4. assert N1 == N0 + K
//
// Assertions
//   1: baseline acquire_vars returned an error in vreg 1
//   2: a setup syscall (create_page_frame / create_var / map_pf)
//      returned an error word
//   3: second acquire_vars returned an error in vreg 1
//   4: post-creation count - baseline count != K (the controlled
//      delta did not match)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const K: usize = 2;

fn syscallCount(word: u64) u8 {
    return @truncate((word >> 12) & 0xFF);
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: baseline.
    const baseline = syscall.acquireVars(caps.SLOT_SELF_IDC);
    // On success, v1 is either OK (no handles returned) or a packed
    // handle word; only error codes 1..15 indicate failure per
    // §[error_codes].
    if (testing.isHandleError(baseline.regs.v1)) {
        testing.fail(1);
        return;
    }
    const n0: u8 = syscallCount(baseline.word);

    // Step 2: mint K pf-mapped VARs.
    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const var_caps = caps.VarCap{ .r = true, .w = true };
    const var_caps_word: u64 = @as(u64, var_caps.toU16());
    const pf_caps_word: u64 = @as(u64, pf_caps.toU16());
    // §[create_var] props: cur_rwx in bits 0-2; sz=0 (4 KiB) default;
    // cch=0 (wb) default. Set r|w to match VAR caps.
    const props_rw: u64 = 0b011;

    var i: usize = 0;
    while (i < K) {
        const cpf = syscall.createPageFrame(pf_caps_word, 0, 1);
        if (testing.isHandleError(cpf.v1)) {
            testing.fail(2);
            return;
        }
        const pf_handle: caps.HandleId = @truncate(cpf.v1 & 0xFFF);

        const cvar = syscall.createVar(var_caps_word, props_rw, 1, 0, 0);
        if (testing.isHandleError(cvar.v1)) {
            testing.fail(2);
            return;
        }
        const var_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);

        const mp = syscall.mapPf(var_handle, &.{ 0, @as(u64, pf_handle) });
        if (mp.v1 != @intFromEnum(errors.Error.OK)) {
            testing.fail(2);
            return;
        }

        i += 1;
    }

    // Step 3: post-creation count.
    const after = syscall.acquireVars(caps.SLOT_SELF_IDC);
    if (testing.isHandleError(after.regs.v1)) {
        testing.fail(3);
        return;
    }
    const n1: u8 = syscallCount(after.word);

    // Step 4: delta.
    if (@as(usize, n1) != @as(usize, n0) + K) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
