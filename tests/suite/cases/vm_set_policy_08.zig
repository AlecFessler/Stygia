// Spec §[vm_set_policy] — test 08.
//
// "[test 08] on aarch64 with kind=1, the VM's `sysreg_policies` table is
//  replaced by the count entries; subsequent guest sysreg accesses match
//  against this table per §[vm_policy]."
//
// Spec semantics
//   §[vm_set_policy] aarch64 row 1: "kind=1 replaces `sysreg_policies`,
//   3 vregs/entry: `[2+3i+0]` = `{op0, op1, crn, crm, op2, _pad[3]}`;
//   `[2+3i+1]` = `read_value`; `[2+3i+2]` = `write_mask`."
//   §[vm_policy] aarch64: "A guest sysreg read matching the tuple in
//   `sysreg_policies` resumes with `read_value`; a guest sysreg write
//   matching the tuple is applied masked by `write_mask` ... Non-matching
//   sysreg accesses deliver a `vm_exit` event."
//
//   The full assertion ("subsequent guest sysreg accesses match against
//   this table") requires running guest code that issues a sysreg access
//   covered by the replacement table, and observing either the matching
//   resume value (read) or the masked write effect. The aarch64 kernel
//   now has the runloop-side consultation path
//   (kernel/arch/aarch64/vm_runloop.zig: tryHandleSysregPolicy), but
//   this suite child still cannot stage and execute a guest payload.
//
// Strategy — partial aarch64 coverage, not guest-access proof
//   The old version used kind=1,count=0, which was a vacuous empty
//   replacement and did not prove that an aarch64 SysregPolicy entry
//   can be accepted. This version is intentionally aarch64-only for
//   the meaningful path:
//     1. On x86-64, `kind=1` selects `cr_policies`, not
//        `sysreg_policies`, and the aarch64 tuple word would be
//        rejected as reserved-bit pollution by the x86 CR layout. We
//        therefore return a degraded skip/pass on non-aarch64 builds.
//     2. On aarch64 with no hardware virtualization, VM creation
//        returns E_NODEV. Without a VM there is no policy table to
//        replace, so we degrade with pass-with-id-0.
//     3. On aarch64 with virtualization, install a non-empty
//        kind=1,count=1 SysregPolicy entry, clear the table with
//        count=0, then reinstall the non-empty entry. This proves the
//        syscall-visible replacement path for a real sysreg policy
//        table, including repeated replacement, but it still does not
//        prove that a subsequent guest MRS/MSR matched the entry.
//
// Blocker for full bead closure
//   A full feature proof still needs a guest-execution harness in the
//   suite: map guest code, create/run a vCPU, issue an MRS/MSR for the
//   selected tuple, and assert the runloop resumes with `read_value`
//   or applies `(old & ~write_mask) | (guest & write_mask)` without
//   delivering a vm_exit. That is harness work, not a kernel-consultation
//   gap in the current source.
//
//   E_NODEV degradation
//     `create_virtual_machine` returns E_NODEV on platforms without
//     hardware virtualization (§[create_virtual_machine] test 03). On
//     such platforms the VM cannot be minted at all and the spec
//     assertion under test (sysreg_policies replacement) is doubly
//     unreachable. We tolerate that outcome with pass-with-id-0,
//     mirroring create_vcpu_05's smoke shape.
//
// Defusing other vm_set_policy error paths
//   - test 01 (E_BADCAP not a valid VM handle): we mint a real VM.
//   - test 02 (E_PERM no `policy` cap on [1]): we mint with
//     VmCap{ .policy = true }; the runner grants vm_ceiling = 0x01
//     (the policy bit) so the cap is in-range.
//   - test 03 (E_INVAL count exceeds MAX_*): count = 1, well under
//     MAX_SYSREG_POLICIES (32).
//   - test 04 (E_INVAL reserved bits in [1] or any entry): handle slot
//     is in the low 12 bits of [1]; upper 52 bits stay zero by
//     construction (vmSetPolicy wrapper). The entry's tuple uses only
//     bytes 0..4; pad bytes 5..7 stay zero.
//
// Action
//   1. Non-aarch64 builds return a degraded skip/pass because kind=1
//      targets the wrong table there.
//   2. createPageFrame(caps={r,w}, props=0, pages=1) — smallest valid
//      frame, backs the VmPolicy struct.
//   3. createVmar + mapPf so userspace can plant a known-zero VmPolicy.
//   4. Zero the VmPolicy region with volatile stores.
//   5. createVirtualMachine(caps={.policy=true}, policy_pf). Tolerate
//      E_NODEV with degraded pass since the kind=1 replacement path
//      is unreachable without a VM.
//   6. vmSetPolicy(vm_handle, kind=1, count=1, one SysregPolicy entry)
//      must return OK.
//   7. vmSetPolicy(vm_handle, kind=1, count=0, &.{}) must return OK.
//   8. vmSetPolicy(vm_handle, kind=1, count=1, same entry) must return OK.
//
// Assertions
//   1: setup — createPageFrame returned an error word.
//   2: setup — createVmar returned an error word.
//   3: setup — mapPf returned non-OK in vreg 1.
//   4: setup — createVirtualMachine returned an unexpected error
//      (anything other than a valid handle or E_NODEV).
//   9: vm_set_policy(kind=1,count=1) returned non-OK for a valid
//      aarch64 SysregPolicy entry.
//  10: vm_set_policy(kind=1,count=0) returned non-OK for a clear.
//  11: vm_set_policy(kind=1,count=1) returned non-OK on reinstall.

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

// §[vm_policy] aarch64 sizeof(VmPolicy) = 1776; x86-64 = 976. Both
// fit in 4 KiB. We zero the larger of the two so the same source
// works under either arch's VmPolicy layout.
const VM_POLICY_BYTES: usize = 1776;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    if (builtin.cpu.arch != .aarch64) {
        // Non-aarch64 builds cannot exercise `sysreg_policies`: the
        // same kind bit selects a different table. Report an explicit
        // degraded skip/pass instead of proving the wrong primitive.
        testing.pass();
        return;
    }

    // 1. Page frame backing the VmPolicy struct.
    const policy_pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, policy_pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1,
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const policy_pf: HandleId = @truncate(cpf.v1 & 0xFFF);

    // 2. VMAR + mapPf so userspace can plant a zero VmPolicy.
    const policy_var_caps = caps.VmarCap{ .r = true, .w = true };
    const cvar = syscall.createVmar(
        @as(u64, policy_var_caps.toU16()),
        0b011, // cur_rwx = r|w
        1,
        0, // preferred_base = kernel chooses
        0, // device_region = none
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(2);
        return;
    }
    const policy_var: HandleId = @truncate(cvar.v1 & 0xFFF);
    const policy_base: u64 = cvar.v2;

    const map_result = syscall.mapPf(policy_var, &.{ 0, policy_pf });
    if (map_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // 3. Zero the VmPolicy region. Volatile keeps ReleaseSmall from
    //    folding the store against the kernel's later read on the
    //    create_virtual_machine path.
    const policy_dst: [*]volatile u8 = @ptrFromInt(policy_base);
    var i: usize = 0;
    while (i < VM_POLICY_BYTES) {
        policy_dst[i] = 0;
        i += 1;
    }

    // 4. Mint a VM with the `policy` cap so vmSetPolicy can authorize.
    //    On no-virt hosts this returns E_NODEV; the kind=1 replacement
    //    path is unreachable so we degrade with pass-with-id-0.
    const vm_caps = caps.VmCap{ .policy = true };
    const cvm = syscall.createVirtualMachine(
        @as(u64, vm_caps.toU16()),
        policy_pf,
    );
    if (cvm.v1 == @intFromEnum(errors.Error.E_NODEV)) {
        testing.pass();
        return;
    }
    if (testing.isHandleError(cvm.v1)) {
        testing.fail(4);
        return;
    }
    const vm_handle: HandleId = @truncate(cvm.v1 & 0xFFF);

    // 5. Install a real aarch64 SysregPolicy entry. We use SCTLR_EL1:
    //       op0=3, op1=0, CRn=1, CRm=0, op2=0
    //    The tuple is packed into bytes 0..4 of vreg 2; bytes 5..7
    //    are the reserved pad and remain zero. The read/write values
    //    are intentionally non-zero so this is not an empty-table
    //    acceptance smoke.
    const sctlr_el1_tuple: u64 =
        (@as(u64, 3) << 0) |
        (@as(u64, 0) << 8) |
        (@as(u64, 1) << 16) |
        (@as(u64, 0) << 24) |
        (@as(u64, 0) << 32);
    const read_value: u64 = 0x0000_0000_00C5_18D1;
    const write_mask: u64 = 0x0000_0000_0000_FFFF;
    const entry: [3]u64 = .{ sctlr_el1_tuple, read_value, write_mask };

    const replace_result = syscall.vmSetPolicy(vm_handle, 1, 1, &entry);
    if (replace_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(9);
        return;
    }

    // 6. Clear the sysreg policy table. This leg keeps the original
    //    empty replacement covered, but only after a non-empty table
    //    has already been accepted.
    const clear_result = syscall.vmSetPolicy(vm_handle, 1, 0, &.{});
    if (clear_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(10);
        return;
    }

    // 7. Reinstall the non-empty entry to prove replacement remains
    //    live after a clear. Guest-side matching remains blocked on a
    //    suite harness that can run an MRS/MSR in the VM.
    const reinstall_result = syscall.vmSetPolicy(vm_handle, 1, 1, &entry);
    if (reinstall_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(11);
        return;
    }

    testing.pass();
}
