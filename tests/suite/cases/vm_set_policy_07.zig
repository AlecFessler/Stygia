// Spec §[vm_set_policy] vm_set_policy — test 07.
//
// "[test 07] on aarch64 with kind=0, the VM's `id_reg_responses` table
//  is replaced by the count entries; subsequent guest reads of matching
//  ID_AA64* registers return the configured values per §[vm_policy]."
//
// Demonstrated stale-test weakness
//   The previous version was a degraded x86-only smoke: it hard-coded
//   x86-64's 976-byte VmPolicy layout, then called
//   vmSetPolicy(kind=0,count=0,&.{}). That is vacuous for this spec
//   sentence. On x86-64, kind=0 selects `cpuid_responses`, not
//   aarch64 `id_reg_responses`, and count=0 only proves that an empty
//   replacement is accepted on the active architecture. It neither
//   installed an IdRegResponse entry nor reached the aarch64 table.
//
// Strategy — partial aarch64 coverage, not guest-read proof
//   This test now follows the local pattern from vm_set_policy_08:
//     1. On non-aarch64 builds, return an explicit degraded pass. The
//        same kind selector owns `cpuid_responses` there, and
//        vm_set_policy_05 owns that x86-64 surface.
//     2. On aarch64 with no hardware virtualization, tolerate E_NODEV
//        from create_virtual_machine. Without a VM, the replacement
//        path is unreachable.
//     3. On aarch64 with virtualization, install a non-empty
//        kind=0,count=1 IdRegResponse for ID_AA64PFR0_EL1, clear the
//        table with count=0, then reinstall the non-empty entry. This
//        proves the syscall-visible mutable replacement path for the
//        real aarch64 id_reg_responses table, including repeated
//        replacement.
//
//   This still does not claim the second half of the spec sentence:
//   observing a guest read return the configured value requires a
//   suite harness that can map guest code, create/run a vCPU, execute
//   an MRS ID_AA64* instruction, and inspect the result. The aarch64
//   kernel run loop does consult `id_reg_responses`; the remaining
//   blocker is the suite-level guest/vCPU witness.
//
// Defusing other vm_set_policy error paths
//   - test 01 (E_BADCAP not a valid VM handle): we mint a real VM.
//   - test 02 (E_PERM no `policy` cap): we mint with
//     VmCap{ .policy = true }; the runner grants vm_ceiling = 0x01.
//   - test 03 (E_INVAL count exceeds MAX_*): count = 1, well under
//     MAX_ID_REG_RESPONSES (62).
//   - test 04 (E_INVAL reserved bits): the handle slot is low 12 bits
//     only, and the entry tuple uses bytes 0..4 with pad bytes 5..7
//     zero.
//
// Action
//   1. Non-aarch64 builds return degraded pass because kind=0 targets
//      cpuid_responses there.
//   2. Stage VmPolicy (PF + VMAR + map_pf + zero).
//   3. createVirtualMachine(caps={.policy=true}, policy_pf) — VM handle
//      (or degraded pass on E_NODEV).
//   4. vmSetPolicy(vm_handle, kind=0, count=1, one IdRegResponse entry)
//      must return OK.
//   5. vmSetPolicy(vm_handle, kind=0, count=0, &.{}) must return OK.
//   6. vmSetPolicy(vm_handle, kind=0, count=1, same entry) must return
//      OK.
//
// Assertions
//   1: setup — createPageFrame returned an error word.
//   2: setup — createVmar returned an error word.
//   3: setup — mapPf returned non-OK in vreg 1.
//   4: setup — createVirtualMachine returned an unexpected error
//      (anything other than a valid handle or E_NODEV).
//   9: vm_set_policy(kind=0,count=1) returned non-OK for a valid
//      aarch64 IdRegResponse entry.
//  10: vm_set_policy(kind=0,count=0) returned non-OK for a clear.
//  11: vm_set_policy(kind=0,count=1) returned non-OK on reinstall.

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

// §[vm_policy] aarch64 sizeof(VmPolicy) = 1776; x86-64 = 976. Both
// fit in 4 KiB. We zero the larger layout so this source builds under
// either arch, while only aarch64 reaches the meaningful path.
const VM_POLICY_BYTES: usize = 1776;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    if (builtin.cpu.arch != .aarch64) {
        // Non-aarch64 builds cannot exercise `id_reg_responses`: kind=0
        // selects the x86-64 CPUID table there, covered by test 05.
        testing.pass();
        return;
    }

    // 1. Page frame backing the VmPolicy struct.
    const policy_pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf_policy = syscall.createPageFrame(
        @as(u64, policy_pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB), restart_policy = 0
        1,
    );
    if (testing.isHandleError(cpf_policy.v1)) {
        testing.fail(1);
        return;
    }
    const policy_pf: HandleId = @truncate(cpf_policy.v1 & 0xFFF);

    // 2. VMAR + map so userspace can zero the policy bytes.
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
    //    folding the stores against the kernel's later read on the
    //    create_virtual_machine path.
    const policy_dst: [*]volatile u8 = @ptrFromInt(policy_base);
    var i: usize = 0;
    while (i < VM_POLICY_BYTES) {
        policy_dst[i] = 0;
        i += 1;
    }

    // 4. Mint the VM with caps.policy = true so vmSetPolicy can
    //    authorize. On no-virt hosts this returns E_NODEV; the aarch64
    //    table replacement path is unreachable, so degrade with pass.
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

    // 5. Install a real aarch64 IdRegResponse entry. We use
    //    ID_AA64PFR0_EL1:
    //      op0=3, op1=0, CRn=0, CRm=4, op2=0
    //    The tuple is packed into bytes 0..4 of vreg 2; bytes 5..7
    //    are the reserved pad and remain zero. The value is
    //    intentionally non-zero so this is not an empty-table smoke.
    const id_aa64pfr0_el1_tuple: u64 =
        (@as(u64, 3) << 0) |
        (@as(u64, 0) << 8) |
        (@as(u64, 0) << 16) |
        (@as(u64, 4) << 24) |
        (@as(u64, 0) << 32);
    const configured_value: u64 = 0x1122_3344_5566_7788;
    const entry: [2]u64 = .{ id_aa64pfr0_el1_tuple, configured_value };

    const replace_result = syscall.vmSetPolicy(vm_handle, 0, 1, &entry);
    if (replace_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(9);
        return;
    }

    // 6. Clear the ID register response table. This retains the
    //    empty-replacement case, but only after a real entry has been
    //    accepted.
    const clear_result = syscall.vmSetPolicy(vm_handle, 0, 0, &.{});
    if (clear_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(10);
        return;
    }

    // 7. Reinstall the non-empty entry to prove replacement remains
    //    live after a clear. Guest-side readback remains blocked on a
    //    suite harness that can run MRS ID_AA64PFR0_EL1 inside the VM.
    const reinstall_result = syscall.vmSetPolicy(vm_handle, 0, 1, &entry);
    if (reinstall_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(11);
        return;
    }

    testing.pass();
}
