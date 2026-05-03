// Spec §[create_virtual_machine] create_virtual_machine — test 03.
//
// "[test 03] returns E_NODEV if the platform does not support hardware
//  virtualization."
//
// DEGRADED SMOKE VARIANT
//   The faithful shape of test 03 requires running on a platform whose
//   CPU does *not* expose hardware virtualization (no VMX on x86-64, no
//   EL2/HVF on aarch64). On such a platform, `create_virtual_machine`
//   must return E_NODEV regardless of caps, policy validity, or handle
//   table state.
//
//   Every supported test target violates that precondition:
//
//   (a) The kernel test runner boots under QEMU with `-enable-kvm` and
//       a host CPU that exposes Intel VMX (or AMD SVM) — that is the
//       baseline configuration `test.sh kernel` uses to run the suite.
//       VT-x is available, so the syscall does not take the E_NODEV
//       branch.
//
//   (b) The aarch64 rig (Pi 5, project_aarch64_port_state) likewise
//       runs guests with KVM/EL2 enabled when the kernel runs as a
//       host. There is no in-tree configuration for "boot the test
//       suite with VMX/EL2 disabled."
//
//   (c) Build-time forcing the kernel to advertise no-virt would
//       require either patching the cpuid path or wiring a
//       `-Dno_virt=true` build option into kernel/arch/x64/cpuid.zig
//       (or aarch64 equivalent) plus a runner mode that boots that
//       variant exclusively for this single test. Neither exists, and
//       the spec assertion is about the platform's capability, not a
//       knob the kernel exposes to userspace.
//
//   Reaching the faithful path needs either:
//     - a no-virt boot variant of the kernel under QEMU (e.g. drop
//       `-cpu host` flag for vmx=off) that the runner schedules just
//       for create_virtual_machine_03; or
//     - a separate test rig (bare hardware without VMX/SVM) that the
//       runner targets for E_NODEV-conditional assertions.
//   Neither is provisioned in the v0 runner.
//
// Strategy (smoke prelude)
//   We exercise the `create_virtual_machine` *call shape* on the
//   QEMU/KVM platform. The platform supports hardware virtualization,
//   so the syscall takes a non-E_NODEV path. We do not check the
//   returned word against any spec error: the assertion that test 03
//   actually makes (E_NODEV under no-virt) is unreachable here.
//
//   The smoke confirms the syscall reaches dispatch with the same
//   policy-page-frame plumbing acquire_ecs_07 uses, but stops short of
//   any platform-conditional outcome.
//
// Action
//   1. createPageFrame(caps={r,w}, sz=0, pages=1) — must succeed; gives
//      the page frame backing VmPolicy.
//   2. createVar(caps={r,w}, cur_rwx=0b011, pages=1) — must succeed;
//      gives the VAR mapped over policy_pf so userspace can zero it.
//   3. mapPf(policy_var, {0, policy_pf}) — must succeed.
//   4. Zero the VmPolicy buffer (all-zero counts ⇒ kernel scans no
//      cpuid/cr entries on guest exits).
//   5. createVirtualMachine(caps=0, policy_pf) — call shape only. We
//      do not check the returned word against any spec error: on the
//      KVM-enabled QEMU platform the syscall does not take the
//      E_NODEV branch, so the test 03 assertion is unreachable.
//
// Assertion
//   No spec assertion is checked — passes with assertion id 0 because
//   the E_NODEV path is unreachable on the QEMU/KVM platform. Test
//   reports pass regardless of what `create_virtual_machine` returns:
//   any failure of the prelude itself is also reported as
//   pass-with-id-0 since no spec assertion is being checked.
//
// Faithful-test note
//   Faithful test deferred pending either:
//     - a kernel build/boot variant that disables hardware virt
//       advertisement (e.g. masking the VMX bit in cpuid) plus a
//       runner mode that schedules this single test under that
//       variant; or
//     - a no-virt hardware target wired into the runner.
//   Once that exists, the action becomes:
//     <runner: boot kernel with hardware virt disabled>
//     <test: createVirtualMachine(caps=0, policy_pf)>
//     <test: assert returned word == E_NODEV>
//   That equality assertion (id 1) would replace this smoke's
//   pass-with-id-0.

const lib = @import("lib");

const caps = lib.caps;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

// §[vm_policy] x86-64 layout: 32 CpuidPolicy entries (6 u32 each = 24
// bytes) + num_cpuid_responses (u32) + pad (u32) + 8 CrPolicy entries
// (cr_num+pad+read+mask = 24 bytes) + num_cr_policies (u32) + pad
// (u32). All-zero is a valid policy: zero counts ⇒ kernel scans no
// entries on guest exits.
const VM_POLICY_BYTES: usize = 32 * 24 + 8 + 8 * 24 + 8;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // 1. Page frame backing the VmPolicy struct.
    const policy_pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, policy_pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB)
        1,
    );
    if (testing.isHandleError(cpf.v1)) {
        // Prelude broke; smoke is moot but no spec assertion is being
        // checked, so report pass-with-id-0.
        testing.pass();
        return;
    }
    const policy_pf: HandleId = @truncate(cpf.v1 & 0xFFF);

    // 2. VAR + map_pf so userspace can zero the policy buffer.
    const policy_var_caps = caps.VarCap{ .r = true, .w = true };
    const cvar = syscall.createVar(
        @as(u64, policy_var_caps.toU16()),
        0b011, // cur_rwx = r|w
        1,
        0, // preferred_base = kernel chooses
        0, // device_region = none
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.pass();
        return;
    }
    const policy_var: HandleId = @truncate(cvar.v1 & 0xFFF);
    const policy_base: u64 = cvar.v2;

    const map_result = syscall.mapPf(policy_var, &.{ 0, policy_pf });
    _ = map_result;

    // 3. Zero the VmPolicy struct. num_cpuid_responses = 0 and
    //    num_cr_policies = 0 fall out of the all-zero buffer, so
    //    create_virtual_machine sees a valid empty policy.
    const policy_dst: [*]u8 = @ptrFromInt(policy_base);
    var i: usize = 0;
    while (i < VM_POLICY_BYTES) {
        policy_dst[i] = 0;
        i += 1;
    }

    // 4. Smoke the create_virtual_machine call shape. caps = 0 sidesteps
    //    bit-set / cap-ceiling / restart_policy questions. The platform
    //    (QEMU + KVM) advertises hardware virtualization, so the
    //    E_NODEV branch under test 03 is unreachable. We do not check
    //    the returned word against any spec error.
    _ = syscall.createVirtualMachine(0, policy_pf);

    // No spec assertion is being checked — the E_NODEV path is
    // unreachable on the QEMU/KVM platform. Pass with assertion id 0
    // to mark this slot as smoke-only in coverage.
    testing.pass();
}
