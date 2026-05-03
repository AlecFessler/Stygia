// Spec §[vm_set_policy] vm_set_policy — test 07.
//
// "[test 07] on aarch64 with kind=0, the VM's `id_reg_responses` table
//  is replaced by the count entries; subsequent guest reads of matching
//  ID_AA64* registers return the configured values per §[vm_policy]."
//
// DEGRADED SMOKE VARIANT
//   The faithful shape of test 07 is "guest read of an ID_AA64* sysreg
//   matching an entry's (op0, op1, crn, crm, op2) tuple resumes with
//   the entry's value, while ID-reg accesses absent from the table
//   deliver a vm_exit." Reaching that property requires the kernel
//   build target to be aarch64: per §[vm_set_policy] the kind selector
//   is overloaded across architectures, and on aarch64 with kind=0 the
//   syscall replaces `id_reg_responses`; on x86-64 with kind=0 it
//   replaces `cpuid_responses` (test 05).
//
//   The runner builds for x86-64 only — `tests/suite/build.zig`
//   resolves the test target with `cpu_arch = .x86_64`, and there is
//   no in-tree aarch64 runner image. On the x86-64 build target a
//   vm_set_policy(kind=0) call dispatches to the cpuid_responses path,
//   so the syscall cannot exercise the aarch64 id_reg_responses table
//   regardless of how the entries are framed.
//
//   Reaching the faithful path needs:
//     - an aarch64 runner build (cpu_arch = .aarch64) that boots the
//       same root_service against the aarch64 kernel; or
//     - a per-test arch override in the manifest so test 07 ships only
//       on aarch64 builds.
//   Neither is provisioned here.
//
// Strategy (smoke prelude)
//   We exercise the vm_set_policy call shape on the x86-64 build
//   target. Setup mirrors tests 05/06 — a zeroed VmPolicy page frame
//   plus a VM minted with caps.policy = true so the earlier gates
//   (test 01 / 02 / 03 / 04) are inert. The sole assertion checked is
//   that the prelude (page-frame + VMAR + map_pf + VM creation) reaches
//   the syscall site without an unexpected handle error; a smoke-pass
//   on E_NODEV preserves the no-virt path. The kind=0 vm_set_policy
//   call's return is *not* checked: on x86-64 it touches the
//   cpuid_responses table, not the aarch64 id_reg_responses table this
//   spec sentence is about.
//
// Action
//   1. Stage VmPolicy (PF + VMAR + map_pf + zero).
//   2. createVirtualMachine(caps={.policy=true}, policy_pf) — VM handle
//      (or smoke-pass on E_NODEV).
//   3. vmSetPolicy call shape only — return ignored, since the aarch64
//      id_reg_responses path is unreachable on x86-64.
//
// Assertions
//   1: setup — create_page_frame for the policy frame returned an
//      error word.
//   2: setup — create_vmar for the policy mapping returned an error
//      word.
//   3: setup — map_pf for the policy mapping returned non-OK.
//   4: setup — create_virtual_machine returned an unexpected error
//      (anything other than a valid handle or E_NODEV).
//
// Faithful-test note
//   Faithful test deferred pending an aarch64 runner build. Once that
//   exists, the action becomes:
//     <build runner with cpu_arch = .aarch64>
//     <test: build IdRegResponse entry per §[vm_set_policy] aarch64
//      kind=0 layout — vreg [2+2i+0] packs (op0, op1, crn, crm, op2,
//      _pad u8[3]); vreg [2+2i+1] is value u64>
//     <test: vmSetPolicy(vm, kind=0, count=1, &entry) — assert OK>
//   That OK assertion (id 5) would replace this smoke's pass-with-id-0.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

// §[vm_policy] x86-64: 32 cpuid + count + pad + 8 cr + count + pad
// = 976 bytes. Same constant as create_virtual_machine_06 / map_guest_05.
// The x86-64 layout drives the prelude here because the build target
// is x86-64; the aarch64 layout (id_reg + sysreg tables) is not reached
// from this binary regardless of what the test exercises.
const VM_POLICY_BYTES: usize = 32 * 24 + 8 + 8 * 24 + 8;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

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
    //    folding the stores against the kernel's read.
    const policy_dst: [*]volatile u8 = @ptrFromInt(policy_base);
    var i: usize = 0;
    while (i < VM_POLICY_BYTES) {
        policy_dst[i] = 0;
        i += 1;
    }

    // 4. Mint the VM with caps.policy = true. Runner grants `crvm` and
    //    vm_ceiling = 0x01, so policy stays subset of the ceiling. The
    //    VM handle therefore carries the `policy` cap — earlier gates
    //    (test 01 / 02) are inert.
    const vm_caps = caps.VmCap{ .policy = true };
    const cvm = syscall.createVirtualMachine(
        @as(u64, vm_caps.toU16()),
        policy_pf,
    );
    if (cvm.v1 == @intFromEnum(errors.Error.E_NODEV)) {
        // No hardware virtualization — test 07 unreachable through any
        // construction. Smoke-pass.
        testing.pass();
        return;
    }
    if (testing.isHandleError(cvm.v1)) {
        testing.fail(4);
        return;
    }
    const vm_handle: HandleId = @truncate(cvm.v1 & 0xFFF);

    // 5. Smoke the vm_set_policy(kind=0) call shape. On the x86-64
    //    build target this reaches the cpuid_responses path, not the
    //    aarch64 id_reg_responses table that spec sentence 07 asserts
    //    against; the returned word is therefore not checked. count=0
    //    keeps the call inert with respect to whichever table the
    //    kernel routes to.
    _ = syscall.vmSetPolicy(vm_handle, 0, 0, &.{});

    // No spec assertion is being checked — the aarch64 id_reg_responses
    // path is unreachable on the x86-64 build target. Pass with
    // assertion id 0 to mark this slot as smoke-only in coverage.
    testing.pass();
}
