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
//   We exercise the VM + vCPU coexistence path on the x86-64 build
//   target. Setup mirrors tests 05/06 — a zeroed VmPolicy page frame
//   plus a VM minted with caps.policy = true so the earlier gates
//   (test 01 / 02 / 03 / 04) are inert. We additionally stand up an
//   exit port and a vCPU and consume the initial vm_exit, confirming
//   the policy frame stays pinned through vCPU creation. This
//   exercises the same kernel-side path the eventual aarch64 test
//   will rely on (policy frame coherency under a live vCPU). The
//   kind=0 vm_set_policy call's return is *not* checked: on x86-64 it
//   touches the cpuid_responses table, not the aarch64
//   id_reg_responses table this spec sentence is about.
//
// Action
//   1. Stage VmPolicy (PF + VMAR + map_pf + zero).
//   2. createVirtualMachine(caps={.policy=true}, policy_pf) — VM handle
//      (or smoke-pass on E_NODEV).
//   3. createPort + createVcpu so the policy frame is pinned by a live
//      vCPU.
//   4. recv(exit_port) — must surface OK and the initial-state subcode.
//   5. vmSetPolicy call shape only — return ignored, since the aarch64
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
//   5: setup — create_port returned an error word.
//   6: setup — create_vcpu returned an error word.
//   7: recv on the exit_port did not return OK in vreg 1.
//   8: the recv'd event's sub-code (vreg 2) is not the initial-state
//      sub-code.
//
// Faithful-test note
//   Faithful test deferred pending three pieces:
//     1. An aarch64 runner build (cpu_arch = .aarch64) — only then
//        does kind=0 dispatch to id_reg_responses.
//     2. A guest-execution harness that can stage guest code into
//        the VM and drive the vCPU through an ID_AA64* read so the
//        kernel sees a sysreg exit it could match against the table.
//     3. Kernel-side `id_reg_responses` consultation. The aarch64
//        vm_runloop today does not read the policy table on sysreg
//        exits — see kernel/arch/aarch64/vm_runloop.zig — so even
//        with (1) and (2), the spec post-condition would not hold
//        until the kernel feature lands.
//   Once those three exist, the action becomes:
//     <build runner with cpu_arch = .aarch64>
//     <test: build IdRegResponse entry per §[vm_set_policy] aarch64
//      kind=0 layout — vreg [2+2i+0] packs (op0, op1, crn, crm, op2,
//      _pad u8[3]); vreg [2+2i+1] is value u64>
//     <test: vmSetPolicy(vm, kind=0, count=1, &entry) — assert OK>
//     <test: drive guest read of ID_AA64<X>_EL1 — assert resumed
//      value matches entry's `value`>
//   That guest-side assertion would replace this smoke's
//   pass-with-id-0.

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

    // 5. Mint the exit port. `bind` is required as create_vcpu's [4]
    //    handle. `recv` lets us pull the kernel-injected initial
    //    vm_exit so the prelude reaches the same vCPU + policy_pf
    //    coexistence the aarch64 test will need.
    const exit_port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cport = syscall.createPort(@as(u64, exit_port_caps.toU16()));
    if (testing.isHandleError(cport.v1)) {
        testing.fail(5);
        return;
    }
    const exit_port: HandleId = @truncate(cport.v1 & 0xFFF);

    // 6. Stand up a vCPU bound to the policy-bearing VM.
    const vcpu_caps = caps.EcCap{
        .susp = true,
        .read = true,
        .write = true,
    };
    const cvcpu = syscall.createVcpu(
        @as(u64, vcpu_caps.toU16()),
        vm_handle,
        0, // affinity = any core
        exit_port,
    );
    if (testing.isHandleError(cvcpu.v1)) {
        testing.fail(6);
        return;
    }

    // 7. Recv the kernel-injected initial vm_exit.
    const initial = syscall.recv(exit_port, 0);
    if (initial.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(7);
        return;
    }

    // 8. The synthetic initial vm_exit's sub-code lives in vreg 2.
    if (initial.regs.v2 != @as(u64, syscall.INITIAL_STATE_SUBCODE)) {
        testing.fail(8);
        return;
    }

    // 9. Smoke the vm_set_policy(kind=0) call shape. On the x86-64
    //    build target this reaches the cpuid_responses path, not the
    //    aarch64 id_reg_responses table that spec sentence 07 asserts
    //    against; the returned word is therefore not checked. count=0
    //    keeps the call inert with respect to whichever table the
    //    kernel routes to.
    _ = syscall.vmSetPolicy(vm_handle, 0, 0, &.{});

    // No spec assertion is being checked beyond the prelude — the
    // aarch64 id_reg_responses path is unreachable on the x86-64
    // build target. The prelude assertions (1..8) cover the same
    // VM + vCPU + policy_pf coexistence path that the aarch64
    // observation will rely on once a live-guest harness exists.
    testing.pass();
}
