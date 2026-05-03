// Spec §[suspend] — test 06.
//
// "[test 06] returns E_INVAL if [1] references a vCPU."
//
// Spec semantics
//   §[suspend]: the syscall suspends a non-vCPU EC and delivers a
//   suspension event on a port. vCPU ECs have their own delivery channel
//   (the exit_port bound at create_vcpu time) and are resumed via reply
//   on vm_exit reply handles, not via the suspend syscall — so
//   `suspend` on a vCPU EC handle is rejected with E_INVAL.
//
// Strategy
//   To isolate the vCPU rejection branch, every preceding gate must be
//   defused so the kernel's only remaining check is the EC-is-vCPU
//   discriminator:
//     - test 01 (E_BADCAP [1] not a valid EC handle): we mint a real
//       vCPU EC via create_vcpu and pass its handle.
//     - test 02 (E_BADCAP [2] not a valid port handle): we mint a real
//       destination port via create_port.
//     - test 03 (E_PERM [1] lacks `susp`): the vCPU EC is minted with
//       `susp` set in its caps word. The vCPU's `susp` bit must lie
//       within the VM's owning domain `ec_inner_ceiling` (the runner
//       grants ec_inner_ceiling = 0xFF, which covers `susp` = bit 5).
//     - test 04 (E_PERM [2] lacks `bind`): the destination port is
//       minted with `bind` set.
//     - test 05 (E_INVAL reserved bits): the syscall word stays clean
//       (issueReg encodes only the syscall id; vregs carry [1]/[2]).
//   With those gates inert, the kernel's vCPU-discriminator check is
//   the only remaining rejection path — it must fire and return E_INVAL.
//
//   Setting up the vCPU follows the same chain as create_vcpu_05 /
//   create_vcpu_10: page frame backing a zero VmPolicy, a temporary VAR
//   to write that policy from userspace, create_virtual_machine with
//   `policy = 1`, a port to serve as the vCPU's exit_port, and finally
//   create_vcpu. The vCPU's destination port for this test is a
//   second, distinct port — using exit_port directly would also be
//   valid (since exit_port has `bind`), but minting a separate port
//   keeps the suspend-side cap requirements decoupled from the vCPU
//   construction surface.
//
// E_NODEV degradation
//   `create_virtual_machine` returns E_NODEV on platforms without
//   hardware virtualization (§[create_virtual_machine] test 03). On
//   such platforms a vCPU cannot be minted at all and the spec
//   assertion under test (E_INVAL from suspend on a vCPU handle) is
//   unreachable. Mirroring create_vcpu_05/_10's smoke shape, we
//   degrade with pass-with-id-0 — the QEMU/KVM runner exposes VMX/SVM,
//   so this branch is not expected to fire there but the degraded
//   path keeps the test honest on no-virt rigs.
//
// Action
//   1. createPageFrame(caps={r,w}, props=0, pages=1) — backs VmPolicy.
//   2. createVar(caps={r,w}, cur_rwx=r|w, pages=1) + mapPf at offset 0.
//   3. Zero VM_POLICY_BYTES (all-zero counts ⇒ valid empty policy).
//   4. createVirtualMachine(caps={.policy=true}, policy_pf). Tolerates
//      E_NODEV (degraded smoke pass).
//   5. createPort(caps={bind}) — exit_port for the vCPU.
//   6. createVcpu(caps_word with susp=1, vm_handle, affinity=0,
//      exit_port) — vCPU EC handle held by this domain.
//   7. createPort(caps={bind}) — destination port for the suspend call.
//   8. suspendEc(vcpu_handle, dest_port, &.{}) — must return E_INVAL.
//
// Assertions
//   1: setup — any setup syscall (page frame, var, map_pf, exit port,
//      create_vcpu, dest port) returned an error word.
//   2: suspend did not return E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

// §[vm_policy] x86-64: 32 CpuidPolicy (24 B) + num_cpuid (4 B) + pad
// (4 B) + 8 CrPolicy (24 B) + num_cr (4 B) + pad (4 B) = 976 B.
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
        testing.fail(1);
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
        testing.fail(1);
        return;
    }
    const policy_var: HandleId = @truncate(cvar.v1 & 0xFFF);
    const policy_base: u64 = cvar.v2;

    const map_result = syscall.mapPf(policy_var, &.{ 0, policy_pf });
    if (map_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    // 3. Zero the VmPolicy region. Volatile keeps ReleaseSmall from
    //    folding the store against the kernel's read of the page frame.
    const policy_dst: [*]volatile u8 = @ptrFromInt(policy_base);
    var i: usize = 0;
    while (i < VM_POLICY_BYTES) {
        policy_dst[i] = 0;
        i += 1;
    }

    // 4. Mint a VM. caps = {.policy = true} stays within the runner-
    //    granted vm_ceiling (which covers the `policy` bit). On no-virt
    //    platforms create_virtual_machine returns E_NODEV — degrade
    //    with pass-with-id-0 since the spec assertion under test is
    //    unreachable without a real vCPU handle.
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
        testing.fail(1);
        return;
    }
    const vm_handle: HandleId = @truncate(cvm.v1 & 0xFFF);

    // 5. Mint the exit port for the vCPU. `bind` is required for the
    //    port to be usable as the destination of vm_exit deliveries.
    const exit_port_caps = caps.PortCap{ .bind = true };
    const cep = syscall.createPort(@as(u64, exit_port_caps.toU16()));
    if (testing.isHandleError(cep.v1)) {
        testing.fail(1);
        return;
    }
    const exit_port: HandleId = @truncate(cep.v1 & 0xFFF);

    // 6. §[create_vcpu] caps word layout: bits 0-15 = EcCap, bits 32-33
    //    = priority. We need `susp` set on the resulting handle so
    //    suspend test 03's E_PERM gate cannot fire ahead of test 06.
    //    Priority = 0 stays within any ceiling. All other bits clean.
    const vcpu_ec_caps = caps.EcCap{ .susp = true };
    const cvcpu = syscall.createVcpu(
        @as(u64, vcpu_ec_caps.toU16()),
        vm_handle,
        0, // affinity = 0 (any core)
        exit_port,
    );
    if (testing.isHandleError(cvcpu.v1)) {
        testing.fail(1);
        return;
    }
    const vcpu_handle: HandleId = @truncate(cvcpu.v1 & 0xFFF);

    // 7. Destination port for the suspend syscall. `bind` is required
    //    on the port handle so suspend test 04's E_PERM gate cannot
    //    fire ahead of test 06.
    const dest_port_caps = caps.PortCap{ .bind = true };
    const cdp = syscall.createPort(@as(u64, dest_port_caps.toU16()));
    if (testing.isHandleError(cdp.v1)) {
        testing.fail(1);
        return;
    }
    const dest_port: HandleId = @truncate(cdp.v1 & 0xFFF);

    // 8. Issue the suspend. With handles valid (defuses tests 01, 02),
    //    `susp` on [1] (defuses test 03), `bind` on [2] (defuses test
    //    04), and reserved bits clean (defuses test 05), the only
    //    remaining rejection path is the vCPU-discriminator check.
    const result = syscall.suspendEc(vcpu_handle, dest_port, &.{});
    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
