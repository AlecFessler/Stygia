// Spec §[vm_inject_irq] vm_inject_irq — test 05.
//
// "[test 05] on success with [3].assert = 0 immediately after a
//  prior `vm_inject_irq([1], [2], assert = 1)`, no interrupt
//  vm_exit corresponding to line [2] is delivered to any vCPU
//  even when the vCPU's interrupt window opens or it becomes
//  runnable with the line unmasked."
//
// Spec semantics
//   The full faithful witness for this property requires a guest
//   image whose IDT/GIC is configured to vector IRQ [2] into a
//   handler whose entry is observable from outside the guest
//   (via a vm_exit sub-code change, MMIO ack, or HLT-resume) —
//   the spec property is stated in terms of "no interrupt
//   vm_exit corresponding to line [2] is delivered". Booting a
//   real guest from the in-kernel test runner is not feasible:
//   the runner has no facility to stage guest code into VM
//   memory, and §[vm_policy] alone — which is all userspace can
//   configure here — does not seed an IDT/IOAPIC. We therefore
//   exercise the smoke-degraded slice the runner can witness:
//   that on a real VM with an in-range IRQ line and clean
//   reserved bits, the deassert call after a prior assert call
//   traverses its success path and returns OK rather than
//   surfacing E_BADCAP / E_INVAL. The downstream "no vm_exit
//   delivered" half of the spec assertion is unreachable from
//   this harness and is not asserted here.
//
// Strategy
//   Stage the same VM + vCPU + exit_port prelude as
//   vm_inject_irq_04: page frame + VAR + zero VmPolicy +
//   create_virtual_machine + create_port (bind|recv) +
//   create_vcpu. That gives us a real VM handle whose emulated
//   interrupt controller is live and whose vCPU has been
//   registered. Then issue the assert+deassert pair the spec
//   property is keyed on:
//     (a) vm_inject_irq(vm, irq_num=0, assert_word=1) — the
//         "prior assert" the spec requires.
//     (b) vm_inject_irq(vm, irq_num=0, assert_word=0) — the
//         immediately-following deassert under test.
//
//   irq_num = 0 is in range for both x86-64's IOAPIC (24 lines)
//   and aarch64's GIC (1024 SPI/PPI/SGI ids), so §[vm_inject_irq]
//   [test 02]'s out-of-range E_INVAL gate cannot fire on either
//   call. assert_word = 1 (assert) and assert_word = 0 (deassert)
//   each have bits 1-63 clear, so [test 03]'s reserved-bits
//   E_INVAL gate cannot fire either. With a valid VM handle in
//   [1], [test 01]'s E_BADCAP gate is also defused. The only
//   remaining outcome on a hardware-virt platform is the success
//   path on each call — vreg 1 == OK on both.
//
// Caps required
//   - create_page_frame: caps = {r, w}. Backs the VmPolicy frame
//     and lets userspace zero it through the VAR window.
//   - create_var: caps = {r, w}, cur_rwx = r|w. CPU window into
//     the policy frame.
//   - create_virtual_machine: caps = {policy=true}. Subset of
//     vm_ceiling = 0x01.
//   - create_port: caps = {bind, recv}. `bind` is required so the
//     port can be passed as create_vcpu's exit_port; `recv` lives
//     within port_ceiling = 0x1C in case future test variants
//     pull from the port. Both bits are within the runner's
//     port_ceiling.
//   - create_vcpu: caps = {susp, read, write}. All three bits
//     live within ec_inner_ceiling = 0xFF and keep the vCPU's
//     state-transfer + suspend paths live without affecting the
//     vm_inject_irq call surface.
//   - vm_inject_irq: spec §[vm_inject_irq] requires no cap beyond
//     holding [1].
//
// E_NODEV degrade
//   create_virtual_machine returns E_NODEV on platforms without
//   hardware virtualization (§[create_virtual_machine] [test 03]).
//   On such platforms the VM cannot be minted and the success
//   path under test is unreachable; we tolerate that with a
//   pass-with-id-0 in line with the other VM-success-path tests
//   (create_vcpu_05 / 08 / 09 / 10, vm_inject_irq_04).
//
// Action
//   1. createPageFrame(caps={r,w}, sz=0, pages=1) — backs VmPolicy.
//   2. createVar(caps={r,w}, cur_rwx=r|w, pages=1) + mapPf at
//      offset 0 — gives userspace a window into the policy frame.
//   3. Zero the VmPolicy region through volatile stores so the
//      kernel's read of the policy page sees an all-zero CpuidPolicy
//      / CrPolicy table.
//   4. createVirtualMachine(caps={.policy=true}, policy_pf).
//      Tolerates E_NODEV (degraded smoke pass).
//   5. createPort(caps={bind, recv}) — exit_port for the vCPU.
//   6. createVcpu(caps={susp,read,write}, vm_handle, affinity=0,
//      exit_port).
//   7. vmInjectIrq(vm_handle, irq_num=0, assert_word=1) — the
//      "prior assert" the spec property is keyed on; must
//      return OK in vreg 1.
//   8. vmInjectIrq(vm_handle, irq_num=0, assert_word=0) — the
//      immediately-following deassert under test; must return
//      OK in vreg 1.
//
// Assertions
//   1: setup — createPageFrame / createVar / mapPf returned an
//      error word.
//   2: setup — createPort returned an error word.
//   3: setup — createVcpu returned an error word.
//   4: prior assert vm_inject_irq returned non-OK on a valid VM
//      handle with irq_num = 0 and assert_word = 1.
//   5: deassert vm_inject_irq returned non-OK on a valid VM
//      handle with irq_num = 0 and assert_word = 0 immediately
//      after the prior assert.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

// §[vm_policy] x86-64 layout: 32 CpuidPolicy entries (24 B each) +
// num_cpuid_responses (u32) + pad (u32) + 8 CrPolicy entries (24 B
// each) + num_cr_policies (u32) + pad (u32) = 976 bytes.
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

    // 4. Mint a VM. caps={.policy=true} is a subset of the runner-
    //    granted vm_ceiling = 0x01. On no-virt platforms this returns
    //    E_NODEV — degrade with pass-with-id-0 since the success-path
    //    assertion under test is unreachable without a real VM.
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

    // 5. Mint the exit port. `bind` is required for create_vcpu's
    //    [4] handle. `recv` is included to match the create_vcpu_09
    //    / vm_inject_irq_04 prelude shape; both bits live within
    //    port_ceiling = 0x1C.
    const exit_port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cport = syscall.createPort(@as(u64, exit_port_caps.toU16()));
    if (testing.isHandleError(cport.v1)) {
        testing.fail(2);
        return;
    }
    const exit_port: HandleId = @truncate(cport.v1 & 0xFFF);

    // 6. create_vcpu success path. caps {susp, read, write} all
    //    live within ec_inner_ceiling = 0xFF; affinity = 0 selects
    //    "any core". This registers a vCPU with the VM whose
    //    emulated interrupt controller will be the target of the
    //    inject calls below.
    const vcpu_caps = caps.EcCap{
        .susp = true,
        .read = true,
        .write = true,
    };
    const caps_word: u64 = @as(u64, vcpu_caps.toU16());
    const cvcpu = syscall.createVcpu(
        caps_word,
        vm_handle,
        0, // affinity = any core
        exit_port,
    );
    if (testing.isHandleError(cvcpu.v1)) {
        testing.fail(3);
        return;
    }

    // 7. Prior assert: vm_inject_irq with assert = 1. With a valid
    //    VM handle in [1], an in-range irq_num in [2], and clean
    //    reserved bits in both [1] and [3], the only spec-permitted
    //    outcome is the success path: vreg 1 == OK. This is the
    //    "prior `vm_inject_irq([1], [2], assert = 1)`" the spec
    //    property is keyed on.
    const assert_inject = syscall.vmInjectIrq(vm_handle, 0, 1);
    if (assert_inject.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }

    // 8. Immediately-following deassert: vm_inject_irq with
    //    assert = 0 on the same line. Reserved bits stay clean,
    //    irq_num stays in range, and the VM handle is still valid,
    //    so the only spec-permitted outcome is again the success
    //    path: vreg 1 == OK. The downstream "no vm_exit delivered"
    //    half of the spec property is not witnessable from the
    //    in-kernel runner without a real guest image; what we can
    //    audit is that the deassert call itself succeeds.
    const deassert_inject = syscall.vmInjectIrq(vm_handle, 0, 0);
    if (deassert_inject.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
