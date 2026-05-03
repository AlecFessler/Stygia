// Spec §[vm_inject_irq] vm_inject_irq — test 03.
//
// "[test 03] returns E_INVAL if any reserved bits are set in [1] or [3]."
//
// Strategy
//   §[vm_inject_irq] [3] is packed as
//     bit 0:    assert / deassert
//     bits 1-63: _reserved
//   We exercise the [3] reserved-bit channel: bit 0 = 1 (assert) plus
//   bit 1 = 1 (reserved). Any other reserved-bit position would do; bit
//   1 is the lowest reserved bit and the simplest to reason about.
//
//   To isolate the reserved-bit rejection every earlier gate must be
//   inert:
//     - test 01 (invalid VM handle) — pass a freshly-minted VM.
//     - test 02 (irq_num exceeds the VM's emulated controller's max) —
//       irq_num = 0 is valid for both x86-64 IOAPIC (0..23) and aarch64
//       GICv2/v3 (0..1019).
//   The caller holds [1] (no extra cap is required by §[vm_inject_irq]).
//
//   VM setup mirrors create_virtual_machine_06 / map_guest_05: stage a
//   4-KiB VmPolicy page frame, map it through a VAR so userspace can
//   zero the policy bytes (so num_cpuid_responses / num_cr_policies are
//   0 — both well under MAX_*), then create_virtual_machine with
//   caps={.policy=true}. The runner grants `crvm` and vm_ceiling = 0x01
//   (the policy bit), so caps stay subset of every ceiling. On a host
//   without hardware virtualization create_virtual_machine returns
//   E_NODEV — that path makes test 03 unreachable through any
//   construction, so we smoke-pass (assertion id 0).
//
// Action
//   1. Stage VmPolicy (PF + VAR + map_pf + zero).
//   2. createVirtualMachine — VM handle (or smoke-pass on E_NODEV).
//   3. vmInjectIrq(vm, irq_num = 0, assert_word = 0b11)
//      — bit 0 set (assert) plus bit 1 set (reserved). Must return
//        E_INVAL per §[vm_inject_irq] test 03.
//
// Assertions
//   1: setup — create_page_frame for the policy frame returned an
//      error word.
//   2: setup — create_var for the policy mapping returned an error
//      word.
//   3: setup — map_pf for the policy mapping returned non-OK.
//   4: setup — create_virtual_machine returned an unexpected error
//      (anything other than a valid handle or E_NODEV).
//   5: vm_inject_irq with reserved bit 1 set in [3] returned a value
//      other than E_INVAL (the spec assertion under test).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

// §[vm_policy] x86-64: 32 cpuid + count + pad + 8 cr + count + pad
// = 976 bytes. Same constant as create_virtual_machine_06.
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

    // 2. VAR + map so userspace can zero the policy bytes.
    const policy_var_caps = caps.VarCap{ .r = true, .w = true };
    const cvar = syscall.createVar(
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

    // 4. Mint the VM. Runner grants crvm + vm_ceiling = 0x01 so
    //    caps={.policy=true} stays subset.
    const vm_caps = caps.VmCap{ .policy = true };
    const cvm = syscall.createVirtualMachine(
        @as(u64, vm_caps.toU16()),
        policy_pf,
    );
    if (cvm.v1 == @intFromEnum(errors.Error.E_NODEV)) {
        // No hardware virtualization — test 03 unreachable through any
        // construction. Smoke-pass.
        testing.pass();
        return;
    }
    if (testing.isHandleError(cvm.v1)) {
        testing.fail(4);
        return;
    }
    const vm_handle: HandleId = @truncate(cvm.v1 & 0xFFF);

    // 5. vmInjectIrq with bit 1 (reserved) set in [3]. Bit 0 = 1 is
    //    the assert bit; bit 1 = 1 violates §[vm_inject_irq] [3]'s
    //    "bits 1-63: _reserved" requirement. The kernel must reject
    //    with E_INVAL per test 03.
    const result = syscall.vmInjectIrq(vm_handle, 0, 0b11);

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
