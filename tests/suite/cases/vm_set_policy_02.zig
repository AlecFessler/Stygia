// Spec §[vm_set_policy] vm_set_policy — test 02.
//
// "[test 02] returns E_PERM if [1] does not have the `policy` cap."
//
// Strategy
//   To isolate the policy-cap rejection we need every earlier gate in
//   §[vm_set_policy] to be inert:
//     - test 01 (invalid VM)  — pass a freshly-minted, valid VM handle.
//   The PERM gate on `policy` must fire before any validation of the
//   kind selector, the count, or entry contents (test 03 / 04). We
//   therefore call with kind = 0, count = 0, entries = &.{} so the only
//   error path that can possibly fire here is the `policy` cap check.
//
//   A VM minted with caps = 0 carries no caps at all (in particular,
//   no `policy`). The runner grants `crvm` and vm_ceiling = 0x01 (the
//   policy bit), so caps = 0 is trivially a subset of vm_ceiling — the
//   create_virtual_machine call succeeds even though the resulting VM
//   handle lacks the `policy` cap.
//
//   On a host without hardware virtualization create_virtual_machine
//   returns E_NODEV; that path makes test 02 unreachable through any
//   construction, so we smoke-pass.
//
// Action
//   1. Stage VmPolicy (PF + VAR + map_pf + zero).
//   2. createVirtualMachine(caps = 0, policy_pf) — VM handle (or
//      smoke-pass on E_NODEV).
//   3. vmSetPolicy(vm, kind = 0, count = 0, entries = &.{}) — must
//      return E_PERM.
//
// Assertions
//   1: setup — create_page_frame for the policy frame returned an
//      error word.
//   2: setup — create_var for the policy mapping returned an error
//      word.
//   3: setup — map_pf for the policy mapping returned non-OK.
//   4: setup — create_virtual_machine returned an unexpected error
//      (anything other than a valid handle or E_NODEV).
//   5: vm_set_policy on a VM lacking the `policy` cap returned a value
//      other than E_PERM (the spec assertion under test).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

// §[vm_policy] x86-64: 32 cpuid + count + pad + 8 cr + count + pad
// = 976 bytes. Same constant as create_virtual_machine_06 / map_guest_05.
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

    // 4. Mint the VM with caps = 0 — the resulting VM handle therefore
    //    lacks the `policy` cap. caps = 0 is a subset of any vm_ceiling,
    //    so the create call succeeds (modulo E_NODEV on hosts without
    //    hardware virtualization).
    const cvm = syscall.createVirtualMachine(0, policy_pf);
    if (cvm.v1 == @intFromEnum(errors.Error.E_NODEV)) {
        // No hardware virtualization — test 02 unreachable through any
        // construction. Smoke-pass.
        testing.pass();
        return;
    }
    if (testing.isHandleError(cvm.v1)) {
        testing.fail(4);
        return;
    }
    const vm_handle: HandleId = @truncate(cvm.v1 & 0xFFF);

    // 5. Call vm_set_policy on the policy-cap-less VM. kind = 0,
    //    count = 0, entries = &.{} so no later gate (count > MAX_*,
    //    reserved bits, etc.) can produce a different return code.
    const result = syscall.vmSetPolicy(vm_handle, 0, 0, &.{});

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
