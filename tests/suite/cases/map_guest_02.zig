// Spec §[map_guest] map_guest — test 02.
//
// "[test 02] returns E_BADCAP if any [2 + 2i + 1] is not a valid
//  page_frame handle."
//
// Strategy
//   To isolate the per-pair page_frame BADCAP gate, every earlier
//   gate in §[map_guest] must be inert:
//     - test 01 (invalid VM)        — pass a freshly-minted VM.
//     - test 03 (N == 0)            — N = 1.
//   With those gates inert, supplying a pair whose page_frame slot is
//   empty must surface E_BADCAP from the page_frame validation step.
//
//   The child domain's handle table is populated by the kernel at
//   `create_capability_domain` time:
//     slot 0  → self
//     slot 1  → initial EC
//     slot 2  → self-IDC
//     slot 3+ → passed_handles (here: just the result port at slot 3)
//   The test then mints a small handful of additional handles for the
//   VM staging — none of which approach the high end of the table.
//   Slot 0xFFE is therefore guaranteed empty (HANDLE_TABLE_MAX - 1 =
//   0xFFF is reserved as the invalid-handle sentinel; 0xFFE is unused
//   and not a valid page_frame).
//
// VM setup mirrors map_guest_05 / create_virtual_machine_06: stage a
// 4-KiB VmPolicy page frame, map it through a VAR so userspace can
// zero the policy bytes (so num_cpuid_responses / num_cr_policies are
// 0 — both well under MAX_*), then create_virtual_machine with
// caps={.policy=true}. The runner grants `crvm` and vm_ceiling = 0x01
// (the policy bit), so caps stay subset of every ceiling. On the
// QEMU/KVM rig VT-x is exposed and the call succeeds; on a host
// without hardware virtualization the call returns E_NODEV — that
// path makes test 02 unreachable through any construction, so we
// smoke-pass (assertion id 0).
//
// Action
//   1. Stage VmPolicy (PF + VAR + map_pf + zero).
//   2. createVirtualMachine — VM handle (or smoke-pass on E_NODEV).
//   3. mapGuest(vm, &.{ 0, 0xFFE }) — must return E_BADCAP because
//      slot 0xFFE is empty.
//
// Assertions
//   1: setup — create_page_frame for the policy frame returned an
//      error word.
//   2: setup — create_var for the policy mapping returned an error
//      word.
//   3: setup — map_pf for the policy mapping returned non-OK.
//   4: setup — create_virtual_machine returned an unexpected error
//      (anything other than a valid handle or E_NODEV).
//   5: map_guest with an invalid page_frame slot returned a value
//      other than E_BADCAP (the spec assertion under test).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

// §[vm_policy] x86-64: 32 cpuid + count + pad + 8 cr + count + pad
// = 976 bytes. Same constant as map_guest_05.
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
        // No hardware virtualization — test 02 unreachable through
        // any construction. Smoke-pass.
        testing.pass();
        return;
    }
    if (testing.isHandleError(cvm.v1)) {
        testing.fail(4);
        return;
    }
    const vm_handle: HandleId = @truncate(cvm.v1 & 0xFFF);

    // 5. Single pair with an invalid page_frame slot. 0xFFE is unused
    //    in this domain's handle table and is not the reserved
    //    invalid-handle sentinel (0xFFF), so the kernel must reject
    //    the pair through the page_frame validity gate.
    const invalid_pf: u64 = 0xFFE;
    const result = syscall.mapGuest(vm_handle, &.{ 0, invalid_pf });

    if (result.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
