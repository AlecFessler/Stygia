// Spec §[unmap_guest] unmap_guest — test 05.
//
// "[test 05] on success, each page_frame's installation in [1]'s
// guest physical address space is removed; subsequent guest accesses
// to those guest_addr ranges deliver a `vm_exit` event on the vCPU's
// bound exit_port with sub-code = `ept` (x86-64) or `stage2_fault`
// (aarch64)."
//
// Strategy (smoke-degraded)
//   Faithfully observing "subsequent guest access delivers an
//   ept/stage2_fault vm_exit" requires running a guest, which the
//   in-kernel parallel test runner cannot do (no vCPU stepping, no
//   port recv loop). What is testable here is the structural
//   precondition: after a successful map_guest installs a page_frame
//   in the VM's guest physical address space, unmap_guest of that
//   same page_frame is accepted by the kernel without an error
//   word.
//
//   To isolate that, every earlier gate in §[unmap_guest] must be
//   inert:
//     - test 01 (invalid VM)         — pass a freshly-minted VM.
//     - test 02 (invalid page_frame) — the entry carries a real pf
//                                       handle.
//     - test 03 (N == 0)             — N = 1.
//     - test 04 (pf not currently
//                mapped in [1])      — install pf via map_guest first.
//
//   With pf installed via map_guest({0, pf}), unmap_guest({pf}) on
//   the same VM has no earlier gate left to fire. The kernel must
//   accept the call.
//
// VM setup mirrors map_guest_05 / unmap_guest_04: stage a 4-KiB
// VmPolicy page frame, map it through a VAR so userspace can zero
// the policy bytes (so num_cpuid_responses / num_cr_policies are 0
// — both well under MAX_*), then create_virtual_machine with
// caps={.policy=true}. The runner grants `crvm` and vm_ceiling = 0x01
// (the policy bit), so caps stay subset of every ceiling. On the
// QEMU/KVM rig VT-x is exposed and the call succeeds; on a host
// without hardware virtualization the call returns E_NODEV — that
// path makes test 05 unreachable through any construction, so we
// smoke-pass (assertion id 0).
//
// Action
//   1. Stage VmPolicy (PF + VAR + map_pf + zero).
//   2. createVirtualMachine — VM handle (or smoke-pass on E_NODEV).
//   3. createPageFrame(caps={r,w}, sz=0, pages=1) — pf.
//   4. mapGuest(vm, &.{ 0, pf }) — must succeed (OK).
//   5. unmapGuest(vm, &.{ pf }) — must succeed (OK).
//
// Assertions
//   1: setup — create_page_frame for the policy frame returned an
//      error word.
//   2: setup — create_var for the policy mapping returned an error
//      word.
//   3: setup — map_pf for the policy mapping returned non-OK.
//   4: setup — create_virtual_machine returned an unexpected error
//      (anything other than a valid handle or E_NODEV).
//   5: setup — create_page_frame for pf returned an error word.
//   6: setup — map_guest of pf into the fresh VM returned non-OK.
//   7: unmap_guest of the previously-mapped page_frame returned
//      non-OK (the spec assertion under test, smoke-degraded).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

// §[vm_policy] x86-64: 32 cpuid + count + pad + 8 cr + count + pad
// = 976 bytes. Same constant as map_guest_05 / unmap_guest_04.
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
        // No hardware virtualization — test 05 unreachable through
        // any construction. Smoke-pass.
        testing.pass();
        return;
    }
    if (testing.isHandleError(cvm.v1)) {
        testing.fail(4);
        return;
    }
    const vm_handle: HandleId = @truncate(cvm.v1 & 0xFFF);

    // 5. A fresh page_frame to install in the VM at guest_addr = 0.
    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // sz = 0 (4 KiB)
        1,
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(5);
        return;
    }
    const pf: u64 = @as(u64, cpf.v1 & 0xFFF);

    // 6. Install pf at guest_addr 0 so unmap_guest has something to
    //    actually unmap. Each earlier map_guest gate is inert
    //    (valid VM, valid pf, N=1, guest_addr=0 aligned to any sz,
    //    fresh VM has no prior mappings).
    const map_guest_result = syscall.mapGuest(vm_handle, &.{ 0, pf });
    if (map_guest_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(6);
        return;
    }

    // 7. Unmap pf from the VM. With every earlier §[unmap_guest]
    //    gate inert, the kernel must accept the call and return OK.
    //    (Observing the resulting ept/stage2_fault vm_exit on a
    //    subsequent guest access is not reachable from the in-kernel
    //    parallel test runner — see strategy comment above.)
    const result = syscall.unmapGuest(vm_handle, &.{pf});

    if (result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(7);
        return;
    }

    testing.pass();
}
