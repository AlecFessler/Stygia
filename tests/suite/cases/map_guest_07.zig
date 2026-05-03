// Spec §[map_guest] map_guest — test 07.
//
// "[test 07] on success, a guest read from `guest_addr` returns the
//  paired page_frame's contents, and a guest access whose required
//  rwx is not a subset of `page_frame.r/w/x` delivers a `vm_exit`
//  event on the vCPU's bound exit_port with sub-code = `ept`
//  (x86-64) or `stage2_fault` (aarch64)."
//
// Smoke-degraded approach
//   The full spec property requires:
//     (a) running guest code that performs a load from `guest_addr`
//         and observing it sees the page_frame's contents;
//     (b) running guest code that performs an access whose required
//         rwx exceeds the page_frame's r/w/x and observing the
//         resulting EPT / stage2 vm_exit on the vCPU's exit_port.
//
//   Both arms require a real guest payload (instructions to execute
//   inside the VM) and a vCPU run loop. The current in-kernel
//   parallel test runner has no facility to author and load guest
//   code into the VM's guest physical address space and drive a
//   vCPU through enough exits to witness either arm. Per the task
//   brief we degrade to a smoke-pass that observes the kernel
//   accepts the success-path mapGuest call: a fresh VM, a 4-KiB
//   page_frame with caps {r,w}, and a single pair at guest_addr = 0
//   (4-KiB-aligned). This faithfully exercises the syscall's
//   accept-on-success path; the guest-observable consequences in
//   tests 07's behavioral arms are left for a future test harness
//   that can stage guest payloads.
//
//   On a host without hardware virtualization, create_virtual_machine
//   returns E_NODEV (§[create_virtual_machine] test 03). In that
//   regime the success path under test is unreachable through any
//   construction, so we smoke-pass with assertion id 0 — same shape
//   as map_guest_04 / map_guest_05 / create_vcpu_09.
//
// VM setup mirrors map_guest_04 / map_guest_05: stage a 4-KiB
// VmPolicy page frame, map it through a VAR so userspace can zero
// the policy bytes (num_cpuid_responses = 0, num_cr_policies = 0 —
// both well under MAX_*), then create_virtual_machine with caps =
// {.policy = true}. The runner grants `crvm` and vm_ceiling = 0x01
// (the policy bit), so caps stay subset of every ceiling.
//
// Action
//   1. Stage VmPolicy (PF + VAR + map_pf + zero).
//   2. createVirtualMachine — VM handle (or smoke-pass on E_NODEV).
//   3. createPageFrame(caps={r,w}, sz=0, pages=1) — pf_target.
//   4. mapGuest(vm, &.{ 0, pf_target }) — must return OK.
//
// Assertions
//   1: setup — create_page_frame for the policy frame returned an
//      error word.
//   2: setup — create_var for the policy mapping returned an error
//      word.
//   3: setup — map_pf for the policy mapping returned non-OK.
//   4: setup — create_virtual_machine returned an unexpected error
//      (anything other than a valid handle or E_NODEV).
//   5: setup — create_page_frame for pf_target returned an error
//      word.
//   6: map_guest on the success path returned non-OK (the
//      smoke-degraded witness for test 07's success-path arm).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

// §[vm_policy] x86-64: 32 cpuid + count + pad + 8 cr + count + pad
// = 976 bytes. Same constant as map_guest_04 / map_guest_05 /
// create_virtual_machine_06.
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
        // No hardware virtualization — test 07's success-path arm is
        // unreachable through any construction. Smoke-pass.
        testing.pass();
        return;
    }
    if (testing.isHandleError(cvm.v1)) {
        testing.fail(4);
        return;
    }
    const vm_handle: HandleId = @truncate(cvm.v1 & 0xFFF);

    // 5. A valid 4-KiB page frame for the pair. caps = {r,w} so the
    //    success path is fully unconstrained on permissions; sz = 0
    //    means the pf's page size is 4 KiB and guest_addr = 0 is
    //    aligned to it.
    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf_target = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // sz = 0 (4 KiB)
        1,
    );
    if (testing.isHandleError(cpf_target.v1)) {
        testing.fail(5);
        return;
    }
    const pf_target: u64 = @as(u64, cpf_target.v1 & 0xFFF);

    // 6. Single pair, guest_addr = 0 (aligned to 4 KiB). Every
    //    earlier gate in §[map_guest] is inert:
    //      - test 01: vm_handle is freshly minted.
    //      - test 02: pf_target is freshly minted.
    //      - test 03: N = 1.
    //      - test 04: 0 is aligned to any sz.
    //      - test 05: only one pair, no intra-call overlap possible.
    //      - test 06: fresh VM has no prior guest mappings.
    //    So the kernel's only reachable outcome is the success path.
    const result = syscall.mapGuest(vm_handle, &.{ 0, pf_target });

    if (result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(6);
        return;
    }

    testing.pass();
}
