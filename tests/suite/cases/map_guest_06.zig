// Spec §[map_guest] map_guest — test 06.
//
// "[test 06] returns E_INVAL if any pair's range overlaps an existing
//  mapping in the VM's guest physical address space."
//
// Strategy
//   To isolate the cross-call overlap rejection we need every earlier
//   gate in §[map_guest] to be inert on the second call:
//     - test 01 (invalid VM)          — pass a freshly-minted VM.
//     - test 02 (invalid page_frame)  — every pair carries a real pf.
//     - test 03 (N == 0)              — N = 1.
//     - test 04 (guest_addr unaligned to pf.sz) — guest_addr = 0,
//                                       aligned to any sz.
//     - test 05 (intra-call overlap)  — only one pair per call.
//
//   First map_guest installs pf_a at guest_addr = 0 covering
//   [0, 4 KiB). Second map_guest tries to install pf_b at the same
//   guest_addr; its range is also [0, 4 KiB). The two ranges are
//   identical and therefore overlap an existing mapping. Per
//   §[map_guest] test 06 the kernel must return E_INVAL.
//
//   Two distinct page_frame handles are used so the rejection cannot
//   be ascribed to anything other than overlap with the prior
//   installation.
//
// VM setup mirrors map_guest_05: stage a 4-KiB VmPolicy page frame,
// map it through a VAR so userspace can zero the policy bytes (so
// num_cpuid_responses / num_cr_policies are 0 — both well under
// MAX_*), then create_virtual_machine with caps={.policy=true}. The
// runner grants `crvm` and vm_ceiling = 0x01 (the policy bit), so
// caps stay subset of every ceiling. On the QEMU/KVM rig VT-x is
// exposed and the call succeeds; on a host without hardware
// virtualization the call returns E_NODEV — that path makes test 06
// unreachable through any construction, so we smoke-pass
// (assertion id 0).
//
// Action
//   1. Stage VmPolicy (PF + VAR + map_pf + zero).
//   2. createVirtualMachine — VM handle (or smoke-pass on E_NODEV).
//   3. createPageFrame(caps={r,w}, sz=0, pages=1) twice — pf_a, pf_b.
//   4. mapGuest(vm, &.{ 0, pf_a }) — must succeed (no error).
//   5. mapGuest(vm, &.{ 0, pf_b }) — must return E_INVAL (overlap
//      with the installed pf_a mapping).
//
// Assertions
//   1: setup — create_page_frame for the policy frame returned an
//      error word.
//   2: setup — create_var for the policy mapping returned an error
//      word.
//   3: setup — map_pf for the policy mapping returned non-OK.
//   4: setup — create_virtual_machine returned an unexpected error
//      (anything other than a valid handle or E_NODEV).
//   5: setup — create_page_frame for pf_a or pf_b returned an error
//      word.
//   6: first map_guest (installing pf_a) returned non-OK — overlap
//      gate cannot be exercised without a successful prior mapping.
//   7: second map_guest with a range overlapping the prior
//      installation returned a value other than E_INVAL (the spec
//      assertion under test).

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
        // No hardware virtualization — test 06 unreachable through
        // any construction. Smoke-pass.
        testing.pass();
        return;
    }
    if (testing.isHandleError(cvm.v1)) {
        testing.fail(4);
        return;
    }
    const vm_handle: HandleId = @truncate(cvm.v1 & 0xFFF);

    // 5. Two distinct page frames, each 4 KiB.
    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf_a = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // sz = 0 (4 KiB)
        1,
    );
    if (testing.isHandleError(cpf_a.v1)) {
        testing.fail(5);
        return;
    }
    const pf_a: u64 = @as(u64, cpf_a.v1 & 0xFFF);

    const cpf_b = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0,
        1,
    );
    if (testing.isHandleError(cpf_b.v1)) {
        testing.fail(5);
        return;
    }
    const pf_b: u64 = @as(u64, cpf_b.v1 & 0xFFF);

    // 6. Install pf_a at guest_addr = 0 covering [0, 4 KiB). This
    //    establishes the existing mapping that the second call must
    //    collide with.
    const first = syscall.mapGuest(vm_handle, &.{ 0, pf_a });
    if (first.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(6);
        return;
    }

    // 7. Second map_guest with pf_b at the same guest_addr. Its
    //    range [0, 4 KiB) overlaps the existing pf_a installation;
    //    spec requires E_INVAL.
    const result = syscall.mapGuest(vm_handle, &.{ 0, pf_b });

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(7);
        return;
    }

    testing.pass();
}
