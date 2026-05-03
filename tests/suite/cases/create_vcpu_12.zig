// Spec §[create_vcpu] — test 12.
//
// "[test 12] immediately after creation, an initial vm_exit event is
//  delivered on `[4] exit_port` with zeroed guest state in the vregs
//  and the initial-state sub-code."
//
// Spec semantics
//   §[create_vcpu] (around the test list): "Immediately upon creation,
//   the kernel enqueues a vm_exit-style delivery on `exit_port`
//   representing the initial 'not yet started' condition: the reply
//   cap is valid, all guest-state vregs are zero, and the exit
//   sub-code is the initial-state sub-code." The creator recvs this
//   event, writes the real initial guest state into the vregs, and
//   replies with a resume action to enter guest mode.
//
//   §[vm_exit_state] enumerates per-arch vm_exit sub-codes (cpuid, io,
//   mmio, ept, hlt, ...). The `initial_state` sub-code is the explicit
//   table entry for the synthetic exit injected at create_vcpu time:
//   sub-code 13 on x86-64, sub-code 10 on aarch64. libz exposes the
//   arch-dispatched value as `syscall.INITIAL_STATE_SUBCODE`.
//
// Strategy
//   The setup mirrors create_vcpu_10 — mint a VmPolicy page frame, map
//   it, zero the policy bytes, mint a VM with `policy` cap, mint an
//   exit_port with `bind | recv`, and call create_vcpu with caps = 0
//   so every other §[create_vcpu] gate (caps subset, priority,
//   affinity, reserved bits, badcap on [2]/[4]) is defused. On
//   success the kernel must have already enqueued the initial vm_exit
//   on the exit_port, so the very next `recv(exit_port)` returns
//   immediately with the synthetic event.
//
//   Event readout
//     Per §[vm_exit_state] the vm_exit-style delivery's vreg 2 carries
//     the exit sub-code (the kernel's `setEventSubcode` writes the
//     register-passed vreg 2 — rbx on x86-64). vregs 1 and 3 carry
//     the syscall return word and the event_addr respectively; for
//     this synthetic exit the kernel passes payload `.{ 0, 0, 0 }`,
//     so vreg 3 should also be 0. Vregs 4..13 are register-passed
//     guest GPR slots — for the initial "not yet started" condition
//     the spec demands those land at the receiver as zero.
//
//   "Zeroed guest state" check
//     The libz `recv` wrapper passes only `port` in vreg 1 and zeroes
//     all other input vregs (Regs default-initializes v2..v13 = 0).
//     Per the kernel's recv slow path the receiver's saved GPRs are
//     preserved across the syscall except for the slots the kernel
//     explicitly stamps — so a spec-compliant initial vm_exit
//     delivery leaves vregs 4..13 as the zeros the wrapper put in,
//     and the assertion is observable end-to-end. Vreg 2 is excluded
//     because the kernel uses that slot for the sub-code delivery
//     channel itself; vreg 3 (= event_addr = 0 here) is included.
//
// E_NODEV degradation
//   `create_virtual_machine` returns E_NODEV on platforms without
//   hardware virtualization (§[create_virtual_machine] test 03). On
//   such platforms the VM cannot be minted and the spec assertion
//   under test (initial vm_exit on the new vCPU's exit_port) becomes
//   unreachable. Tolerate that outcome with pass-with-id-0, mirroring
//   create_vcpu_05/10's smoke shape — the QEMU/KVM runner exposes
//   VMX/SVM, so this branch is not expected to fire there but the
//   degraded path keeps the test honest on no-virt rigs.
//
// Action
//   1. createPageFrame(caps={r,w}, props=0, pages=1) — backs VmPolicy.
//   2. createVar(caps={r,w}, cur_rwx=r|w, pages=1) + mapPf at offset 0.
//   3. Zero VM_POLICY_BYTES so num_cpuid_responses = num_cr_policies = 0.
//   4. createVirtualMachine(caps={.policy=true}, policy_pf). Tolerates
//      E_NODEV (degraded smoke pass).
//   5. createPort(caps={bind, recv}) — exit_port for the vCPU; recv
//      lets us observe the kernel-injected initial vm_exit.
//   6. createVcpu(caps_word=0, vm_handle, affinity=0, exit_port).
//   7. recv(exit_port) — must return OK with the initial vm_exit.
//   8. regs.v2 == syscall.INITIAL_STATE_SUBCODE (13 on x86-64, 10 on
//      aarch64; §[vm_exit_state]).
//   9. regs.v3 and regs.v4..v13 all zero.
//
// Assertions
//   1: setup — createPageFrame returned an error word.
//   2: setup — createVar returned an error word.
//   3: setup — mapPf returned non-OK in vreg 1.
//   4: setup — createVirtualMachine returned an error word other than
//      E_NODEV (E_NODEV smoke-passes with assertion id 0).
//   5: setup — createPort returned an error word.
//   6: setup — createVcpu returned an error word.
//   7: recv on the exit_port did not return OK in vreg 1 (the spec
//      assertion: an initial vm_exit must already be queued).
//   8: the recv'd event's sub-code (vreg 2) is not the §[vm_exit_state]
//      `initial_state` sub-code (x86-64: 13, aarch64: 10).
//   9: any guest-state vreg observed via the register-passed slots is
//      non-zero — vreg 3 (= guest rdx / event_addr, expected 0) and
//      vregs 4..13 (= guest rbp, rsi, rdi, r8, r9, r10, r12..r15).

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
    //    folding the store against the kernel's read of the page frame.
    const policy_dst: [*]volatile u8 = @ptrFromInt(policy_base);
    var i: usize = 0;
    while (i < VM_POLICY_BYTES) {
        policy_dst[i] = 0;
        i += 1;
    }

    // 4. Mint a VM. caps = {.policy = true} stays within the runner-
    //    granted vm_ceiling that covers the `policy` bit. On no-virt
    //    platforms create_virtual_machine returns E_NODEV — degrade
    //    with pass-with-id-0 since the spec assertion under test is
    //    unreachable without a real VM handle.
    const vm_caps = caps.VmCap{ .policy = true };
    const cvm = syscall.createVirtualMachine(
        @as(u64, vm_caps.toU16()),
        policy_pf,
    );
    if (cvm.v1 == @intFromEnum(errors.Error.E_NODEV)) {
        // No-virt platform: spec assertion unreachable.
        testing.pass();
        return;
    }
    if (testing.isHandleError(cvm.v1)) {
        testing.fail(4);
        return;
    }
    const vm_handle: HandleId = @truncate(cvm.v1 & 0xFFF);

    // 5. Mint the exit port. `bind` is required for the port to be
    //    usable as the destination of create_vcpu's vm_exit deliveries
    //    (the §[create_vcpu] [4] handle-cap check). `recv` lets the
    //    test EC pull the kernel-injected initial vm_exit back off
    //    the port.
    const exit_port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, exit_port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(5);
        return;
    }
    const exit_port: HandleId = @truncate(cp.v1 & 0xFFF);

    // 6. §[create_vcpu] caps word layout: caps in bits 0-15, priority
    //    in 32-33, reserved elsewhere. caps = 0 is a subset of any
    //    inner ceiling; priority = 0 stays inside the runner-granted
    //    pri ceiling; reserved bits stay clear.
    const result = syscall.createVcpu(
        0, // caps_word: caps=0, priority=0, reserved=0
        vm_handle,
        0, // affinity = 0 (any core)
        exit_port,
    );
    if (testing.isHandleError(result.v1)) {
        testing.fail(6);
        return;
    }

    // 7. The kernel must have enqueued the initial vm_exit on
    //    exit_port at create_vcpu time, so this recv returns
    //    immediately with the synthetic event rather than blocking.
    const got = syscall.recv(exit_port, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(7);
        return;
    }

    // 8. §[vm_exit_state]: the exit sub-code rides in the receiver's
    //    vreg 2 (rbx on x86-64). Per §[create_vcpu] the synthetic
    //    initial event must carry the `initial_state` sub-code (13 on
    //    x86-64, 10 on aarch64).
    if (got.regs.v2 != @as(u64, syscall.INITIAL_STATE_SUBCODE)) {
        testing.fail(8);
        return;
    }

    // 9. Spec demands "all guest-state vregs are zero" for the initial
    //    vm_exit. Check every register-passed vreg outside the
    //    sub-code slot. vreg 1 is the syscall return (0 = OK) which
    //    coincidentally also matches "guest rax = 0"; vreg 2 is
    //    excluded because the kernel uses that slot for the sub-code
    //    delivery channel; vreg 3 (event_addr / guest rdx) is the
    //    payload[0] value the kernel passed (0). vregs 4..13 cover
    //    the remaining register-passed guest GPRs.
    const non_zero =
        got.regs.v3 |
        got.regs.v4 |
        got.regs.v5 |
        got.regs.v6 |
        got.regs.v7 |
        got.regs.v8 |
        got.regs.v9 |
        got.regs.v10 |
        got.regs.v11 |
        got.regs.v12 |
        got.regs.v13;
    if (non_zero != 0) {
        testing.fail(9);
        return;
    }

    testing.pass();
}
