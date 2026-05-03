// Spec §[reply] — test 08.
//
// "[test 08] on success when the reply is typed `vm_exit` and the
//  receiver wrote the `initial_state` sub-code into the reply (vreg 70
//  on x86-64, vreg 117 on aarch64), the kernel re-delivers an initial
//  vm_exit on the vCPU's exit_port without entering guest mode; a
//  subsequent `recv` on the exit_port returns a vm_exit whose sub-code
//  is `initial_state`."
//
// Spec semantics
//   §[reply] types every reply by the originating event_type at recv
//   time. A reply typed `vm_exit` ordinarily routes to the vCPU's
//   guest-state writeback path: the kernel reads the §[vm_exit_state]
//   window from the receiver's user stack (vregs 14..N), projects it
//   onto guest state gated by the EC `write` cap, and re-enters guest
//   mode. The `initial_state` sub-code (13 on x86-64, 10 on aarch64) is
//   the receiver's signal that no real guest state is being supplied —
//   it acknowledges the synthetic create-time vm_exit (§[create_vcpu])
//   without actually starting the vCPU. In that case the kernel keeps
//   the vCPU not-started and re-enqueues the same synthetic initial
//   vm_exit on the bound exit_port, so a subsequent recv observes the
//   `initial_state` sub-code again.
//
// Strategy
//   Reuse the create_vcpu_09 / create_vcpu_12 prelude verbatim — mint a
//   VmPolicy page frame, zero it, mint a VM (tolerating E_NODEV), mint
//   an exit_port with `bind | recv`, and mint a vCPU with `read | write`
//   so the reply's state-writeback path is gated correctly. Then drive
//   the three observable predicates of test 08 in order:
//     (a) The first recv on exit_port returns the kernel-injected
//         initial vm_exit. We assert OK in vreg 1, event_type = vm_exit
//         (5) in syscall_word bits 44-48, a non-zero reply_handle_id in
//         bits 32-43, and sub-code = INITIAL_STATE_SUBCODE in vreg 2
//         (the kernel's GPR-backed sub-code mirror; see the matching
//         observation in create_vcpu_12).
//     (b) `replyVmExit(reply_handle, INITIAL_STATE_SUBCODE)` reserves
//         the §[vm_exit_state] window above SP, writes the sub-code at
//         vreg 70 / 117, and issues `reply` (syscall 52). The spec
//         demands OK and that the kernel routes through the
//         re-deliver-initial branch instead of guest entry.
//     (c) A second recv on exit_port must return OK with sub-code =
//         INITIAL_STATE_SUBCODE — direct evidence that the kernel
//         re-delivered the synthetic initial vm_exit rather than entered
//         guest mode (which would either run the all-zero guest forever
//         or surface a different sub-code on the next exit).
//
// Caps required to reach the success paths under test
//   - create_port: caps = {bind, recv}. `bind` lets us pass the port as
//     create_vcpu's exit_port; `recv` lets us call recv on it. Both
//     bits live within the runner-granted port_ceiling = 0x1C.
//   - create_vcpu: caps = {read, write}. `write` is the gate the kernel
//     checks before applying the receiver's vm_exit-state writeback to
//     guest state; without it the spec routes the writeback away from
//     guest state and the re-deliver-initial branch would never fire on
//     a no-`write` rig. `read` keeps the corresponding read path live.
//     Bits 6-7 stay within ec_inner_ceiling = 0xFF. We omit `susp` —
//     test 08 never calls `suspend` on the vCPU.
//   - reply: no self-handle cap required (per §[reply]) — the reply
//     handle itself authorizes the operation.
//
// Defusing other reply error paths
//   - test 01 (E_BADCAP): we use the kernel-minted reply_handle_id
//     pulled from the first recv's syscall_word bits 32-43.
//   - test 02 (E_INVAL on reserved bits): replyVmExit composes the
//     syscall word as syscall_num | (reply_handle << 12) only;
//     bits 24-63 stay clear.
//   - test 03 (E_TERM): the vCPU was just created and never
//     terminated; this branch is unreachable here.
//
// E_NODEV degrade
//   create_virtual_machine returns E_NODEV on platforms without
//   hardware virtualization (§[create_virtual_machine] test 03). On
//   such platforms the spec assertion under test (re-delivery of the
//   initial vm_exit) is unreachable — no vCPU, no reply typed vm_exit.
//   Tolerate that with pass-with-id-0, matching create_vcpu_09 / 12.
//
// Action
//   1. createPageFrame(caps={r,w}, sz=0, pages=1) — backs VmPolicy.
//   2. createVar(caps={r,w}, cur_rwx=r|w, pages=1) + mapPf at offset 0.
//   3. Zero the VmPolicy region.
//   4. createVirtualMachine(caps={.policy=true}, policy_pf). Tolerates
//      E_NODEV (degraded smoke pass).
//   5. createPort(caps={bind, recv}) — exit_port for the vCPU.
//   6. createVcpu(caps={read, write}, vm_handle, affinity=0, exit_port).
//   7. recv(exit_port, 0) — must return OK; observe event_type=vm_exit
//      in syscall_word bits 44-48, a reply_handle_id in bits 32-43, and
//      sub-code = INITIAL_STATE_SUBCODE in vreg 2.
//   8. replyVmExit(reply_handle, INITIAL_STATE_SUBCODE) — must return OK.
//   9. recv(exit_port, 0) — must return OK with vreg 2 =
//      INITIAL_STATE_SUBCODE (the re-delivered synthetic initial exit).
//
// Assertions
//   1: setup — createPageFrame / createVar / mapPf / createPort /
//      createVcpu returned an error word.
//   2: first recv on exit_port returned an error word in vreg 1.
//   3: first recv's syscall_word event_type field (bits 44-48) was not
//      vm_exit (= 5).
//   4: first recv's syscall_word reply_handle_id field (bits 32-43)
//      was zero (slot 0 is the self-handle, never a reply handle).
//   5: first recv's vreg 2 was not INITIAL_STATE_SUBCODE — the kernel
//      did not deliver the synthetic initial vm_exit per §[create_vcpu].
//   6: replyVmExit returned non-OK in vreg 1.
//   7: second recv on exit_port returned an error word in vreg 1.
//   8: second recv's vreg 2 was not INITIAL_STATE_SUBCODE — the kernel
//      did not re-deliver the synthetic initial vm_exit per the
//      §[reply] [test 08] property under test.

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

// §[event_type]: vm_exit = 5.
const EVENT_TYPE_VM_EXIT: u64 = 5;

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
    //    E_NODEV — degrade with pass-with-id-0 since the spec assertion
    //    under test is unreachable without a real VM.
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

    // 5. Mint the exit port. `bind` is required so the port is usable
    //    as create_vcpu's [4] handle without firing §[create_vcpu]
    //    [test 05]. `recv` lets us pull the initial vm_exit + the
    //    re-delivered initial vm_exit off the port. Both bits live
    //    within the runner-granted port_ceiling = 0x1C.
    const exit_port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cport = syscall.createPort(@as(u64, exit_port_caps.toU16()));
    if (testing.isHandleError(cport.v1)) {
        testing.fail(1);
        return;
    }
    const exit_port: HandleId = @truncate(cport.v1 & 0xFFF);

    // 6. create_vcpu success path. caps={read, write} keeps the
    //    state-transfer path live across recv/reply: `write` gates the
    //    vm_exit-state writeback the kernel inspects on reply, which is
    //    the path we need active for the kernel to even consider the
    //    initial_state-sub-code-special-case branch under test.
    const vcpu_caps = caps.EcCap{ .read = true, .write = true };
    const caps_word: u64 = @as(u64, vcpu_caps.toU16());
    const cvcpu = syscall.createVcpu(
        caps_word,
        vm_handle,
        0, // affinity = any core
        exit_port,
    );
    if (testing.isHandleError(cvcpu.v1)) {
        testing.fail(1);
        return;
    }

    // 7. First recv: consume the kernel-injected initial vm_exit
    //    enqueued at create_vcpu time. Per §[create_vcpu], the kernel
    //    enqueues this synchronously, so the recv returns immediately.
    const first = syscall.recv(exit_port, 0);
    if (errors.isError(first.regs.v1)) {
        testing.fail(2);
        return;
    }

    // §[event_state]: syscall_word bits 44-48 = event_type. The
    //    initial vm_exit must carry event_type = 5 (vm_exit).
    const first_event_type: u64 = (first.word >> 44) & 0x1F;
    if (first_event_type != EVENT_TYPE_VM_EXIT) {
        testing.fail(3);
        return;
    }

    // §[event_state]: syscall_word bits 32-43 = reply_handle_id. Slot 0
    //    is the self-handle; a real reply handle slot is non-zero.
    const reply_handle_id: u64 = (first.word >> 32) & 0xFFF;
    if (reply_handle_id == 0) {
        testing.fail(4);
        return;
    }
    const reply_handle: HandleId = @truncate(reply_handle_id);

    // §[vm_exit_state]: the exit sub-code rides in the receiver's
    //    vreg 2 GPR slot for the kernel-injected initial event (see
    //    create_vcpu_12 for the matching observation). The synthetic
    //    initial event must carry sub-code = INITIAL_STATE_SUBCODE
    //    (13 on x86-64, 10 on aarch64).
    if (first.regs.v2 != @as(u64, syscall.INITIAL_STATE_SUBCODE)) {
        testing.fail(5);
        return;
    }

    // 8. Reply with the initial_state sub-code. replyVmExit reserves
    //    the §[vm_exit_state] window above SP, zeroes it, writes the
    //    sub-code at vreg 70 (x86-64) / 117 (aarch64), and issues
    //    `reply` (syscall 52). Per §[reply] [test 08], the kernel must
    //    keep the vCPU not-started and re-deliver an initial vm_exit
    //    on exit_port instead of entering guest mode.
    const reply_result = syscall.replyVmExit(
        reply_handle,
        syscall.INITIAL_STATE_SUBCODE,
    );
    if (reply_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(6);
        return;
    }

    // 9. Second recv: the spec property under test. The kernel must
    //    have re-enqueued the synthetic initial vm_exit on exit_port,
    //    so this recv returns immediately.
    const second = syscall.recv(exit_port, 0);
    if (errors.isError(second.regs.v1)) {
        testing.fail(7);
        return;
    }

    // §[reply] [test 08]: the re-delivered exit's sub-code must be
    //    INITIAL_STATE_SUBCODE — direct evidence that the kernel took
    //    the re-deliver-initial branch rather than entered guest mode.
    if (second.regs.v2 != @as(u64, syscall.INITIAL_STATE_SUBCODE)) {
        testing.fail(8);
        return;
    }

    testing.pass();
}
