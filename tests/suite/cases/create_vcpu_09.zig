// Spec §[create_vcpu] — test 09.
//
// "[test 09] on success, `suspend` on the returned EC handle returns
//  E_INVAL, and after `recv` on [4] consumes the initial vm_exit and
//  `reply` on its reply handle, a subsequent `recv` on [4] returns a
//  vm_exit whose vreg layout matches §[vm_exit_state] for VM [2]'s
//  architecture."
//
// Spec semantics
//   §[create_vcpu] guarantees an initial vm_exit-style delivery on the
//   exit_port at creation time and that the vCPU is driven through
//   that port's recv/reply lifecycle, NOT through the explicit
//   `suspend` syscall — §[suspend] [test 06] codifies that as
//   E_INVAL when [1] references a vCPU. After consuming the initial
//   exit and replying, the kernel re-delivers a fresh vm_exit event
//   on the exit_port whose layout matches §[vm_exit_state] for the
//   VM's arch.
//
//   Typed-reply routing (§[reply]): reply handles are tagged at recv
//   time with the originating event_type. For a reply typed
//   `vm_exit`, the kernel projects the §[vm_exit_state] window from
//   the receiver's user stack onto the vCPU's GuestState UNLESS the
//   receiver wrote `initial_state` into the exit sub-code slot
//   (vreg 70 on x86-64, vreg 117 on aarch64), in which case the
//   kernel keeps the vCPU not-started and re-delivers an initial
//   vm_exit on the bound exit_port.
//
// Strategy
//   Drive create_vcpu down its success path with the same defusing
//   prelude as create_vcpu_08 / create_vcpu_10, then exercise the
//   four observable predicates of test 09 in sequence:
//     (a) suspend(ec_handle, exit_port) returns E_INVAL.
//     (b) recv(exit_port) consumes the initial vm_exit and yields a
//         reply handle id in syscall_word bits 32-43.
//     (c) replyVmExit(reply_handle, INITIAL_STATE_SUBCODE) — the
//         initial_state handshake. Tells the kernel "stay
//         not-started"; the kernel does not VMLAUNCH and instead
//         re-enqueues an initial vm_exit on the exit_port.
//     (d) a second recv(exit_port) returns successfully — i.e. the
//         kernel delivered another vm_exit on the same port without
//         turning the recv path into an error.
//
//   Replying with the initial_state sub-code is what makes the
//   re-delivered vm_exit safe: a plain `reply` would project the
//   (zeroed) guest-state vregs we did not modify onto the vCPU's
//   GuestState, mark the vCPU started, and the kernel would VMLAUNCH
//   with all-zero state on the next entry. The handshake suppresses
//   the projection + start so the second recv still witnesses a
//   fresh vm_exit (with sub-code = `initial_state`), satisfying the
//   spec property "subsequent recv on [4] returns a vm_exit whose
//   vreg layout matches §[vm_exit_state]".
//
//   Per the task brief we deliberately do NOT pin specific vreg
//   values in the second exit beyond the fact that recv took the
//   success path: the layout itself is established by the kernel's
//   recv state-transfer path. All we need from observation is that
//   recv returned without setting an error code in vreg 1, i.e. the
//   call traversed the success path in §[recv] rather than
//   surfacing E_BADCAP / E_PERM / E_CLOSED / E_FULL.
//
// Caps required to reach the success paths under test
//   - create_port: caps = {bind, recv}. `bind` lets us pass the port
//     as create_vcpu's exit_port and as suspend's [2] without firing
//     §[suspend] [test 04] E_PERM. `recv` lets us call recv without
//     firing §[recv] [test 02] E_PERM. Both bits are within the
//     runner's port_ceiling = 0x1C (xfer/recv/bind at field-bits
//     2-4, see runner/primary.zig).
//   - create_vcpu: caps = {susp, read, write}. `susp` lets us call
//     suspend on the EC handle without firing §[suspend] [test 03]
//     E_PERM, so the kernel actually reaches the [test 06]
//     vCPU-target check this test 09 is paired against. `read` +
//     `write` keep the recv/reply state-transfer path live should
//     the kernel decide to pre-stage state in the second event;
//     they don't gate the assertions under test directly. All three
//     bits (5, 6, 7) are within the runner's ec_inner_ceiling = 0xFF.
//   - priority = 0, affinity = 0, reserved bits clean — same as
//     create_vcpu_08 / 10 to defuse tests 03 / 06 / 07.
//
// Defusing other create_vcpu error paths (same as create_vcpu_08)
//   - test 01: runner grants `crec` on the test self-handle.
//   - test 02: caps {susp,read,write} (= bits 5-7) are within the
//     runner-granted ec_inner_ceiling = 0xFF.
//   - test 03: priority = 0 stays under the runner-granted pri = 3.
//   - test 04: we mint a real VM via create_virtual_machine.
//   - test 05: we mint a real port via create_port with `bind`.
//   - test 06: affinity = 0 selects "any core".
//   - test 07: caps_word keeps reserved bits 16-31, 34-63 clean and
//     priority bits clean.
//
// E_NODEV degrade
//   create_virtual_machine returns E_NODEV on platforms without
//   hardware virtualization (§[create_virtual_machine] test 03). On
//   such platforms the VM cannot be minted and the spec assertion
//   under test is unreachable; we tolerate that with pass-with-id-0,
//   matching create_vcpu_05 / 08 / 10's degraded shape.
//
// Action
//   1. createPageFrame(caps={r,w}, sz=0, pages=1) — backs VmPolicy.
//   2. createVmar(caps={r,w}, cur_rwx=r|w, pages=1) + mapPf at offset
//      0 — gives userspace a CPU window into the policy frame.
//   3. Zero the VmPolicy region.
//   4. createVirtualMachine(caps={.policy=true}, policy_pf).
//      Tolerates E_NODEV (degraded smoke pass).
//   5. createPort(caps={bind, recv}) — exit_port for the vCPU.
//   6. createVcpu(caps={susp,read,write}, vm_handle, affinity=0,
//      exit_port).
//   7. suspendEc(ec_handle, exit_port) — must return E_INVAL per
//      §[suspend] [test 06].
//   8. recv(exit_port) — must succeed (no error word) and yield a
//      reply handle id.
//   9. replyVmExit(reply_handle, INITIAL_STATE_SUBCODE) — the
//      initial_state handshake. Reserves the §[vm_exit_state] stack
//      window above SP, zeroes it, writes the initial_state sub-code
//      at vreg 70 (x86-64) / vreg 117 (aarch64), and invokes `reply`.
//      Per typed-reply routing in §[reply], the kernel keeps the
//      vCPU not-started and re-enqueues an initial vm_exit on the
//      exit_port instead of attempting guest entry. Must succeed.
//  10. recv(exit_port) — must succeed (no error word). This is the
//      "subsequent recv" of the spec property; success here
//      witnesses that a vm_exit was delivered on the port with the
//      §[vm_exit_state] layout (the layout itself is set by the
//      kernel's recv path, not something userspace can audit
//      vreg-by-vreg without an oracle).
//
// Assertions
//   1: setup — createPageFrame / createVmar / mapPf / createPort /
//      createVcpu returned an error word.
//   2: suspend on the vCPU EC handle returned something other than
//      E_INVAL.
//   3: first recv on the exit_port returned an error word in vreg 1.
//   4: replyVmExit on the recv'd reply handle returned non-OK.
//   5: second recv on the exit_port returned an error word in vreg 1.

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

    // 2. VMAR + map_pf so userspace can zero the policy buffer.
    const policy_var_caps = caps.VmarCap{ .r = true, .w = true };
    const cvar = syscall.createVmar(
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
    //    assertions under test are unreachable without a real VM.
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
    //    [4] handle and for the suspend syscall's [2] handle that
    //    test 09 paired against. `recv` is required so we can pull
    //    the initial vm_exit + the post-reply vm_exit off the port
    //    without firing §[recv] [test 02]. Both bits live within
    //    the runner-granted port_ceiling = 0x1C (bits 2-4).
    const exit_port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cport = syscall.createPort(@as(u64, exit_port_caps.toU16()));
    if (testing.isHandleError(cport.v1)) {
        testing.fail(1);
        return;
    }
    const exit_port: HandleId = @truncate(cport.v1 & 0xFFF);

    // 6. create_vcpu success path. caps include `susp` so the suspend
    //    call below reaches the vCPU-target check (§[suspend] [test
    //    06]) instead of failing earlier with E_PERM. `read` + `write`
    //    keep the state-transfer path live across recv/reply for the
    //    second exit. Bits 5-7 are within ec_inner_ceiling = 0xFF.
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
        testing.fail(1);
        return;
    }
    const ec_handle: HandleId = @truncate(cvcpu.v1 & 0xFFF);

    // 7. §[suspend] [test 06]: suspend on a vCPU EC handle must
    //    return E_INVAL. The port carries `bind`, the EC handle
    //    carries `susp`, and reserved bits are clean — so the only
    //    spec-defined path to E_INVAL on this call is the vCPU-target
    //    check.
    const suspend_result = syscall.suspendEc(ec_handle, exit_port, &.{});
    if (suspend_result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    // 8. recv the initial vm_exit. Per §[create_vcpu], the kernel
    //    enqueues this at create_vcpu time, so the recv must not
    //    block. A successful recv leaves vreg 1 untouched by the
    //    error path; treat any value <= 15 (per §[error_codes]) as
    //    an error word and fail.
    const first = syscall.recv(exit_port, 0);
    if (errors.isError(first.regs.v1)) {
        testing.fail(3);
        return;
    }
    const reply_handle: HandleId = @truncate((first.word >> 32) & 0xFFF);

    // 9. Reply with the initial_state handshake. Per §[reply]'s
    //    typed-reply routing, a vm_exit-typed reply normally projects
    //    the §[vm_exit_state] stack window onto the vCPU's GuestState
    //    and marks the vCPU started — which here would mean VMLAUNCH
    //    with all-zero guest state on the next entry. Writing the
    //    `initial_state` sub-code (vreg 70 on x86-64, vreg 117 on
    //    aarch64) tells the kernel to keep the vCPU not-started and
    //    re-deliver another initial vm_exit on the exit_port, so the
    //    second recv below witnesses a fresh vm_exit with the
    //    §[vm_exit_state] layout (sub-code = `initial_state`).
    const reply_result = syscall.replyVmExit(reply_handle, syscall.INITIAL_STATE_SUBCODE);
    if (reply_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }

    // 10. Second recv. Per spec, a subsequent recv on the exit_port
    //     returns a vm_exit with §[vm_exit_state] layout. Success-path
    //     evidence is an OK vreg 1 (no error word); the layout itself
    //     is established by the kernel's recv state-transfer path and
    //     is not vreg-comparable here without an oracle for which
    //     fields are non-`_reserved` for the just-fired sub-code.
    const second = syscall.recv(exit_port, 0);
    if (errors.isError(second.regs.v1)) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
