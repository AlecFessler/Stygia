// Spec §[reply] reply — test 21.
//
// "[test 21] on success when `pair_count > 0` and the reply is typed
//  `vm_exit` and the receiver wrote the `initial_state` sub-code (vreg
//  70 on x86-64, vreg 117 on aarch64), the kernel re-delivers an
//  initial vm_exit on the vCPU's exit_port without entering guest mode;
//  the N attached handles are still installed in the vCPU's domain at
//  slots [tstart, tstart+N)."
//
// Spec semantics
//   §[reply] routes reply handles by their event_type tag at recv
//   time. A reply tagged `vm_exit` projects the §[vm_exit_state]
//   window from the receiver's user stack onto the vCPU's GuestState,
//   then resumes the vCPU into guest mode — UNLESS the receiver wrote
//   `initial_state` into the exit sub-code slot (vreg 70 on x86-64,
//   vreg 117 on aarch64), in which case the kernel keeps the vCPU
//   not-started and re-enqueues an initial vm_exit on the bound
//   exit_port.
//
//   The "stay not-started" handshake suppresses guest entry, but the
//   standard pair-attachment rules still execute: the N pair entries
//   at vregs [128-N..127] are validated and installed into the vCPU's
//   owning domain at slots [tstart, tstart+N) per
//   §[handle_attachments]. Test 21 exercises that joint contract:
//   the not-started re-delivery AND the handle install both fire.
//
// Strategy
//   The setup mirrors create_vcpu_09's success path (mint a VmPolicy
//   page frame, map+zero, mint a VM, mint an exit port, mint a vCPU
//   that defuses every other §[create_vcpu] gate). The vCPU is minted
//   in the test EC's own capability domain (target=self semantics of
//   create_vcpu), so the install lands in the test's own table — the
//   spec property "installed at [tstart, tstart+N)" is still observable
//   indirectly: with `move = 1` on each pair entry, the SOURCE slot
//   becomes empty after the call, so a subsequent syscall referencing
//   the source handle id must return E_BADCAP.
//
//   Two extra page_frame handles are minted with caps = {move, r, w} —
//   `move = 1` is required on the source for a `move = 1` pair entry
//   per §[handle_attachments] [test 07] (E_PERM otherwise). With the
//   handles being page_frames (not the source EC, the VM, the port,
//   the vCPU EC, or the policy VAR), the kernel installs them in the
//   vCPU's domain (= the test's domain) at some [tstart, tstart+2)
//   slots without coalescing against any pre-existing handle.
//
//   The exit_port carries `xfer` so the recv-minted reply handle is
//   tagged `xfer = 1` (§[reply] reply-cap minting) — the reply cap
//   §[reply] [test 09] gates on.
//
// Action
//   1. Standard create_vcpu_09 prelude — page_frame for the policy,
//      VAR + map_pf, zero the policy bytes, create_virtual_machine
//      (E_NODEV → degraded smoke pass), create_port({bind, recv,
//      xfer}), create_vcpu(caps={susp,read,write}, exit_port).
//   2. createPageFrame(caps={move,r,w}, sz=0, pages=1) — first
//      attachment.
//   3. createPageFrame(caps={move,r,w}, sz=0, pages=1) — second
//      attachment.
//   4. recv(exit_port) — consumes the kernel-injected initial vm_exit;
//      yields reply_handle_id in the syscall word's bits 32-43.
//   5. replyTransferVmExit(reply_handle, [pf_a move=1, pf_b move=1],
//      INITIAL_STATE_SUBCODE) — must return OK. Pair entries are packed
//      with caps = {move, r, w} (the page_frames' existing caps; the
//      target subset cannot exceed the source's caps per
//      §[handle_attachments]) and move = 1.
//   6. recv(exit_port) — must return OK with regs.v2 ==
//      INITIAL_STATE_SUBCODE. Witnesses the "kernel kept the vCPU
//      not-started and re-delivered an initial vm_exit" half of the
//      spec.
//   7. delete(pf_a_id) — must return E_BADCAP. Witnesses the install
//      half: with move = 1, the source slot was vacated and the kernel
//      placed pf_a into [tstart, tstart+2). A delete on the source id
//      now hits an empty slot.
//   8. delete(pf_b_id) — must return E_BADCAP. Same observation for
//      the second pair entry.
//
// Assertions
//   1: setup — any syscall in the create_vcpu_09 prelude returned an
//      error word (createPageFrame / createVar / mapPf / createPort /
//      createVcpu).
//   2: setup — minting the first attachment page_frame failed.
//   3: setup — minting the second attachment page_frame failed.
//   4: first recv on the exit_port did not return OK.
//   5: replyTransferVmExit did not return OK.
//   6: second recv on the exit_port returned non-OK or the recv'd
//      sub-code in vreg 2 was not INITIAL_STATE_SUBCODE — the kernel
//      either errored out or projected guest state instead of
//      re-delivering an initial vm_exit.
//   7: delete on the first source page_frame id did not return
//      E_BADCAP — the move = 1 install did not vacate the source slot.
//   8: delete on the second source page_frame id did not return
//      E_BADCAP — same install observable for the second pair entry.
//
// E_NODEV degrade
//   create_virtual_machine returns E_NODEV on platforms without
//   hardware virtualization (§[create_virtual_machine] test 03). On
//   such platforms the spec assertion under test is unreachable;
//   tolerate that with pass-with-id-0, matching create_vcpu_09 /
//   create_vcpu_12's degraded shape.

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

    // 1a. Page frame backing the VmPolicy struct.
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

    // 1b. VAR + map_pf so userspace can zero the policy buffer.
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

    // 1c. Zero the VmPolicy region. Volatile keeps ReleaseSmall from
    //     folding the store against the kernel's read.
    const policy_dst: [*]volatile u8 = @ptrFromInt(policy_base);
    var i: usize = 0;
    while (i < VM_POLICY_BYTES) {
        policy_dst[i] = 0;
        i += 1;
    }

    // 1d. Mint a VM. caps = {.policy = true} ⊆ runner's vm_ceiling.
    //     E_NODEV on no-virt platforms degrades to pass-with-id-0.
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

    // 1e. Exit port. `bind` for create_vcpu's [4], `recv` for the
    //     test EC to dequeue events, `xfer` so the recv-minted reply
    //     handle carries `xfer = 1` per §[reply] reply-cap minting —
    //     the cap §[reply_transfer] [test 02] gates on. All three
    //     bits sit inside the runner-granted port_ceiling = 0x1C.
    const exit_port_caps = caps.PortCap{
        .bind = true,
        .recv = true,
        .xfer = true,
    };
    const cport = syscall.createPort(@as(u64, exit_port_caps.toU16()));
    if (testing.isHandleError(cport.v1)) {
        testing.fail(1);
        return;
    }
    const exit_port: HandleId = @truncate(cport.v1 & 0xFFF);

    // 1f. create_vcpu success path. caps include `read` + `write` so
    //     the recv/reply state-transfer path is live across the
    //     vm_exit handshake. Bits 5-7 sit inside the runner's
    //     ec_inner_ceiling = 0xFF.
    const vcpu_caps = caps.EcCap{
        .susp = true,
        .read = true,
        .write = true,
    };
    const cvcpu = syscall.createVcpu(
        @as(u64, vcpu_caps.toU16()),
        vm_handle,
        0, // affinity = any core
        exit_port,
    );
    if (testing.isHandleError(cvcpu.v1)) {
        testing.fail(1);
        return;
    }

    // 2. First attachment page_frame. caps include `move` (bit 0) so
    //    the pair-entry move = 1 gate (§[handle_attachments] [test 07])
    //    finds `move` on the source. r + w round out a non-degenerate
    //    page_frame cap word — the kernel installs the target with the
    //    same caps in the vCPU's domain.
    const pf_attach_caps = caps.PfCap{
        .move = true,
        .r = true,
        .w = true,
    };
    const cpf_a = syscall.createPageFrame(
        @as(u64, pf_attach_caps.toU16()),
        0,
        1,
    );
    if (testing.isHandleError(cpf_a.v1)) {
        testing.fail(2);
        return;
    }
    const pf_a_id: HandleId = @truncate(cpf_a.v1 & 0xFFF);

    // 3. Second attachment page_frame. Same cap shape.
    const cpf_b = syscall.createPageFrame(
        @as(u64, pf_attach_caps.toU16()),
        0,
        1,
    );
    if (testing.isHandleError(cpf_b.v1)) {
        testing.fail(3);
        return;
    }
    const pf_b_id: HandleId = @truncate(cpf_b.v1 & 0xFFF);

    // 4. Consume the kernel-injected initial vm_exit; reply_handle_id
    //    rides in the syscall word's bits 32-43 per §[recv].
    const got = syscall.recv(exit_port, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }
    const reply_handle: HandleId = @truncate((got.word >> 32) & 0xFFF);

    // 5. reply_transfer typed `vm_exit` with the initial_state
    //    handshake AND two pair entries (move = 1). The libz wrapper
    //    reserves the §[vm_exit_state] window above SP, zeroes it,
    //    writes INITIAL_STATE_SUBCODE at vreg 70 (x86-64) / 117
    //    (aarch64), and writes the N pair entries at vregs
    //    [128-N..127] per §[handle_attachments].
    const pair_a = caps.PairEntry{
        .id = pf_a_id,
        .caps = pf_attach_caps.toU16(),
        .move = true,
    };
    const pair_b = caps.PairEntry{
        .id = pf_b_id,
        .caps = pf_attach_caps.toU16(),
        .move = true,
    };
    const rt = syscall.replyTransferVmExit(
        reply_handle,
        &.{ pair_a.toU64(), pair_b.toU64() },
        syscall.INITIAL_STATE_SUBCODE,
    );
    if (rt.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(5);
        return;
    }

    // 6. Second recv: the kernel must have re-delivered an initial
    //    vm_exit on the exit_port instead of entering guest mode. The
    //    sub-code in vreg 2 must be INITIAL_STATE_SUBCODE per
    //    §[vm_exit_state].
    const got2 = syscall.recv(exit_port, 0);
    if (got2.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(6);
        return;
    }
    if (got2.regs.v2 != @as(u64, syscall.INITIAL_STATE_SUBCODE)) {
        testing.fail(6);
        return;
    }

    // 7. Source slot for pf_a was vacated by the move = 1 pair entry;
    //    the kernel installed pf_a in the vCPU's domain at [tstart,
    //    tstart+2). A delete on the source id now hits an empty slot
    //    and must return E_BADCAP per §[delete].
    const del_a = syscall.delete(pf_a_id);
    if (del_a.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(7);
        return;
    }

    // 8. Same observable for pf_b.
    const del_b = syscall.delete(pf_b_id);
    if (del_b.v1 != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(8);
        return;
    }

    testing.pass();
}
