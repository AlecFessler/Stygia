// Spec §[create_vcpu] create_vcpu — test 02.
//
// "[test 02] returns E_PERM if caps is not a subset of the VM's
//  owning domain's `ec_inner_ceiling`."
//
// Strategy
//   The vCPU EC handle's caps argument is `[1].caps` (bits 0-15 of
//   the caps word, an EcCap). The kernel mints the new EC handle into
//   the capability domain that holds the VM handle, bounded by that
//   owning domain's self-handle `ec_inner_ceiling` — an 8-bit field
//   carrying EcCap bits 0-7 (move/copy/saff/spri/term/susp/read/write)
//   per §[capability_domain] field0.
//
//   The runner spawns each test domain with `ec_inner_ceiling = 0xFF`
//   (every bit the 8-bit ceiling can carry, see runner/primary.zig).
//   A VM created by this domain has it as the owning domain, so the
//   ceiling under test is 0xFF.
//
//   `ec_inner_ceiling` is structurally only 8 bits. EcCap bits >= 8 —
//   `restart_policy` (8-9), `bind` (10), `rebind` (11), `unbind`
//   (12) — are unconditionally outside ec_inner_ceiling regardless of
//   the value installed in the ceiling field. The same construction
//   create_execution_context_03 uses for self's ec_inner_ceiling
//   applies here: setting `bind` (bit 10) in caps cannot be a subset
//   of any 8-bit ceiling, so the kernel must reject with E_PERM. This
//   is faithful, not degraded — narrowing ec_inner_ceiling further is
//   unnecessary because EcCap bits 8+ are out-of-range by structure.
//
//   Setup chain (mirrors create_virtual_machine_06's VM construction
//   with a clean zeroed VmPolicy so the VM creation lands in OK
//   rather than E_INVAL):
//     1. create_page_frame(caps={r,w}, sz=0, pages=1) — 4 KiB backing
//        store for the VmPolicy struct.
//     2. create_var(caps={r,w}, cur_rwx=r|w, pages=1) + map_pf at
//        offset 0 — CPU-visible window so we can zero the bytes.
//     3. Zero VM_POLICY_BYTES so num_cpuid_responses / num_cr_policies
//        are both 0 (well under MAX_* — tests 06/07 cannot fire).
//     4. create_virtual_machine(caps={policy=true}, policy_pf) — the
//        runner grants `crvm` and vm_ceiling = 0x01, so this stays
//        within every ceiling. On the QEMU/KVM platform the call
//        succeeds (VT-x exposed); E_NODEV is acceptable as an early
//        bail because then test 02 is not reachable through any
//        construction.
//     5. create_port(caps={bind=true}) — port handle for [4]
//        exit_port. `bind` is the cap §[port] requires for use as a
//        create_vcpu exit_port.
//     6. create_vcpu(caps={bind=true}, vm, affinity=0, exit_port) —
//        EcCap.bind (bit 10) is outside the owning domain's 8-bit
//        ec_inner_ceiling (= 0xFF). Must return E_PERM.
//
//   Choices that keep the call off the other reject paths:
//     - test 01 (E_PERM, missing crec): runner grants crec.
//     - test 03 (E_PERM, priority exceeds caller's pri ceiling):
//       priority = 0, well within pri = 3.
//     - test 04 (E_BADCAP invalid VM): we pass a fresh, valid VM.
//     - test 05 (E_BADCAP invalid port): we pass a fresh port with
//       `bind` cap.
//     - test 06 (E_INVAL affinity bits outside core count): affinity
//       = 0 ("any core") has no out-of-range bits.
//     - test 07 (E_INVAL reserved bits in [1]): only bits 0-15 of
//       caps_word are set; bits 32-33 (priority) = 0, all other bits
//       = 0.
//
// Action
//   1. Stage VmPolicy (PF + VAR + map + zero).
//   2. createVirtualMachine — must return a VM handle (or E_NODEV,
//      treated as a non-failure no-op on platforms without VT-x).
//   3. createPort(caps={bind}) — must return a port handle.
//   4. createVcpu(caps={bind=true}, vm, 0, port) — must return
//      E_PERM.
//
// Assertions
//   1: create_page_frame returned an error word.
//   2: create_var returned an error word.
//   3: map_pf returned non-OK.
//   4: create_virtual_machine returned an unexpected error
//      (anything other than a valid handle or E_NODEV).
//   5: create_port returned an error word.
//   6: create_vcpu returned a value other than E_PERM.

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
    const cpf = syscall.createPageFrame(
        @as(u64, policy_pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB), restart_policy = 0
        1,
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const policy_pf: HandleId = @truncate(cpf.v1 & 0xFFF);

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
    //    caps={.policy=true} stays subset. On QEMU/KVM (the test
    //    rig) VT-x is exposed and this succeeds; E_NODEV is the only
    //    spec-listed reason to bail without firing test 02.
    const vm_caps = caps.VmCap{ .policy = true };
    const cvm = syscall.createVirtualMachine(
        @as(u64, vm_caps.toU16()),
        policy_pf,
    );
    if (cvm.v1 == @intFromEnum(errors.Error.E_NODEV)) {
        // No hardware virtualization — test 02 unreachable through
        // any construction. Pass: this is not the failure mode we
        // are checking.
        testing.pass();
        return;
    }
    if (testing.isHandleError(cvm.v1)) {
        testing.fail(4);
        return;
    }
    const vm_handle: HandleId = @truncate(cvm.v1 & 0xFFF);

    // 5. Mint an exit port. `bind` is the cap §[port] requires for
    //    using a port as a create_vcpu exit_port (port cap bit 4).
    const port_caps = caps.PortCap{ .bind = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(5);
        return;
    }
    const port_handle: HandleId = @truncate(cp.v1 & 0xFFF);

    // 6. The bit under test: EcCap.bind (bit 10) sits outside the
    //    VM's owning domain's 8-bit ec_inner_ceiling. Every other
    //    EcCap field stays zero so the only ceiling violation is the
    //    bind bit. priority = 0 stays within pri = 3.
    const ec_caps = caps.EcCap{ .bind = true };
    const caps_word: u64 = @as(u64, ec_caps.toU16());

    const result = syscall.createVcpu(
        caps_word,
        vm_handle,
        0, // affinity = any core; no out-of-range bits (test 06)
        port_handle,
    );

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(6);
        return;
    }

    testing.pass();
}
