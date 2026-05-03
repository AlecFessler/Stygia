// Spec §[create_vcpu] — test 06.
//
// "[test 06] returns E_INVAL if [3] affinity has bits set outside the
//  system's core count."
//
// Spec semantics
//   §[create_vcpu] [3]: "64-bit core mask; bit N = 1 allows the vCPU to
//   run on core N. 0 = any core (kernel chooses)." A bit set at an
//   index >= the system's core count names a core that does not exist;
//   the kernel must reject the call with E_INVAL rather than fall back
//   to "any core" or silently mask the offending bit.
//
// Strategy
//   Build a clean create_vcpu invocation where the affinity argument
//   is the only spec violation, so E_INVAL on bit-out-of-range is the
//   sole reachable failure path:
//     - [1] caps = 0: no caps to subset-check (test 02 passes
//       trivially), priority = 0 (within the runner's pri ceiling, so
//       test 03 passes), and reserved bits are clean (test 07 passes).
//     - [2] vm_handle: a freshly minted VM handle (test 04 passes).
//     - [3] affinity: 1 << 63. The kernel test runner uses
//       `-smp cores=4` (build.zig:345), so the system's core count is
//       4. Bit 63 is far outside [0, 4) and is a single bit so the
//       diagnostic is unambiguous.
//     - [4] exit_port: a freshly minted port with `bind` set so the
//       port-validity and bind-cap checks pass (test 05 passes).
//
//   Setup chain:
//     1. create_page_frame(caps={r,w}, sz=0, pages=1) — VmPolicy
//        backing store. 4 KiB > sizeof(VmPolicy) (= 976 bytes), so
//        create_virtual_machine test 05 (page_frame too small) cannot
//        fire ahead of us.
//     2. create_var(caps={r,w}, cur_rwx=r|w, pages=1) + map_pf at
//        offset 0 — gives a CPU-visible window so we can zero the
//        policy buffer.
//     3. Zero VmPolicy bytes through the mapped VAR. Zero counts
//        (num_cpuid_responses = num_cr_policies = 0) are valid per
//        §[vm_policy], so create_virtual_machine accepts the policy.
//     4. create_virtual_machine(caps=0, policy_pf) — caps=0 sidesteps
//        any VmCap subset / restart_policy questions.
//     5. create_port(caps={bind, recv}) — exit port. `bind` is
//        required for create_vcpu to accept the port (§[port_cap]
//        bit 4 names bind as the cap that authorizes using a port as
//        the destination of a create_vcpu's exit_port).
//     6. create_vcpu(caps=0, vm, affinity = 1 << 63, exit_port) —
//        must return E_INVAL.
//
// Assertions
//   1: setup — create_page_frame returned an error word
//   2: setup — create_var returned an error word
//   3: setup — map_pf returned non-OK in vreg 1
//   4: setup — create_virtual_machine returned an error word
//   5: setup — create_port returned an error word
//   6: create_vcpu returned a value other than E_INVAL — the kernel
//      either accepted the out-of-range affinity bit or short-circuited
//      to a different error code, both spec violations.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

// §[vm_policy] x86-64 layout: 32 CpuidPolicy entries (24 bytes each) +
// num_cpuid_responses (u32) + pad (u32) + 8 CrPolicy entries (24 bytes
// each) + num_cr_policies (u32) + pad (u32). All-zero is a valid
// policy: zero counts ⇒ kernel scans no entries.
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

    // 3. Zero the VmPolicy struct so num_cpuid_responses and
    //    num_cr_policies fall out as 0 — a valid empty policy.
    const policy_dst: [*]u8 = @ptrFromInt(policy_base);
    var i: usize = 0;
    while (i < VM_POLICY_BYTES) {
        policy_dst[i] = 0;
        i += 1;
    }

    // 4. Create the VM. caps = 0 keeps the call within vm_ceiling
    //    regardless of the runner's grant.
    const cvm = syscall.createVirtualMachine(0, policy_pf);
    if (testing.isHandleError(cvm.v1)) {
        testing.fail(4);
        return;
    }
    const vm_handle: HandleId = @truncate(cvm.v1 & 0xFFF);

    // 5. Exit port. `bind` is required for the create_vcpu cap check
    //    on [4]; `recv` is harmless and matches the canonical exit-
    //    port shape used by acquire_ecs_07 and the spec narrative.
    const exit_port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, exit_port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(5);
        return;
    }
    const exit_port: HandleId = @truncate(cp.v1 & 0xFFF);

    // 6. The runner uses `-smp cores=4` (build.zig: -smp cores=4), so
    //    bit 63 names a core far outside [0, 4). Every other input is
    //    clean, so E_INVAL on the affinity range check is the only
    //    spec-mandated outcome.
    const bad_affinity: u64 = @as(u64, 1) << 63;
    const cvcpu = syscall.createVcpu(0, vm_handle, bad_affinity, exit_port);

    if (cvcpu.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(6);
        return;
    }

    testing.pass();
}
