// Spec §[capabilities] acquire_ecs — test 07.
//
// "[test 07] vCPUs in the target domain are not included in the
//  returned handles."
//
// Spec semantics
//   acquire_ecs walks the target domain's bound ECs and returns
//   handles for the non-vCPU ones. vCPUs are ECs in the kernel's data
//   model (created via `create_vcpu` and bound to a VM), but the
//   §[acquire_ecs] surface filters them out so a debugger inspecting a
//   capability domain through an `aqec` IDC sees the regular ECs only;
//   vCPU state is the VM's responsibility, not the domain debugger's.
//
// Strategy (single-domain self-IDC variant)
//   The test capability domain holds its own self-IDC at slot 2
//   (SLOT_SELF_IDC), minted by `create_capability_domain` with caps =
//   the inner cridc_ceiling. The runner's child cridc_ceiling = 0x3F
//   exposes IDC bits 0-5 — including `aqec` (bit 3) — so the test
//   domain is self-authorized to call `acquire_ecs(SLOT_SELF_IDC)`.
//
//   At spawn time the domain has exactly one EC bound to it: the
//   initial EC at slot 1. We then create a vCPU bound to the same
//   domain (the spec binds a vCPU to "the capability domain that holds
//   the VM handle" — that's us, since we created the VM) and re-issue
//   `acquire_ecs`. The post-condition for test 07 is that the vCPU
//   handle is NOT among the returned handles; equivalently the count
//   stays at 1 and the single returned handle still refers to the
//   initial EC.
//
//   Setup chain (each step must succeed before the assertion is
//   meaningful — failures get distinct assertion ids):
//     1. create_page_frame(1 page) for the VmPolicy buffer.
//     2. create_var + map_pf to install the page frame at a known
//        vaddr so we can zero the policy struct (zero counts ⇒ kernel
//        reads no entries; spec §[vm_policy] allows num_*=0).
//     3. zero the VmPolicy bytes through the mapped VAR.
//     4. create_virtual_machine(caps=0, policy_pf) — caps=0 keeps the
//        VM handle's caps within `vm_ceiling` regardless of the
//        domain's vm_ceiling field.
//     5. create_port(caps={bind, recv}) for the vCPU's exit_port. The
//        domain doesn't actually need to handle exits; the port just
//        has to exist and be `bind`-capable so create_vcpu accepts it.
//     6. create_vcpu(caps=0, vm, affinity=0, exit_port). The vCPU EC
//        binds to this domain because we hold the VM handle.
//     7. acquire_ecs(SLOT_SELF_IDC). The kernel must return count = 1
//        with the single vreg slot referring to the initial EC.
//
//   The VM-on-test-domain layout doesn't require crossing a capability
//   domain boundary, so we can stay inside a single test ELF without
//   the multi-domain test infra called out by revoke_06. The only
//   subtlety is that test ECs created by the runner can't actually
//   start a vCPU — `create_vcpu` requires the caller's self-handle to
//   have `crec`, which the runner grants. The vCPU stays suspended on
//   its exit_port (initial vm_exit event waiting); we never recv it.
//   That's fine for this test: vCPU existence is what acquire_ecs has
//   to filter on, not vCPU runtime state.
//
// Assertions
//   1: setup — create_page_frame returned an error word
//   2: setup — create_var returned an error word
//   3: setup — map_pf returned non-success in vreg 1
//   4: setup — create_virtual_machine returned an error word
//   5: setup — create_port returned an error word
//   6: setup — create_vcpu returned an error word
//   7: acquire_ecs returned an error code in vreg 1 instead of a
//      handle word (testing.isHandleError on v1)
//   8: count field (syscall word bits 12-19) != 1 — vCPU was either
//      included (count >= 2) or initial EC was missing (count == 0)
//   9: vreg 1 holds the vCPU's EC handle id rather than the initial
//      EC's handle id — vCPU leaked into the returned set despite
//      count being 1 (e.g. a future bug that swapped initial-EC for
//      vCPU under aliasing rules)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

// §[vm_policy] x86-64 layout: 32 CpuidPolicy entries (6 u32 each = 24
// bytes) + num_cpuid_responses (u32) + pad (u32) + 8 CrPolicy entries
// (cr_num+pad+read+mask = 24 bytes) + num_cr_policies (u32) + pad
// (u32). All-zero is a valid policy: zero counts ⇒ kernel scans no
// entries on guest exits.
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

    // 3. Zero the VmPolicy struct. num_cpuid_responses = 0 and
    //    num_cr_policies = 0 fall out of the all-zero buffer, so
    //    create_virtual_machine sees a valid empty policy.
    const policy_dst: [*]u8 = @ptrFromInt(policy_base);
    var i: usize = 0;
    while (i < VM_POLICY_BYTES) {
        policy_dst[i] = 0;
        i += 1;
    }

    // 4. Create the VM. caps = 0 (no `policy` cap needed; we won't
    //    call vm_set_policy from this test) sidesteps any VmCap
    //    bit-set / restart_policy questions.
    const cvm = syscall.createVirtualMachine(0, policy_pf);
    if (testing.isHandleError(cvm.v1)) {
        testing.fail(4);
        return;
    }
    const vm_handle: HandleId = @truncate(cvm.v1 & 0xFFF);

    // 5. Exit port. bind so create_vcpu accepts it; recv is included
    //    so a future debug path could drain the initial vm_exit event,
    //    but this test does not do so.
    const exit_port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, exit_port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(5);
        return;
    }
    const exit_port: HandleId = @truncate(cp.v1 & 0xFFF);

    // 6. Create the vCPU. caps = 0; affinity = 0 (any core). The
    //    returned EC handle is what acquire_ecs MUST filter out.
    const cvcpu = syscall.createVcpu(0, vm_handle, 0, exit_port);
    if (testing.isHandleError(cvcpu.v1)) {
        testing.fail(6);
        return;
    }
    const vcpu_ec: HandleId = @truncate(cvcpu.v1 & 0xFFF);

    // 7. Walk the test domain's ECs through its self-IDC. The slot-2
    //    self-IDC was minted by create_capability_domain with caps =
    //    the inner cridc_ceiling, which the runner sets to 0x3F —
    //    bits 0-5 of IdcCap, including `aqec` at bit 3.
    const got = syscall.acquireEcs(caps.SLOT_SELF_IDC);

    // On success, vreg 1 is the first returned handle word, not OK
    // (§[acquire_ecs]: "writes them to vregs [1..N]"). On error, vreg
    // 1 carries an error code (≤ 15 per §[error_codes]).
    if (testing.isHandleError(got.regs.v1)) {
        testing.fail(7);
        return;
    }

    // §[acquire_ecs] count occupies syscall word bits 12-19.
    const count: u8 = @truncate((got.word >> 12) & 0xFF);
    if (count != 1) {
        testing.fail(8);
        return;
    }

    // Returned handle id at vreg 1 must reference the initial EC, not
    // the vCPU. Equality with vcpu_ec means the kernel handed back the
    // vCPU's EC handle in violation of test 07.
    const returned_ec: HandleId = @truncate(got.regs.v1 & 0xFFF);
    if (returned_ec == vcpu_ec) {
        testing.fail(9);
        return;
    }

    testing.pass();
}
