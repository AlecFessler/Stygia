// Spec §[vm_set_policy] vm_set_policy — test 09.
//
// "[test 09] on success, the table for the other kind is unchanged."
//
// Spec semantics
//   §[vm_set_policy] replaces a single VmPolicy table on the VM,
//   atomically. The kind selector picks `cpuid_responses` (kind=0) or
//   `cr_policies` (kind=1) on x86-64; the table for the *other* kind
//   must be left untouched. Without a guest running we cannot read the
//   kernel-internal tables back nor observe a guest CPUID/CR access,
//   so the strict spec-mandated observation channel is unreachable
//   from this runner.
//
// Strategy
//   The runner spawns child capability domains without vCPUs and
//   never enters guest mode, so the spec's observation point — guest
//   CPUID/CR exits matching against the configured tables — is not
//   reachable here. The faithful surrogate left to us is functional:
//   after a successful vm_set_policy(kind=0, ...), a subsequent
//   vm_set_policy(kind=1, ...) must still succeed all the way up to
//   that kind's MAX_*. If kind=0's call had clobbered or zeroed the
//   kind=1 table's bookkeeping the second call could not faithfully
//   replace MAX_CR_POLICIES entries; the symmetric test against
//   kind=0 after kind=1 closes the loop.
//
//   This is explicitly a smoke surrogate for test 09: the assertion
//   it carries is "neither kind=0 nor kind=1 errors out when invoked
//   after the other kind", which is necessary-but-not-sufficient for
//   the spec's "other kind unchanged" contract. A vCPU-running test
//   would replace this once the runner gains that capability.
//
// Defusing other vm_set_policy error paths
//   - test 01 (E_BADCAP): we mint a real VM via createVirtualMachine.
//   - test 02 (E_PERM no `policy` cap): runner grants vm_ceiling =
//     0x01 covering the policy bit; we request caps={.policy=true}.
//   - test 03 (E_INVAL count > MAX_*): we use count=1 for both kinds,
//     well under MAX_CPUID_POLICIES (32) and MAX_CR_POLICIES (8).
//   - test 04 (E_INVAL reserved bits): handle slot fits in 12 bits;
//     entry payloads use spec-defined fields only.
//
// Entry layout (x86-64)
//   kind=0 (cpuid_responses), 3 vregs/entry, one entry:
//     vreg 2 = {leaf u32, subleaf u32}
//     vreg 3 = {eax u32,  ebx u32}
//     vreg 4 = {ecx u32,  edx u32}
//   kind=1 (cr_policies), 3 vregs/entry, one entry:
//     vreg 2 = {cr_num u8, _pad u8[7]}     — cr_num = 0 (CR0)
//     vreg 3 = read_value u64
//     vreg 4 = write_mask u64
//
// E_NODEV degrade
//   §[create_virtual_machine] returns E_NODEV when the platform does
//   not advertise hardware virtualization. The QEMU/KVM runner
//   target does, but a no-virt rig leaves this assertion unreachable;
//   smoke-pass with id 0 in that case.
//
// Action
//   1. createPageFrame(caps={r,w}, sz=0, pages=1) — backs VmPolicy.
//   2. createVar + mapPf so userspace can zero the policy buffer.
//   3. Zero VM_POLICY_BYTES so both num_* counts seed at zero.
//   4. createVirtualMachine(caps={.policy=true}, policy_pf).
//   5. vmSetPolicy(vm, kind=0, count=1, one CPUID entry) — must OK.
//   6. vmSetPolicy(vm, kind=1, count=1, one CR entry) — must OK.
//   7. vmSetPolicy(vm, kind=0, count=1, different CPUID entry) — OK.
//   8. vmSetPolicy(vm, kind=1, count=1, different CR entry) — OK.
//
// Assertions
//   1: setup — page frame / var / map_pf / VM creation returned an
//      unexpected error.
//   2: vm_set_policy(kind=0) after fresh VM did not return OK.
//   3: vm_set_policy(kind=1) after the kind=0 set did not return OK
//      (would suggest the kind=0 call corrupted kind=1 state).
//   4: vm_set_policy(kind=0) after the kind=1 set did not return OK.
//   5: vm_set_policy(kind=1) after the second kind=0 set did not
//      return OK.

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

    // 2. VAR + map_pf so userspace can zero the policy buffer the
    //    kernel reads on the create_virtual_machine path.
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
    //    folding the stores against the kernel's read.
    const policy_dst: [*]volatile u8 = @ptrFromInt(policy_base);
    var i: usize = 0;
    while (i < VM_POLICY_BYTES) {
        policy_dst[i] = 0;
        i += 1;
    }

    // 4. Mint the VM. Runner grants `crvm` and vm_ceiling = 0x01
    //    (the policy bit), so caps={.policy=true} stays subset.
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
        testing.fail(1);
        return;
    }
    const vm_handle: HandleId = @truncate(cvm.v1 & 0xFFF);

    // 5. vm_set_policy(kind=0) with one CPUID entry. The entry covers
    //    leaf=1, subleaf=0 (the "feature info" leaf — guaranteed to
    //    have well-defined eax/ebx/ecx/edx semantics on x86-64).
    //    Layout from §[vm_set_policy] x86-64 kind=0:
    //      vreg 2 = {leaf u32, subleaf u32}
    //      vreg 3 = {eax u32,  ebx u32}
    //      vreg 4 = {ecx u32,  edx u32}
    const cpuid0_word0: u64 = (@as(u64, 0) << 32) | @as(u64, 1); // leaf=1, subleaf=0
    const cpuid0_word1: u64 = (@as(u64, 0xCAFE0000) << 32) | @as(u64, 0xBEEF0000);
    const cpuid0_word2: u64 = (@as(u64, 0x12340000) << 32) | @as(u64, 0x56780000);

    const set0_a = syscall.vmSetPolicy(
        vm_handle,
        0, // kind = 0 (cpuid_responses)
        1, // count
        &.{ cpuid0_word0, cpuid0_word1, cpuid0_word2 },
    );
    if (set0_a.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    // 6. vm_set_policy(kind=1) with one CR entry. Covering CR0 with a
    //    benign read_value and a zero write_mask (writes ignored).
    //    Layout from §[vm_set_policy] x86-64 kind=1:
    //      vreg 2 = {cr_num u8, _pad u8[7]}
    //      vreg 3 = read_value u64
    //      vreg 4 = write_mask u64
    const cr0_word0: u64 = 0; // cr_num = 0, _pad = 0
    const cr0_word1: u64 = 0; // read_value
    const cr0_word2: u64 = 0; // write_mask

    const set1_a = syscall.vmSetPolicy(
        vm_handle,
        1, // kind = 1 (cr_policies)
        1, // count
        &.{ cr0_word0, cr0_word1, cr0_word2 },
    );
    if (set1_a.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // 7. Replace kind=0 with a different entry. If the prior kind=1
    //    call had clobbered the kind=0 table's count/state in some
    //    way that broke a faithful replace, this would surface.
    const cpuid1_word0: u64 = (@as(u64, 0) << 32) | @as(u64, 0); // leaf=0
    const cpuid1_word1: u64 = (@as(u64, 0x11110000) << 32) | @as(u64, 0x22220000);
    const cpuid1_word2: u64 = (@as(u64, 0x33330000) << 32) | @as(u64, 0x44440000);

    const set0_b = syscall.vmSetPolicy(
        vm_handle,
        0,
        1,
        &.{ cpuid1_word0, cpuid1_word1, cpuid1_word2 },
    );
    if (set0_b.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }

    // 8. Replace kind=1 again. Same rationale — the second kind=0
    //    set must not have affected kind=1's ability to replace.
    const cr1_word0: u64 = 4; // cr_num = 4 (CR4)
    const cr1_word1: u64 = 0;
    const cr1_word2: u64 = 0;

    const set1_b = syscall.vmSetPolicy(
        vm_handle,
        1,
        1,
        &.{ cr1_word0, cr1_word1, cr1_word2 },
    );
    if (set1_b.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
