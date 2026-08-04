// Spec §[vm_set_policy] vm_set_policy — test 05.
//
// "[test 05] on x86-64 with kind=0, the VM's `cpuid_responses` table
//  is replaced by the count entries; subsequent guest CPUIDs match
//  against this table per §[vm_policy], and the prior contents are no
//  longer matched."
//
// Strategy
//   The strict observable shape of test 05 is "guest CPUID at (leaf,
//   subleaf) of an entry returns the entry's (eax, ebx, ecx, edx),
//   while leaves that were in the *prior* table no longer match." That
//   end-to-end witness requires a fully-driven vCPU running real guest
//   code that issues CPUID and a recv loop on the exit_port that
//   inspects the resumed sub-code in the post-started vreg-70 stack
//   slot. That stack-window protocol (vregs 14..73 at [user_rsp + 8 ..
//   + 488]) is implemented in the libz `replyVmExit` wrapper; staging
//   real guest code (instruction bytes + GDT/IDT/segs/CR0/CR3/EFER)
//   into the VM's guest physical address space and driving CPUID is
//   not provisioned by this single-EC runner — create_vcpu_09 hits
//   the same wall and stops at the initial_state handshake.
//
//   What we observe end-to-end here without a guest payload is the
//   syscall-visible replacement contract: a policy-bearing VM accepts
//   a kind=0 table, accepts an empty replacement, and accepts a later
//   replacement. This does not prove live-vCPU CPUID interception; it
//   proves the mutable table update path exposed by the syscall.
//
//   To isolate the success path we need every earlier gate to be
//   inert:
//     - test 01 (invalid VM)         — pass a freshly-minted VM.
//     - test 02 (missing policy cap) — mint the VM with caps.policy=
//                                      true.
//     - test 03 (count > MAX_*)      — count = 1 stays well under
//                                      MAX_CPUID_POLICIES = 32.
//     - test 04 (reserved bits)      — handle id sits in bits 0-11 of
//                                      [1] with the upper bits zero;
//                                      the entry payload uses every
//                                      bit per the §[vm_set_policy]
//                                      kind=0 layout (no reserved
//                                      space inside the u64s).
//
//   On x86-64 kind=0 each entry occupies 3 vregs:
//     [2 + 3i + 0] = {leaf u32, subleaf u32}      (low 32 = leaf)
//     [2 + 3i + 1] = {eax  u32, ebx     u32}      (low 32 = eax)
//     [2 + 3i + 2] = {ecx  u32, edx     u32}      (low 32 = ecx)
//   We supply one entry seeding `leaf = 0x4000_0000` (a hypervisor-
//   reserved leaf with no architectural meaning, so it can't collide
//   with any prior seed) and a fixed (eax,ebx,ecx,edx) tuple.
//
//   The runner grants `crvm` and vm_ceiling = 0x01 (the policy bit),
//   so caps={.policy=true} stays a subset of the ceiling; the
//   create_virtual_machine call succeeds. On a host without hardware
//   virtualization create_virtual_machine returns E_NODEV; that path
//   makes test 05 unreachable through any construction, so we
//   smoke-pass.
//
// Action
//   1. Stage VmPolicy (PF + VMAR + map_pf + zero).
//   2. createVirtualMachine(caps={.policy=true}, policy_pf) — VM handle
//      (or smoke-pass on E_NODEV).
//   3. vmSetPolicy(vm, kind=0, count=1, entries=&entry) — must return
//      OK, witnessing live-mutable replacement of the cpuid_responses
//      table.
//   4. vmSetPolicy(vm, kind=0, count=0, entries=&.{}) — clears the
//      table; must return OK. Witnesses that count=0 replacement is a
//      valid clear.
//   5. vmSetPolicy(vm, kind=0, count=1, &entry) — re-installs the
//      same entry; must return OK. Closes the loop on repeated
//      replacement of the current table — the third successive
//      replacement must land cleanly.
//
// Assertions
//   1: setup — create_page_frame for the policy frame returned an
//      error word.
//   2: setup — create_vmar for the policy mapping returned an error
//      word.
//   3: setup — map_pf for the policy mapping returned non-OK.
//   4: setup — create_virtual_machine returned an unexpected error
//      (anything other than a valid handle or E_NODEV).
//   9: vm_set_policy on the success path with one entry returned a
//      value other than OK (the spec assertion under test —
//      successful replacement of the cpuid_responses table).
//  10: vm_set_policy with count=0 (clear) returned a value other than
//      OK — empty-table replacement is broken.
//  11: vm_set_policy with the re-installed entry returned a value
//      other than OK — the third successive replacement failed.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

// §[vm_policy] x86-64: 32 cpuid + count + pad + 8 cr + count + pad
// = 976 bytes. Same constant as create_virtual_machine_06 / map_guest_05.
const VM_POLICY_BYTES: usize = 32 * 24 + 8 + 8 * 24 + 8;

// Per §[vm_set_policy] x86-64 kind=0: each entry is 3 vregs encoding
// {leaf, subleaf}, {eax, ebx}, {ecx, edx}. Count = 1 < MAX_CPUID_POLICIES
// = 32 keeps test 03 inert. Hypervisor-reserved CPUID leaf 0x4000_0000
// is a stable, architecturally-meaningless choice for the seed entry.
const SEED_LEAF: u32 = 0x4000_0000;
const SEED_SUBLEAF: u32 = 0;
const SEED_EAX: u32 = 0xDEAD_BEEF;
const SEED_EBX: u32 = 0xCAFE_BABE;
const SEED_ECX: u32 = 0x1234_5678;
const SEED_EDX: u32 = 0x9ABC_DEF0;

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

    // 2. VMAR + map so userspace can zero the policy bytes.
    const policy_var_caps = caps.VmarCap{ .r = true, .w = true };
    const cvar = syscall.createVmar(
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

    // 4. Mint the VM with caps.policy = true. Runner grants `crvm` and
    //    vm_ceiling = 0x01, so policy stays subset of the ceiling. The
    //    VM handle therefore carries the `policy` cap and test 02
    //    cannot fire.
    const vm_caps = caps.VmCap{ .policy = true };
    const cvm = syscall.createVirtualMachine(
        @as(u64, vm_caps.toU16()),
        policy_pf,
    );
    if (cvm.v1 == @intFromEnum(errors.Error.E_NODEV)) {
        // No hardware virtualization — test 05 unreachable through any
        // construction. Smoke-pass.
        testing.pass();
        return;
    }
    if (testing.isHandleError(cvm.v1)) {
        testing.fail(4);
        return;
    }
    const vm_handle: HandleId = @truncate(cvm.v1 & 0xFFF);

    // 5. Build the entry. Each u64 packs two u32 fields per the kind=0
    //    layout: low 32 bits = first field, high 32 bits = second.
    const entry: [3]u64 = .{
        (@as(u64, SEED_SUBLEAF) << 32) | @as(u64, SEED_LEAF),
        (@as(u64, SEED_EBX) << 32) | @as(u64, SEED_EAX),
        (@as(u64, SEED_EDX) << 32) | @as(u64, SEED_ECX),
    };

    // 6. Replace cpuid_responses with one entry. count = 1 <
    //     MAX_CPUID_POLICIES = 32 (test 03 inert); the libz wrapper
    //     takes the handle as u12 so reserved bits in [1] are clean
    //     (test 04 inert); each entry u64 is fully populated by spec
    //     layout, so no per-entry reserved bits are set. The remaining
    //     failure surface is the test 05 success path itself.
    const replace_result = syscall.vmSetPolicy(vm_handle, 0, 1, &entry);
    if (replace_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(9);
        return;
    }

    // 7. Clear the cpuid_responses table by replacing it with count=0.
    //     §[vm_set_policy] does not special-case count=0; the spec
    //     sentence "the table is replaced by the count entries" admits
    //     count=0 as the empty replacement.
    const clear_result = syscall.vmSetPolicy(vm_handle, 0, 0, &.{});
    if (clear_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(10);
        return;
    }

    // 8. Re-install the same entry. Three back-to-back replacements
    //     (1 entry → 0 entries → 1 entry) close the loop on
    //     the *current* table state, not stale state from a prior
    //     install. Any failure to accept repeated replacement would
    //     surface on this third call.
    const reinstall_result = syscall.vmSetPolicy(vm_handle, 0, 1, &entry);
    if (reinstall_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(11);
        return;
    }

    testing.pass();
}
