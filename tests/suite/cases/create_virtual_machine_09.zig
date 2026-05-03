// Spec §[create_virtual_machine] — test 09.
//
// "[test 09] on success, the caller receives a VM handle with caps =
//  `[1].caps`."
//
// Strategy
//   Drive create_virtual_machine down its success path with the same
//   prelude as create_virtual_machine_06 (page frame + VAR + map_pf +
//   zero VmPolicy buffer), but leave every num_* count at zero so the
//   policy is a valid empty policy and the kernel takes neither the
//   cpuid nor cr overflow branch. Reserved bits in [1] stay clean and
//   caps={.policy=true} is a subset of the runner-granted
//   vm_ceiling = 0x01 (the policy bit), so the E_PERM, E_BADCAP, and
//   E_INVAL paths are all defused.
//
//   On a working kernel + virt-capable platform create_virtual_machine
//   returns a fresh VM handle in vreg 1. The caps field of a handle
//   lives in word0 bits 48-63 of the cap table entry — part of the
//   static handle layout — so a fresh `readCap` against the read-only-
//   mapped table is authoritative without `sync` (same pattern as
//   create_var_18 / restrict_06).
//
// E_NODEV degrade
//   §[create_virtual_machine] line 1450 lists E_NODEV when the platform
//   does not advertise hardware virtualization. The QEMU/KVM runner
//   target does, but a future runner variant (e.g. a no-virt boot for
//   test 03's faithful path) could surface E_NODEV here. In that case
//   the success-path assertion is unreachable; we report pass-with-
//   id-0 to mark this slot as degraded rather than failing on a
//   platform-conditional outcome.
//
// Defusing other create_virtual_machine error paths
//   - test 01 (E_PERM no `crvm`): runner spawns child with `crvm`.
//   - test 02 (E_PERM caps not subset of vm_ceiling): runner grants
//     vm_ceiling = 0x01; we request caps = {.policy=true} (= 0x01).
//   - test 04 (E_BADCAP): we pass a freshly-minted page frame.
//   - test 05 (E_INVAL frame too small): 4 KiB > sizeof(VmPolicy).
//   - test 06/07 (E_INVAL num_* exceeds MAX_*): both counts left zero.
//   - test 08 (E_INVAL reserved bits): caps high bits stay zero via
//     VmCap packed struct.
//
// Action
//   1. createPageFrame(caps={r,w}, sz=0, pages=1).
//   2. createVar(caps={r,w}, cur_rwx=0b011, pages=1) + mapPf at
//      offset 0 — gives userspace a CPU window into the policy frame.
//   3. Zero the VmPolicy region (volatile to keep ReleaseSmall from
//      folding the store away ahead of the kernel's read).
//   4. createVirtualMachine(caps={.policy=true}, policy_pf).
//   5. readCap(cap_table_base, returned_handle) — verify caps ==
//      {.policy=true}.
//
// Assertions
//   1: setup — any of createPageFrame / createVar / mapPf failed.
//   2: returned VM handle's caps field does not equal requested caps.

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
    //    kernel will read on the create_virtual_machine path.
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

    // 3. Zero the VmPolicy region. All-zero counts (num_cpuid_responses
    //    = 0, num_cr_policies = 0) are a valid empty policy: the kernel
    //    scans no entries on guest exits. Volatile keeps ReleaseSmall
    //    from folding the store against the kernel's read.
    const policy_dst: [*]volatile u8 = @ptrFromInt(policy_base);
    var i: usize = 0;
    while (i < VM_POLICY_BYTES) {
        policy_dst[i] = 0;
        i += 1;
    }

    // 4. Issue create_virtual_machine on the success path. Runner
    //    grants `crvm` and vm_ceiling = 0x01 (the policy bit), so
    //    caps={.policy=true} is a subset of the ceiling.
    const requested = caps.VmCap{ .policy = true };
    const cvm = syscall.createVirtualMachine(
        @as(u64, requested.toU16()),
        policy_pf,
    );

    // E_NODEV degrade: if the runner ever boots a no-virt variant for
    // this test, the spec-mandated success path is unreachable.
    if (cvm.v1 == @intFromEnum(errors.Error.E_NODEV)) {
        testing.pass();
        return;
    }

    if (testing.isHandleError(cvm.v1)) {
        testing.fail(1);
        return;
    }
    const vm_handle: u12 = @truncate(cvm.v1 & 0xFFF);

    // 5. Read the freshly-minted handle and verify caps == requested.
    const cap = caps.readCap(cap_table_base, vm_handle);
    if (cap.caps() != requested.toU16()) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
