// Spec §[create_vcpu] — test 08.
//
// "[test 08] on success, the caller receives an EC handle with caps =
//  `[1].caps`."
//
// Strategy
//   Drive create_vcpu down its success path with the same defusing
//   prelude as create_vcpu_07, but instead of provoking E_INVAL, we
//   request a non-trivial caps word and verify the returned EC handle
//   carries exactly that caps field.
//
//   The caps field of a handle lives in word0 bits 48-63 of the cap
//   table entry — part of the static handle layout, not a kernel-
//   mutable field0/field1 snapshot — so a fresh `readCap` against the
//   read-only-mapped table is authoritative without `sync` (same
//   pattern as create_var_18 / create_virtual_machine_09).
//
//   Use multi-bit caps {read, write} so the assertion exercises a
//   non-trivial bit pattern and is sensitive to either bit being
//   dropped or any stray bit being set on the way through the kernel.
//   Bits 6-7 of EcCap are well within the runner-granted
//   ec_inner_ceiling = 0xFF (bits 0-7).
//
// Defusing other create_vcpu error paths
//   - test 01 (E_PERM no `crec`): runner spawns child with `crec`.
//   - test 02 (E_PERM caps not subset of ec_inner_ceiling): runner
//     grants ec_inner_ceiling = 0xFF; {read, write} = bits 6-7 stays
//     within that subset.
//   - test 03 (E_PERM priority exceeds ceiling): priority = 0, well
//     under the runner-granted pri = 3.
//   - test 04 (E_BADCAP not a valid VM handle): we mint a real VM via
//     create_virtual_machine.
//   - test 05 (E_BADCAP not a valid port handle): we mint a real port
//     via create_port with `bind`.
//   - test 06 (E_INVAL affinity outside core count): affinity = 0
//     selects "any core".
//   - test 07 (E_INVAL reserved bits in [1]): EcCap packed struct
//     keeps reserved bits 16-31, 34-63 clean and priority = 0 keeps
//     bits 32-33 clean.
//
// E_NODEV degrade
//   create_virtual_machine returns E_NODEV on platforms without
//   hardware virtualization. On such platforms the VM cannot be minted
//   and the spec assertion under test is unreachable. We tolerate that
//   outcome with pass-with-id-0, mirroring create_vcpu_05's degraded
//   shape.
//
// Action
//   1. createPageFrame(caps={r,w}, sz=0, pages=1) — backs VmPolicy.
//   2. createVar(caps={r,w}, cur_rwx=0b011, pages=1) + mapPf at
//      offset 0 — gives userspace a CPU window into the policy frame.
//   3. Zero the VmPolicy region (volatile so ReleaseSmall does not
//      fold the store away ahead of the kernel's read).
//   4. createVirtualMachine(caps={.policy=true}, policy_pf). Tolerates
//      E_NODEV (degraded smoke pass). On success captures vm_handle.
//   5. createPort(caps={.bind=true}) — exit_port for the vCPU.
//   6. createVcpu(caps={.read=true,.write=true}, vm_handle, affinity=0,
//      exit_port) — must succeed.
//   7. readCap(cap_table_base, returned_handle) — verify caps ==
//      requested.
//
// Assertions
//   1: setup — any of createPageFrame / createVar / mapPf /
//      createPort failed, or createVcpu returned an error word.
//   2: returned EC handle's caps field does not equal requested caps.

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
    //    = 0, num_cr_policies = 0) are a valid empty policy. Volatile
    //    keeps ReleaseSmall from folding the store against the kernel's
    //    read of the page frame.
    const policy_dst: [*]volatile u8 = @ptrFromInt(policy_base);
    var i: usize = 0;
    while (i < VM_POLICY_BYTES) {
        policy_dst[i] = 0;
        i += 1;
    }

    // 4. Mint a VM. caps={.policy=true} is a subset of the runner-
    //    granted vm_ceiling = 0x01. On no-virt platforms this returns
    //    E_NODEV — degrade with pass-with-id-0 since the success-path
    //    assertion is unreachable without a real VM handle.
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

    // 5. Mint a port for the vCPU's exit_port arg. Runner grants
    //    `crpt` and port_ceiling covers `bind`.
    const port_caps = caps.PortCap{ .bind = true };
    const cport = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cport.v1)) {
        testing.fail(1);
        return;
    }
    const exit_port: HandleId = @truncate(cport.v1 & 0xFFF);

    // 6. Issue create_vcpu on the success path. caps={read,write} are
    //    EcCap bits 6-7, within the ec_inner_ceiling = 0xFF subset.
    //    priority = 0 stays under the runner-granted pri = 3, affinity
    //    = 0 selects "any core", and reserved bits stay clean.
    const requested = caps.EcCap{ .read = true, .write = true };
    const cvcpu = syscall.createVcpu(
        @as(u64, requested.toU16()),
        vm_handle,
        0,
        exit_port,
    );
    if (testing.isHandleError(cvcpu.v1)) {
        testing.fail(1);
        return;
    }
    const ec_handle: u12 = @truncate(cvcpu.v1 & 0xFFF);

    // 7. Read the freshly-minted EC handle and verify caps ==
    //    requested.
    const cap = caps.readCap(cap_table_base, ec_handle);
    if (cap.caps() != requested.toU16()) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
