// Spec §[create_vcpu] — test 11.
//
// "[test 11] on success, the EC's affinity is set to `[3]`."
//
// Spec semantics
//   §[execution_context] handle ABI: affinity lives in field1 bits 0-63
//   as the current 64-bit core affinity mask (bit N = 1 means the EC may
//   run on core N). §[create_vcpu] [3] is the same 64-bit core mask
//   passed at creation time; the kernel must seed the new vCPU EC's
//   field1 affinity from that argument.
//
// Strategy
//   To isolate the success-path affinity assertion every other gate must
//   be defused so create_vcpu actually returns a handle:
//     - test 01 (E_PERM no `crec`): runner grants `crec` on the test
//       domain's self-handle (runner/primary.zig).
//     - test 02 (E_PERM caps not subset of ec_inner_ceiling): caps = 0
//       is a subset of any ceiling.
//     - test 03 (E_PERM priority exceeds caller's ceiling): priority = 2
//       stays within the runner-granted ceiling = 3 and is non-zero so
//       a default-initialized field would not coincidentally pass test 10.
//     - test 04 (E_BADCAP not a valid VM handle): we mint a real VM via
//       create_virtual_machine.
//     - test 05 (E_BADCAP not a valid port handle): we mint a real port
//       via create_port.
//     - test 06 (E_INVAL affinity bits outside core count): the runner
//       boots QEMU with `-smp cores=4`, so valid affinity bits are 0..3.
//       We pick affinity = 0b0010 (pin to core 1) — non-zero so a freshly
//       zero-initialized field1 would not coincidentally pass, and inside
//       the legal core range so test 06 does not fire.
//     - test 07 (E_INVAL reserved bits in [1]): caps_word's bits 16-31
//       and 34-63 stay clear.
//
//   On success, the kernel writes the authoritative EC handle snapshot
//   into the caller's slot at create time, so we readCap directly out
//   of the read-only handle table mapped at cap_table_base and check
//   field1 equals the requested affinity mask. This mirrors
//   create_vcpu_10's check for the priority field on the same handle.
//
// VM policy buffer
//   create_virtual_machine takes a `policy_page_frame` whose first bytes
//   are a VmPolicy struct. An all-zero buffer is a valid policy (zero
//   counts ⇒ kernel scans no entries). We mint a page frame, map it via
//   a temporary VAR, zero VM_POLICY_BYTES, and pass the frame to
//   create_virtual_machine — the same setup chain as create_vcpu_10.
//
// E_NODEV degradation
//   `create_virtual_machine` returns E_NODEV on platforms without
//   hardware virtualization (§[create_virtual_machine] test 03). On
//   such platforms the VM cannot be minted and the spec assertion
//   under test (affinity on the EC handle returned from create_vcpu)
//   becomes unreachable. We tolerate that outcome with pass-with-id-0,
//   mirroring create_vcpu_10's smoke shape — the QEMU/KVM runner
//   exposes VMX/SVM, so this branch is not expected to fire there but
//   the degraded path keeps the test honest on no-virt rigs.
//
// Action
//   1. createPageFrame(caps={r,w}, props=0, pages=1) — backs VmPolicy.
//   2. createVar(caps={r,w}, cur_rwx=r|w, pages=1) + mapPf at offset 0.
//   3. Zero VM_POLICY_BYTES so num_cpuid_responses = num_cr_policies = 0.
//   4. createVirtualMachine(caps={.policy=true}, policy_pf). Tolerates
//      E_NODEV (degraded smoke pass).
//   5. createPort(caps={bind}) — exit_port for the vCPU.
//   6. createVcpu(caps_word = priority << 32 with priority = 2,
//                 vm_handle, affinity = 0b0010, exit_port).
//   7. readCap(cap_table_base, ec_handle).field1 == 0b0010.
//
// Assertions
//   1: setup — any setup syscall (page frame, var, map_pf, create_port)
//      returned an error word, or createVcpu returned an error word.
//   2: handle's field1 affinity does not equal the requested mask.

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

    // 4. Mint a VM. caps = {.policy = true} stays within the runner-
    //    granted vm_ceiling that covers the `policy` bit. On no-virt
    //    platforms create_virtual_machine returns E_NODEV — degrade
    //    with pass-with-id-0 since the spec assertion under test is
    //    unreachable without a real VM handle.
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

    // 5. Mint the exit port. `bind` cap is required for the port to be
    //    usable as the destination of create_vcpu's vm_exit deliveries.
    const exit_port_caps = caps.PortCap{ .bind = true };
    const cp = syscall.createPort(@as(u64, exit_port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const exit_port: HandleId = @truncate(cp.v1 & 0xFFF);

    // 6. §[create_vcpu] caps word layout:
    //      bits  0-15: caps           (0 — subset of any inner ceiling)
    //      bits 32-33: priority       (2 — within ceiling = 3)
    //      bits 34-63: _reserved      (0)
    //
    //    affinity = 0b0010 pins the vCPU to core 1. Bit 1 is inside the
    //    runner's `-smp cores=4` core count, so test 06's E_INVAL gate
    //    does not fire; the mask is non-zero so a kernel that left
    //    field1 zero-initialized would visibly fail.
    const requested_priority: u64 = 2;
    const requested_affinity: u64 = 0b0010;
    const caps_word: u64 = requested_priority << 32;

    const result = syscall.createVcpu(
        caps_word,
        vm_handle,
        requested_affinity,
        exit_port,
    );
    if (testing.isHandleError(result.v1)) {
        testing.fail(1);
        return;
    }
    const ec_handle: HandleId = @truncate(result.v1 & 0xFFF);

    // 7. §[execution_context] field1 bits 0-63 = affinity. Read the cap
    //    entry out of the read-only handle table mapped at cap_table_base.
    //    The kernel writes the authoritative snapshot at create time,
    //    so a fresh `sync` is not required for the read to be observable.
    const cap = caps.readCap(cap_table_base, ec_handle);
    if (cap.field1 != requested_affinity) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
