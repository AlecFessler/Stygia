// Spec §[vm_set_policy] vm_set_policy — test 04.
//
// "[test 04] returns E_INVAL if any reserved bits are set in [1] or
//  any entry."
//
// Strategy
//   §[capabilities] establishes that handle arguments carry only the
//   12-bit handle id in bits 0-11 of their vreg; bits 12-63 are
//   _reserved. Setting any reserved bit in [1] must surface E_INVAL at
//   the syscall ABI layer per §[syscall_abi].
//
//   To isolate the reserved-bit rejection we need every earlier gate in
//   §[vm_set_policy] to be inert:
//     - test 01 (invalid VM)        — pass a freshly-minted VM whose
//                                      handle id sits in bits 0-11.
//     - test 02 (missing policy cap) — mint the VM with
//                                      caps={.policy=true} so the cap
//                                      check passes.
//     - test 03 (count > MAX_*)     — count = 0 stays well under
//                                      MAX_CPUID_POLICIES (32 on
//                                      x86-64) for kind = 0.
//   With count = 0 and entries = &.{}, no per-entry payload exists, so
//   the only reserved-bit channel exercised is [1].
//
//   The libz `vmSetPolicy` wrapper takes the handle as `u12`, which
//   strips the reserved bits before issuing — so we bypass it via
//   `syscall.issueReg` (matches the create_vcpu_07 reference shape) to
//   put bit 63 of [1] on the wire. Bit 63 is the top of the bits 12-63
//   reserved range; using the highest reserved bit keeps it well clear
//   of the 12-bit handle id field below.
//
//   The runner grants `crvm` and vm_ceiling = 0x01 (the policy bit), so
//   caps={.policy=true} stays a subset of the ceiling; the
//   create_virtual_machine call succeeds. On a host without hardware
//   virtualization create_virtual_machine returns E_NODEV; that path
//   makes test 04 unreachable through any construction, so we
//   smoke-pass.
//
// Action
//   1. Stage VmPolicy (PF + VAR + map_pf + zero).
//   2. createVirtualMachine(caps={.policy=true}, policy_pf) — VM handle
//      (or smoke-pass on E_NODEV).
//   3. issueReg(.vm_set_policy, extraVmKind(0, 0),
//      .{ .v1 = vm_handle | (1<<63) }) — must return E_INVAL because
//      bit 63 of [1] is reserved.
//
// Assertions
//   1: setup — create_page_frame for the policy frame returned an
//      error word.
//   2: setup — create_var for the policy mapping returned an error
//      word.
//   3: setup — map_pf for the policy mapping returned non-OK.
//   4: setup — create_virtual_machine returned an unexpected error
//      (anything other than a valid handle or E_NODEV).
//   5: vm_set_policy with reserved bit 63 set in [1] returned a value
//      other than E_INVAL (the spec assertion under test).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

// §[vm_policy] x86-64: 32 cpuid + count + pad + 8 cr + count + pad
// = 976 bytes. Same constant as create_virtual_machine_06 / map_guest_05.
const VM_POLICY_BYTES: usize = 32 * 24 + 8 + 8 * 24 + 8;

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
        // No hardware virtualization — test 04 unreachable through any
        // construction. Smoke-pass.
        testing.pass();
        return;
    }
    if (testing.isHandleError(cvm.v1)) {
        testing.fail(4);
        return;
    }
    const vm_handle: HandleId = @truncate(cvm.v1 & 0xFFF);

    // 5. Bit 63 of [1] is the top of the bits 12-63 _reserved range
    //    per §[capabilities]. count = 0 keeps test 03 inert, kind = 0
    //    selects cpuid_responses on x86-64 / id_reg_responses on
    //    aarch64, and entries = &.{} means no per-entry reserved-bit
    //    surface. Bypass the libz `vmSetPolicy` wrapper (which takes
    //    the handle as u12 and would mask bit 63 off) by issuing
    //    directly through `issueReg`.
    const reserved_bit_in_v1: u64 = @as(u64, vm_handle) | (@as(u64, 1) << 63);
    const result = syscall.issueReg(
        .vm_set_policy,
        syscall.extraVmKind(0, 0),
        .{ .v1 = reserved_bit_in_v1 },
    );

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
