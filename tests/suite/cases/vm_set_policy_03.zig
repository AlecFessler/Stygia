// Spec §[vm_set_policy] vm_set_policy — test 03.
//
// "[test 03] returns E_INVAL if count exceeds the active (kind, arch)'s
//  MAX_* constant from §[vm_policy]."
//
// Strategy
//   To isolate the count-bound rejection we need every earlier gate in
//   §[vm_set_policy] to be inert:
//     - test 01 (invalid VM)        — pass a freshly-minted, valid VM.
//     - test 02 (missing policy cap) — mint the VM with caps.policy=true.
//   Tests 04+ (reserved bits in [1]/entries) cannot fire ahead of 03
//   when [1]'s reserved bits are clear and `entries` is the empty slice
//   (no per-entry payload to validate).
//
//   On x86-64 the active table for kind=0 is `cpuid_responses`, bounded
//   by `MAX_CPUID_POLICIES = 32` per §[vm_policy]. The smallest count
//   that strictly exceeds this bound is 33. The vreg-ABI count field
//   (syscall word bits 13-20, 8 bits) accommodates 33 trivially, so the
//   value reaches the kernel intact.
//
//   The runner grants `crvm` and vm_ceiling = 0x01 (the policy bit), so
//   caps={.policy=true} stays a subset of the ceiling; the
//   create_virtual_machine call succeeds. On a host without hardware
//   virtualization create_virtual_machine returns E_NODEV; that path
//   makes test 03 unreachable through any construction, so we
//   smoke-pass.
//
// Action
//   1. Stage VmPolicy (PF + VAR + map_pf + zero).
//   2. createVirtualMachine(caps={.policy=true}, policy_pf) — VM handle
//      (or smoke-pass on E_NODEV).
//   3. vmSetPolicy(vm, kind=0, count=33, entries=&.{}) — must return
//      E_INVAL because 33 > MAX_CPUID_POLICIES = 32.
//
// Assertions
//   1: setup — create_page_frame for the policy frame returned an
//      error word.
//   2: setup — create_var for the policy mapping returned an error
//      word.
//   3: setup — map_pf for the policy mapping returned non-OK.
//   4: setup — create_virtual_machine returned an unexpected error
//      (anything other than a valid handle or E_NODEV).
//   5: vm_set_policy with count exceeding MAX_CPUID_POLICIES returned a
//      value other than E_INVAL (the spec assertion under test).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

// §[vm_policy] x86-64: 32 cpuid + count + pad + 8 cr + count + pad
// = 976 bytes. Same constant as create_virtual_machine_06 / map_guest_05.
const VM_POLICY_BYTES: usize = 32 * 24 + 8 + 8 * 24 + 8;

// Per §[vm_policy] kind=0 is bounded by:
//   x86-64: MAX_CPUID_POLICIES  = 32 → smallest over-max is 33
//   aarch64: MAX_ID_REG_RESPONSES = 62 → smallest over-max is 63
// Pick at comptime so the request reaches the kernel just past the
// active arch's limit.
const OVER_MAX_KIND0: u8 = switch (@import("builtin").cpu.arch) {
    .x86_64 => 33,
    .aarch64 => 63,
    else => @compileError("vm_set_policy_03 not configured for this arch"),
};

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
        // No hardware virtualization — test 03 unreachable through any
        // construction. Smoke-pass.
        testing.pass();
        return;
    }
    if (testing.isHandleError(cvm.v1)) {
        testing.fail(4);
        return;
    }
    const vm_handle: HandleId = @truncate(cvm.v1 & 0xFFF);

    // 5. `OVER_MAX_KIND0` is one past the active arch's kind=0 bound
    //    (`MAX_CPUID_POLICIES` on x86-64, `MAX_ID_REG_RESPONSES` on
    //    aarch64). entries = &.{} keeps the per-entry validation gate
    //    inert; reserved bits in [1] are clear by construction.
    const result = syscall.vmSetPolicy(vm_handle, 0, OVER_MAX_KIND0, &.{});

    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
