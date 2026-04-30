// Spec §[create_virtual_machine] — test 07.
//
// "[test 07] returns E_INVAL if `VmPolicy.num_cr_policies` exceeds
//  `MAX_CR_POLICIES`."
//
// Strategy
//   create_virtual_machine reads the VmPolicy struct from offset 0 of
//   the supplied page_frame. Per §[vm_policy] x86-64, the layout is:
//
//     offset   field
//     0..767   cpuid_responses[32]            (32 * 24 = 768 bytes)
//     768..771 num_cpuid_responses (u32)
//     772..775 _pad0 (u32)
//     776..967 cr_policies[8]                 (8 * 24 = 192 bytes)
//     968..971 num_cr_policies (u32)
//     972..975 _pad1 (u32)
//
//   MAX_CR_POLICIES = 8. The kernel must reject any policy whose
//   `num_cr_policies` exceeds the static array bound, since the field
//   selects how many entries the kernel reads on guest CR exits and an
//   out-of-range count would imply reading past the table. Spec line
//   1458 names that bound check explicitly with E_INVAL. The cpuid
//   table is unaffected here (its count stays 0, well under
//   MAX_CPUID_POLICIES = 32), so test 06 — the symmetric cpuid-table
//   overflow — does not fire ahead of this one.
//
//   Per §[vm_policy] aarch64, the equivalent of `num_cr_policies` is
//   `num_sysreg_policies`. The aarch64 layout is:
//
//     offset    field
//     0..991    id_reg_responses[62]              (62 * 16 = 992)
//     992..995  num_id_reg_responses (u32)
//     996..999  _pad0 (u32)
//     1000..1767 sysreg_policies[32]              (32 * 24 = 768)
//     1768..1771 num_sysreg_policies (u32)
//     1772..1775 _pad1 (u32)
//
//   MAX_SYSREG_POLICIES = 32. We branch on `builtin.cpu.arch` to plant
//   the overflowed count at the matching offset for the running arch.
//
//   Setup chain:
//     1. create_page_frame(caps={r,w}, props=0, pages=1) — backing
//        store for the VmPolicy struct. 4 KiB > 976 bytes.
//     2. create_var(caps={r,w}, props={cur_rwx=r|w}, pages=1) +
//        map_pf at offset 0 — gives us a CPU-visible window into the
//        page frame so we can plant the overflowed count.
//     3. Zero the VmPolicy region, then write num_cr_policies =
//        MAX_CR_POLICIES + 1 (= 9) at byte offset 968. The all-zero
//        base ensures every other field (cpuid table, num_cpuid, cr
//        table, pads) is in-range, so the only invariant violated is
//        the one under test.
//     4. create_virtual_machine(caps={policy=true}, policy_pf). The
//        runner provisions the test domain with `crvm` (per
//        runner/primary.zig) and `vm_ceiling` covering the `policy`
//        bit (bit 48 of ceilings_inner = 0x01), so the call cannot
//        short-circuit on E_PERM ahead of the VmPolicy validation.
//
//   The volatile pointer cast on the write is defensive: under
//   ReleaseSmall the optimizer is otherwise free to assume the user
//   buffer is uninitialized after the page_frame mint and to fold the
//   store away. Routing the store through a `*volatile u32` keeps the
//   bytes on the page frame the kernel will read.
//
// Assertions
//   1: setup — create_page_frame returned an error word
//   2: setup — create_var returned an error word
//   3: setup — map_pf returned non-OK in vreg 1
//   4: create_virtual_machine returned a value other than E_INVAL
//      (success path or any other error code is a spec violation —
//      the kernel must reject this exact policy with E_INVAL).

const builtin = @import("builtin");

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

// Per-arch §[vm_policy] table-overflow probe. The runner builds a
// single ELF that boots on whichever arch the kernel is built for, so
// the constants are picked at comptime against `builtin.cpu.arch`.
const overflow_field: PolicyOverflow = switch (builtin.cpu.arch) {
    .x86_64 => .{
        .vm_policy_bytes = 32 * 24 + 8 + 8 * 24 + 8, // 976
        .field_offset = 32 * 24 + 8 + 8 * 24, // 968 — num_cr_policies
        .max_value = 8, // MAX_CR_POLICIES
    },
    .aarch64 => .{
        .vm_policy_bytes = 62 * 16 + 8 + 32 * 24 + 8, // 1776
        .field_offset = 62 * 16 + 8 + 32 * 24, // 1768 — num_sysreg_policies
        .max_value = 32, // MAX_SYSREG_POLICIES
    },
    else => @compileError("create_virtual_machine_07 not configured for this arch"),
};

const PolicyOverflow = struct {
    vm_policy_bytes: usize,
    field_offset: usize,
    max_value: u32,
};

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

    // 2. VAR + map_pf so userspace can plant the policy bytes the
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

    // 3. Zero the VmPolicy region first, then plant the overflowed
    //    count. Volatile keeps ReleaseSmall from folding the store
    //    against the kernel's read.
    const policy_dst: [*]volatile u8 = @ptrFromInt(policy_base);
    var i: usize = 0;
    while (i < overflow_field.vm_policy_bytes) {
        policy_dst[i] = 0;
        i += 1;
    }
    const overflow_ptr: *volatile u32 = @ptrFromInt(policy_base + overflow_field.field_offset);
    overflow_ptr.* = overflow_field.max_value + 1; // one past the bound

    // 4. The runner grants `crvm` and ceilings_inner.vm_ceiling = 0x01
    //    (the `policy` bit) — so caps={.policy=true} stays subset of
    //    the ceiling, leaving E_INVAL on VmPolicy validation as the
    //    spec-mandated outcome ahead of any later checks.
    const vm_caps = caps.VmCap{ .policy = true };
    const cvm = syscall.createVirtualMachine(
        @as(u64, vm_caps.toU16()),
        policy_pf,
    );

    if (cvm.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(4);
        return;
    }

    testing.pass();
}
