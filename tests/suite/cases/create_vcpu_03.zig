// Spec §[create_vcpu] — test 03.
//
// "[test 03] returns E_PERM if priority exceeds the caller's priority
//  ceiling."
//
// Spec semantics
//   §[capability_domain] places the priority ceiling in the SelfCap
//   `pri` field (bits 14-15 of the SelfCap word). §[create_vcpu] caps
//   word bits 32-33 carry the requested priority for the new vCPU EC,
//   "0-3, bounded by caller's priority ceiling". The kernel must
//   short-circuit to E_PERM when the requested priority exceeds the
//   caller's ceiling.
//
// Strategy
//   The runner mints each child capability domain with `pri = 3` (max),
//   so an in-bounds 0..3 priority on its own cannot exceed the ceiling.
//   We first lower our self-handle's ceiling via `restrict`; bitwise
//   subset semantics (§[capabilities] restrict, "Most cap fields use
//   bitwise subset semantics") accept reducing pri = 3 (0b11) to pri = 1
//   (0b01) since 0b01 is a strict subset of 0b11. We keep `crec` and
//   `crvm`/`crpf`/`crvr`/`crpt` set so the test 01 (`crec`) check and
//   the VM/port-frame setup steps below succeed, leaving the priority
//   comparison as the only spec-mandated failure path on the final
//   create_vcpu call.
//
//   With ceiling = 1 we then construct a minimal but spec-valid set of
//   inputs to create_vcpu so the only error gate that fires is test 03:
//
//     - [2] vm_handle: a freshly created VM. Defuses test 04 (E_BADCAP).
//     - [4] exit_port: a freshly minted port with `bind` cap. Defuses
//       test 05 (E_BADCAP).
//     - [3] affinity = 0: spec-defined "any core". Defuses test 06.
//     - [1] caps low bits = 0 (no caps requested on the EC handle); the
//       runner grants `ec_inner_ceiling = 0xFF`, so 0 is a subset.
//       Defuses test 02. Reserved bits 34-63 = 0 defuses test 07.
//     - [1] priority = 2, encoded in bits 32-33. priority = 2 (numeric)
//       exceeds ceiling = 1 — the spec text says "exceeds", a numeric
//       comparison rather than a bitwise subset check.
//
//   With every other gate cleared, the priority-ceiling check from
//   test 03 is the only error path the kernel can take, and the
//   syscall must return E_PERM.
//
// VM policy buffer
//   create_virtual_machine takes a `policy_page_frame` whose first
//   bytes are a VmPolicy struct. An all-zero buffer is a valid policy
//   (zero counts ⇒ kernel scans no entries). We mint a page frame,
//   map it via a temporary VAR, zero VM_POLICY_BYTES, and pass the
//   frame in. This mirrors acquire_ecs_07's setup.
//
// Action
//   1. restrict(SLOT_SELF, SelfCap{crec, crvm, crvr, crpf, crpt, pri=1})
//      — must succeed (bitwise subset of runner-minted caps).
//   2. mint policy page frame, VAR, zero policy bytes — setup.
//   3. create_virtual_machine(caps=0, policy_pf) — must succeed.
//   4. create_port(caps={bind}) — must succeed.
//   5. create_vcpu(caps = priority<<32 with priority=2,
//                  vm_handle, affinity=0, exit_port)
//      — must return E_PERM.
//
// Assertions
//   1: restrict on the self-handle returned non-OK
//   2: setup — create_page_frame returned an error word
//   3: setup — create_var returned an error word
//   4: setup — map_pf returned non-success in vreg 1
//   5: setup — create_virtual_machine returned an error word
//   6: setup — create_port returned an error word
//   7: create_vcpu returned something other than E_PERM

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

// §[vm_policy] x86-64 layout: 32 CpuidPolicy entries (24 B each) +
// num_cpuid_responses (u32) + pad (u32) + 8 CrPolicy entries (24 B
// each) + num_cr_policies (u32) + pad (u32). All-zero is a valid
// policy (zero counts ⇒ kernel scans no entries on guest exits).
const VM_POLICY_BYTES: usize = 32 * 24 + 8 + 8 * 24 + 8;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // 1. Lower the priority ceiling from 3 (runner default) to 1.
    //    Keep `crec` (test 01 gate) and the creation bits we need for
    //    setup steps below. Bitwise subset semantics: pri = 0b01 is a
    //    strict subset of pri = 0b11.
    const restricted_self = caps.SelfCap{
        .crec = true,
        .crvm = true,
        .crvr = true,
        .crpf = true,
        .crpt = true,
        .pri = 1,
    };
    const restrict_result = syscall.restrict(
        caps.SLOT_SELF,
        @as(u64, restricted_self.toU16()),
    );
    if (restrict_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(1);
        return;
    }

    // 2. Page frame backing the VmPolicy struct.
    const policy_pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, policy_pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB), restart_policy = 0
        1,
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(2);
        return;
    }
    const policy_pf: HandleId = @truncate(cpf.v1 & 0xFFF);

    const policy_var_caps = caps.VarCap{ .r = true, .w = true };
    const cvar = syscall.createVar(
        @as(u64, policy_var_caps.toU16()),
        0b011, // cur_rwx = r|w
        1,
        0, // preferred_base = kernel chooses
        0, // device_region = none
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(3);
        return;
    }
    const policy_var: HandleId = @truncate(cvar.v1 & 0xFFF);
    const policy_base: u64 = cvar.v2;

    const map_result = syscall.mapPf(policy_var, &.{ 0, policy_pf });
    if (map_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }

    // Zero the policy buffer so num_cpuid_responses = 0 and
    // num_cr_policies = 0 fall out, satisfying the size and bound
    // checks performed by create_virtual_machine. Volatile keeps
    // ReleaseSmall from folding the store against the kernel's read
    // of the policy page during create_virtual_machine.
    const policy_dst: [*]volatile u8 = @ptrFromInt(policy_base);
    var i: usize = 0;
    while (i < VM_POLICY_BYTES) {
        policy_dst[i] = 0;
        i += 1;
    }

    // 3. Create the VM. caps = 0 keeps the VM handle's caps within
    //    `vm_ceiling` regardless of the domain's vm_ceiling field, so
    //    test 02 (E_PERM caps not subset) cannot fire.
    const cvm = syscall.createVirtualMachine(0, policy_pf);
    if (testing.isHandleError(cvm.v1)) {
        testing.fail(5);
        return;
    }
    const vm_handle: HandleId = @truncate(cvm.v1 & 0xFFF);

    // 4. Mint the exit port. `bind` cap is required for the port to be
    //    usable as the destination of create_vcpu's vm_exit deliveries.
    const exit_port_caps = caps.PortCap{ .bind = true };
    const cp = syscall.createPort(@as(u64, exit_port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(6);
        return;
    }
    const exit_port: HandleId = @truncate(cp.v1 & 0xFFF);

    // 5. §[create_vcpu] caps word layout:
    //      bits  0-15: caps           (0 — subset of any inner ceiling)
    //      bits 32-33: priority       (2 — exceeds ceiling = 1)
    //      bits 34-63: _reserved      (0)
    //
    //    priority = 2 numerically exceeds the ceiling = 1 we just set.
    //    The spec text "exceeds" is a numeric comparison; bitwise
    //    subset semantics that govern restrict do not apply here.
    const priority: u64 = 2;
    const caps_word: u64 = priority << 32;

    const result = syscall.createVcpu(
        caps_word,
        vm_handle,
        0, // affinity = 0 (any core) — defuses test 06
        exit_port,
    );

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(7);
        return;
    }

    testing.pass();
}
