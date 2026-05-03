// Spec §[vm_set_policy] — test 06.
//
// "[test 06] on x86-64 with kind=1, the VM's `cr_policies` table is
//  replaced by the count entries; subsequent guest CR accesses match
//  against this table per §[vm_policy]."
//
// Spec semantics
//   §[vm_set_policy] x86-64 kind=1 replaces the VM's `cr_policies`
//   table. Per the per-arch entry layout (spec line 1650):
//     [2+3i+0] = {cr_num u8, _pad u8[7]}
//     [2+3i+1] = read_value u64
//     [2+3i+2] = write_mask u64
//   The syscall word's bit 12 carries `kind` (= 1 here) and bits 13-20
//   carry `count`. Per §[vm_policy] x86-64 the table holds up to
//   MAX_CR_POLICIES = 8 entries.
//
// Strategy
//   The full observable in the spec text — "subsequent guest CR accesses
//   match against this table per §[vm_policy]" — requires a vCPU
//   actually executing a guest CR read or write so the kernel's CR-exit
//   handler can match against the freshly installed table. That guest-
//   execution path is the same one create_vcpu_09 needs and which is
//   currently unimplemented in this suite (no test in tests/suite/tests
//   reaches guest-mode execution). The portion of the spec line that
//   *is* black-box-testable through the syscall ABI alone is the table-
//   replacement step — the kernel must accept a kind=1 vm_set_policy
//   with a valid CR policy table and return success. A failure on this
//   path means the table was never replaced, in which case the second
//   half of the spec line ("subsequent guest CR accesses match") is
//   trivially unobservable. We assert the success path here and leave
//   the guest-side match to a future test that runs a vCPU.
//
//   To isolate the success path every prior-numbered gate must be
//   defused so vm_set_policy actually returns OK:
//     - test 01 (E_BADCAP no valid VM):  we mint a real VM via
//                                        create_virtual_machine.
//     - test 02 (E_PERM no `policy`):    runner grants `crvm` and
//                                        vm_ceiling = 0x01 (the policy
//                                        bit), and we mint with caps =
//                                        {.policy = true}.
//     - test 03 (count > MAX_*):         count = 1 ≤ MAX_CR_POLICIES = 8.
//     - test 04 (reserved bits in [1] /
//                any entry):              [1] is the bare 12-bit handle
//                                         id; the CrPolicy entries set
//                                         only the documented fields
//                                         (cr_num at byte 0 of the
//                                         first vreg, read_value, and
//                                         write_mask). The spec layout
//                                         leaves bits 8-63 of the first
//                                         vreg as `_pad u8[7]` — we
//                                         keep them zero to avoid any
//                                         `_reserved` interpretation.
//
//   On x86-64 we choose cr_num = 0 (CR0) — a CR the guest will touch
//   in any realistic boot — and a read_value / write_mask combo that
//   names a non-zero policy: read_value = 0x0000_0000_8000_0011 (PE,
//   ET, PG bits — a typical post-paging CR0 silhouette), write_mask =
//   0xFFFF_FFFF_FFFF_FFFF (allow all writes). These specific bit
//   patterns are not asserted on by this test — it only checks that
//   the kernel accepts the table, not what guest semantics later
//   surface — but they keep the test legible if a future guest-side
//   observation is wired up.
//
// E_NODEV degradation
//   create_virtual_machine returns E_NODEV on platforms without
//   hardware virtualization. Without a VM handle there is no table to
//   replace and the spec assertion under test is unreachable. We
//   tolerate that outcome with a smoke pass, mirroring create_vcpu_05
//   / create_vcpu_10 / map_guest_05.
//
// Action
//   1. createPageFrame(caps={r,w}, props=0, pages=1) — backs VmPolicy.
//   2. createVar(caps={r,w}, cur_rwx=r|w, pages=1) + mapPf at offset 0.
//   3. Zero VM_POLICY_BYTES so num_cpuid_responses = num_cr_policies = 0
//      in the seed policy (well under both MAX_* bounds).
//   4. createVirtualMachine(caps={.policy=true}, policy_pf). Tolerates
//      E_NODEV (degraded smoke pass).
//   5. vmSetPolicy(vm_handle, kind=1, count=1, &.{
//          /* [2+3*0+0] cr_num u8 + pad u8[7] */ 0x00,
//          /* [2+3*0+1] read_value             */ 0x0000_0000_8000_0011,
//          /* [2+3*0+2] write_mask             */ 0xFFFF_FFFF_FFFF_FFFF,
//      })
//      must return OK.
//
// Assertions
//   1: setup — create_page_frame returned an error word.
//   2: setup — create_var returned an error word.
//   3: setup — map_pf returned non-OK in vreg 1.
//   4: setup — create_virtual_machine returned an unexpected error
//      (anything other than a valid handle or E_NODEV).
//   5: vm_set_policy with kind=1 and a valid 1-entry CR policy table
//      returned a value other than OK (the spec assertion under test
//      via the syscall-ABI observable).

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

    // 3. Zero the VmPolicy region. Volatile keeps ReleaseSmall from
    //    folding the stores against the kernel's read.
    const policy_dst: [*]volatile u8 = @ptrFromInt(policy_base);
    var i: usize = 0;
    while (i < VM_POLICY_BYTES) {
        policy_dst[i] = 0;
        i += 1;
    }

    // 4. Mint the VM. Runner grants `crvm` and vm_ceiling = 0x01 (the
    //    `policy` bit) so caps={.policy=true} stays subset and test 02
    //    (E_PERM no `policy`) cannot fire ahead of us.
    const vm_caps = caps.VmCap{ .policy = true };
    const cvm = syscall.createVirtualMachine(
        @as(u64, vm_caps.toU16()),
        policy_pf,
    );
    if (cvm.v1 == @intFromEnum(errors.Error.E_NODEV)) {
        // No hardware virtualization — table replacement is
        // unreachable through any construction. Smoke-pass.
        testing.pass();
        return;
    }
    if (testing.isHandleError(cvm.v1)) {
        testing.fail(4);
        return;
    }
    const vm_handle: HandleId = @truncate(cvm.v1 & 0xFFF);

    // 5. vm_set_policy with kind=1 and one CrPolicy entry.
    //    Per §[vm_set_policy] x86-64, the entry occupies vregs
    //    [2..4] (3 vregs) starting at vreg 2:
    //       vreg 2 = { cr_num u8, _pad u8[7] }
    //       vreg 3 = read_value u64
    //       vreg 4 = write_mask u64
    //    Bit-packing into u64s for the libz wrapper:
    //       entry[0] = cr_num at byte 0; pad bytes zeroed.
    //       entry[1] = read_value
    //       entry[2] = write_mask
    const cr_num: u64 = 0; // CR0
    const read_value: u64 = 0x0000_0000_8000_0011; // PE | ET | PG
    const write_mask: u64 = 0xFFFF_FFFF_FFFF_FFFF; // allow all writes
    const result = syscall.vmSetPolicy(
        vm_handle,
        1, // kind = 1 (cr_policies)
        1, // count = 1 entry
        &.{ cr_num, read_value, write_mask },
    );
    if (result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
