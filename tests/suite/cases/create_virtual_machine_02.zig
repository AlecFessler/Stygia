// Spec §[create_virtual_machine] create_virtual_machine — test 02.
//
// "[test 02] returns E_PERM if caps is not a subset of the caller's
//  `vm_ceiling`."
//
// Strategy
//   `vm_ceiling` is an 8-bit subfield of the calling domain's
//   self-handle field0. Per §[create_capability_domain]'s
//   ceilings_inner layout (which "matches self-handle field0") the
//   subfield occupies bits 40-47; only bit 0 (`policy`, at field0
//   bit 40) is defined within vm_ceiling, bits 1-7 of the subfield
//   are reserved. The runner (runner/primary.zig) installs the test
//   domain with vm_ceiling = 0x01, so every defined vm_ceiling bit
//   is already set in the caller.
//
//   (SPEC AMBIGUITY: §[capability_domain] field0 places vm_ceiling
//   at bits 48-55, but §[create_capability_domain] explicitly
//   declares its ceilings_inner argument layout — also at bits 40-47
//   for vm_ceiling — "matches self-handle field0". The runner and
//   create_capability_domain_11.zig both treat field0 as identical
//   to the ceilings_inner packing; this test follows that convention.)
//
//   `[1] caps` for create_virtual_machine carries a 16-bit VmCap word
//   in bits 0-15. VmCap defines bit 0 (`policy`) and bit 1
//   (`restart_policy`); bits 2-15 are reserved. The kernel's subset
//   check compares the caps requested against the caller's vm_ceiling.
//
//   To exercise test 02 faithfully we'd need a caps value that
//   contains a defined VmCap bit that maps to a vm_ceiling bit clear
//   in the caller. With vm_ceiling = 0x01 already setting the only
//   bit vm_ceiling defines (`policy`), a faithful E_PERM cannot be
//   distinguished from other failure modes:
//     - caps with bit 1 (`restart_policy`) set — gated by
//       restart_policy_ceiling.vm_restart_max per §[restart_semantics]
//       test 04, not by vm_ceiling, so this routes through the
//       restart-policy gate rather than the vm_ceiling subset rule.
//     - caps with bits 2-15 set — reserved bits trip
//       §[create_virtual_machine] test 08 (E_INVAL), not E_PERM.
//
// Degraded smoke
//   The task is permanently degraded under the current spec — there
//   is no value of `caps` that can route through the vm_ceiling
//   subset check rather than the reserved-bit check or the
//   restart-policy ceiling gate, given the runner grants the entire
//   defined vm_ceiling surface and the only other defined VmCap bit
//   has its own ceiling.
//
//   The test ships as a smoke variant: it issues a real
//   `create_virtual_machine` syscall with caps = 0x01 (`policy` only,
//   strictly a subset of vm_ceiling = 0x01) and a deliberately invalid
//   `policy_page_frame` handle (id 0 = self-handle, not a page frame).
//   Per spec test 04 this routes to E_BADCAP. Passing means the
//   syscall did NOT return E_PERM — the only thing this smoke can
//   distinguish about the subset rule.
//
//   If a future spec revision widens vm_ceiling beyond bit 0 (or the
//   runner narrows its installed vm_ceiling so a defined vm_ceiling
//   bit is clear in the caller), the test self-promotes to a faithful
//   probe — see runFaithfulProbe below, which mirrors
//   create_capability_domain_11.zig.
//
// Action (smoke)
//   1. createVirtualMachine(caps = 0x01, policy_pf = 0)
//      — must NOT return E_PERM (spec test 04 routes this to
//      E_BADCAP).
//
// Assertions
//   1: createVirtualMachine returned E_PERM (no superset constructed,
//      so this would indicate a kernel that gates vm_ceiling on a
//      bit the smoke deliberately keeps inside the ceiling).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Bitmask of currently-defined bits inside the 8-bit vm_ceiling
// subfield. Per §[capability_domain] only bit 0 (`policy`) is defined
// in vm_ceiling; bits 1-7 are reserved.
const VM_CEILING_DEFINED: u8 = 0x01;

pub fn main(cap_table_base: u64) void {
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    // vm_ceiling lives at field0 bits 40-47 (see file header on the
    // ceilings_inner / field0 layout convention).
    const caller_vm_ceiling: u8 = @truncate((self_cap.field0 >> 40) & 0xFF);

    // If a future spec widens vm_ceiling so a defined vm_ceiling bit
    // is clear in the caller, build a faithful superset probe and
    // assert E_PERM. See the trailing block.
    const undefined_clear_in_caller: u8 =
        (~caller_vm_ceiling) & VM_CEILING_DEFINED;
    if (undefined_clear_in_caller != 0) {
        runFaithfulProbe(caller_vm_ceiling, undefined_clear_in_caller);
        return;
    }

    // Degraded-smoke path: every defined vm_ceiling bit is already
    // set in the caller, so we cannot construct a caps value that
    // routes through the vm_ceiling subset check rather than another
    // failure mode. Issue a syscall with caps = 0x01 (a strict subset
    // of the caller's vm_ceiling, never E_PERM on this rule) and
    // policy_pf = 0 (invalid page-frame handle by design — slot 0 is
    // the self-handle, not a page frame). Per spec test 04 the kernel
    // must surface E_BADCAP — anything except E_PERM is acceptable.
    const vm_caps = caps.VmCap{ .policy = true };
    const caps_word: u64 = @as(u64, vm_caps.toU16());

    const result = syscall.createVirtualMachine(caps_word, 0);

    if (result.v1 == @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}

// Future-spec faithful probe. Reachable only if a later spec defines
// additional vm_ceiling bits (or the runner narrows its installed
// vm_ceiling) so a defined vm_ceiling bit is clear in the caller.
// Mirrors create_capability_domain_11.zig.
fn runFaithfulProbe(
    caller_vm_ceiling: u8,
    undefined_clear_in_caller: u8,
) void {
    // Find the lowest defined vm_ceiling bit clear in
    // caller_vm_ceiling and set it in caps to construct a strict
    // superset. The corresponding VmCap bit lives at the same
    // bit position, since vm_ceiling and VmCap share their `policy`
    // bit at position 0.
    var extra_bit: u8 = 0;
    var i: u3 = 0;
    while (true) {
        const mask: u8 = @as(u8, 1) << i;
        if ((undefined_clear_in_caller & mask) != 0) {
            extra_bit = mask;
            break;
        }
        if (i == 7) break;
        i += 1;
    }
    const new_caps: u8 = caller_vm_ceiling | extra_bit;

    // Mint a 4 KiB page frame so [2] is a valid handle and the kernel
    // must surface E_PERM from the vm_ceiling subset check before
    // reaching the policy_page_frame validation path.
    const pf_caps = caps.PfCap{ .move = true, .r = true, .w = true };
    const cpf = syscall.createPageFrame(@as(u64, pf_caps.toU16()), 0, 1);
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const pf_handle: caps.HandleId = @truncate(cpf.v1 & 0xFFF);

    const caps_word: u64 = @as(u64, new_caps);
    const result = syscall.createVirtualMachine(caps_word, pf_handle);

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
