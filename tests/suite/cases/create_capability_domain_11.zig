// Spec §[create_capability_domain] create_capability_domain — test 11.
//
// "[test 11] returns E_PERM if `vm_ceiling` is not a subset of the
//  caller's `vm_ceiling`."
//
// Strategy
//   `vm_ceiling` is an 8-bit subfield (bits 40-47) of `ceilings_inner`
//   (field0) per §[capability_domain]. Within that subfield only bit 0
//   (`policy`) is defined; bits 1-7 are reserved. The runner
//   (runner/primary.zig) installs the test domain with vm_ceiling =
//   0x01 — every defined bit is already set in the caller.
//
//   The subset check is bitwise. To exercise test 11 we'd need a
//   value v with `(v & ~caller_vm_ceiling) != 0` and v containing only
//   defined bits. With the caller's vm_ceiling = 0x01 and only bit 0
//   defined, no such v exists: any superset bit lands in a reserved
//   slot, which §[create_capability_domain] test 17 routes to E_INVAL,
//   not E_PERM.
//
// Degraded smoke
//   The task is permanently degraded under the current spec — there
//   is no superset value of vm_ceiling that can route through the
//   subset check rather than the reserved-bit check, given the runner
//   grants the entire defined surface. The test ships as a smoke
//   variant: it issues a real `create_capability_domain` syscall via
//   `issueReg` with `vm_ceiling = 0x01` (subset) and `elf_pf = 0`
//   (deliberately invalid handle) so the call exercises the syscall
//   linkage and argument-encoding paths without depending on a real
//   page frame. The kernel will surface a non-E_PERM error on the
//   `elf_pf` handle check (test 13: E_BADCAP). Passing means the
//   syscall did NOT return E_PERM — the only thing this smoke can
//   distinguish about the subset rule.
//
//   If a future spec revision widens vm_ceiling beyond bit 0 (or the
//   runner narrows its installed vm_ceiling), this test should be
//   rewritten to construct a real superset and assert E_PERM, mirroring
//   create_capability_domain_06.zig — a worked example in the second
//   half of this file shows the shape such a rewrite would take.
//
// Action
//   1. issueReg(create_capability_domain, vm_ceiling=0x01, elf_pf=0)
//      — must NOT return E_PERM (it returns E_BADCAP under test 13).
//
// Assertions
//   1: createCapabilityDomain returned E_PERM (no superset constructed,
//      so this would indicate a kernel that gates on something
//      orthogonal to the subset rule we cannot exercise).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Bitmask of currently-defined bits inside the 8-bit vm_ceiling
// subfield. Per §[create_capability_domain] only bit 0 (`policy`) is
// defined; bits 1-7 are reserved and routed to test 17.
const VM_CEILING_DEFINED: u8 = 0x01;

pub fn main(cap_table_base: u64) void {
    const self_cap = caps.readCap(cap_table_base, caps.SLOT_SELF);
    const caller_vm_ceiling: u8 = @truncate((self_cap.field0 >> 40) & 0xFF);

    // If a future spec widens vm_ceiling, build a faithful superset
    // probe and assert E_PERM. See the trailing block.
    const undefined_clear_in_caller: u8 =
        (~caller_vm_ceiling) & VM_CEILING_DEFINED;
    if (undefined_clear_in_caller != 0) {
        runFaithfulProbe(caller_vm_ceiling, undefined_clear_in_caller);
        return;
    }

    // Degraded-smoke path: no defined bit is clear in the caller, so
    // we cannot construct a superset that avoids the reserved-bit
    // check. Issue a syscall with vm_ceiling = 0x01 (a strict subset
    // of the caller, never E_PERM on this rule) and elf_pf = 0
    // (invalid handle) so the smoke probe links and loads cleanly
    // without minting a real page frame. Per spec test 13 the kernel
    // must surface E_BADCAP for elf_pf=0 — anything except E_PERM is
    // an acceptable outcome here.
    const vm_ceiling_subset: u64 = 0x01;
    const ceilings_inner: u64 =
        (0x001C_011F_3F01_FFFF & ~(@as(u64, 0xFF) << 40)) |
        (vm_ceiling_subset << 40);
    const ceilings_outer: u64 = 0x0000_003F_03FE_FFFF;

    const result = syscall.createCapabilityDomain(
        0, // [1] caps
        ceilings_inner, // [2]
        ceilings_outer, // [3]
        0, // [4] elf_pf — invalid by design
        0, // [5] initial_ec_affinity
        &[_]u64{}, // [6+] no passed handles
    );

    if (result.v1 == @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}

// Future-spec faithful probe. Reachable only if a later spec defines
// additional vm_ceiling bits and the caller's vm_ceiling lacks at
// least one of them. Mirrors create_capability_domain_06.zig.
fn runFaithfulProbe(
    caller_vm_ceiling: u8,
    undefined_clear_in_caller: u8,
) void {
    // Find the lowest defined bit clear in caller_vm_ceiling and set
    // it to construct a strict superset.
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
    const new_vm_ceiling: u8 = caller_vm_ceiling | extra_bit;

    // Mint a 4 KiB page frame so [4] is a valid handle and the kernel
    // must surface E_PERM from the ceiling check before reaching ELF
    // parsing.
    const pf_caps = caps.PfCap{ .move = true, .r = true, .w = true };
    const cpf = syscall.createPageFrame(@as(u64, pf_caps.toU16()), 0, 1);
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const pf_handle: caps.HandleId = @truncate(cpf.v1 & 0xFFF);

    const template_inner: u64 = 0x001C_011F_3F01_FFFF;
    const ceilings_inner: u64 =
        (template_inner & ~(@as(u64, 0xFF) << 40)) |
        (@as(u64, new_vm_ceiling) << 40);
    const ceilings_outer: u64 = 0x0000_003F_03FE_FFFF;

    const result = syscall.createCapabilityDomain(0, ceilings_inner, ceilings_outer, pf_handle, 0, // initial_ec_affinity
        &[_]u64{});

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
