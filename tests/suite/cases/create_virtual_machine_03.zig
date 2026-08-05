// Spec §[create_virtual_machine] — test 03.
//
// "[test 03] returns E_NODEV if the platform does not support hardware
//  virtualization."
//
// Runner contract
//   This test has meaningful behaviour in both halves of the matrix:
//     - no-HV: assert the spec's exact E_NODEV result.
//     - HV-present: assert the syscall does not incorrectly surface
//       E_NODEV when virtualization is available.
//
//   The no-HV half is the bead-closing proof. In the precommit matrix,
//   that is Pi-hosted aarch64 QEMU/KVM, which does not expose nested
//   EL2 to Stygia, so `vmSupported()` is false and create_virtual_machine
//   must return E_NODEV. HV-present runs (x86 KVM, bare-metal Pi tryboot,
//   and aarch64 TCG with `virtualization=on`) preserve positive coverage
//   but are not sufficient evidence for test 03 by themselves.
//
// Strategy
//   `info_system` reports the kernel's platform feature mask in vreg 2;
//   §[system_info] defines bit 0 as hardware virtualization support.
//   Issue create_virtual_machine with a valid, zeroed VmPolicy page
//   frame and caps = 0 so that E_BADCAP, E_INVAL, and E_PERM paths are
//   not intentionally triggered ahead of the E_NODEV path under test.
//
//   On no-HV pass, the test reports assertion_id = 8 (the numeric E_NODEV
//   value) instead of the usual zero. Normal summaries still print PASS,
//   while the focused Pi KVM `-Drunner_diag=true` boot emits
//   `code=1 aid=8`, giving serial-log evidence that the exact E_NODEV
//   return was observed. HV-present passes keep assertion_id = 0.
//
// Assertions
//   1: setup — create_page_frame returned an error word.
//   2: setup — create_vmar returned an error word.
//   3: setup — map_pf returned non-OK in vreg 1.
//   4: info_system reports no hardware virtualization, but
//      create_virtual_machine did not return E_NODEV.
//   5: info_system reports hardware virtualization, but
//      create_virtual_machine returned E_NODEV.

const builtin = @import("builtin");

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;
const E_NODEV = @intFromEnum(errors.Error.E_NODEV);
const OK = @intFromEnum(errors.Error.OK);

// §[vm_policy] per-arch policy struct sizes. The page frame is expected
// to be zero-filled by the kernel, but explicitly clearing the full
// policy footprint keeps the test independent of allocator state.
const VM_POLICY_BYTES: usize = switch (builtin.cpu.arch) {
    .x86_64 => 32 * 24 + 8 + 8 * 24 + 8, // 976
    .aarch64 => 62 * 16 + 8 + 32 * 24 + 8, // 1776
    else => @compileError("create_virtual_machine_03 not configured for this arch"),
};

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const system_info = syscall.infoSystem();
    const hardware_virtualization_supported = (system_info.v2 & 1) != 0;

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

    const policy_var_caps = caps.VmarCap{ .r = true, .w = true };
    const cvar = syscall.createVmar(
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
    if (map_result.v1 != OK) {
        testing.fail(3);
        return;
    }

    const policy_dst: [*]volatile u8 = @ptrFromInt(policy_base);
    var i: usize = 0;
    while (i < VM_POLICY_BYTES) {
        policy_dst[i] = 0;
        i += 1;
    }

    const result = syscall.createVirtualMachine(0, policy_pf);

    if (!hardware_virtualization_supported) {
        if (result.v1 != E_NODEV) {
            testing.fail(4);
            return;
        }
        testing.report(testing.PASS_CODE, E_NODEV);
        return;
    } else {
        if (result.v1 == E_NODEV) {
            testing.fail(5);
            return;
        }
    }

    testing.pass();
}
