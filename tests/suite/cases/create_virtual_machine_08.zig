// Spec §[create_virtual_machine] — test 08.
//
// "[test 08] returns E_INVAL if any reserved bits are set in [1]."
//
// Strategy
//   §[create_virtual_machine] pins the layout of [1] explicitly:
//     [1] caps:  bits  0-15 = caps; bits 16-63 = _reserved.
//   Setting any bit in the reserved range must surface E_INVAL at the
//   syscall ABI layer regardless of whether the rest of the call would
//   otherwise have succeeded (§[syscall_abi]).
//
//   To isolate the reserved-bit check we make every other
//   create_virtual_machine prelude check pass — same shape as
//   create_virtual_machine_05 — and then dial in a single reserved bit
//   on top of an otherwise-valid caps word. We use bit 63 of [1] (the
//   top of the 48-bit reserved range) which sits well above the 16-bit
//   live `caps` field and cannot be mistaken for a real cap that the
//   kernel would reject for a different reason.
//
//   Defusing other create_virtual_machine error paths
//     - test 01 (E_PERM no `crvm`): runner spawns the child with `crvm`
//       in `child_self` (see runner/primary.zig spawnOne).
//     - test 02 (E_PERM caps not subset of vm_ceiling): runner grants
//       the child `vm_ceiling = 0x01` (policy bit only). We keep the
//       low 16 bits of [1] = 0, a subset of any ceiling, so only the
//       reserved bit is non-zero.
//     - test 03 (E_NODEV no hardware virtualization): out of test
//       control; if the platform reports E_NODEV ahead of the reserved-
//       bit check, this test cannot distinguish kernels and would
//       legitimately fail. The reserved-bit check is an ABI-layer
//       concern and per §[syscall_abi] applies "regardless of whether
//       the rest of the call would otherwise have succeeded", so the
//       expected ordering is reserved-bits before E_NODEV.
//     - test 04 (E_BADCAP not a valid page frame): we pass a freshly
//       minted page frame.
//     - test 05 (E_INVAL undersized policy_page_frame): smallest valid
//       page frame is 1 page = 4096 B > sizeof(VmPolicy) on both archs.
//     - test 06/07 (E_INVAL num_*_responses exceeds MAX_*): page frame
//       comes back zero-filled by the kernel, so all num_* fields read
//       0, well under their max bounds.
//
//   The libz `syscall.createVirtualMachine` wrapper takes a u64 for
//   caps so it does not strip upper bits, but we still bypass it via
//   `syscall.issueReg` to mirror the create_var_17 reference pattern
//   and keep the call shape explicit at the ABI layer.
//
// Action
//   1. create_page_frame(caps={r,w}, props=0, pages=1) — smallest
//      valid frame the spec lets us mint, ensures test 04/05 are
//      defused.
//   2. createVirtualMachine via issueReg with [1] = (1 << 63), [2] =
//      pf_handle — must return E_INVAL.
//
// Assertions
//   1: setup — create_page_frame returned an error word
//   2: reserved bit set in [1] did not return E_INVAL.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // 1. Smallest valid page frame: 1 page of 4 KiB = 4096 B (> 976 B
    //    sizeof(VmPolicy) on x86-64; > 1776 B on aarch64). r|w included
    //    so the kernel can read the policy bytes back without an
    //    unrelated permission check tripping ahead of the reserved-bit
    //    check.
    const pf_caps = caps.PfCap{ .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB), restart_policy = 0
        1, // pages
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const pf_handle: HandleId = @truncate(cpf.v1 & 0xFFF);

    // 2. Issue create_virtual_machine with bit 63 of [1] set — sits in
    //    the bits 16-63 _reserved range of the caps word. Low 16 bits
    //    are 0 so caps is a subset of any vm_ceiling and test 02 cannot
    //    fire ahead of the reserved-bit check.
    const caps_with_reserved: u64 = @as(u64, 1) << 63;
    const r = syscall.issueReg(.create_virtual_machine, 0, .{
        .v1 = caps_with_reserved,
        .v2 = pf_handle,
    });
    if (r.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
