// Spec §[create_virtual_machine] — test 05.
//
// "[test 05] returns E_INVAL if `policy_page_frame` is smaller than
//  `sizeof(VmPolicy)`."
//
// Strategy
//   `create_virtual_machine` is documented in §[create_virtual_machine]
//   as taking a `policy_page_frame` whose first bytes form a `VmPolicy`
//   struct (§[vm_policy]). If the frame is smaller than that struct,
//   the kernel cannot read the policy without reading past end-of-frame
//   and must reject with E_INVAL.
//
//   To trip the size check we want the smallest possible page frame
//   that is still a *valid* page frame handle (so test 04's E_BADCAP
//   path doesn't fire ahead of test 05). §[create_page_frame] test 04
//   forbids `pages = 0`, and §[page_frame] field0 says `sz = 0` is the
//   smallest page size at 4 KiB, so the smallest valid frame is exactly
//   one 4 KiB page = 4096 bytes.
//
// SPEC AMBIGUITY — degraded test, assertion is unreachable today
//   `sizeof(VmPolicy)` per §[vm_policy] for x86-64 evaluates to:
//     CpuidPolicy (24 B) * MAX_CPUID_POLICIES (32) = 768 B
//     num_cpuid_responses (4 B) + _pad0 (4 B)      =   8 B
//     CrPolicy (24 B) * MAX_CR_POLICIES (8)        = 192 B
//     num_cr_policies (4 B) + _pad1 (4 B)          =   8 B
//     -------------------------------------------- = 976 B
//   For aarch64:
//     IdRegResponse (16 B) * MAX_ID_REG_RESPONSES (62) = 992 B
//     num_id_reg_responses (4 B) + _pad0 (4 B)         =   8 B
//     SysregPolicy (24 B) * MAX_SYSREG_POLICIES (32)   = 768 B
//     num_sysreg_policies (4 B) + _pad1 (4 B)          =   8 B
//     ------------------------------------------------ = 1776 B
//   Both totals fit comfortably inside a single 4 KiB page. The
//   smallest valid page frame the spec lets us create (1 page, sz=0)
//   is therefore *larger* than `sizeof(VmPolicy)`, and there is no
//   spec-conformant way to construct an undersized `policy_page_frame`.
//
//   This test is preserved as a tripwire: if a future spec revision
//   either grows VmPolicy beyond 4 KiB or introduces a sub-4-KiB page
//   class, the assertion below becomes faithfully reachable and this
//   stub will need updating to feed the now-undersized frame. Until
//   then the test exercises the syscall path end-to-end and checks
//   that the kernel does *not* return E_INVAL via the size clause for
//   an oversized frame — a crude but useful guard against an inverted
//   comparison in the kernel's policy-size check.
//
//   On the v0 kernel (which doesn't yet implement
//   create_virtual_machine end-to-end) the call will surface E_NODEV
//   (test 03), E_INVAL via some other clause, or a different error.
//   The only outcome this test treats as a hard failure is a non-zero,
//   non-OK return that *equals* E_INVAL — because if E_INVAL fires on
//   a 4 KiB frame, the only spec-listed source of E_INVAL on this call
//   that depends on the page frame's *size* is test 05, and that path
//   should be unreachable here. (Tests 06/07/08 are E_INVAL too, but
//   they depend on the policy contents and the [1] caps word, which
//   we control to defuse them — see below.)
//
// Defusing other create_virtual_machine error paths
//   - test 01 (E_PERM no `crvm`): runner spawns the child with `crvm`
//     in `child_self` (see runner/primary.zig spawnOne), so this
//     test's caller has it.
//   - test 02 (E_PERM caps not subset of vm_ceiling): runner grants
//     the child `vm_ceiling = 0x01` (policy bit only). We pass [1]
//     caps = 0, a subset of any ceiling.
//   - test 03 (E_NODEV no hardware virtualization): out of test
//     control; tolerated as a non-failure outcome (see above).
//   - test 04 (E_BADCAP not a valid page frame): we pass a freshly
//     minted page frame.
//   - test 06/07 (E_INVAL num_*_responses exceeds MAX_*): page frame
//     comes back zero-filled by the kernel, so all num_* fields read
//     0, well under their max bounds.
//   - test 08 (E_INVAL reserved bits in [1]): we pass [1] = 0.
//
// Action
//   1. create_page_frame(caps={r,w,move}, props=0, pages=1)
//        — smallest valid frame, sz = 0 (4 KiB), 1 page.
//   2. create_virtual_machine(caps = 0, policy_pf = pf)
//        — exercise the syscall.
//   3. assert vreg 1 != E_INVAL
//        (DEGRADED: assertion is currently unreachable in either
//        direction; we check that E_INVAL is NOT returned on an
//        oversized frame, which is the contrapositive of test 05.
//        On a working kernel and oversized frame the call either
//        succeeds or returns one of the other listed errors — none
//        of which is E_INVAL, so this passes. On a v0 stub kernel
//        any non-E_INVAL return likewise passes.)
//
// Assertions
//   1: create_page_frame returned an error word
//   2: create_virtual_machine returned E_INVAL on an oversized
//      policy frame (i.e. the size-check inequality is inverted, or
//      the policy is being read but the kernel mis-bounds the read)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1 — smallest valid page frame: 1 page of 4 KiB = 4096 B.
    // r|w included so a future revision of this test that needs to
    // populate the frame doesn't have to re-mint; move is set so any
    // future xfer path (e.g. a full create_vcpu flow) doesn't trip an
    // unrelated cap check. Setting these does not affect the size
    // comparison we exercise here.
    const pf_caps = caps.PfCap{ .move = true, .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props: sz = 0 (4 KiB), restart_policy = 0
        1, // pages
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const pf_handle: u12 = @truncate(cpf.v1 & 0xFFF);

    // Step 2 — issue create_virtual_machine. [1] caps = 0 to dodge
    // test 02 (subset of vm_ceiling) and test 08 (reserved bits clean).
    const result = syscall.createVirtualMachine(0, pf_handle);

    // Step 3 — the spec-listed E_INVAL-from-size path (test 05) must
    // not fire on an oversized frame. Any other outcome (OK, E_NODEV,
    // E_FULL, E_NOMEM, ...) is acceptable for this degraded check.
    if (result.v1 == @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}
