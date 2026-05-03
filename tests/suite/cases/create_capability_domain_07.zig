// Spec §[create_capability_domain] create_capability_domain — test 07.
//
// "[test 07] returns E_PERM if any field in `restart_policy_ceiling`
//  exceeds the caller's corresponding field."
//
// Strategy
//   `restart_policy_ceiling` lives in ceilings_outer ([3]) bits 16-31.
//   Within that 16-bit sub-field:
//     bits 0-1: ec_restart_max     (numeric: 0=kill / 1=restart / 2=persist / 3=_reserved)
//     bits 2-3: var_restart_max    (numeric: 0=free / 1=decommit / 2=preserve / 3=snapshot)
//     bit  4:   pf_restart_max     (drop / keep)
//     bit  5:   dr_restart_max     (drop / keep)
//     bit  6:   port_restart_max   (drop / keep)
//     bit  7:   vm_restart_max     (drop / keep)
//     bit  8:   idc_restart_max    (drop / keep)
//     bit  9:   tm_restart_max     (drop / keep)
//     bits 10-15: _reserved
//
//   The runner (runner/primary.zig) installs ceilings_outer
//   = 0x0000_003F_03FE_FFFF, so the test domain's restart_policy_ceiling
//   sub-field = 0x03FE — ec_restart_max=2, var_restart_max=3, all type
//   bools=1.
//
//   We construct a `ceilings_outer` whose `restart_policy_ceiling`
//   sub-field has `ec_restart_max = 3`, which exceeds the caller's 2.
//   Every other ceiling field in [3] is set within the caller's
//   bounds (or zeroed) so the kernel's only available reject reason
//   is the restart_policy_ceiling check.
//
//   Other arguments (caps, ceilings_inner, elf_page_frame,
//   passed_handles) are constructed to be valid in isolation: the
//   kernel can freely evaluate them without tripping a different
//   E_PERM/E_BADCAP path before reaching the restart_policy_ceiling
//   subset check. SPEC AMBIGUITY: the spec does not pin the order in
//   which create_capability_domain validates its arguments. The path
//   we exercise is the one dictated by all-other-args-valid, so any
//   valid kernel implementation that enforces test 07 must report
//   E_PERM here regardless of evaluation order.
//
// Action
//   1. create_capability_domain(self_caps subset, ceilings_inner valid,
//        ceilings_outer with rpc.ec_restart_max = 3, valid pf, no passed)
//      — must return E_PERM
//
// Assertions
//   1: createCapabilityDomain returned something other than E_PERM
//   (we don't separately gate on the page frame setup since
//    stage-failure here would surface as a different error code, not
//    E_PERM, and assertion 1 still flags it)

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Stage a minimal, valid page frame for [4]. Any single page is
    // fine — the kernel must reject on the restart_policy_ceiling
    // subset check before it ever parses the ELF, so the page frame
    // contents are immaterial. (If the kernel did parse first and
    // returned E_INVAL, assertion 1 would still flag the divergence.)
    const pf_caps = caps.PfCap{ .move = true, .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props.sz = 0 (4 KiB)
        1, // 1 page
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const pf_handle: u12 = @truncate(cpf.v1 & 0xFFF);

    // [1] caps: self_caps subset of the runner-installed self caps.
    // The runner grants the test crcd | crec | crvr | crpf | crvm |
    // crpt | pmu | fut_wake | timer | pri=3. Pick a strict subset.
    // idc_rx (bits 16-23) is left zero — runner installs idc_rx = 0
    // implicitly (the runner's [1] is just self_caps), so any nonzero
    // idc_rx in our call would also be a subset violation.
    const self_caps = caps.SelfCap{
        .crcd = true,
    };
    const v1_caps: u64 = @as(u64, self_caps.toU16());

    // [2] ceilings_inner: zero is always a subset of any caller
    // ceiling. Reserved bits stay zero — see test 17.
    const ceilings_inner: u64 = 0;

    // [3] ceilings_outer: build the violator. ec_outer_ceiling and
    // var_outer_ceiling (bits 0-15) are zeroed (subsets); fut_wait_max
    // (bits 32-37) is zero (subset of caller's 63). The
    // restart_policy_ceiling sub-field at bits 16-31 has
    // ec_restart_max = 3, which exceeds the caller's ec_restart_max =
    // 2 installed by the runner.
    //
    // restart_policy_ceiling sub-field encoding:
    //   bits 0-1: ec_restart_max = 0b11 (= 3)   -> exceeds caller's 2
    //   bits 2-3: var_restart_max = 0           -> subset
    //   bits 4-9: pf/dr/port/vm/idc/tm = 0      -> subsets
    //   bits 10-15: reserved = 0
    // = 0x0003
    const restart_policy_ceiling: u64 = 0x0003;
    const ceilings_outer: u64 = restart_policy_ceiling << 16;

    // No passed handles. The runner exposes a result port at slot 3
    // for the test's own use (testing.report), but we don't pass it
    // through to a child here — we never construct the child.
    const passed_handles: [0]u64 = .{};

    const result = syscall.createCapabilityDomain(v1_caps, ceilings_inner, ceilings_outer, pf_handle, 0, // initial_ec_affinity
        passed_handles[0..]);

    if (result.v1 != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}
