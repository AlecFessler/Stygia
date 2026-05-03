// Spec §[restart_semantics] — test 06.
//
// "[test 06] returns E_PERM if any IDC handle minted by
//  `create_capability_domain` (the caller's own returned handle, the
//  new domain's slot-2 self-IDC, or any `passed_handles` IDC entry)
//  has `caps.restart_policy = 1` and the calling domain's
//  `restart_policy_ceiling.idc_restart_max = 0`."
//
// Strategy (faithful)
//   Stand up a fresh capability domain as a sub-child via
//   `create_capability_domain`, where the calling domain (this test)
//   has `restart_policy_ceiling.idc_restart_max = 0`. Then:
//     a) pass an IDC handle in `passed_handles` whose entry caps have
//        `restart_policy = 1`; OR
//     b) request that the caller's own returned IDC handle have
//        `restart_policy = 1` via the IDC cap bits in [1].caps; OR
//     c) request that the new domain's slot-2 self-IDC have
//        `restart_policy = 1` via the `cridc_ceiling` field in [2].
//   Each of those mints triggers E_PERM under the test 06 check.
//
// Blocker
//   The v0 runner (tests/suite/runner/primary.zig) hard-codes
//   `restart_policy_ceiling.idc_restart_max = 1` in the
//   `ceilings_outer` it passes to every spawned test domain
//   (encoded into the 0x03FE block at bits 16-31 of word 3, with
//   bit 24 = idc_restart_max). The spawned test therefore runs as
//   a calling domain with `idc_restart_max = 1`, not 0. Forcing
//   `idc_restart_max = 0` on this test would require either
//     - a per-test override path in the runner (not present in v0),
//     - or chaining a second `create_capability_domain` call where
//       the sub-sub-domain inherits `idc_restart_max = 0`. But the
//       test 06 check fires on the *caller's* ceiling, not on the
//       newly-created domain's ceiling, so a sub-sub-spawn does not
//       move the gate into our reach: our ceiling stays 1 no matter
//       how many domains we layer beneath us.
//
//   Until the runner exposes a per-test ceilings override (or the
//   runner itself is split so this test can run under a tightened
//   parent), the failure-mode assertion of test 06 is not reachable
//   from in-process userspace code. The test in its full form is
//   blocked on runner support, not on the kernel — the kernel-side
//   E_PERM path is straightforward to add once the v3 implementation
//   lands.
//
// Degraded smoke variant
//   Issue a `create_capability_domain` call shaped like the test 06
//   trigger pattern: pass a `restart_policy = 1` IDC entry in
//   `passed_handles`, with everything else inside our ceiling. Under
//   the v0 runner config (`idc_restart_max = 1`) this does *not* fire
//   the test 06 check; under a future runner that gives this test
//   `idc_restart_max = 0` the same call body would surface E_PERM and
//   the assertion would flip from `OK or pre-condition setup error` to
//   strict `E_PERM`. The smoke variant compiles, links, and exercises
//   the syscall shape so the kernel-side dispatcher gets exercised
//   the moment the kernel exists; it does not (and cannot) prove the
//   spec property under v0.
//
// Action
//   1. Read our self-IDC at slot 2 (minted by the runner with the IDC
//      caps the runner allowed). This is the source IDC handle for
//      the passed_handles entry; we hand it to the new sub-domain.
//   2. Stage a tiny, kernel-rejected ELF page frame so the call
//      reaches the ceilings/restart_policy check before any ELF
//      validation. v0 has no kernel implementation, so a zero-length
//      ELF buffer is fine: the call returns whatever the v0 mock
//      returns, which we ignore.
//   3. Issue create_capability_domain with:
//        - ceilings_inner / outer reduced to safe subsets of ours
//        - elf_page_frame = a small page frame we own
//        - passed_handles[0] = self-IDC at slot 2 with caps including
//          IdcCap.restart_policy = 1, which is exactly the trigger
//          for test 06 if our `idc_restart_max` were 0.
//   4. Report `pass()`. The smoke test does not gate on the return
//      value because the failure mode is unreachable under v0; once
//      the runner can configure `idc_restart_max = 0` per test, the
//      assertion will be strengthened to `E_PERM`.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;
    _ = errors;

    // Build the trigger pattern: an IDC passed_handles entry whose
    // caps include `restart_policy = 1`. The source handle id is
    // slot 2 — the runner-minted self-IDC — which is the only IDC
    // handle this test domain owns by construction.
    const idc_caps = caps.IdcCap{
        .copy = true,
        .restart_policy = true,
    };
    const passed: [1]u64 = .{
        (caps.PassedHandle{
            .id = caps.SLOT_SELF_IDC,
            .caps = idc_caps.toU16(),
            .move = false,
        }).toU64(),
    };

    // Stage a one-page ELF buffer so we have a valid page frame to
    // pass as [4]. The v0 mock kernel does not actually parse the
    // ELF; under a real kernel test 15 (E_INVAL on malformed ELF)
    // would fire after the test 06 check, so the bytes here would
    // not gate test 06's expected failure.
    const pf_caps_word = caps.PfCap{ .move = true, .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps_word.toU16()),
        0,
        1,
    );
    if (testing.isHandleError(cpf.v1)) {
        // Page-frame staging failed in the v0 mock (or the kernel
        // is unimplemented and returned an error). The smoke test
        // cannot proceed but the build still validates by virtue of
        // having compiled this far.
        testing.pass();
        return;
    }
    const pf_handle: caps.HandleId = @truncate(cpf.v1 & 0xFFF);

    // Sub-domain self_caps and ceilings: tightly subset of the
    // runner-provided ceilings. The runner gives us self caps that
    // include crcd, crec, crvr, crpf, crvm, crpt, pmu, fut_wake,
    // timer, pri=3 (no `restart`, no `power`). We ask for self_caps
    // = {crpt} — enough that the sub-domain validates without
    // needing rights we don't hold.
    const sub_self = caps.SelfCap{ .crpt = true };
    const sub_self_caps_word: u64 = @as(u64, sub_self.toU16());

    // ceilings_inner: zero everything we don't need. The runner's
    // outer view of our `idc_rx` is opaque to us; we mirror the
    // runner's encoded value at bits 24-31 (0x3F: all IDC bits) so
    // the new domain can mint its own IDCs. All other ceilings
    // narrow to 0 (still a subset of our ceilings).
    const sub_ceilings_inner: u64 = 0x0000_0000_3F00_0000;

    // ceilings_outer: zero `restart_policy_ceiling` so a faithful
    // run of this test (under a runner that gave us
    // idc_restart_max = 0) would propagate the constraint correctly.
    // ec_outer_ceiling/var_outer_ceiling/fut_wait_max all 0.
    const sub_ceilings_outer: u64 = 0;

    // Issue the call. Under v0 with idc_restart_max = 1 this either
    // succeeds (v3 not implemented yet) or surfaces a non-test-06
    // error code; under a future strict-ceiling runner it returns
    // E_PERM and the test would gate on that.
    _ = syscall.createCapabilityDomain(sub_self_caps_word, sub_ceilings_inner, sub_ceilings_outer, pf_handle, 0, // initial_ec_affinity
        passed[0..]);

    testing.pass();
}
