// Spec §[capability_domain] self_handle — test 01.
//
// "[test 01] when a domain receives an IDC handle over IDC, the
//  installed handle's caps = intersection of the granted caps and the
//  receiver's `idc_rx`."
//
// Spec semantics
//   §[idc_rx]: each capability domain carries an `idc_rx` mask in its
//   self-handle field0 (bits 32-39). When that domain receives an IDC
//   handle as a handle attachment over IDC (via suspend/recv or
//   reply_transfer per §[handle_attachments]), the kernel installs the
//   handle with caps = the entry's granted caps ANDed with the
//   receiver's `idc_rx`. This is how a domain bounds the privileges of
//   any IDC handle reaching it from outside, regardless of what the
//   sender attempted to grant.
//
// Faithful variant (deferred — needs cross-domain IDC plumbing)
//   The spec-faithful test requires two distinct capability domains
//   communicating over IDC:
//     1. Receiver R is created with a known `idc_rx` mask M (e.g.,
//        IdcCap{ .copy = true, .crec = true } — `aqec` cleared).
//     2. Sender S holds an IDC handle to R with caps a strict superset
//        of M (e.g., {copy, crec, aqec}).
//     3. S calls `suspend` on a port bound to R, attaching an IDC
//        handle entry whose caps include `aqec`.
//     4. R calls `recv`, dequeues the suspension, and the kernel
//        installs the IDC handle into R's table per §[handle_attachments].
//     5. R reads the installed slot and asserts caps == granted ∩ M
//        — specifically, that `aqec` is cleared because M cleared it.
//
//   This needs (a) a way to spawn a child capability domain from a
//   test ELF (currently each test is itself a single capability
//   domain, with no path to embed and stage a second ELF as a child),
//   and (b) the cross-domain suspend/recv handle-attachment path
//   wired through libz (the IDC pair-entry layout lives at high vregs
//   per §[handle_attachments] and the libz `suspendEc` wrapper still
//   panics on attachments != 0). Both are tracked elsewhere; the same
//   gap blocks several create_capability_domain and handle_attachments
//   tests.
//
// Degraded variant (this file)
//   The closest single-domain code path is `restrict` on the slot-2
//   self-IDC handle. The kernel pre-populates slot 2 of every fresh
//   capability domain with an IDC handle to itself (§[create_capability_domain],
//   §[cridc_ceiling]); that handle has cap-restrict semantics
//   identical to any IDC handle the receiver would later install via
//   IDC. Restricting it to a subset of the original caps is the same
//   bitwise mask operation the kernel performs at recv time when
//   intersecting granted caps with `idc_rx`: in both cases, the slot's
//   resulting caps word equals the AND of the prior caps and the mask.
//   We verify that property locally:
//
//     - read slot 2's current caps C0 (whatever cridc_ceiling the
//       primary supplied at spawn);
//     - choose a mask M = IdcCap{ .copy = true } (a single bit);
//     - call restrict(slot 2, C0 & M);
//     - readCap and assert the caps word equals C0 & M.
//
//   This is a strict subset of the spec rule (it only exercises the
//   bitwise-AND step, not the IDC delivery path) and pins the local
//   invariant the kernel must satisfy for the full path to be correct.
//
// Action
//   1. readCap(cap_table_base, SLOT_SELF_IDC)         — observe C0
//   2. restrict(SLOT_SELF_IDC, C0 & M)                — must succeed
//   3. readCap(cap_table_base, SLOT_SELF_IDC)         — verify caps == C0 & M
//
// Assertions
//   1: slot 2 is not an IDC handle (test infra precondition violated)
//   2: restrict returned non-success in vreg 1
//   3: handle's caps after restrict do not equal C0 & M

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    const before = caps.readCap(cap_table_base, caps.SLOT_SELF_IDC);
    if (before.handleType() != .capability_domain) {
        testing.fail(1);
        return;
    }
    const c0: u16 = before.caps();

    // Mask M models a receiver's `idc_rx` keeping only `copy`.
    const mask = caps.IdcCap{ .copy = true };
    const masked: u16 = c0 & mask.toU16();

    const result = syscall.restrict(caps.SLOT_SELF_IDC, @as(u64, masked));
    if (result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(2);
        return;
    }

    const after = caps.readCap(cap_table_base, caps.SLOT_SELF_IDC);
    if (after.caps() != masked) {
        testing.fail(3);
        return;
    }

    testing.pass();
}
