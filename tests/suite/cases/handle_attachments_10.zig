// Spec §[handle_attachments] — test 10.
//
// "[test 10] when the suspend resumes with `E_CLOSED` before any recv,
//  no entry is moved or copied."
//
// Strategy
//   §[handle_attachments] last paragraph before the tests:
//
//     "The kernel validates the entries at suspend time. The actual
//      move/copy is performed at recv time — if the suspend resumes
//      with E_CLOSED before any recv, no attachment is moved or
//      copied and the sender's table is unchanged."
//
//   The spec line under test is the visible behaviour of that rule.
//   To exercise it we need:
//
//     (a) A suspending EC with N > 0 valid pair entries — at least one
//         `move = 1` and at least one `move = 0`, so the post-resume
//         "unchanged sender table" check covers both branches.
//     (b) A suspended state in which the port becomes terminally closed
//         before any recv consumes the event.
//     (c) A side observation, after the suspend returns, that every
//         source handle is still resident in the sender's domain table
//         with its caps intact.
//
//   §[capabilities] (port row) defines the closing transition that
//   resumes suspended senders:
//
//     "Decrement the recv refcount if this handle has `recv`. ... When
//      the recv refcount hits zero, suspended senders resume with
//      E_CLOSED."
//
//   So we mint a port whose only handle in the test domain carries
//   bind + recv + xfer caps, queue up two pair entries, suspend the
//   test EC itself onto that port, and arrange for a sibling EC in
//   the same capability domain to release the port handle while the
//   test EC is suspended. The port's recv refcount drops from 1 to 0
//   with no recv ever queued, the kernel resumes the test EC with
//   E_CLOSED, and the sender-table-unchanged invariant is what we
//   probe afterwards.
//
//   Sibling-EC mechanic: ECs created with target = self (the test EC's
//   own capability domain) share the same handle table per
//   §[create_execution_context]. The test EC stores the port handle id
//   into a process-global with release ordering; the sibling EC's
//   entry function loads it with acquire ordering, calls
//   `delete(port_id)`, and halts. When the test EC suspends itself the
//   sibling becomes the only runnable EC in the domain and the
//   scheduler picks it up; once it executes the delete the recv
//   refcount transition fires and the test EC's suspend resumes.
//
//   Pair-entry mechanic: §[handle_attachments] says "When N > 0, the
//   entries occupy vregs [128-N..127]". libz's `suspendEc` panics on
//   N > 0 because the existing wrapper has no high-vreg path wired,
//   so this test issues the syscall via raw inline asm, allocating a
//   920-byte stack pad covering the syscall word at [rsp + 0] and
//   vregs 14..127 at [rsp + 8..rsp + 920). Entry[0] lands at vreg 126
//   ([rsp + 904]) and entry[1] at vreg 127 ([rsp + 912]) for N = 2.
//
//   Source-handle mechanic: each pair entry needs a source handle in
//   the test domain that satisfies the entry's `move` field per
//   §[handle_attachments] tests 04/05 — `move = 1` requires the
//   source to have `move`, `move = 0` requires it to have `copy`.
//   Two page frames satisfy this cleanly: PF_A with caps `move + r`
//   for the `move = 1` entry, PF_B with caps `copy + r` for the
//   `move = 0` entry. Page-frame creation rights live under the
//   child's `crpf` self cap (granted by the runner) and the child's
//   `pf_ceiling` already permits `move + copy + rwx, max_sz = 0`.
//
//   Observation mechanic: after the suspend resumes we read the test
//   domain's read-only-mapped cap table at the PF slots. Per
//   §[capabilities], a handle's `word0` carries a non-zero type tag in
//   bits 12-15 while it is live; if the kernel had moved either source
//   the slot would have been released and the type tag would now read
//   zero. We explicitly check the type tag is `page_frame` and that
//   the caps field still holds the move/copy bit the entry's `move`
//   semantics relied on (move bit for PF_A, copy bit for PF_B), so a
//   regression that incorrectly applied the move/copy at suspend time
//   instead of at recv time can't masquerade as a pass.
//
//   SPEC AMBIGUITY: §[handle_attachments] does not pin the precise
//   ordering inside [128-N..127] — i.e., whether entry[0] at vreg 126
//   or vreg 127 is the "first" entry. The ordering doesn't matter for
//   test 10 (no recv consumes them), but tests 08/09 will need to pin
//   it. This test arbitrarily places entry[0] at the lower of the two
//   high vregs (126) and entry[1] at the upper (127).
//
//   Other failure paths on the suspend itself:
//     - test 01 E_PERM if N > 0 and port lacks `xfer`: port gets `xfer`.
//     - test 02 E_BADCAP if any entry's source id is invalid: PF
//       handle ids come from successful create_page_frame.
//     - test 03 E_PERM if entry caps ⊄ source caps: entry caps = {r}
//       which both PFs hold.
//     - test 04 E_PERM if move = 1 and source lacks `move`: PF_A has
//       `move` cap.
//     - test 05 E_PERM if move = 0 and source lacks `copy`: PF_B has
//       `copy` cap.
//     - test 06 E_INVAL if reserved bits set: PairEntry packed struct
//       zeroes _reserved_lo and _reserved_hi.
//     - test 07 E_INVAL if two entries share a source: PF_A and PF_B
//       are distinct handles.
//
//   And on suspend itself (§[suspend] tests 01..07): target = the test
//   EC's own slot 1 (valid EC, has `susp` since runner-granted
//   ec_inner_ceiling lets us mint with susp), port = the freshly minted
//   port (valid handle, has `bind`), no reserved bits, target is not a
//   vCPU and is not already suspended.
//
// Action
//   1. create_port(caps = bind|recv|xfer)
//      — must succeed (port_ceiling = 0x1C permits these three).
//   2. create_page_frame(caps = move|r, props = sz=0, pages = 1)
//      — must succeed (PF_A, source for the move=1 entry).
//   3. create_page_frame(caps = copy|r, props = sz=0, pages = 1)
//      — must succeed (PF_B, source for the move=0 entry).
//   4. Publish port_id via release store; create_execution_context
//      pointing at deleterEntry, target = self, priority = 0,
//      affinity = 0.
//      — must succeed.
//   5. Issue suspend(self_ec=1, port, [pair_a (move=1, PF_A, caps=r),
//                                       pair_b (move=0, PF_B, caps=r)])
//      via raw asm with the 920-byte stack pad.
//      — must resume with vreg 1 (rax) = E_CLOSED.
//   6. readCap(cap_table_base, PF_A.id) must show type = page_frame
//      and caps still includes the `move` bit.
//   7. readCap(cap_table_base, PF_B.id) must show type = page_frame
//      and caps still includes the `copy` bit.
//
// Assertions
//   1: create_port for the test port returned an error word
//   2: create_page_frame for PF_A returned an error word
//   3: create_page_frame for PF_B returned an error word
//   4: create_execution_context for the deleter sibling returned an
//      error word
//   5: suspend did not resume with E_CLOSED
//   6: PF_A's slot is not a live page_frame handle after resume (the
//      `move = 1` entry was applied despite no recv ever happening)
//   7: PF_A's caps lost the `move` bit after resume (suggesting a
//      partial mutation of the source even though the spec mandates
//      the table be unchanged)
//   8: PF_B's slot is not a live page_frame handle after resume (the
//      `move = 0` entry somehow released the source)
//   9: PF_B's caps lost the `copy` bit after resume (partial mutation
//      of the source on the copy path)

const builtin = @import("builtin");
const std = @import("std");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Process-global the test EC writes (release) and the deleter sibling
// reads (acquire). Both ECs run in the same capability domain so this
// is shared memory in the strict sense.
var deleter_port_id: u32 = 0;

// Sibling-EC entry. Loads the port handle id the test EC published,
// drops the only port handle in the table (the recv-cap holder), and
// halts. The delete decrements the port's recv refcount from 1 to 0;
// per §[capabilities] (port row) that transition resumes suspended
// senders with E_CLOSED — exactly what test 10 needs.
fn deleterEntry() callconv(.c) noreturn {
    const id_u32 = @atomicLoad(u32, &deleter_port_id, .acquire);
    const id: u12 = @truncate(id_u32);
    _ = syscall.delete(id);
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfi"),
            else => @compileError("unsupported arch"),
        }
    }
}

// Issue `suspend` with two pair entries in vregs 126 and 127. libz's
// generic `suspendEc` panics on N > 0 because it has no high-vreg
// path wired; here we hand-roll the stack-pad sequence the spec ABI
// requires.
//
// Stack layout while the syscall is executing (per §[syscall_abi] /
// §[event_state] vreg-to-stack mapping `vreg N at [rsp + (N-13)*8]`
// for 14 ≤ N ≤ 127):
//   [rsp +   0] syscall word
//   [rsp +   8] vreg 14   (zeroed)
//   ...         ...
//   [rsp + 896] vreg 125  (zeroed)
//   [rsp + 904] vreg 126  (entry_a)
//   [rsp + 912] vreg 127  (entry_b)
//
// Total pad = 920 bytes (1 word + 114 vregs * 8). On return rax holds
// vreg 1 (= the syscall's status code per §[error_codes]).
fn suspendWithTwoAttachmentsX64(
    word: u64,
    v1: u64,
    v2: u64,
    entry_a: u64,
    entry_b: u64,
) u64 {
    var rax_out: u64 = undefined;
    asm volatile (
        \\ subq $920, %%rsp
        \\ movq %%rsp, %%rdi
        \\ xorl %%eax, %%eax
        \\ movq $113, %%rcx
        \\ rep stosq
        \\ movq %%r8, 904(%%rsp)
        \\ movq %%r9, 912(%%rsp)
        \\ movq %%r10, (%%rsp)
        \\ movq %%r12, %%rax
        \\ movq %%r13, %%rbx
        \\ movq %%r10, %%rcx
        \\ syscall
        \\ addq $920, %%rsp
        : [out_rax] "={rax}" (rax_out),
        : [w] "{r10}" (word),
          [iv1] "{r12}" (v1),
          [iv2] "{r13}" (v2),
          [ea] "{r8}" (entry_a),
          [eb] "{r9}" (entry_b),
        : .{ .rbx = true, .rcx = true, .rdx = true, .rbp = true, .rsi = true, .rdi = true, .r11 = true, .r14 = true, .r15 = true, .memory = true, .cc = true });

    return rax_out;
}

fn suspendWithTwoAttachmentsArm(
    word: u64,
    v1: u64,
    v2: u64,
    entry_a: u64,
    entry_b: u64,
) u64 {
    // aarch64 high-vreg layout: vreg N at [sp + (N-31)*8] for 32 ≤ N ≤ 127.
    // vreg 126 = [sp + 760]; vreg 127 = [sp + 768]. Reserve 784 bytes
    // (16-byte aligned) covering [sp+0] (word) through [sp+776].
    var x0_out: u64 = undefined;
    asm volatile (
        \\ sub sp, sp, #784
        \\ str %[ea], [sp, #760]
        \\ str %[eb], [sp, #768]
        \\ str %[w], [sp]
        \\ svc #0
        \\ add sp, sp, #784
        : [out_x0] "={x0}" (x0_out),
        : [w] "r" (word),
          [iv1] "{x0}" (v1),
          [iv2] "{x1}" (v2),
          [ea] "r" (entry_a),
          [eb] "r" (entry_b),
        : .{ .x1 = true, .x2 = true, .x3 = true, .x4 = true, .x5 = true,
             .x6 = true, .x7 = true, .x8 = true, .x9 = true, .x10 = true,
             .x11 = true, .x12 = true, .x13 = true, .x14 = true, .x15 = true,
             .x16 = true, .x17 = true, .x19 = true, .x20 = true, .x21 = true,
             .x22 = true, .x23 = true, .x24 = true, .x25 = true, .x26 = true,
             .x27 = true, .x28 = true, .x29 = true, .x30 = true, .memory = true });

    return x0_out;
}

fn suspendWithTwoAttachments(
    target_ec: u64,
    port: u12,
    entry_a: u64,
    entry_b: u64,
) u64 {
    const word: u64 = syscall.buildWord(.@"suspend", syscall.extraCount(2));
    const v1: u64 = target_ec;
    const v2: u64 = @as(u64, port);
    return switch (builtin.cpu.arch) {
        .x86_64 => suspendWithTwoAttachmentsX64(word, v1, v2, entry_a, entry_b),
        .aarch64 => suspendWithTwoAttachmentsArm(word, v1, v2, entry_a, entry_b),
        else => @compileError("unsupported arch"),
    };
}

pub fn main(cap_table_base: u64) void {
    // Step 1: mint the test port. bind + recv + xfer is the minimum
    // cap set: bind so suspend test 04 doesn't reject; recv so the
    // port begins with a non-zero recv refcount that can later
    // transition to zero; xfer so handle_attachments test 01 doesn't
    // reject the N > 0 suspend. PortCap.toU16() = 0x1C = port_ceiling
    // exactly, so no ceiling violation.
    const port_caps = caps.PortCap{
        .bind = true,
        .recv = true,
        .xfer = true,
    };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: PF_A — source for the `move = 1` pair entry. caps =
    // move + r so handle_attachments test 04 (entry move=1 needs
    // source.move) and test 03 (entry caps = {r} ⊆ source caps) both
    // pass. max_sz = 0 stays inside the runner's pf_ceiling (max_sz =
    // 0). props.sz = 0 (4 KiB pages); pages = 1.
    const pf_a_caps = caps.PfCap{
        .move = true,
        .r = true,
    };
    const cpfa = syscall.createPageFrame(
        @as(u64, pf_a_caps.toU16()),
        0,
        1,
    );
    if (testing.isHandleError(cpfa.v1)) {
        testing.fail(2);
        return;
    }
    const pf_a_handle: u12 = @truncate(cpfa.v1 & 0xFFF);

    // Step 3: PF_B — source for the `move = 0` pair entry. caps =
    // copy + r so test 05 (entry move=0 needs source.copy) and test 03
    // both pass.
    const pf_b_caps = caps.PfCap{
        .copy = true,
        .r = true,
    };
    const cpfb = syscall.createPageFrame(
        @as(u64, pf_b_caps.toU16()),
        0,
        1,
    );
    if (testing.isHandleError(cpfb.v1)) {
        testing.fail(3);
        return;
    }
    const pf_b_handle: u12 = @truncate(cpfb.v1 & 0xFFF);

    // Step 4: publish the port id then mint the deleter sibling. The
    // release store pairs with the acquire load in `deleterEntry` so
    // the sibling reads the just-written id even if the kernel
    // schedules it on another core. priority = 0, affinity = 0
    // (kernel chooses) keep us inside the runner-granted ceilings.
    @atomicStore(u32, &deleter_port_id, @as(u32, port_handle), .release);

    const deleter_caps = caps.EcCap{ .restart_policy = 0 };
    const deleter_caps_word: u64 = @as(u64, deleter_caps.toU16());
    const deleter_entry_addr: u64 = @intFromPtr(&deleterEntry);
    const cec = syscall.createExecutionContext(
        deleter_caps_word,
        deleter_entry_addr,
        1, // stack_pages
        0, // target = self (same domain → shared handle table)
        0, // affinity = any core
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(4);
        return;
    }
    // The deleter handle id itself is irrelevant to the test logic —
    // we never reference the EC again.

    // Step 5: build pair entries and dispatch suspend. PairEntry
    // packed-struct construction zeroes _reserved_lo / _reserved_hi
    // automatically, neutralizing handle_attachments test 06 (E_INVAL
    // on reserved bits in an entry).
    const entry_caps = caps.PfCap{ .r = true };
    const pair_a = caps.PairEntry{
        .id = pf_a_handle,
        .caps = entry_caps.toU16(),
        .move = true,
    };
    const pair_b = caps.PairEntry{
        .id = pf_b_handle,
        .caps = entry_caps.toU16(),
        .move = false,
    };

    // SLOT_INITIAL_EC = 1 is the test EC itself per
    // §[create_capability_domain]'s slot-1 invariant.
    const status = suspendWithTwoAttachments(
        @as(u64, caps.SLOT_INITIAL_EC),
        port_handle,
        pair_a.toU64(),
        pair_b.toU64(),
    );
    if (status != @intFromEnum(errors.Error.E_CLOSED)) {
        testing.fail(5);
        return;
    }

    // Step 6: PF_A — `move = 1` source. Spec: "no attachment is moved
    // or copied". The slot must still hold a live page_frame handle
    // and the `move` cap bit must still be set. Reading directly from
    // the read-only-mapped cap table avoids issuing an intervening
    // syscall (which would itself implicitly refresh the snapshot via
    // the sync side effect; immediate cap-table reads see exactly
    // what the kernel wrote at the suspend's resume edge).
    const cap_a = caps.readCap(cap_table_base, pf_a_handle);
    if (cap_a.handleType() != .page_frame) {
        testing.fail(6);
        return;
    }
    {
        const cap_bits: u16 = cap_a.caps();
        const pf_caps_obs: caps.PfCap = @bitCast(cap_bits);
        if (!pf_caps_obs.move) {
            testing.fail(7);
            return;
        }
    }

    // Step 7: PF_B — `move = 0` source. The copy path does not
    // mutate the source even at recv time, but spec test 10 still
    // requires the table to be unchanged on the E_CLOSED path; we
    // probe the same liveness + caps invariant here.
    const cap_b = caps.readCap(cap_table_base, pf_b_handle);
    if (cap_b.handleType() != .page_frame) {
        testing.fail(8);
        return;
    }
    {
        const cap_bits: u16 = cap_b.caps();
        const pf_caps_obs: caps.PfCap = @bitCast(cap_bits);
        if (!pf_caps_obs.copy) {
            testing.fail(9);
            return;
        }
    }

    testing.pass();
}
