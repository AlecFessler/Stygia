// Spec §[reply] reply — test 19.
//
// "[test 19] on success when `pair_count > 0`, the resumed EC's syscall
//  word carries `pair_count = N` and `tstart = S`; the next N slots
//  `[S, S+N)` in the resumed EC's domain contain the inserted handles
//  per §[handle_attachments] (caps intersected with `idc_rx` for IDC
//  handles, verbatim otherwise)."
//
// Strategy
//   reply's success path with pair_count > 0 needs (a) a live reply
//   handle to consume, (b) a suspended EC to resume, and (c) at least
//   one source handle to attach. All three live in the same single-
//   domain test:
//
//     - The test EC mints a port with bind|recv|xfer (xfer is required
//       to mint a reply handle whose `xfer` cap is set, which is in
//       turn required by reply with pair_count > 0 per §[reply]).
//     - It mints a sibling EC bound to the same domain with susp+term
//       (rp=0). The sibling self-suspends on the port via raw asm so
//       that on resume the kernel populates ITS syscall word with
//       pair_count and tstart per §[event_state]; an externally-
//       suspended EC has no syscall pad to write.
//     - The test EC blocks in recv on the port; the kernel mints a
//       reply handle in the test EC's table and returns its slot in
//       the recv syscall word.
//     - The test EC issues reply with pair_count=1 and a single pair
//       entry referencing a page frame handle (a non-IDC type so the
//       caps land verbatim — no idc_rx intersection to disentangle).
//       The pair entry is in vreg 127 per §[handle_attachments]; the
//       libz `reply` wrapper covers only the bare-reply path, so we
//       issue the syscall inline. Reservation pad: 920 bytes (912 for
//       vregs 14..127 plus 8 for the syscall word pushed last). Vreg
//       127 lands at [rsp+912] after the push.
//
//   The test EC's domain is the resumed EC's domain (we created the
//   sibling with target=self), so the inserted handle slot is visible
//   to us through the read-only cap table mapping. The sibling, after
//   resume, writes its observed post-resume syscall word back to a
//   shared global; the test EC reads it to learn N and S.
//
// Verification
//   1. reply returns OK in vreg 1.
//   2. The reply slot in our table is no longer a reply handle
//      (consumed per reply test 04).
//   3. Sibling-observed pair_count == 1.
//   4. Sibling-observed tstart S references a page_frame handle in our
//      cap table whose caps == the entry's caps verbatim (the source
//      was a page frame, not an IDC handle, so no intersection).
//
// SPEC AMBIGUITY: the spec talks about "the resumed EC's syscall word
// `pair_count = N` and `tstart = S`" without distinguishing how the
// resumed EC entered the suspended state. Realistic interpretations
// require the resumed EC to have been in a syscall (its rsp pointing
// at the syscall pad with vreg 0 at [rsp+0]); otherwise the kernel
// would clobber whatever return-address word happened to be at the
// EC's rsp+0. The sibling here self-suspends so we observe the
// post-resume word through the captured rcx.
//
// SPEC AMBIGUITY: spec §[event_state] tabulates the *recv-side*
// syscall word layout (pair_count at bits 12-19, tstart at bits 20-31,
// etc.); the resumed sender's post-resume word reuses the same field
// positions in this test on the assumption that the kernel mirrors the
// receiver's word into the resumed EC's syscall word. Bit 0-11 of the
// resumed word is treated as _reserved per the recv layout.
//
// Assertions
//   1: setup — create_port for the test port returned an error word
//   2: setup — create_page_frame returned an error word (source handle)
//   3: setup — create_execution_context for the sibling returned an error
//   4: setup — recv on the test port returned an error code in vreg 1
//   5: setup — recv populated reply_handle_id = 0 (no reply handle minted)
//   6: reply returned non-OK in vreg 1
//   7: the reply handle slot still reads as a reply handle after the call
//      (not consumed)
//   8: pair_count field of the resumed EC's syscall word != 1
//   9: tstart field of the resumed EC's syscall word references a slot
//      that does NOT contain a page_frame handle, or whose caps differ
//      from the entry's caps (handle missing or caps did not land
//      verbatim)

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const HandleId = caps.HandleId;

// Cross-EC channel. Sibling and test EC share the same address space
// (single domain, same ELF); these globals are an in-process mailbox.
var g_ready: u32 = 0;
var g_port_handle_id: u64 = 0;
var g_sibling_self_handle_id: u64 = 0;
var g_sibling_observed_word: u64 = 0;
var g_sibling_done: u32 = 0;

// Caps minted on the page frame whose handle we'll attach via the pair
// entry. Captured at module scope so the sibling-side verification can
// confirm the kernel installed the handle "verbatim" per §[handle_attachments].
const ATTACH_PF_CAPS: caps.PfCap = .{ .move = true, .r = true, .w = true };

fn siblingEntry() callconv(.c) noreturn {
    // Spin until the test EC has installed our handle ids. The sibling
    // EC starts running the moment create_execution_context returns,
    // racing the test EC; the test EC writes the globals AFTER it
    // captures the returned EC handle.
    while (@atomicLoad(u32, &g_ready, .acquire) == 0) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("pause" ::: .{ .memory = true }),
            .aarch64 => asm volatile ("yield" ::: .{ .memory = true }),
            else => @compileError("unsupported target architecture"),
        }
    }

    const port_id: u64 = g_port_handle_id;
    const self_ec_id: u64 = g_sibling_self_handle_id;

    // Self-suspend on the port. syscall_num = 14 (suspend), no pair
    // attachments from the sender side. Capture the post-resume syscall
    // word so we can read pair_count / tstart.
    const word_in: u64 = @intFromEnum(syscall.SyscallNum.@"suspend");
    var word_out: u64 = undefined;
    switch (builtin.cpu.arch) {
        .x86_64 => {
            var rax_out: u64 = undefined;
            var rbx_out: u64 = undefined;
            asm volatile (
                \\ pushq %%rcx
                \\ syscall
                \\ popq %%rcx
                : [wo] "={rcx}" (word_out),
                  [v1o] "={rax}" (rax_out),
                  [v2o] "={rbx}" (rbx_out),
                : [wi] "{rcx}" (word_in),
                  [v1i] "{rax}" (self_ec_id),
                  [v2i] "{rbx}" (port_id),
                : .{
                    .rdx = true,
                    .rbp = true,
                    .rsi = true,
                    .rdi = true,
                    .r8 = true,
                    .r9 = true,
                    .r10 = true,
                    .r11 = true,
                    .r12 = true,
                    .r13 = true,
                    .r14 = true,
                    .r15 = true,
                    .memory = true,
                });
        },
        .aarch64 => {
            // Self-suspend: vreg 0 = syscall word at [sp+0],
            // vreg 1 = x0 = self EC handle, vreg 2 = x1 = port handle.
            // Capture post-resume word from [sp+0]. Reserve 16 bytes
            // (16-byte aligned, no high vregs needed).
            var x0_out: u64 = undefined;
            var x1_out: u64 = undefined;
            asm volatile (
                \\ sub sp, sp, #16
                \\ str %[wi], [sp]
                \\ svc #0
                \\ ldr %[wo], [sp]
                \\ add sp, sp, #16
                : [wo] "=&r" (word_out),
                  [v1o] "={x0}" (x0_out),
                  [v2o] "={x1}" (x1_out),
                : [wi] "r" (word_in),
                  [v1i] "{x0}" (self_ec_id),
                  [v2i] "{x1}" (port_id),
                : .{ .x2 = true, .x3 = true, .x4 = true, .x5 = true, .x6 = true,
                     .x7 = true, .x8 = true, .x9 = true, .x10 = true, .x11 = true,
                     .x12 = true, .x13 = true, .x14 = true, .x15 = true, .x16 = true,
                     .x17 = true, .x19 = true, .x20 = true, .x21 = true, .x22 = true,
                     .x23 = true, .x24 = true, .x25 = true, .x26 = true, .x27 = true,
                     .x28 = true, .x29 = true, .x30 = true, .memory = true });
        },
        else => @compileError("unsupported target architecture"),
    }

    @atomicStore(u64, &g_sibling_observed_word, word_out, .release);
    @atomicStore(u32, &g_sibling_done, 1, .release);

    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfe"),
            else => @compileError("unsupported target architecture"),
        }
    }
}

pub fn main(cap_table_base: u64) void {
    // 1. Mint our own port with bind|recv|xfer. The runner passes a
    //    port at SLOT_FIRST_PASSED but with caps={xfer,bind} (no recv);
    //    we need recv to dequeue our sibling's suspension event, and
    //    xfer to mint a reply handle whose `xfer` cap is set so that
    //    reply with pair_count > 0 (which requires xfer on the reply)
    //    doesn't get rejected with E_PERM (test 09).
    const port_caps_word = caps.PortCap{
        .xfer = true,
        .recv = true,
        .bind = true,
        .@"suspend" = true,
    };
    const cp = syscall.createPort(@as(u64, port_caps_word.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: HandleId = @truncate(cp.v1 & 0xFFF);

    // 2. Mint the page frame whose handle we'll attach as a pair entry.
    //    A page frame is a non-IDC type, so the receiver's `idc_rx`
    //    does NOT mask the entry's caps — they land verbatim, which is
    //    the branch we want to assert in test 19.
    const cpf = syscall.createPageFrame(
        @as(u64, ATTACH_PF_CAPS.toU16()),
        0, // props: sz = 0 (4 KiB)
        1,
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(2);
        return;
    }
    const pf_handle: HandleId = @truncate(cpf.v1 & 0xFFF);

    // 3. Mint the sibling EC bound to this domain with susp+term and
    //    rp=0. susp is necessary because the sibling self-suspends; we
    //    don't actually use term but it keeps the cap profile minimal.
    //    rp=0 sidesteps any restart_policy ceiling interaction.
    //    Priority = 1 (normal) so the sibling can be dispatched while
    //    the test EC is also at pri=1 — without this, sibling sits at
    //    pri=0 (idle) and never preempts the test EC's busy-poll on
    //    g_sibling_done, leaving the result undelivered.
    const ec_caps = caps.EcCap{
        .susp = true,
        .term = true,
        .restart_policy = 0,
    };
    const ec_caps_word: u64 = @as(u64, ec_caps.toU16()) | (@as(u64, 1) << 32);
    const cec = syscall.createExecutionContext(
        ec_caps_word,
        @intFromPtr(&siblingEntry),
        1, // stack_pages
        0, // target = self (this domain)
        0, // affinity_mask = 0 means kernel chooses
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(3);
        return;
    }
    const sibling_ec: HandleId = @truncate(cec.v1 & 0xFFF);

    // Hand the sibling its operating handles, then release it.
    @atomicStore(u64, &g_port_handle_id, @as(u64, port_handle), .release);
    @atomicStore(u64, &g_sibling_self_handle_id, @as(u64, sibling_ec), .release);
    @atomicStore(u32, &g_ready, 1, .release);

    // 4. Block waiting for the sibling's suspension event. The kernel
    //    mints a reply handle in our table and returns its slot id in
    //    the recv syscall word's bits 32-43.
    const got = syscall.recv(port_handle, 0);
    if (testing.isHandleError(got.regs.v1)) {
        testing.fail(4);
        return;
    }
    const reply_handle_id: HandleId = @truncate((got.word >> 32) & 0xFFF);
    if (reply_handle_id == 0) {
        testing.fail(5);
        return;
    }

    // 5. Issue reply with pair_count=1 attaching the page frame handle.
    //    libz `reply` covers only the bare-reply path, so we do the
    //    inline-asm path:
    //
    //      sub  $912, %rsp           # space for vregs 14..127
    //      mov  pair_entry, 904(%rsp) # vreg 127
    //      push %rcx                  # syscall word at [rsp]; vreg 127 now at [rsp+912]
    //      syscall
    //      add  $920, %rsp            # discard pad + word
    //
    //    Syscall word: syscall_num=52 (reply) | (pair_count=1)<<12 |
    //    (reply_handle_id<<20). Per §[reply] the reply_handle_id rides
    //    in syscall-word bits 20-31 rather than in vreg 1.
    const pair_entry = caps.PairEntry{
        .id = pf_handle,
        .caps = ATTACH_PF_CAPS.toU16(),
        .move = true, // remove from our table on resume; matches PfCap.move = true above
    };
    const entry_u64: u64 = pair_entry.toU64();
    const word: u64 =
        @as(u64, @intFromEnum(syscall.SyscallNum.reply)) |
        (@as(u64, 1) << 12) |
        ((@as(u64, reply_handle_id) & 0xFFF) << 20);

    var rt_v1_out: u64 = undefined;
    switch (builtin.cpu.arch) {
        .x86_64 => {
            asm volatile (
                \\ subq $912, %%rsp
                \\ movq %[entry], 904(%%rsp)
                \\ pushq %%rcx
                \\ syscall
                \\ addq $920, %%rsp
                : [v1o] "={rax}" (rt_v1_out),
                : [wi] "{rcx}" (word),
                  [entry] "r" (entry_u64),
                : .{
                    .rcx = true,
                    .r11 = true,
                    .memory = true,
                });
        },
        .aarch64 => {
            // aarch64: vreg 127 = [sp + 768]; reserve 784 bytes.
            asm volatile (
                \\ sub sp, sp, #784
                \\ str %[word], [sp]
                \\ str %[entry], [sp, #768]
                \\ svc #0
                \\ add sp, sp, #784
                : [v1o] "={x0}" (rt_v1_out),
                : [word] "r" (word),
                  [entry] "r" (entry_u64),
                : .{ .x1 = true, .x2 = true, .x3 = true, .x4 = true, .x5 = true,
                     .x6 = true, .x7 = true, .x8 = true, .x9 = true, .x10 = true,
                     .x11 = true, .x12 = true, .x13 = true, .x14 = true, .x15 = true,
                     .x16 = true, .x17 = true, .x19 = true, .x20 = true, .x21 = true,
                     .x22 = true, .x23 = true, .x24 = true, .x25 = true, .x26 = true,
                     .x27 = true, .x28 = true, .x29 = true, .x30 = true, .memory = true });
        },
        else => @compileError("unsupported target architecture"),
    }

    if (rt_v1_out != @intFromEnum(errors.Error.OK)) {
        testing.fail(6);
        return;
    }

    // 6. Reply handle must be consumed (slot freed). Read it back; if
    //    its handleType is still `.reply`, the kernel did not consume.
    const reply_slot = caps.readCap(cap_table_base, @as(u32, reply_handle_id));
    if (reply_slot.handleType() == .reply) {
        testing.fail(7);
        return;
    }

    // 7. Wait for the sibling to resume and report what it observed.
    //    The sibling writes its post-resume syscall word to
    //    g_sibling_observed_word and sets g_sibling_done. Spinning is
    //    safe — both ECs are bound to this domain on the same scheduler;
    //    the kernel will schedule the sibling.
    while (@atomicLoad(u32, &g_sibling_done, .acquire) == 0) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("pause" ::: .{ .memory = true }),
            .aarch64 => asm volatile ("yield" ::: .{ .memory = true }),
            else => @compileError("unsupported target architecture"),
        }
    }
    const sibling_word = @atomicLoad(u64, &g_sibling_observed_word, .acquire);

    // §[event_state] receiver-side word layout (also applied to the
    // resumed sender's syscall word per the SPEC AMBIGUITY note above):
    //   bits 12-19: pair_count
    //   bits 20-31: tstart
    const pair_count: u8 = @truncate((sibling_word >> 12) & 0xFF);
    const tstart: u12 = @truncate((sibling_word >> 20) & 0xFFF);
    if (pair_count != 1) {
        testing.fail(8);
        return;
    }

    // 8. The next N=1 slots starting at S=tstart in the resumed EC's
    //    domain (== ours) must hold the inserted handles. For our
    //    page-frame entry, the install caps are the entry's caps
    //    verbatim (no idc_rx intersection because page_frame is not an
    //    IDC handle type).
    const installed = caps.readCap(cap_table_base, @as(u32, tstart));
    if (installed.handleType() != .page_frame or
        installed.caps() != ATTACH_PF_CAPS.toU16())
    {
        testing.fail(9);
        return;
    }

    testing.pass();
}
