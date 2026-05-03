// Spec §[reply_transfer] reply_transfer — test 14.
//
// "[test 14] on success when the originating EC handle had the `write`
//  cap, the resumed EC's state reflects modifications written to the
//  receiver's event-state vregs between recv and reply_transfer;
//  otherwise modifications are discarded."
//
// Strategy
//   The assertion has two halves: a `write`-cap-held branch in which
//   modifications applied between recv and reply_transfer must reach
//   the resumed EC, and a `write`-cap-absent branch in which the same
//   modifications must be silently discarded. Both branches must hold
//   on the same kernel build, so the test exercises each in turn
//   inside the same test EC.
//
//   For each branch we materialize a sibling EC `W` in this test's
//   capability domain, suspend it on a port the test EC owns with
//   `bind | recv | xfer`, recv the suspension event to obtain a reply
//   handle for W, then issue `reply_transfer(reply, [pair])` with
//   exactly one attached handle and a single state modification:
//   vreg 14 (RIP) is rewritten to point at a worker function that
//   stores a sentinel into a process-global word.
//
//   Because the test EC and W share an address space (both ECs were
//   spawned with `target = self`), the global word is an out-of-band
//   side channel. After the reply_transfer the test EC yields and
//   atomically loads the global; the load result is the sole observable
//   that distinguishes "state mod applied" from "state mod discarded":
//
//     * write cap held  → kernel installs vreg 14 (alt RIP) into W's
//                         state; W resumes at the worker, writes
//                         the sentinel, then halts. The test EC
//                         eventually observes the sentinel.
//     * write cap absent → kernel discards vreg-14's value; W resumes
//                          at its pre-suspend RIP (in `dummyEntry`'s
//                          hlt loop) and never reaches the worker.
//                          The global stays at its sentinel-distinct
//                          baseline.
//
//   Other vregs (RFLAGS at 15, RSP at 16, FS.base at 17, GS.base at 18,
//   plus the GPR vregs 1..13 except for vreg 1 which we must overwrite
//   with the reply handle id as the syscall argument) are deliberately
//   left at the values the kernel snapshotted from W at recv time. With
//   the `write` cap held, the kernel re-applies those snapshot values
//   verbatim — a no-op modification — so RIP is the only observable
//   change. With the `write` cap absent, the kernel ignores the entire
//   vreg view, so what we leave there is moot.
//
//   The pair-entry attachment exists solely to satisfy reply_transfer's
//   `N >= 1` requirement (test 03: E_INVAL if N is 0). The test mints
//   a fresh page_frame handle in the test EC's table with the `copy`
//   cap and attaches it with `move = 0`; the resumed W gains a copy of
//   that handle in slots [tstart, tstart+1), but the test never reads
//   it back — its only role is letting reply_transfer through the
//   N == 0 guard.
//
// Stack-pad layout
//   v3 syscall ABI maps vreg 0 to [rsp + 0] at syscall time, vreg 14 to
//   [rsp + 8], …, vreg 127 to [rsp + 8 + (127 - 13) * 8] = [rsp + 912].
//   Total footprint = 920 bytes (1 word + 114 high-vreg slots). libz's
//   `replyTransfer` panics on N > 0 because the high-vreg pad is not
//   yet wired through `issueStack`, so this test inlines the recv +
//   reply_transfer pair into a single asm volatile block that:
//     1. allocates the 920-byte pad with `subq $920, %rsp`;
//     2. issues recv (syscall_num = 49) reading port handle from vreg 1;
//     3. saves the kernel-returned syscall word (carries reply_handle_id
//        in bits 32..43 per §[recv]);
//     4. modifies [rsp + 8] = vreg 14 (RIP) to the worker entry;
//     5. writes the pair entry at [rsp + 912] = vreg 127;
//     6. extracts reply_handle_id and places it in rax = vreg 1;
//     7. issues reply_transfer (syscall_num = 53 | (1 << 12));
//     8. tears down the pad.
//   recv and reply_transfer share the pad: recv populates vregs 14..127
//   with W's snapshot, the test mutates only vreg 14 and vreg 127, and
//   reply_transfer reads the same pad. Doing both in one block avoids
//   any compiler-emitted stack write or function call corrupting the
//   recv-written high-vreg view between the two syscalls.
//
// Action (per branch)
//   1. create_execution_context(target=self, caps=branch_caps,
//                               entry=&dummyEntry, stack_pages=1,
//                               affinity=ANY)                   — must succeed
//   2. suspend(W, port)                                          — must return OK
//   3. recv(port) (inside the combined asm)                      — must return OK
//   4. reply_transfer(reply, [pair_entry], modifying RIP)        — must return OK
//   5. yield-poll the global. write-cap branch must observe the
//      sentinel within a bounded number of iterations; write-cap-
//      absent branch must NOT observe it within the same bound.
//
// Assertions
//    1: branch-A (write cap) — create_execution_context for W1 failed
//    2: branch-A — page_frame creation for the attached handle failed
//    3: branch-A — suspend(W1, port) did not return OK
//    4: branch-A — recv (inside combined asm) returned a non-OK status
//    5: branch-A — reply_transfer returned a non-OK status
//    6: branch-A — yield-poll exhausted without observing the sentinel
//                  (RIP modification was NOT applied despite write cap)
//    7: branch-B (no write cap) — create_execution_context for W2 failed
//    8: branch-B — page_frame creation for the attached handle failed
//    9: branch-B — suspend(W2, port) did not return OK
//   10: branch-B — recv (inside combined asm) returned a non-OK status
//   11: branch-B — reply_transfer returned a non-OK status
//   12: branch-B — yield-poll observed the sentinel (RIP modification
//                  was applied even without write cap)

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Local halt-forever entry. libz `testing.dummyEntry` uses bare `hlt`,
// which only assembles on x86. Arch-dispatched twin keeps the test
// compiling on aarch64.
fn localDummyEntry() noreturn {
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfi"),
            else => @compileError("unsupported target architecture"),
        }
    }
}

// Sentinel and observation slots. Both ECs share the test domain's
// address space, so these globals are the side channel from each W's
// alt-RIP worker back to the test EC. Distinct slots keep the two
// branches decoupled — branch B mutating result_2 cannot accidentally
// retroactively pass branch A's sentinel observation.
const SENTINEL: u64 = 0xBEEF_CAFE_DEAD_F00D;
const BASELINE: u64 = 0xAAAA_AAAA_AAAA_AAAA;

// Worker entries for the two branches. Each stores SENTINEL into its
// branch-specific global, then halts. `callconv(.naked)` keeps the
// entry stack-clean: a non-naked function would emit a frame prologue
// (`push %rbp; mov %rsp, %rbp`), which dereferences rsp; v3
// reply-transfer state delivery only guarantees a well-formed stack
// when RSP (vreg 16) was re-installed from a sane snapshot. The recv
// path leaves vreg 16 pointing at W's pre-suspend stack, which is
// fine, but a naked entry simply does not depend on it.
//
// The globals are referenced via rip-relative addressing through the
// exported symbols `result_1` / `result_2` to avoid R_X86_64_64
// relocations, which fail under PIE. SENTINEL is folded into a
// 64-bit immediate via `movabsq`.
export var result_1: u64 = BASELINE;
export var result_2: u64 = BASELINE;

fn altEntry1() callconv(.naked) noreturn {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile (
            \\ movabsq %[sentinel], %%rax
            \\ movq %%rax, result_1(%%rip)
            \\ 1: hlt
            \\ jmp 1b
            :
            : [sentinel] "i" (SENTINEL),
        ),
        .aarch64 => asm volatile (
            \\ movz x0, #0xF00D
            \\ movk x0, #0xDEAD, lsl #16
            \\ movk x0, #0xCAFE, lsl #32
            \\ movk x0, #0xBEEF, lsl #48
            \\ adrp x1, result_1
            \\ add x1, x1, :lo12:result_1
            \\ str x0, [x1]
            \\ 1: wfi
            \\ b 1b
            ::
        ),
        else => @compileError("unsupported target architecture"),
    }
}

fn altEntry2() callconv(.naked) noreturn {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile (
            \\ movabsq %[sentinel], %%rax
            \\ movq %%rax, result_2(%%rip)
            \\ 1: hlt
            \\ jmp 1b
            :
            : [sentinel] "i" (SENTINEL),
        ),
        .aarch64 => asm volatile (
            \\ movz x0, #0xF00D
            \\ movk x0, #0xDEAD, lsl #16
            \\ movk x0, #0xCAFE, lsl #32
            \\ movk x0, #0xBEEF, lsl #48
            \\ adrp x1, result_2
            \\ add x1, x1, :lo12:result_2
            \\ str x0, [x1]
            \\ 1: wfi
            \\ b 1b
            ::
        ),
        else => @compileError("unsupported target architecture"),
    }
}

// Combined recv + reply_transfer with a single-vreg state modification.
// Returns the recv status code in `.recv_status` and the
// reply_transfer status code in `.xfer_status`. If recv fails,
// reply_transfer is skipped and `.xfer_status` is set to a synthetic
// nonzero marker so the caller still surfaces the recv failure.
const RecvXferResult = struct {
    recv_status: u64,
    xfer_status: u64,
};

// Static I/O block for the combined-syscall asm helper. The v3 ABI
// clobbers every GPR except rsp on each syscall (vregs 1..13 + rcx +
// r11), so an asm body that wraps two syscalls cannot afford a
// register input or output — there are simply no registers left after
// the clobber list. Routing inputs and outputs through static memory
// keeps the asm operand count to zero registers; rip-relative
// addressing under PIE costs no GPR.
const AsmIO = extern struct {
    port: u64,
    new_rip: u64,
    pair_entry: u64,
    recv_status: u64,
    xfer_status: u64,
};
export var asm_io: AsmIO = undefined;

fn recvAndReplyTransferWithRipMod(
    port_handle: u12,
    new_rip: u64,
    pair_entry: u64,
) RecvXferResult {
    asm_io.port = @as(u64, port_handle);
    asm_io.new_rip = new_rip;
    asm_io.pair_entry = pair_entry;
    asm_io.recv_status = 0;
    asm_io.xfer_status = 0;

    // §[syscall_abi] / libz/syscall.zig comment: syscall_num lives in
    // bits 0-11 of vreg 0; reply_transfer's `pair_count` lives in bits
    // 12-19; reply_handle_id (per the new ABI) lives in bits 20-31.
    // Both syscall words are inlined as immediates below: recv = 49
    // (syscall_num only, extra = 0). reply_transfer's word is computed
    // at runtime as (53 | (1 << 12)) | (rid << 20) = 4149 | (rid << 20)
    // because rid comes out of recv's returned word.
    //
    // Stack-pad layout after `subq $920, %rsp`:
    //   [rsp + 0]   vreg 0  — syscall word (rewritten between phases)
    //   [rsp + 8]   vreg 14 — RIP (kernel populates during recv;
    //                         caller overwrites to new_rip)
    //   [rsp + 16..40]      — RFLAGS / RSP / FS / GS (left as recv'd)
    //   [rsp + 912] vreg 127 — pair entry attachment for reply_transfer

    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile (
            \\ subq $920, %%rsp
            // ─── PHASE 1 — recv ───────────────────────────────────────────
            \\ movq $49, (%%rsp)
            \\ movq asm_io+0(%%rip), %%rax
            \\ syscall
            \\ movq %%rax, asm_io+24(%%rip)
            \\ movq (%%rsp), %%r11
            \\ testq %%rax, %%rax
            \\ jne 1f
            // ─── PHASE 2 — modify state, reply_transfer ───────────────────
            \\ movq asm_io+8(%%rip), %%rax
            \\ movq %%rax, 8(%%rsp)
            \\ movq asm_io+16(%%rip), %%rax
            \\ movq %%rax, 912(%%rsp)
            \\ movq %%r11, %%rax
            \\ movabsq $0xFFF00000000, %%rcx
            \\ andq %%rcx, %%rax
            \\ shrq $12, %%rax
            \\ orq $4149, %%rax
            \\ movq %%rax, (%%rsp)
            \\ syscall
            \\ movq %%rax, asm_io+32(%%rip)
            \\ jmp 2f
            \\ 1:
            \\ movq $-1, asm_io+32(%%rip)
            \\ 2:
            \\ addq $920, %%rsp
            :
            :
            : .{ .rax = true, .rbx = true, .rcx = true, .rdx = true, .rbp = true, .rsi = true, .rdi = true, .r8 = true, .r9 = true, .r10 = true, .r11 = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true, .memory = true }),
        .aarch64 => asm volatile (
            // 784-byte pad: vreg 0 at [sp+0], vregs 32..127 at
            // [sp+8..768]. On aarch64 vregs 1..31 ride in x0..x30 (so
            // vreg 14 = x13 — modified directly between phases).
            \\ sub sp, sp, #784
            // ─── PHASE 1 — recv ───────────────────────────────────────────
            // syscall word = 49 (recv), no extra fields.
            \\ mov x9, #49
            \\ str x9, [sp]
            // vreg 1 (port) = x0; vreg 2 unused for our purposes.
            \\ adrp x9, asm_io
            \\ add x9, x9, :lo12:asm_io
            \\ ldr x0, [x9, #0]
            \\ svc #0
            // Stash recv status (vreg 1 = x0).
            \\ adrp x9, asm_io
            \\ add x9, x9, :lo12:asm_io
            \\ str x0, [x9, #24]
            // Save returned syscall word (carries reply_handle_id) for
            // post-recv consumption.
            \\ ldr x10, [sp]
            // Bail if recv failed.
            \\ cbnz x0, 1f
            // ─── PHASE 2 — modify state, reply_transfer ───────────────────
            // vreg 14 = x13 := new_rip. (On aarch64 vreg 14 is in a
            // GPR rather than on the stack — write the register
            // directly between phases.)
            \\ adrp x9, asm_io
            \\ add x9, x9, :lo12:asm_io
            \\ ldr x13, [x9, #8]
            // vreg 127 = [sp + 768] := pair entry.
            \\ ldr x11, [x9, #16]
            \\ str x11, [sp, #768]
            // reply_transfer syscall word: extract rid from saved
            // recv word (bits 32-43), shift down by 12 so it sits in
            // bits 20-31, then OR in syscall_num (53) | (1 << 12) =
            // 4149.
            \\ ubfx x12, x10, #32, #12
            \\ lsl x12, x12, #20
            \\ mov x14, #4149
            \\ orr x12, x12, x14
            \\ str x12, [sp]
            \\ svc #0
            \\ adrp x9, asm_io
            \\ add x9, x9, :lo12:asm_io
            \\ str x0, [x9, #32]
            \\ b 2f
            \\ 1:
            \\ adrp x9, asm_io
            \\ add x9, x9, :lo12:asm_io
            \\ mov x12, #-1
            \\ str x12, [x9, #32]
            \\ 2:
            \\ add sp, sp, #784
            :
            :
            : .{ .x0 = true, .x1 = true, .x2 = true, .x3 = true, .x4 = true, .x5 = true,
                 .x6 = true, .x7 = true, .x8 = true, .x9 = true, .x10 = true, .x11 = true,
                 .x12 = true, .x13 = true, .x14 = true, .x15 = true, .x16 = true, .x17 = true,
                 .x19 = true, .x20 = true, .x21 = true, .x22 = true, .x23 = true, .x24 = true,
                 .x25 = true, .x26 = true, .x27 = true, .x28 = true, .x29 = true, .x30 = true,
                 .memory = true }),
        else => @compileError("unsupported target architecture"),
    }

    return .{
        .recv_status = asm_io.recv_status,
        .xfer_status = asm_io.xfer_status,
    };
}

// Yield to scheduler N times; allow same-core systems to make
// observable progress on W's resume.
fn yieldN(n: u32) void {
    var i: u32 = 0;
    while (i < n) {
        _ = syscall.yieldEc(0);
        i += 1;
    }
}

// Mint a fresh page-frame handle to use as the reply_transfer
// attachment. Caps include `copy` so the pair entry can carry
// `move = 0` and pass §[handle_attachments] [test 05] (which
// requires `copy` on the source for a copy-style entry).
fn mintAttachmentPf() ?u12 {
    const pf_caps = caps.PfCap{
        .copy = true,
        .r = true,
        .w = true,
    };
    const pf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props.sz = 0 (4 KiB)
        1, // pages
    );
    if (testing.isHandleError(pf.v1)) return null;
    return @truncate(pf.v1 & 0xFFF);
}

// Build the §[handle_attachments] pair entry for a copy-style transfer
// of the page-frame handle. Caps installed in W's domain copy of the
// handle are a subset of the source's caps.
fn buildPairEntry(pf_handle: u12) u64 {
    const transfer_caps = caps.PfCap{
        .copy = true,
        .r = true,
    };
    return (caps.PairEntry{
        .id = pf_handle,
        .caps = transfer_caps.toU16(),
        .move = false,
    }).toU64();
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Mint the result port. bind + recv + xfer is the full cap set
    // reply_transfer demands of the originating port (xfer is required
    // for N > 0; bind keeps the port alive while recv pulls W off it).
    const port_caps = caps.PortCap{
        .bind = true,
        .recv = true,
        .xfer = true,
    };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        // Port creation underpins both branches; treat as branch-A
        // setup failure so the assertion id is still in range.
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // ─── Branch A: originating EC handle has `write` cap ───────────
    {
        // W1 caps:
        //   - susp:    needed by §[suspend] [test 03] for the
        //              suspend(W1, port) call.
        //   - write:   the cap under test. Holding it on the
        //              originating EC handle is the precondition the
        //              spec line names for "modifications are applied".
        //   - read:    not strictly required (the test doesn't read
        //              the snapshot vregs), but harmless and matches
        //              the typical "controllable child" cap shape.
        //   - restart_policy = 0: keeps the call inside the runner-
        //              granted ec_restart_max ceiling and prevents
        //              any restart fallback from re-resurrecting W1.
        const w1_caps = caps.EcCap{
            .susp = true,
            .read = true,
            .write = true,
            .restart_policy = 0,
        };
        // Priority = 1 (normal) at bits 32-33 of the caps word so W1
        // is dispatchable on equal footing with the test EC. Without
        // this W1 would sit at the default pri=0 (idle) and the
        // yield-poll loop below could never witness an altEntry write
        // — the test EC always outranks an idle sibling on the run
        // queue.
        const ec_caps_word: u64 = @as(u64, w1_caps.toU16()) | (@as(u64, 1) << 32);
        const entry: u64 = @intFromPtr(&localDummyEntry);
        const cec = syscall.createExecutionContext(
            ec_caps_word,
            entry,
            1, // stack_pages
            0, // target = self
            0, // affinity = any core
        );
        if (testing.isHandleError(cec.v1)) {
            testing.fail(1);
            return;
        }
        const w1_handle: u12 = @truncate(cec.v1 & 0xFFF);

        const pf_handle_opt = mintAttachmentPf();
        if (pf_handle_opt == null) {
            testing.fail(2);
            return;
        }
        const pf_handle = pf_handle_opt.?;

        const sus = syscall.issueReg(.@"suspend", 0, .{
            .v1 = w1_handle,
            .v2 = port_handle,
        });
        if (sus.v1 != @intFromEnum(errors.Error.OK)) {
            testing.fail(3);
            return;
        }

        const new_rip: u64 = @intFromPtr(&altEntry1);
        const pair_entry: u64 = buildPairEntry(pf_handle);
        const r = recvAndReplyTransferWithRipMod(port_handle, new_rip, pair_entry);
        if (r.recv_status != @intFromEnum(errors.Error.OK)) {
            testing.fail(4);
            return;
        }
        if (r.xfer_status != @intFromEnum(errors.Error.OK)) {
            testing.fail(5);
            return;
        }

        // Yield-poll the side-channel global. Each iteration yields
        // to the scheduler so a same-core W has a chance to be
        // dispatched. Bound matches yield_03's heuristic.
        const MAX_ATTEMPTS: u32 = 64;
        var attempt: u32 = 0;
        var observed_a: u64 = BASELINE;
        while (attempt < MAX_ATTEMPTS) {
            yieldN(1);
            observed_a = @atomicLoad(u64, &result_1, .acquire);
            if (observed_a == SENTINEL) break;
            attempt += 1;
        }
        if (observed_a != SENTINEL) {
            testing.fail(6);
            return;
        }
    }

    // ─── Branch B: originating EC handle does NOT have `write` cap ─
    {
        // W2 caps mirror W1 but explicitly drop `write`. The spec line
        // gates the state-modification application on this single
        // cap; everything else is held constant so the only variable
        // between branch A and branch B is the cap under test.
        const w2_caps = caps.EcCap{
            .susp = true,
            .read = true,
            // .write intentionally omitted
            .restart_policy = 0,
        };
        // Priority = 1 (normal) for the same reason as branch A — see
        // comment there. Branch B asserts the SENTINEL is NOT
        // observed, but we still need W2 to be schedulable so it can
        // resume into its dummyEntry hlt loop. If the kernel
        // erroneously applied the RIP modification despite the
        // missing `write` cap, W2 must be capable of running for the
        // sentinel-distinct baseline to be falsified.
        const ec_caps_word: u64 = @as(u64, w2_caps.toU16()) | (@as(u64, 1) << 32);
        const entry: u64 = @intFromPtr(&localDummyEntry);
        const cec = syscall.createExecutionContext(
            ec_caps_word,
            entry,
            1,
            0,
            0,
        );
        if (testing.isHandleError(cec.v1)) {
            testing.fail(7);
            return;
        }
        const w2_handle: u12 = @truncate(cec.v1 & 0xFFF);

        const pf_handle_opt = mintAttachmentPf();
        if (pf_handle_opt == null) {
            testing.fail(8);
            return;
        }
        const pf_handle = pf_handle_opt.?;

        const sus = syscall.issueReg(.@"suspend", 0, .{
            .v1 = w2_handle,
            .v2 = port_handle,
        });
        if (sus.v1 != @intFromEnum(errors.Error.OK)) {
            testing.fail(9);
            return;
        }

        const new_rip: u64 = @intFromPtr(&altEntry2);
        const pair_entry: u64 = buildPairEntry(pf_handle);
        const r = recvAndReplyTransferWithRipMod(port_handle, new_rip, pair_entry);
        if (r.recv_status != @intFromEnum(errors.Error.OK)) {
            testing.fail(10);
            return;
        }
        if (r.xfer_status != @intFromEnum(errors.Error.OK)) {
            testing.fail(11);
            return;
        }

        // Yield-poll for the same bound; the spec demands the
        // sentinel NOT appear because the RIP modification must have
        // been discarded. We use the same iteration count as branch
        // A so any same-core scheduling that was sufficient to land
        // the write in branch A is also sufficient time for an
        // erroneous write here to land within the budget.
        const MAX_ATTEMPTS: u32 = 64;
        var attempt: u32 = 0;
        var observed_b: u64 = BASELINE;
        while (attempt < MAX_ATTEMPTS) {
            yieldN(1);
            observed_b = @atomicLoad(u64, &result_2, .acquire);
            if (observed_b == SENTINEL) break;
            attempt += 1;
        }
        if (observed_b == SENTINEL) {
            testing.fail(12);
            return;
        }
    }

    testing.pass();
}
