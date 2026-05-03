// Spec §[reply] reply_transfer — test 15.
//
// "[test 15] on success, the suspended EC is resumed."
//
// Strategy
//   reply_transfer's resumption contract: after the call consumes the
//   reply handle, the EC referenced by the reply (the dequeued sender)
//   becomes runnable again and resumes execution. Test 15 only requires
//   observing that resume — the handle-attachment payload is exercised
//   by tests 12/13 and the state-write semantics by test 14.
//
//   To witness the resumption inside a single test EC we materialize a
//   reply handle locally, then verify that consuming it via
//   reply_transfer causes the suspended sender's entry to actually run.
//
//   Setup pipeline (mirrors the terminate_07 reference for the
//   suspend/recv half, then extends with a custom entry for the
//   resumed-side observable):
//     1. Mint a port with bind|recv|xfer. `bind` lets the test EC
//        suspend an EC on it; `recv` lets the test EC dequeue the
//        suspension; `xfer` causes recv to mint the reply handle with
//        `xfer = 1` (the reply cap reply_transfer requires per
//        §[reply_transfer] [test 02]).
//     2. Mint a sibling EC W with caps {copy, term, susp, rp = 0}.
//        - `susp` lets the test EC queue W onto the port.
//        - `term` keeps the EC handle non-trivially scoped (matches
//          the reference template).
//        - `copy` lets us pass W's own EC handle as the
//          reply_transfer pair entry's source with move = 0
//          (§[handle_attachments] requires `copy` on a move = 0
//          source).
//        - rp = 0 (kill on domain restart) keeps the call inside the
//          runner-granted ec_inner_ceiling = 0xFF.
//        W's entry is `siblingEntry`, which writes RESUMED_MAGIC to
//        the static `resumed_marker` and busy-pauses. The marker
//        starts at 0, so observing RESUMED_MAGIC after the
//        reply_transfer is positive evidence W's entry actually
//        executed (i.e., W was resumed).
//     3. suspend(W, port) — non-blocking on the test EC since [1] !=
//        self (per §[suspend]: "[1] may reference the calling EC; the
//        syscall returns after the calling EC is resumed" — when [1]
//        is *not* the caller, suspend just queues the target).
//     4. recv(port) — returns immediately with reply_handle_id in the
//        syscall word's bits 32-43 (port has the test EC as a live
//        bind-cap holder, so no E_CLOSED; the table has plenty of
//        free slots, so no E_FULL).
//     5. Pre-condition: assert resumed_marker is still 0. W has not
//        run yet (it was suspended before any timeslice, and the
//        scheduler can't pick it while it sits on the port).
//     6. reply_transfer(reply_handle, [W move=0 caps={copy}]) — the
//        sole syscall under test. N = 1 (test 03 forbids N = 0). The
//        pair entry's source is W's EC handle in the test's table;
//        move = 0 with caps = {copy} satisfies §[handle_attachments]
//        test 05 (move = 0 requires `copy` on the source). Reply cap
//        `xfer` is present on the reply handle (the recv'ing port had
//        `xfer`, so recv minted the reply with `xfer = 1`).
//
//        SPEC AMBIGUITY: §[reply_transfer] places pair entries at
//        vregs `[128-N..127]` per §[handle_attachments]. The libz
//        `replyTransfer` wrapper still panics on N > 0 because the
//        high-vreg stack layout is not yet wired through the generic
//        `issueStack` helper. This test issues the syscall with
//        explicit inline asm: reserve 920 stack bytes for vregs
//        14..127, push the syscall word, then write the single pair
//        entry at `[rsp + 912]` (the post-push slot of vreg 127),
//        execute `syscall`, and unwind. The syscall word encodes
//        `syscall_num | (N << 12) | (reply_handle_id << 20)` per the
//        new §[reply_transfer] ABI (syscall_num bits 0-11, pair_count
//        bits 12-19, reply_handle_id bits 20-31).
//     7. yield(W) — §[yield] [test 03]: "when [1] is a valid handle to
//        a runnable EC, an observable side effect performed by the
//        target EC ... is visible to the caller before the caller's
//        next syscall returns." After the reply_transfer success, W
//        is runnable; yield(W) gives W the next slice. When yield
//        returns, W's atomic store of RESUMED_MAGIC must already be
//        visible to the test EC.
//     8. Assert resumed_marker == RESUMED_MAGIC.
//
//   Note: the resumed EC's domain is the same as the test EC's
//   domain (W was created with target = self), so the kernel inserts
//   the pair-entry handle into our own table at some [tstart, tstart+1)
//   slot. Per §[capabilities] handle-table coalescing: "Operations
//   that would mint a duplicate handle into a table already containing
//   one referencing the same object instead coalesce" — passing W's
//   handle to W's own domain coalesces with the existing slot, which
//   is fine. Test 15 asserts only resumption, not the placement
//   semantics that test 12 covers.
//
// Action
//   1. create_port({bind, recv, xfer})        — must succeed
//   2. create_execution_context(target=self,
//        caps={copy, term, susp, rp=0},
//        entry=&siblingEntry)                 — must succeed
//   3. suspend(W, port)                       — must return OK
//   4. recv(port)                             — must return OK and
//      yield reply_handle_id in the syscall word
//   5. assert resumed_marker == 0             — pre-condition
//   6. reply_transfer(reply_handle_id,
//        N=1, vreg127 = pair{src=W, caps=copy, move=0})
//                                             — must return OK
//   7. yield(W)                               — flushes W's side effect
//   8. assert resumed_marker == RESUMED_MAGIC
//
// Assertions
//   1: setup port creation failed (createPort returned an error word)
//   2: setup EC creation failed (createExecutionContext returned an
//      error word)
//   3: suspend did not return OK
//   4: recv did not return OK
//   5: pre-condition violated — marker was already set before
//      reply_transfer (W somehow ran before being suspended)
//   6: reply_transfer did not return OK
//   7: yield did not return OK
//   8: resumed_marker did not equal RESUMED_MAGIC after yield(W),
//      i.e., W never ran — the sender was not actually resumed

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const RESUMED_MAGIC: u64 = 0xC0FFEE;

// Lives in the domain's data segment. W and the test EC share the
// address space (same capability domain), so a write from W is visible
// to the test EC after a `yield(W)` per §[yield] test 03.
var resumed_marker: u64 = 0;

// W's entry. Writes RESUMED_MAGIC into the shared marker, then spins
// in a `pause` loop until the scheduler preempts. The atomic store
// with seq_cst ordering pins the visibility ordering relative to the
// test EC's read after yield(W).
fn siblingEntry() callconv(.c) noreturn {
    @atomicStore(u64, &resumed_marker, RESUMED_MAGIC, .seq_cst);
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("pause" ::: .{ .memory = true }),
            .aarch64 => asm volatile ("yield" ::: .{ .memory = true }),
            else => @compileError("unsupported target architecture"),
        }
    }
}

// reply_transfer with N = 1, single pair entry at vreg 127.
//
// The libz wrapper for reply_transfer is a stub (panics on N > 0)
// because §[handle_attachments] places pair entries at vregs
// [128-N..127] — the high end of the vreg space — and the generic
// `issueStack` helper does not yet thread that wide pad. The asm
// below is the minimal explicit form for the N = 1 case: reserve a
// 920-byte pad covering vregs 14..127, push the syscall word, write
// the pair entry into the slot that maps to vreg 127 once the word
// is on the stack, syscall, then unwind both the word and the pad.
//
// Layout during syscall (after `pushq %rcx`):
//   [rsp +   0] syscall word (vreg 0); carries reply_handle_id in
//               bits 20-31 per the new §[reply_transfer] ABI
//   [rsp +   8] vreg 14
//   ...
//   [rsp + 912] vreg 127 ← pair entry written here
//   [rsp + 920] caller-frame return ground
//
// Register-backed vregs are unused by reply_transfer per the new ABI
// (the reply_handle_id rides in the syscall word, not vreg 1) but are
// listed as clobbers because the syscall instruction's restore
// boundary may touch them.
fn replyTransferOne(reply_handle_id: u12, pair_entry: u64) u64 {
    const word: u64 = (@as(u64, 53) & 0xFFF) |
        (@as(u64, 1) << 12) |
        ((@as(u64, reply_handle_id) & 0xFFF) << 20);
    switch (builtin.cpu.arch) {
        .x86_64 => {
            var v1_out: u64 = undefined;
            asm volatile (
                \\ subq $920, %%rsp
                \\ pushq %%rcx
                \\ movq %%rdi, 912(%%rsp)
                \\ syscall
                \\ addq $928, %%rsp
                : [v1] "={rax}" (v1_out),
                : [pair] "{rdi}" (pair_entry),
                  [word] "{rcx}" (word),
                : .{ .rcx = true, .r11 = true, .memory = true });
            return v1_out;
        },
        .aarch64 => {
            // aarch64: vreg 127 = [sp + 768]; reserve 784 bytes.
            var x0_out: u64 = undefined;
            asm volatile (
                \\ sub sp, sp, #784
                \\ str %[word], [sp]
                \\ str %[pair], [sp, #768]
                \\ svc #0
                \\ add sp, sp, #784
                : [v1] "={x0}" (x0_out),
                : [word] "r" (word),
                  [pair] "r" (pair_entry),
                : .{ .x1 = true, .x2 = true, .x3 = true, .x4 = true, .x5 = true,
                     .x6 = true, .x7 = true, .x8 = true, .x9 = true, .x10 = true,
                     .x11 = true, .x12 = true, .x13 = true, .x14 = true, .x15 = true,
                     .x16 = true, .x17 = true, .x19 = true, .x20 = true, .x21 = true,
                     .x22 = true, .x23 = true, .x24 = true, .x25 = true, .x26 = true,
                     .x27 = true, .x28 = true, .x29 = true, .x30 = true, .memory = true });
            return x0_out;
        },
        else => @compileError("unsupported target architecture"),
    }
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint the port. xfer is required so that recv mints the
    // reply handle with `xfer = 1` — the reply cap §[reply_transfer]
    // [test 02] gates on. bind is required for suspend, recv is
    // required for recv. All three sit inside the runner-granted
    // port_ceiling = 0x1C (xfer | recv | bind).
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

    // Step 2: mint W. copy is needed so the reply_transfer pair entry
    // can carry W with move = 0 (§[handle_attachments] [test 05]:
    // move = 0 requires `copy` on the source). susp lets us queue W
    // onto the port. term is included for parity with the
    // reference terminate_07 template — not strictly required here.
    // restart_policy = 0 (kill) keeps the caps a subset of the
    // runner's ec_inner_ceiling = 0xFF.
    const w_caps = caps.EcCap{
        .copy = true,
        .term = true,
        .susp = true,
        .restart_policy = 0,
    };
    // §[create_execution_context] caps word: caps in bits 0-15,
    // target_caps in 16-31 (ignored when target = self), priority in
    // 32-33. priority = 0 stays inside the runner pri ceiling.
    const ec_caps_word: u64 = @as(u64, w_caps.toU16());
    const entry: u64 = @intFromPtr(&siblingEntry);
    const cec = syscall.createExecutionContext(
        ec_caps_word,
        entry,
        1, // stack_pages = 1 (4 KiB) is enough for the trivial entry
        0, // target = self
        0, // affinity = any
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(2);
        return;
    }
    const w_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // Step 3: queue W as a suspended sender on the port. Non-blocking
    // because [1] != self.
    const sus = syscall.issueReg(.@"suspend", 0, .{
        .v1 = w_handle,
        .v2 = port_handle,
    });
    if (sus.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Step 4: recv to materialize the reply handle. The reply handle
    // id lives in syscall word bits 32-43 per §[recv].
    const got = syscall.recv(port_handle, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }
    const reply_handle_id: u12 = @truncate((got.word >> 32) & 0xFFF);

    // Step 5: pre-condition — W has not run yet.
    if (@atomicLoad(u64, &resumed_marker, .seq_cst) != 0) {
        testing.fail(5);
        return;
    }

    // Step 6: reply_transfer. Build the pair entry referencing W with
    // caps = {copy} and move = 0 — the minimum that satisfies the
    // move/cap gating for the source. Caps installed in the receiver
    // (W's own domain = the test domain) are these caps verbatim
    // (W is not an IDC handle, so idc_rx does not intersect them).
    const pair_caps = caps.EcCap{ .copy = true };
    const pair = caps.PairEntry{
        .id = w_handle,
        .caps = pair_caps.toU16(),
        .move = false,
    };
    const rt_v1 = replyTransferOne(reply_handle_id, pair.toU64());
    if (rt_v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(6);
        return;
    }

    // Step 7: yield to W. §[yield] [test 03] guarantees W's side
    // effect is visible to the test EC before this syscall returns.
    const y = syscall.yieldEc(@as(u64, w_handle));
    if (y.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(7);
        return;
    }

    // Step 8: observe the marker. If reply_transfer truly resumed W,
    // W's entry has executed and the atomic store has landed.
    if (@atomicLoad(u64, &resumed_marker, .seq_cst) != RESUMED_MAGIC) {
        testing.fail(8);
        return;
    }

    testing.pass();
}
