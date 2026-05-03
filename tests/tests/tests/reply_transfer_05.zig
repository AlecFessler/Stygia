// Spec §[reply] reply_transfer — test 05.
//
// "[test 05] returns E_BADCAP if any pair entry's source handle id is
//  not valid in the caller's domain."
//
// Strategy
//   The assertion needs the kernel to reach the per-entry source-id
//   validation step. To get that far the call must:
//     - present a valid reply handle (else test 01 fires first),
//     - present a reply handle whose `xfer` cap is set (else test 02
//       fires first),
//     - carry 1 ≤ N ≤ 63 (else test 03),
//     - keep all reserved bits cleared in [1] and the pair entry (else
//       test 04),
//     - keep pair-entry source ids unique (else test 09; trivial here
//       because N=1).
//
//   Producing a valid reply handle with `xfer` requires a port that
//   has the `xfer` cap at recv time — per §[reply] the kernel mints
//   the reply handle with `xfer = 1` if and only if the recv'ing port
//   had the `xfer` cap. The runner-granted port_ceiling allows
//   `xfer | recv | bind` (caps bits 2-4), so the test mints the port
//   with all three.
//
//   Pipeline: mint a port with {bind, recv, xfer}; mint EC W with
//   {term, susp, restart_policy=0}; suspend(W, port) to queue W as a
//   suspended sender; recv(port) to dequeue the suspension and pull
//   back the reply handle id in the recv syscall word's bits 32-43;
//   call reply_transfer with N=1 and a single pair entry whose source
//   id is `0xFFF` (slot 4095 — well above any handle the test EC has
//   ever allocated; the test EC's used slots are all clustered near
//   the bottom of the table).
//
//   The pair entry's `caps` field is set to a single bit (`move = 1`
//   in the entry's caps word, bit 16) and the entry's `move` flag (bit
//   32) is set so reserved-bit validation (§[handle_attachments] test
//   06 / reply_transfer test 04) passes; the unused reserved bits stay
//   zero.
//
// reply_transfer ABI
//   Spec §[reply].reply_transfer:
//
//     reply_transfer([1] reply, [128-N..127] pair_entries) -> void
//       syscall_num = 53
//       syscall word bits 12-19: N (1..63)
//
//   With N=1 the single pair entry occupies vreg 127. Per §[syscall_abi]
//   vreg N for 14 ≤ N ≤ 127 lives at [rsp + (N-13)*8] when the syscall
//   executes. For vreg 127 that is [rsp + 912]. libz's `replyTransfer`
//   wrapper panics on N>0 (the high-vreg path is unwired in v0), so this
//   test issues the syscall via inline asm: subq the high-vreg pad,
//   write the entry into the vreg-127 slot, push the syscall word so the
//   kernel sees vreg 0 at [rsp + 0], `syscall`, then unwind.
//
// Action
//   1. create_port(caps={bind, recv, xfer})    — must succeed
//   2. create_execution_context(target=self,
//        caps={term, susp, rp=0})              — must succeed
//   3. suspend(W, port)                        — must return OK
//      (non-blocking on the test EC since [1] != self)
//   4. recv(port)                              — must return OK and
//      yield a reply_handle_id in the syscall word
//   5. reply_transfer(reply_handle_id,
//        pair_entry={id=0xFFF, caps=move,
//        move=1})                              — must return E_BADCAP
//
// Assertions
//   1: setup port creation failed (createPort returned an error word)
//   2: setup EC creation failed (createExecutionContext returned an
//      error word)
//   3: suspend itself did not return OK
//   4: recv did not return OK
//   5: reply_transfer returned something other than E_BADCAP

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Local halt-forever entry. libz `testing.dummyEntry` uses bare `hlt`,
// which only assembles on x86. Mirror it here with arch dispatch so
// the test EC compiles on aarch64 too.
fn localDummyEntry() noreturn {
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfi"),
            else => @compileError("unsupported target architecture"),
        }
    }
}

// Inline-asm reply_transfer for N=1. The single pair entry is placed at
// vreg 127. On x86 vreg 127 = [rsp + 912]; on aarch64 vreg 127 =
// [sp + 768]. Returns the kernel's vreg 1 (rax/x0) — the error code or
// 0 on success.
fn replyTransferOneEntry(reply_handle_id: u12, pair_entry: u64) u64 {
    // Spec §[syscall_abi] / §[reply_transfer]: syscall_num in bits 0-11;
    // pair_count `N` in bits 12-19; reply_handle_id in bits 20-31. N=1.
    const word: u64 = (@as(u64, 53) & 0xFFF) |
        ((@as(u64, 1) & 0xFF) << 12) |
        ((@as(u64, reply_handle_id) & 0xFFF) << 20);

    switch (builtin.cpu.arch) {
        .x86_64 => {
            var ov1: u64 = undefined;
            asm volatile (
                \\ subq $912, %%rsp
                \\ movq %[entry], 904(%%rsp)
                \\ pushq %%rcx
                \\ syscall
                \\ addq $920, %%rsp
                : [v1] "={rax}" (ov1),
                : [word] "{rcx}" (word),
                  [entry] "{rdi}" (pair_entry),
                : .{ .rcx = true, .r11 = true, .memory = true });
            return ov1;
        },
        .aarch64 => {
            var ov1: u64 = undefined;
            asm volatile (
                \\ sub sp, sp, #784
                \\ str %[word], [sp]
                \\ str %[entry], [sp, #768]
                \\ svc #0
                \\ add sp, sp, #784
                : [v1] "={x0}" (ov1),
                : [word] "r" (word),
                  [entry] "r" (pair_entry),
                : .{ .x1 = true, .x2 = true, .x3 = true, .x4 = true, .x5 = true,
                     .x6 = true, .x7 = true, .x8 = true, .x9 = true, .x10 = true,
                     .x11 = true, .x12 = true, .x13 = true, .x14 = true, .x15 = true,
                     .x16 = true, .x17 = true, .x19 = true, .x20 = true, .x21 = true,
                     .x22 = true, .x23 = true, .x24 = true, .x25 = true, .x26 = true,
                     .x27 = true, .x28 = true, .x29 = true, .x30 = true, .memory = true });
            return ov1;
        },
        else => @compileError("unsupported target architecture"),
    }
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint the port. xfer is required so the reply handle the
    // kernel mints at recv has its `xfer` cap (else reply_transfer
    // test 02 fires before test 05's source-id check).
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

    // Step 2: mint W. susp queues W as a suspended sender; term keeps
    // the sender controllable; restart_policy=0 keeps W inside the
    // runner-granted ceiling and prevents domain-restart from masking
    // the test's lifetime guarantees.
    const w_caps = caps.EcCap{
        .term = true,
        .susp = true,
        .restart_policy = 0,
    };
    const ec_caps_word: u64 = @as(u64, w_caps.toU16());
    const entry: u64 = @intFromPtr(&localDummyEntry);
    const cec = syscall.createExecutionContext(
        ec_caps_word,
        entry,
        1,
        0,
        0,
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(2);
        return;
    }
    const w_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // Step 3: queue W as a suspended sender on the port. [1] != self so
    // the call returns immediately rather than blocking the test EC.
    const sus = syscall.issueReg(.@"suspend", 0, .{
        .v1 = w_handle,
        .v2 = port_handle,
    });
    if (sus.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Step 4: recv. Port has the test EC as a live bind-cap holder and
    // W queued as a suspension event, so recv returns immediately with
    // the reply handle id encoded in the syscall word's bits 32-43.
    const got = syscall.recv(port_handle, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }
    const reply_handle_id: u12 = @truncate((got.word >> 32) & 0xFFF);

    // Step 5: reply_transfer with one pair entry whose source id is
    // 4095 — far outside the test EC's used handle range. Per §[reply]
    // reply_transfer test 05, this must surface E_BADCAP.
    //
    // Pair entry encoding (§[handle_attachments]):
    //   bits  0-11: source handle id  = 0xFFF
    //   bits 12-15: _reserved         = 0
    //   bits 16-31: caps              = 0x0001 (move only — minimal
    //                                            valid bit pattern)
    //   bit     32: move              = 1
    //   bits 33-63: _reserved         = 0
    const pair_entry = (caps.PairEntry{
        .id = 0xFFF,
        .caps = (caps.IdcCap{ .move = true }).toU16(),
        .move = true,
    }).toU64();

    const result = replyTransferOneEntry(reply_handle_id, pair_entry);
    if (result != @intFromEnum(errors.Error.E_BADCAP)) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
