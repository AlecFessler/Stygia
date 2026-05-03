// Spec §[reply] reply — test 16.
//
// "[test 16] returns E_INVAL if two pair entries reference the same
//  source handle."
//
// Strategy
//   reply with pair_count > 0 takes a reply handle and N pair entries
//   in the high vregs [128-N..127]. The duplicate-source check fires
//   when two entries name the same source handle id in the caller's
//   domain, regardless of caps/move flag.
//
//   To reach the call we need a valid reply handle in our table. The
//   only way to mint one is `recv` on a port that has had a sender
//   suspended on it. So:
//     1. Mint a port with bind|recv|xfer caps. The xfer bit causes
//        the kernel to mint reply handles on this port with `xfer`
//        set (§[reply] cap minting rule), satisfying test 09's
//        requirement that the reply has `xfer` when pair_count > 0.
//     2. Mint a sibling EC with `susp|term` caps and restart_policy=0.
//        Its entry point is `dummyEntry` (halt-forever); execution
//        body is irrelevant — the EC only needs to exist and be
//        suspendable. restart_policy=0 keeps the create call within
//        the child domain's `restart_policy_ceiling.ec_restart_max`.
//     3. `suspend(sibling, port)` — sibling is dequeued onto the port's
//        suspended-sender queue. We do not attach handles, so the port
//        only needs `bind` for this step (§[suspend] test 04); xfer is
//        not required at suspend time.
//     4. `recv(port)` — the kernel mints a reply handle in our table
//        referencing the suspended sibling and returns its slot id in
//        the syscall word's `reply_handle_id` field (bits 32-43).
//     5. Issue `reply` with pair_count=2 pair entries that both
//        reference the SAME source handle. Per §[reply] test 16 the
//        kernel returns E_INVAL.
//
//   Failure-path neutralization for tests 01/09-15 in spec order:
//     - test 01 (E_BADCAP if [1] not a valid reply): id from recv.
//     - test 09 (E_PERM if reply lacks xfer): port had xfer at create;
//       reply inherits xfer per §[reply] minting rule.
//     - test 10 (E_INVAL if pair_count > 63): N=2.
//     - test 11 (E_INVAL on reserved bits in any pair entry): pair
//       entries packed via caps.PairEntry whose reserved fields
//       default to zero.
//     - test 12 (E_BADCAP if source invalid): we use SLOT_INITIAL_EC,
//       which is always valid in a freshly-spawned child per
//       §[create_capability_domain] test 21.
//     - test 13 (E_PERM if entry caps not subset of source caps):
//       entry caps = 0 (empty set), trivially a subset.
//     - test 14 (E_PERM if move=1 source lacks move): move=false.
//     - test 15 (E_PERM if move=0 source lacks copy): SLOT_INITIAL_EC
//       has caps = ec_inner_ceiling = 0xFF (see runner/primary.zig),
//       which sets bit 1 (`copy`).
//
//   reply's high-vreg pair layout sits at vregs 126-127 for N=2, far
//   above the 13 register-backed vregs. The libz `reply` wrapper
//   covers only the bare-reply path. We issue the syscall via local
//   inline asm: allocate a 920-byte stack pad (covering vregs 14..127
//   at 8 bytes each; vreg 127 = [rsp+912] after the syscall word push),
//   populate vregs 126 and 127 with the duplicate pair entries, push
//   the syscall word, and execute `syscall`. The word is
//   `syscall_num | (N << 12)` per §[syscall_abi] / libz.buildWord
//   with `extraCount(2) = 0x2000`.
//
// Action
//   1. create_port(caps={bind,recv,xfer,move,copy})       — must succeed
//   2. create_execution_context(caps={susp,term},
//                               entry=&dummyEntry,
//                               stack_pages=1, target=self,
//                               affinity=0)                — must succeed
//   3. suspend(sibling, port)                              — must succeed
//   4. recv(port)                                          — must succeed,
//      yields a reply handle id in syscall_word bits 32-43.
//   5. reply(reply, pair_count=2, [PairEntry{1,0,false},
//                                  PairEntry{1,0,false}])  — must return E_INVAL
//
// Assertions
//   1: create_port returned an error word.
//   2: create_execution_context returned an error word.
//   3: suspend returned non-OK.
//   4: recv returned non-OK or reply_handle_id == 0 (slot 0 is the
//      self handle, never used for replies).
//   5: reply returned something other than E_INVAL.

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

// Issue reply with pair_count=2 pair entries placed at vregs 126/127.
// Returns the kernel's error word from rax (vreg 1).
//
// Stack layout at the moment `syscall` executes (rsp = post-push):
//   [rsp + 0]    = syscall word (vreg 0)
//   [rsp + 8]    = vreg 14   ┐
//   ...                       │ 920 bytes covering vregs 14..127
//   [rsp + 904]  = vreg 126   │ (114 vregs × 8 bytes = 912; pad = 920)
//   [rsp + 912]  = vreg 127  ┘
//
// rcx is reserved for the syscall word (sysret clobber); r11 is
// likewise reserved. Memory clobber covers our pad writes.
fn issueReplyDup(reply_id: u12, entry: u64) u64 {
    // syscall_num = 52 (reply), pair_count=2 in bits 12-19,
    // reply_handle_id in bits 20-31 (per §[reply] ABI).
    const word: u64 =
        @as(u64, @intFromEnum(syscall.SyscallNum.reply)) |
        (@as(u64, 2) << 12) |
        ((@as(u64, reply_id) & 0xFFF) << 20);

    switch (builtin.cpu.arch) {
        .x86_64 => {
            var rax_out: u64 = undefined;
            asm volatile (
                \\ subq $920, %%rsp
                \\ movq %%rcx, (%%rsp)
                \\ movq %[entry], 904(%%rsp)
                \\ movq %[entry], 912(%%rsp)
                \\ syscall
                \\ addq $920, %%rsp
                : [rax] "={rax}" (rax_out),
                : [word] "{rcx}" (word),
                  [entry] "r" (entry),
                : .{ .rcx = true, .r11 = true, .memory = true });
            return rax_out;
        },
        .aarch64 => {
            // aarch64 high-vreg layout: vreg 126 = [sp + 760],
            // vreg 127 = [sp + 768]. Reserve 784 bytes.
            var x0_out: u64 = undefined;
            asm volatile (
                \\ sub sp, sp, #784
                \\ str %[word], [sp]
                \\ str %[entry], [sp, #760]
                \\ str %[entry], [sp, #768]
                \\ svc #0
                \\ add sp, sp, #784
                : [v1] "={x0}" (x0_out),
                : [word] "r" (word),
                  [entry] "r" (entry),
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

    // §[port] create_port: mint a port with bind+recv+xfer so this EC
    // can suspend a sibling on it (bind), pull the suspension event
    // out (recv), and have replies minted with the `xfer` cap (xfer).
    // move/copy are included to keep the caps word non-trivial; they
    // are not exercised by this test.
    const port_caps = caps.PortCap{
        .move = true,
        .copy = true,
        .xfer = true,
        .recv = true,
        .bind = true,
    };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // §[create_execution_context]: sibling EC with susp+term so we can
    // suspend it on the port. restart_policy=0 keeps the create within
    // the child domain's restart_policy_ceiling.ec_restart_max=2.
    // priority=0 keeps the EC within the child's pri ceiling of 3.
    const ec_caps = caps.EcCap{
        .susp = true,
        .term = true,
        .restart_policy = 0,
    };
    const caps_word: u64 = @as(u64, ec_caps.toU16());
    const entry: u64 = @intFromPtr(&localDummyEntry);
    const cec = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages
        0, // target = self
        0, // affinity = any
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(2);
        return;
    }
    const sibling: u12 = @truncate(cec.v1 & 0xFFF);

    // §[suspend]: deliver a suspension event for sibling onto our port.
    // No handle attachments at suspend time, so the port only needs
    // `bind` for this step.
    const susp_result = syscall.issueReg(.@"suspend", 0, .{
        .v1 = @as(u64, sibling),
        .v2 = @as(u64, port_handle),
    });
    if (susp_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // §[recv]: dequeue the suspension event. The kernel mints a reply
    // handle in our table and returns its slot id in syscall word
    // bits 32-43 (per §[recv]).
    const got = syscall.recv(port_handle, 0);
    const reply_id: u12 = @truncate((got.word >> 32) & 0xFFF);
    if (reply_id == 0) {
        testing.fail(4);
        return;
    }

    // §[reply] test 16: two pair entries naming the same source handle
    // id. SLOT_INITIAL_EC (slot 1) is always present in a freshly-
    // spawned child with caps = ec_inner_ceiling = 0xFF, so it has both
    // copy and move bits set — neutralizing tests 14/15. entry caps = 0
    // (empty subset) neutralizes test 13.
    const dup = caps.PairEntry{
        .id = caps.SLOT_INITIAL_EC,
        .caps = 0,
        .move = false,
    };
    const dup_word: u64 = dup.toU64();

    const err = issueReplyDup(reply_id, dup_word);
    if (err != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
