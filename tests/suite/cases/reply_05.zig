// Spec §[reply] reply — test 05.
//
// "[test 05] on success when the originating EC handle had the `write`
//  cap, the resumed EC's state reflects modifications written to the
//  receiver's event-state vregs between recv and reply."
//
// Strategy
//   §[event_state] spells out the wiring this assertion rides on:
//   "GPRs are 1:1 with hardware registers during handler execution —
//   the handler reads or modifies EC state by directly reading or
//   writing the hardware register." Between `recv` returning and the
//   `reply` syscall executing, the receiver's GPRs *are* the suspended
//   EC's GPRs. With the originating EC handle's `write` cap present,
//   the kernel resumes the suspended EC with whatever values the
//   receiver leaves in its GPRs at reply-time; with `write` absent,
//   the kernel restores the pre-suspension snapshot (the negative is
//   covered by reply test 06).
//
//   To witness the positive direction we need a suspended EC W whose
//   originating handle carries `write`, plus an observable that W
//   produces deterministically as a function of one of its registers.
//   The test EC and W share an address space (W is created with
//   `target = self`), so W can simply store one of its own registers
//   into a process-global cell. We pick `rbx` (vreg 2) because:
//     - it is part of the §[event_state] x86-64 GPR set (vregs 1..13),
//     - the new `reply` ABI carries the reply_handle_id in the syscall
//       word (bits 12-23) rather than vreg 1, so every register-backed
//       vreg 1..13 is free to carry receiver state mods through the
//       syscall — no GPR is wasted on plumbing the handle,
//     - it is callee-saved in SysV, but W's entry is a naked function
//       so no prologue clobbers it before the store.
//
//   The flow:
//     1. Mint a port with {bind, recv}.
//     2. Mint W with {term, susp, read, write, restart_policy=0} and
//        entry = `observerEntry` (naked: `mov [observed], rbx; spin`).
//        `term` so the test EC can clean up; `susp` so the test EC may
//        suspend W; `read`+`write` so the suspension event exposes and
//        consumes W's state per §[event_state]; restart_policy=0
//        keeps the call inside the runner-granted ec_restart_max.
//     3. `suspend(W, port)`. W has not run; kernel queues it as a
//        suspended sender on the port with a fresh GPR snapshot
//        (kernel-initialized — typically zero).
//     4. `recv(port)`. recv returns immediately because the test EC
//        still holds the port's bind cap. The syscall word carries
//        `reply_handle_id` per §[event_state].
//     5. Issue `reply` with vreg 2 (rbx) = MAGIC. The reply_handle_id
//        rides in the syscall word (bits 12-23) per §[reply]; vregs
//        1..13 are the GPR snapshot the kernel will hand back to W,
//        with vreg 1 (rax) freed up for receiver state modifications
//        under the new ABI.
//     6. `yield(W)` to schedule W. W executes the `mov` storing rbx
//        (now MAGIC) into `observed`, then spins.
//     7. Poll `observed` (with bounded yields to the scheduler so the
//        test EC re-runs after W's timeslice expires).
//
// Action
//   1. create_port(caps={bind, recv})
//   2. create_execution_context(target=self,
//        caps={term, susp, read, write, restart_policy=0},
//        entry=&observerEntry)
//   3. suspend(W, port)                   — must return OK
//   4. recv(port)                         — must return OK
//   5. issueReg(.reply, replyExtra(rid), {v2=MAGIC}) — OK
//      (reply_handle_id rides in syscall-word bits 12-23 under the new
//       ABI; vreg 2 carries the rbx state mod)
//   6. yield(W)                           — schedule W
//   7. poll observed (bounded) until MAGIC or limit hit
//   8. assert observed == MAGIC
//
// Assertions
//   1: setup port creation failed
//   2: setup EC creation failed
//   3: suspend did not return OK
//   4: recv did not return OK
//   5: reply did not return OK
//   6: observed never picked up the MAGIC value W should have written
//      after the reply applied the modified rbx

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Cell W stores its rbx into. Sentinel 0 is distinguishable from MAGIC
// (a non-zero pattern) so a "never wrote" outcome is detectable. The
// test EC and W share an address space (W is created with target=self
// in step 2 below), so W writes here directly. `export` so the inline
// asm can address it via rip-relative addressing; an "m" memory operand
// would route through a stack temp, which a naked entry has no
// well-formed frame for (mirrors the reply_transfer_14 precedent).
export var observed: u64 = 0;

const MAGIC: u64 = 0xC0FFEE_CAFE_BEEF_50;

// W's entry. Naked so no function prologue clobbers vreg 2 (rbx on
// x86-64, x1 on aarch64) before the store. The store uses
// PC-relative addressing on the exported `observed` symbol directly
// — no asm operands, so LLVM cannot spill through the (nonexistent)
// stack frame. After the store W spins so it neither faults nor races
// the test EC's reporter — the runner only cares about the test EC's
// eventual `pass()`/`fail()` suspension on the result port; W never
// touches the result port.
fn observerEntry() callconv(.naked) noreturn {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile (
            \\ movq %%rbx, observed(%%rip)
            \\ 1: pause
            \\    jmp 1b
            ::: .{ .memory = true }),
        .aarch64 => asm volatile (
            \\ adrp x2, observed
            \\ add x2, x2, :lo12:observed
            \\ str x1, [x2]
            \\ 1: yield
            \\    b 1b
            ::: .{ .memory = true }),
        else => @compileError("unsupported arch"),
    }
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint the port. bind keeps the port alive for the recv
    // (no E_CLOSED on the recv path); recv lets the test EC dequeue
    // the suspension event.
    const port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: mint W. read+write are the caps under test for this
    // assertion — read so the recv exposes W's state per §[event_state]
    // (without it, the receiver's vregs would be zeroed per recv test
    // 12), write so reply applies the receiver's GPR modifications to
    // W on resume (the assertion under test). susp lets the test EC
    // suspend W; term lets a future revision tear W down explicitly
    // (currently W just spins after the store and is reaped when its
    // domain — i.e. the test EC's domain — exits). restart_policy=0
    // (kill) stays inside the runner's ec_restart_max ceiling.
    const w_caps = caps.EcCap{
        .term = true,
        .susp = true,
        .read = true,
        .write = true,
        .restart_policy = 0,
    };
    const ec_caps_word: u64 = @as(u64, w_caps.toU16());
    const entry: u64 = @intFromPtr(&observerEntry);
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

    // Step 3: queue W as a suspended sender on the port. Per §[suspend]
    // when [1] != self, the call returns immediately after queuing the
    // target. W has not yet been scheduled so its GPR snapshot is the
    // kernel's freshly-initialized state.
    const sus = syscall.issueReg(.@"suspend", 0, .{
        .v1 = w_handle,
        .v2 = port_handle,
    });
    if (sus.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Step 4: recv. With the test EC as a live bind-cap holder and W
    // queued, recv returns immediately. The syscall word's bits 32-43
    // carry the reply handle id per §[event_state].
    const got = syscall.recv(port_handle, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }
    const reply_handle_id: u12 = @truncate((got.word >> 32) & 0xFFF);

    // Step 5: issue reply with rbx (vreg 2) modified to MAGIC. Under
    // the new ABI the reply_handle_id rides in the syscall word
    // (bits 12-23) rather than in vreg 1, freeing every register-backed
    // vreg to carry receiver state mods through the syscall. With the
    // `write` cap on W's originating handle the kernel resumes W with
    // the receiver's current rbx — which is MAGIC by the time the
    // syscall executes.
    const reply_extra: u64 = (@as(u64, reply_handle_id) & 0xFFF) << 20;
    const rep = syscall.issueReg(.reply, reply_extra, .{
        .v2 = MAGIC,
    });
    if (rep.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(5);
        return;
    }

    // Step 6+7: schedule W and poll. Each iteration explicitly yields to
    // W (mirroring yield_03's bounded poll-and-yield-target pattern) and
    // then re-checks the side-channel. Yielding to the generic scheduler
    // (`yieldEc(0)`) is insufficient here because W has the default
    // priority (idle) — lower than the test EC's normal — so a
    // round-robin pick would always re-dispatch the test EC and starve
    // W. Re-yielding to W on every iteration matches the spec's
    // observable-progress contract: yield(W) gives W the CPU, so any
    // dispatch that gets robbed of its first-instruction window by an
    // immediate preemption (a tick that pended in the kernel-mode IF=0
    // window before the iretq into W) is recoverable on the next
    // iteration rather than starving forever.
    var i: usize = 0;
    while (i < 1024) {
        if (@as(*volatile u64, &observed).* == MAGIC) break;
        _ = syscall.yieldEc(w_handle);
        i += 1;
    }

    if (@as(*volatile u64, &observed).* != MAGIC) {
        testing.fail(6);
        return;
    }

    testing.pass();
}
