// Spec §[suspend] — test 11.
//
// "[test 11] on success, when [1] has the `write` cap, modifications
//  written to the event payload are applied to the target's EC state on
//  reply; otherwise modifications are discarded."
//
// Strategy
//   The assertion needs a witness that proves a modification written by
//   the receiver between `recv` and `reply` lands on the suspended EC's
//   state when (and only when) the EC handle that triggered the
//   suspension carries the `write` cap. The cleanest user-visible
//   probe is a GPR: §[event_state] maps vreg 13 to r15 on x86-64, and
//   r15 is not used by libz for any wrapper machinery, so loading a
//   sentinel into v13 at reply time and having the resumed EC publish
//   r15 to a shared memory location is a direct read-out of the kernel
//   having applied the modification.
//
//   The test EC owns both ends of the pipeline:
//     - It mints a port with `bind | recv`.
//     - It mints a worker EC W with target = self (so W lives in the
//       same address space and can touch globals declared in this
//       file). W is given `susp + write` caps so suspending it routes
//       through the write-cap branch under test.
//     - W's entry function spins on a global `g_released` flag,
//       reads its r15 once `g_released` is non-zero, publishes the
//       value to a global `g_observed`, and halts.
//     - The test EC calls `suspend(W, port)` — W is queued as a
//       suspended sender and stops executing somewhere inside its
//       spin loop.
//     - The test EC calls `recv(port)` — the kernel hands back W's
//       captured GPR snapshot in vregs 1..13 plus a reply handle id
//       in the syscall word.
//     - The test EC sets `g_released = 1` so that, once W is
//       resumed, it immediately exits the spin loop and proceeds to
//       publish r15.
//     - The test EC issues `reply` with vreg 13 loaded with a
//       sentinel value `MAGIC`. By the spec line under test, the
//       kernel applies vreg 13 to W's r15 because W's EC handle had
//       the `write` cap.
//     - The test EC spin-waits on `g_observed`; when it lands on
//       `MAGIC` the modification has been observed end-to-end.
//
//   The sibling assertion (suspend_12: write-cap absent → modifications
//   discarded) is a separate test file. This file exercises only the
//   write-cap-present branch.
//
// Why r15 (vreg 13) and not a lower-numbered GPR
//   libz's `issueReg` puts the syscall input vregs into hardware GPRs
//   (rax, rbx, rdx, rbp, rsi, rdi, r8, r9, r10, r12, r13, r14, r15) so
//   that *all 13* are loaded at syscall entry. v3/v4 are the result-
//   encoding lane the runner expects when the test EC eventually
//   pass()/fail()s. r15 / vreg 13 is the highest-numbered GPR-backed
//   lane, sits clear of those conventions, and is the easiest to read
//   out from the worker via a single `mov %%r15, ...` inline asm.
//   Under the new ABI the reply_handle_id rides in the syscall word
//   (bits 12-23 per §[reply]) rather than in vreg 1, so vregs 1..13
//   are all available as receiver state-mod inputs through the syscall.
//
// Why target=self for W
//   `create_execution_context` with [4] = 0 places W in the test's own
//   capability domain. That keeps W's entry inside the test ELF's
//   text (no need to set up a separate page frame / loader) and lets
//   W and the test EC share globals via .data. Both required caps
//   (`susp` and `write`) are within the runner's `ec_inner_ceiling`
//   which spans bits 0-7 of EcCap (move/copy/saff/spri/term/susp/read/
//   write) per primary.zig.
//
// Why a runtime spin instead of `hlt`
//   `hlt` from CPL3 #GPs (and we'd need `bind`/event-route plumbing to
//   surface that as a fault event the test could observe). A bounded
//   busy-wait on a u64 with `pause` keeps W in a predictable state
//   (i.e., touching no GPRs other than the loop addr/value pair) and
//   leaves r15 free for the kernel to overwrite at resume.
//
// Action
//   1. create_port(caps={bind, recv})             — must succeed
//   2. create_execution_context(target=self,
//        caps={susp, write, restart_policy=0})    — must succeed
//   3. suspend(W, port)                           — must return OK
//   4. recv(port)                                 — must return OK
//   5. set g_released = 1                         — local store
//   6. reply(reply_handle, vreg13 = MAGIC)        — must return OK,
//                                                   carrying the
//                                                   modification
//   7. spin until g_observed != 0                 — bounded by W's
//                                                   wakeup latency
//   8. assert g_observed == MAGIC                 — the spec line
//
// Assertions
//   1: create_port returned an error word
//   2: create_execution_context returned an error word
//   3: suspend did not return OK
//   4: recv did not return OK
//   5: reply did not return OK
//   6: g_observed differed from MAGIC after W resumed (the kernel
//      either dropped the modification entirely or applied a
//      different value)
//
// SPEC AMBIGUITY
//   §[event_state] (line 1852) says GPR-lane vregs are "1:1 with
//   hardware registers during handler execution." It does not pin
//   whether the kernel snapshots GPRs at recv time or whether the
//   recv path simply leaves the suspended EC's GPRs sitting in the
//   physical registers across the context switch. Either reading
//   yields the same observable behavior for this test: the value the
//   receiver places into its v13 input when issuing `reply` is what
//   ends up in W's r15 on resume.

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const MAGIC: u64 = 0xCAFEBABEDEADBEEF;

// Runtime-init globals so the linker keeps them in .bss (their initial
// zero values are exactly what `g_released == 0`/`g_observed == 0`
// require). Both are touched cross-EC, so accesses use atomics with
// acquire/release ordering to avoid the compiler hoisting loads out of
// the spin loop.
var g_released: u64 = 0;
var g_observed: u64 = 0;

fn workerEntry() callconv(.c) noreturn {
    // Spin until the test EC sets `g_released`. The acquire ordering
    // pairs with the release store on the test side and prevents the
    // compiler from caching the load across iterations.
    while (@atomicLoad(u64, &g_released, .acquire) == 0) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("pause"),
            .aarch64 => asm volatile ("yield"),
            else => @compileError("unsupported arch"),
        }
    }

    // Read the vreg-13 backing register directly. Per §[event_state],
    // when W's EC handle had the `write` cap, the kernel applied the
    // receiver's v13 input (== MAGIC) to W's vreg-13 backing register
    // across the suspend/reply cycle. We capture the post-resume
    // value here without any compiler-introduced intermediate use.
    //   x86-64: vreg 13 = r15
    //   aarch64: vreg 13 = x12 (vreg 1..31 = x0..x30)
    var observed: u64 = undefined;
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("movq %%r15, %[out]"
            : [out] "=r" (observed),
            :
            : .{ .memory = false }),
        .aarch64 => asm volatile ("mov %[out], x12"
            : [out] "=r" (observed),
            :
            : .{ .memory = false }),
        else => @compileError("unsupported arch"),
    }

    @atomicStore(u64, &g_observed, observed, .release);

    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfi"),
            else => @compileError("unsupported arch"),
        }
    }
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint the result port. bind + recv are the minimum cap
    // set: the test EC keeps a live bind-cap holder so recv won't
    // return E_CLOSED, and recv itself requires the `recv` cap.
    const port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: mint W with the spec-required caps.
    //   susp  — gates the suspend syscall on this EC handle
    //   write — gates whether modifications written to the event
    //           payload land back on W's state at reply time
    //   restart_policy = 0 (kill) — keeps W from being silently
    //           resurrected by a domain restart fallback if W's
    //           hlt ever traps
    const w_caps = caps.EcCap{
        .susp = true,
        .write = true,
        .restart_policy = 0,
    };
    // §[create_execution_context] caps word: caps in bits 0-15.
    // priority = 0 stays inside the runner's pri ceiling (3).
    const ec_caps_word: u64 = @as(u64, w_caps.toU16());
    const entry: u64 = @intFromPtr(&workerEntry);
    const cec = syscall.createExecutionContext(
        ec_caps_word,
        entry,
        1, // stack_pages: 1 is enough — workerEntry uses no stack
        0, // target = self
        0, // affinity = any core
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(2);
        return;
    }
    const w_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // Step 3: queue W as a suspended sender on the port. libz's
    // `suspendEc` panics on N>0 attachments and pre-loads vregs we
    // don't want clobbered, so we issue the syscall directly with
    // pair_count = 0.
    const sus = syscall.issueReg(.@"suspend", 0, .{
        .v1 = w_handle,
        .v2 = port_handle,
    });
    if (sus.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Step 4: recv. The port has the test EC as a live bind-cap
    // holder and W queued as a suspension event, so recv returns
    // immediately. The reply handle id rides in syscall word bits
    // 32-43 per §[event_state].
    const got = syscall.recv(port_handle, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }
    const reply_handle_id: u12 = @truncate((got.word >> 32) & 0xFFF);

    // Step 5: arm the worker. W is still suspended at this point, so
    // the store cannot be observed until reply lands.
    @atomicStore(u64, &g_released, 1, .release);

    // Step 6: reply with vreg 13 (== r15 on x86-64, per §[event_state])
    // loaded with the sentinel. The kernel applies this to W's r15
    // because W's EC handle had the `write` cap. We bypass the libz
    // `reply` wrapper because that wrapper zeroes vregs 1..13. Under
    // the new ABI the reply_handle_id rides in the syscall word
    // (bits 12-23 per §[reply]).
    const reply_extra: u64 = (@as(u64, reply_handle_id) & 0xFFF) << 12;
    const r = syscall.issueReg(.reply, reply_extra, .{
        .v13 = MAGIC,
    });
    if (r.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(5);
        return;
    }

    // Step 7: spin until W publishes its post-resume r15. The test EC
    // is at runner priority (pri=3) and W is at pri=0, so a plain busy
    // spin starves W under strict-priority scheduling. Yield explicitly
    // to W's handle on each iteration — yield-to-target removes the
    // named EC from its queue regardless of relative priority — so W
    // gets scheduled, completes its r15 read, and stores g_observed.
    // A purely unbounded spin would deadlock if reply silently failed
    // to resume W; the runner's outer scheduling will eventually
    // surface that as a hung test, which is the correct user-visible
    // failure mode.
    while (@atomicLoad(u64, &g_observed, .acquire) == 0) {
        _ = syscall.yieldEc(w_handle);
    }

    // Step 8: confirm the kernel applied our modification verbatim.
    if (@atomicLoad(u64, &g_observed, .acquire) != MAGIC) {
        testing.fail(6);
        return;
    }

    testing.pass();
}
