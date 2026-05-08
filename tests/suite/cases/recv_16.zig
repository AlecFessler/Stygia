// Spec §[recv] recv — test 16.
//
// "[test 16] on success, until the reply handle is consumed, the
//  dequeued sender remains suspended; deleting the reply handle
//  resolves the sender with E_ABANDONED."
//
// Strategy
//   The assertion has two halves and a single setup can witness both:
//     (a) After recv mints the reply handle, the dequeued sender stays
//         suspended until the reply handle is consumed.
//     (b) Deleting the reply handle (one of the two consume paths;
//         `reply` is the other) resumes the sender with E_ABANDONED.
//
//   Producing a sender that observably reports E_ABANDONED requires the
//   sender to *itself* call `suspend(self, port)` so that there is a
//   blocked syscall whose return value is the kernel's resolution
//   verdict. recv_07's pattern (test EC issues `suspend(W, port)` with
//   [1] != self) queues W as a suspended sender but W never made a
//   syscall — there is no syscall return for the kernel to resolve, so
//   E_ABANDONED is not directly observable. recv_16 instead spawns a
//   worker EC W in the same capability domain, hands W the slot id of
//   its own EC handle through a shared global, and has W issue
//   `suspend(self_slot, port)` from `workerEntry`. That is the syscall
//   the kernel resumes with E_ABANDONED on delete; W stores the result
//   in a shared global before halting.
//
//   Witness for (a). Yield to the worker so it reaches the blocking
//   suspend syscall. After recv returns to the test EC, yield to W
//   again and observe `worker_done == 0` — W has not yet returned from
//   suspend. Per §[capabilities] line 176, the only paths that resolve
//   the suspended sender are reply on the reply handle and delete on
//   the reply handle; the test has done neither between recv and this
//   probe, so any non-zero `worker_done` here would falsify "remains
//   suspended until the reply handle is consumed."
//
//   Witness for (b). After observing (a), call `delete(reply_handle)`.
//   Per §[capabilities] line 176 ("If the suspended sender is still
//   waiting, resume them with E_ABANDONED. Release handle"), the
//   kernel resumes W's `suspend` syscall with E_ABANDONED in vreg 1.
//   W captures that into `worker_result`, releases `worker_done`, and
//   halts. The test EC bounded-yield-polls `worker_done`; on
//   observation the recorded result must equal E_ABANDONED.
//
//   Both ECs run in the same capability domain (target=0 on the
//   create_execution_context call), so they share the address space —
//   `worker_self_slot`, `worker_result`, and `worker_done` are
//   process-global side channels reachable from both ends. The handle
//   table is also shared, so the slot id the test EC sees for W is the
//   same id W uses on its self-suspend.
//
//   Pre-call gates the test must clear so no other failure path can
//   mask the assertion under test:
//     - §[create_port] tests 01-04: runner self-handle has `crpt`,
//       caps {bind,recv} ⊆ port_ceiling, no reserved bits set.
//     - §[create_execution_context] tests 01,03,06,08,09,10: runner
//       self-handle has `crec`; w_caps ⊆ ec_inner_ceiling; priority 0;
//       stack_pages 1; affinity 0; reserved bits clear.
//     - §[suspend] tests 01-07 from W's side:
//         test 01 (E_BADCAP): W reads worker_self_slot, which the
//           test EC publishes from the createExecutionContext result.
//         test 02 (E_BADCAP for [2]): port slot is the freshly-minted
//           handle id captured by the test EC.
//         test 03 (E_PERM no `susp`): w_caps.susp = true.
//         test 04 (E_PERM no `bind` on port): port_caps.bind = true.
//         test 05 (reserved bits): syscall.suspendEc zero-fills.
//         test 06 (vCPU): W is a regular EC.
//         test 07 (already suspended): W is freshly created and never
//           prior-suspended.
//     - §[recv] tests 01-06 from the test EC's side:
//         01 (BADCAP): port_handle is the freshly-minted handle.
//         02 (no `recv` cap): port_caps.recv = true.
//         03 (reserved bits): libz wrapper takes u12 and zero-extends.
//         04 (E_CLOSED no bind/route/queue): the test EC holds the
//           port handle with the bind cap, and W queues a suspension
//           event before the test EC recvs.
//         05 (E_CLOSED on blocked recv when bind drops): the test EC
//           never deletes the port handle.
//         06 (E_FULL): the test domain has plenty of free slots for
//           the reply handle and the zero attached handles.
//
// Action
//   1. create_port(caps={bind, recv})            — must succeed
//   2. create_execution_context(target=self, caps={susp, term, rp=0},
//        entry=&workerEntry, stack_pages=1, affinity=0)
//                                                 — must succeed
//   3. publish worker_self_slot, worker_port_slot to W; yield(W)
//      so W reaches its blocking suspend syscall (best-effort —
//      multi-core may run W concurrently; either path resolves to W
//      blocked on the port by the time recv runs)
//   4. recv(port)                                — must return OK
//      (test EC holds the port's bind cap → no E_CLOSED; reply slot
//      and zero attached handles fit easily → no E_FULL)
//   5. yield(W); witness (a) — `worker_done` must still be 0
//   6. delete(reply_handle)                      — must return OK
//   7. bounded yield-and-poll on `worker_done`; on observation
//      `worker_result` must equal E_ABANDONED — witness (b)
//
// Assertions
//   1: setup port creation failed (createPort returned an error word)
//   2: setup EC creation failed (createExecutionContext returned an
//      error word)
//   3: pre-recv yield to the worker did not return OK
//   4: recv did not return OK
//   5: post-recv `worker_done` was non-zero — the dequeued sender did
//      not remain suspended until the reply handle was consumed
//   6: delete on the reply handle did not return OK
//   7: worker did not signal completion within the bounded poll window
//   8: worker observed something other than E_ABANDONED on its
//      blocked suspend — deleting the reply handle did not resolve
//      the sender with E_ABANDONED

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Process-global side channels. Both ECs run in the same capability
// domain, so they share the address space and the handle table.
//   - worker_self_slot: the slot id of W's own EC handle, published by
//     the test EC after createExecutionContext returns. W reads it on
//     entry to issue suspend(self, port).
//   - worker_port_slot: the slot id of the port the test EC mints. W
//     uses it as the suspend target port.
//   - worker_result: the vreg-1 return value of W's suspend syscall.
//     The test EC reads it after worker_done flips to 1 to verify
//     E_ABANDONED.
//   - worker_done: release-store flag W flips after suspend returns;
//     the test EC acquire-loads it as the synchronisation edge.
var worker_self_slot: u12 = 0;
var worker_port_slot: u12 = 0;
var worker_result: u64 = 0;
var worker_done: u64 = 0;

fn workerEntry() callconv(.c) noreturn {
    // The test EC publishes both slot ids before createExecutionContext
    // returns, so the worker's first read sees them. No synchronisation
    // is needed: createExecutionContext happens-before the worker's
    // first instruction (the EC literally does not exist before the
    // call returns).
    const self_slot = worker_self_slot;
    const port_slot = worker_port_slot;
    // §[suspend] [1] = self_slot suspends the calling EC and blocks the
    // syscall until the suspension is resolved. With no attachments the
    // libz wrapper is the safe path (it panics on N>0; N=0 here).
    const sus = syscall.suspendEc(self_slot, port_slot, &.{});
    @atomicStore(u64, &worker_result, sus.v1, .release);
    @atomicStore(u64, &worker_done, 1, .release);
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

    // Step 1: mint the port. bind keeps the test EC as a live bind-cap
    // holder so recv does not return E_CLOSED on the bind path; recv
    // gates the recv call itself. xfer is unused — no handles attached.
    const port_caps = caps.PortCap{ .bind = true, .recv = true, .@"suspend" = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);
    worker_port_slot = port_handle;

    // Step 2: mint W. susp lets W self-suspend onto the port (the spec
    // line under test names "the dequeued sender" — W is that sender).
    // term is held for symmetry with sibling tests but not exercised.
    // restart_policy = 0 (kill) keeps the request inside the runner
    // ec_inner_ceiling and prevents any restart fallback after this
    // test ends.
    const w_caps = caps.EcCap{
        .term = true,
        .susp = true,
        .restart_policy = 0,
    };
    // §[create_execution_context] caps word: caps in bits 0-15,
    // target_caps in 16-31 (ignored when target=self), priority in
    // 32-33. priority = 0 stays inside the runner pri ceiling.
    const ec_caps_word: u64 = @as(u64, w_caps.toU16());
    const entry: u64 = @intFromPtr(&workerEntry);
    const cec = syscall.createExecutionContext(
        ec_caps_word,
        entry,
        1, // stack_pages
        0, // target = self (this domain)
        0, // affinity = any core
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(2);
        return;
    }
    const w_handle: u12 = @truncate(cec.v1 & 0xFFF);
    const w_target: u64 = @as(u64, w_handle);
    worker_self_slot = w_handle;

    // Step 3: yield to W so it reaches the blocking suspend syscall
    // before the test EC calls recv. On a uniprocessor this serialises
    // the path: W enters suspend → blocks → control returns to the
    // test EC. On multi-core, W may execute concurrently; either way
    // the observable behaviour the test asserts (W is queued on the
    // port by the time recv runs) holds because recv blocks on a port
    // with no queued sender, and §[suspend] guarantees W is enqueued
    // by the time its syscall transitions to the blocking state.
    const y1 = syscall.yieldEc(w_target);
    if (y1.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Step 4: recv. The test EC holds the port's bind cap (no
    // E_CLOSED) and W is a queued suspended sender, so recv returns
    // immediately with the kernel-allocated reply handle id encoded in
    // the syscall word per §[recv].
    const got = syscall.recv(port_handle, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }
    // §[recv] syscall word return layout: reply_handle_id in bits 32-43
    // (12 bits).
    const reply_handle_id: u12 = @truncate((got.word >> 32) & 0xFFF);

    // Step 5: witness (a). Yield to W to give it a chance to run; if
    // the kernel were not honouring "remains suspended until the reply
    // handle is consumed," W's suspend would have resolved with some
    // verdict by now and W would have set worker_done. The acquire
    // load pairs with W's release store. A non-zero observation
    // before delete is a violation of the spec line under test.
    _ = syscall.yieldEc(w_target);
    if (@atomicLoad(u64, &worker_done, .acquire) != 0) {
        testing.fail(5);
        return;
    }

    // Step 6: consume the reply handle by deleting it. §[capabilities]
    // line 176: "If the suspended sender is still waiting, resume them
    // with E_ABANDONED. Release handle." The kernel resumes W's
    // blocked suspend with E_ABANDONED in vreg 1.
    const del = syscall.delete(reply_handle_id);
    if (del.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(6);
        return;
    }

    // Step 7: bounded yield-and-poll. Each iteration re-yields to W
    // (no-op if not runnable — yield falls back to the scheduler per
    // §[yield]) and acquire-loads worker_done. On observation, the
    // recorded vreg-1 result must equal E_ABANDONED. Exhausting the
    // bound is a separate failure (assertion 7) so a kernel that
    // never resumes the sender at all is distinguished from one that
    // resumes with the wrong verdict.
    const MAX_ATTEMPTS: usize = 256;
    var attempt: usize = 0;
    while (attempt < MAX_ATTEMPTS) {
        _ = syscall.yieldEc(w_target);
        if (@atomicLoad(u64, &worker_done, .acquire) == 1) {
            const result = @atomicLoad(u64, &worker_result, .acquire);
            if (result != @intFromEnum(errors.Error.E_ABANDONED)) {
                testing.fail(8);
                return;
            }
            testing.pass();
            return;
        }
        attempt += 1;
    }

    testing.fail(7);
}
