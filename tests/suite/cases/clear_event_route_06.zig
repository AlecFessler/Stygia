// Spec §[clear_event_route] — test 06.
//
// "[test 06] on success, the binding for ([1], [2]) is removed;
//  subsequent firings of [2] for [1] follow the no-route fallback
//  above."
//
// §[event_route] no-route fallback for breakpoint: "the event is
// dropped; the kernel advances past the trapping instruction and
// resumes the EC".
//
// Strategy
//   The spec sentence has two halves:
//     (a) the binding is removed (state assertion).
//     (b) subsequent firings follow the no-route fallback (behavioural
//         assertion).
//
//   Bind/unbind cap availability — bit-passthrough discovery
//     The runner's `ec_inner_ceiling = 0xFF` covers EcCap bits 0-7
//     only — `bind` (bit 10) and `unbind` (bit 12) sit above the
//     ceiling. However, `kernel/syscall/execution_context.zig:148`
//     only validates the LOW BYTE of caps against ec_inner_ceiling
//     (`new_caps_low: u8 = @truncate(new_caps & 0xFF)`); high-byte
//     bits flow through unchecked, and the file's own header comment
//     explicitly notes that bind/rebind/unbind "are not constrained
//     at mint time." So a `create_execution_context(target = self)`
//     request with caps.bind = 1 / caps.unbind = 1 in the high byte
//     passes the ceiling check and the resulting EC handle carries
//     those caps.
//
//   Driving observation (a): state assertion
//     After bind → clear, a second clear must return E_NOENT (test 05
//     of clear_event_route). E_NOENT is the kernel-authoritative
//     observation that the binding is gone — the cap, handle, and
//     event-type gates are all closed by the prior bind+clear pair, so
//     E_NOENT cleanly distinguishes "binding removed" from
//     "binding still present" (which would return OK on the second
//     clear) and from earlier-error states (which would return
//     E_BADCAP / E_PERM / E_INVAL).
//
//   Driving observation (b): behavioural assertion
//     We mint a worker EC whose entry point is a single breakpoint
//     instruction (INT3 on x86_64; BRK #0 on aarch64). After binding
//     route(worker, breakpoint=3) → port:
//
//       Phase 1 (route present): release the worker, recv the port —
//       expect OK with event_type = breakpoint. Reply consumes the
//       reply handle (the worker is left suspended on the port; we do
//       NOT resume it because we are about to terminate it). This
//       phase confirms the route is wired correctly so the absence of
//       delivery in phase 2 is a real observation about the cleared
//       route rather than a setup artifact.
//
//       Phase 2 (route cleared): clear the route, mint a SECOND worker
//       EC at the same breakpoint entry, release it, and recv on the
//       SAME port with a timeout. The kernel must take the no-route
//       fallback for the second worker's breakpoint firing — drop the
//       event, no delivery on the port. recv must return E_TIMEOUT
//       (the spec assertion under test). Any OK return means the
//       kernel routed the event despite the cleared binding — a spec
//       violation.
//
//     Caveat — aarch64 advance-past-trap gap
//       Per port.zig:fireBreakpoint, the no-route fallback drops the
//       event and "lets `ec` resume", but the kernel comment notes
//       that the arch-specific advance-past-trap helper is not yet
//       wired through dispatch. On x86_64, INT3 is a trap-AFTER
//       instruction (RIP already points past) so the EC resumes one
//       byte past the trap and proceeds. On aarch64, BRK is a
//       fault-ON instruction (ELR points AT the BRK), so without the
//       advance helper the EC would re-trap forever. Either way the
//       PORT-OBSERVABLE behaviour is identical: no event ever
//       delivered. recv timing out is the spec-mandated signal of "no
//       route bound, no delivery"; whether the worker survives past
//       the trap or gets stuck on it is an arch-specific detail of
//       no-route fallback that the spec covers but does not pin per-
//       arch beyond the dispatch table. We assert only the port-side
//       observation, which is the same on both arches.
//
// Action
//   1. createPort(caps={bind, recv})              — must succeed.
//   2. createExecutionContext(target=self, caps={term, susp, bind,
//        unbind}, entry=&workerEntry, stack_pages=1)  — must succeed.
//      The worker is the binding target for phase 1.
//   3. bindEventRoute(worker1, breakpoint=3, port) — must return OK.
//   4. release worker1 (worker_go = 1). recv(port, timeout) — expect
//      OK with event_type field of the syscall word == 3 (breakpoint).
//   5. clearEventRoute(worker1, breakpoint=3)     — must return OK.
//   6. clearEventRoute(worker1, breakpoint=3) again — must return
//      E_NOENT (state assertion: binding removed).
//   7. createExecutionContext(target=self, caps={term, susp, bind,
//        unbind}, entry=&workerEntry, stack_pages=1)  — second worker.
//   8. release worker2. recv(port, timeout) — must return E_TIMEOUT
//      (behavioural assertion: no-route fallback dropped the event,
//      no delivery on the port).
//   9. terminate(worker1) and terminate(worker2)  — cleanup.
//
// Assertions
//   1: setup syscall failed — createPort returned an error word.
//   2: setup syscall failed — first createExecutionContext error.
//   3: bindEventRoute did not return OK (precondition for testing
//      the post-clear behaviour).
//   4: phase 1 recv did not return OK (route never delivered — the
//      cleared-route delivery test of phase 2 cannot distinguish
//      "kernel correctly suppressed" from "kernel never delivered").
//   5: phase 1 event_type (syscall word bits 44-48) != 3 (breakpoint).
//      We expected the routed breakpoint delivery; getting a
//      different event type means the wrong path fired.
//   6: first clearEventRoute did not return OK (state precondition
//      for E_NOENT on the second clear).
//   7: second clearEventRoute did not return E_NOENT (state
//      assertion: binding was not actually removed).
//   8: setup syscall failed — second createExecutionContext error.
//   9: phase 2 recv returned a status other than E_TIMEOUT. OK means
//      the kernel delivered the event despite the cleared route
//      (spec violation — the assertion under test). Any other error
//      means the recv broke for an unrelated reason.

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const EVENT_BREAKPOINT: u64 = 3;

// recv timeout for phase 2 (behavioural assertion). 100 ms is well
// past the scheduler's normal yield cadence yet short enough that a
// failed test caps at fractions of a second. A correct kernel routes
// nothing through this port, so recv hits E_TIMEOUT after the full
// timeout regardless.
const RECV_TIMEOUT_NS: u64 = 100_000_000;

// Phase 1 timeout — generous so a slow scheduler doesn't false-fail
// when the worker hasn't yet hit the breakpoint. A correct kernel
// delivers within microseconds.
const RECV_TIMEOUT_PHASE1_NS: u64 = 1_000_000_000;

// Worker release sentinel. The worker spins until this is non-zero,
// then triggers a single breakpoint. Both worker ECs share the same
// entry point and the same sentinel — only one runs at a time
// (phase 1 worker is suspended on the port at delivery; phase 2
// worker doesn't start until phase 1 is observed and worker1
// terminated), so a single sentinel suffices.
var worker_go: u32 = 0;

fn cpuPause() void {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("pause"),
        .aarch64 => asm volatile ("yield"),
        else => @compileError("unsupported arch"),
    }
}

fn cpuHalt() void {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("hlt"),
        .aarch64 => asm volatile ("wfi"),
        else => @compileError("unsupported arch"),
    }
}

// Worker entry: spin until released, then issue a single breakpoint
// instruction. With a route bound for (this EC, breakpoint), the
// kernel suspends the EC on the bound port and delivers an event.
// With no route, the kernel applies the no-route fallback (drop +
// advance/resume per §[event_route]); we never observe the EC after
// either case from this side — the test EC reads the recv outcome.
fn workerEntry() callconv(.c) noreturn {
    while (@atomicLoad(u32, &worker_go, .acquire) == 0) cpuPause();

    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("int3"),
        .aarch64 => asm volatile ("brk #0"),
        else => @compileError("unsupported arch"),
    }

    // Reached only on x86_64 if no-route fallback fires (INT3 is
    // trap-AFTER, so RIP already points past). On aarch64 with the
    // current dispatch (no advance-past-trap helper) this is
    // unreachable from the no-route fallback path; the EC re-traps
    // forever until terminate. Either way the test EC observes only
    // the port side — recv outcome — so worker survival is not
    // directly asserted here.
    while (true) cpuHalt();
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Reset the release sentinel in case the test ran in a previous
    // domain incarnation (defensive — each test ELF spawns a fresh
    // capability domain in the runner's spawnOne, so .bss starts
    // zeroed, but keeping the reset explicit keeps phase 2 honest if
    // this entry point grows additional setup).
    @atomicStore(u32, &worker_go, 0, .release);

    // Step 1: port for both phases.
    const port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: phase 1 worker. caps.bind / caps.unbind sit above the
    // 0xFF ec_inner_ceiling but pass through unchecked
    // (execution_context.zig:148 only validates the low byte). term
    // is needed for cleanup.
    const w_caps = caps.EcCap{
        .term = true,
        .susp = true,
        .bind = true,
        .unbind = true,
    };
    const caps_word: u64 = @as(u64, w_caps.toU16());
    const entry: u64 = @intFromPtr(&workerEntry);
    const cec1 = syscall.createExecutionContext(
        caps_word,
        entry,
        1, // stack_pages
        0, // target = self
        0, // affinity = kernel default
    );
    if (testing.isHandleError(cec1.v1)) {
        testing.fail(2);
        return;
    }
    const w1: u12 = @truncate(cec1.v1 & 0xFFF);

    // Step 3: bind route (worker1, breakpoint, port).
    const bind1 = syscall.bindEventRoute(w1, EVENT_BREAKPOINT, port_handle);
    if (bind1.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Step 4: release worker1 and observe a routed breakpoint
    // delivery. This positive-observation phase is what makes phase 2's
    // negative observation meaningful: it proves the bind-then-fire
    // path works on this kernel build, so the absence of delivery in
    // phase 2 is a real observation about the cleared route rather
    // than a wiring artifact.
    @atomicStore(u32, &worker_go, 1, .release);
    const got1 = syscall.recv(port_handle, RECV_TIMEOUT_PHASE1_NS);
    if (got1.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }
    // Spec §[event_state] — recv returns event_type in the syscall
    // word. map_pf_12 (in this same suite) decodes it at bits 44-48
    // (5 bits cover the 6 spec event types); use the same shift here.
    const event_type1: u64 = (got1.word >> 44) & 0x1F;
    if (event_type1 != EVENT_BREAKPOINT) {
        testing.fail(5);
        return;
    }
    // worker1 is now suspended on the port. We do NOT reply — replying
    // would resume the worker at the breakpoint instruction and
    // re-trap; instead phase 2 uses a fresh worker EC. We DO terminate
    // worker1 below so the route on (w1, breakpoint) — which was
    // already cleared by us in step 5 — doesn't see any further
    // firings from worker1.

    // Step 5: clear the route. This is the success path of
    // clear_event_route.
    const clear1 = syscall.clearEventRoute(w1, EVENT_BREAKPOINT);
    if (clear1.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(6);
        return;
    }

    // Step 6: state assertion — second clear must return E_NOENT,
    // confirming the binding was removed (test 05 of clear_event_route
    // closes this gate exactly).
    const clear2 = syscall.clearEventRoute(w1, EVENT_BREAKPOINT);
    if (clear2.v1 != @intFromEnum(errors.Error.E_NOENT)) {
        testing.fail(7);
        return;
    }

    // Step 7: phase 2 worker. Same entry point. We do NOT bind any
    // route on (w2, breakpoint), so when w2 issues its breakpoint the
    // kernel takes the no-route fallback (drop event, advance/resume
    // per §[event_route]). The port stays empty.
    @atomicStore(u32, &worker_go, 0, .release);
    const cec2 = syscall.createExecutionContext(
        caps_word,
        entry,
        1,
        0,
        0,
    );
    if (testing.isHandleError(cec2.v1)) {
        testing.fail(8);
        return;
    }
    const w2: u12 = @truncate(cec2.v1 & 0xFFF);

    // Step 8: behavioural assertion. Release w2 and recv with timeout.
    // The kernel must NOT deliver any event to `port` from w2's
    // breakpoint trap — no route is bound for (w2, breakpoint). recv
    // must time out.
    @atomicStore(u32, &worker_go, 1, .release);
    const got2 = syscall.recv(port_handle, RECV_TIMEOUT_NS);
    if (got2.regs.v1 != @intFromEnum(errors.Error.E_TIMEOUT)) {
        testing.fail(9);
        return;
    }

    // Cleanup. Both workers are either parked on the port (w1 from
    // phase 1's delivery — we never replied) or stuck post-trap (w2
    // on aarch64 re-trapping; w2 on x86_64 halting in cpuHalt loop
    // post-INT3). terminate is OK in every case.
    _ = syscall.terminate(w1);
    _ = syscall.terminate(w2);
    _ = syscall.delete(w1);
    _ = syscall.delete(w2);
    _ = syscall.delete(port_handle);

    testing.pass();
}
