// Spec v3 in-kernel-parallel test runner v2 — primary (root service).
//
// Architecture:
//   - The primary owns all rights and orchestrates tests.
//   - It mints a single result port and spawns each test as its own
//     child process, passing the port handle with `bind |
//     xfer` caps. The kernel scheduler/SMP gives parallelism for free.
//   - Each child performs its assertion logic and calls the libz
//     `testing.report` helper, which suspends the initial thread on the
//     result port with vregs:
//        v3 = result_code (1 = pass, 0 = fail)
//        v4 = assertion_id
//        v5 = test tag (build-time-stable u16 per manifest entry)
//     The primary recv's the suspension event, decodes the tag, and
//     writes the result into a tag-indexed table. Tag = manifest
//     index, so a final pass over the manifest joins names with
//     results without depending on completion order.
//
//   - Tests are pinned round-robin across cores via
//     `create_process` `[5] initial_thread_affinity` (see
//     `-Dspread_cores`). Passing 0 there — "kernel picks any core" —
//     uses local-biased initial placement; x64 can now pull-steal
//     affinity-0 ready Threads, but deterministic runner placement is still
//     better for stability triage.
//
// Future work (per task brief, deferred for the v3 lockdep cycle and
// build-budget reasons):
//   - Per-core *port*, and a per-core runner thread that owns it, so
//     result delivery hits the IPC fast path instead of every child
//     on every core contending for the one shared result port. The
//     affinity pinning above is half of that design; the port
//     sharding is the half still outstanding.

const builtin = @import("builtin");
const std = @import("std");

const lib = @import("lib");
const embedded_tests = @import("embedded_tests");
const libz_loader = @import("libz_loader");
const serial_mod = @import("serial.zig");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;

// Marker read by libz/start.zig at comptime so its libz-bootstrap
// path no-ops in the runner. The runner is statically linked against
// libz/syscall.zig (full inline-asm bodies), holds no libz pf in its
// own cap table, and is the one staging libz.elf for children — it
// must not try to mapPf libz at LIBZ_SLIDE itself.
pub const RUNNER_STATIC = true;

// Spec §[port].recv [2] timeout_ns. Allow enough time for the
// test batches on healthy runs while still detecting hangs.
const RECV_TIMEOUT_NS: u64 = 30_000_000_000;

// stygia-ojs post-timeout probe budget. On a batch recv timeout the
// runner re-arms recv with a deliberately tiny deadline and then with
// second-scale ones, purely to classify WHY the deadline was hit. See
// `probeAfterTimeout` in the batch loop. PROBE_FAST_NS is far shorter
// than any plausible test body, so a delivery on the fast probe means
// the event was ALREADY sitting in the port when the 30 s recv returned
// E_TIMEOUT — i.e. the kernel lost the receiver's wake rather than the
// sender failing to produce a result.
const PROBE_FAST_NS: u64 = 1_000_000;
const PROBE_SLOW_NS: u64 = 1_000_000_000;
const PROBE_SLOW_ROUNDS: usize = 5;

// Tag magic. The build emits each test ELF with `test_tag.TAG =
// TAG_MAGIC | manifest_index`. Tests that explicitly suspend their
// initial thread on the runner's result port outside of `testing.report`
// (or whose suspend frame happens to ride rsi=0 / some other small
// accidental value) would otherwise spoof a real test result and
// overwrite a genuine entry. The runner enforces the magic on every
// inbound event: events without it are dropped before they touch the
// results table. Must match `tag_magic` in `tests/suite/build.zig`.
const TAG_MAGIC: u64 = 0x8000;
const TAG_INDEX_MASK: u64 = 0x7FFF;

// Sentinel phys_base values for the boot-minted test-fixture
// device_regions. Must match
// kernel/boot/userspace_init.zig:grantTestFixtureDevices.
const FIXTURE_DMA_IRQ_PHYS_BASE: u64 = 0xCAFE_0000;
const FIXTURE_PLAIN_PHYS_BASE: u64 = 0xBABE_0000;

pub const ResultCode = enum(u64) {
    fail = 0,
    pass = 1,
    not_run = 0xFFFF_FFFF_FFFF_FFFF,
    _,
};

pub const TestResult = struct {
    code: ResultCode,
    assertion_id: u64,
};

const EventFields = struct {
    recv_status: u64,
    pair_count: u64,
    tstart: u64,
    reply_handle_id: caps.HandleId,
    event_type: u64,
    result_code: ResultCode,
    assertion_id: u64,
    tag: u64,
};

const TOTAL_TESTS: usize = embedded_tests.TOTAL_TEST_COUNT;

// Tag-indexed result table. Tag = manifest index, so the runner can
// walk the manifest and join names with results in O(N) at dump time.
var results: [TOTAL_TESTS]TestResult = blk: {
    var arr: [TOTAL_TESTS]TestResult = undefined;
    for (&arr) |*r| r.* = .{ .code = .not_run, .assertion_id = 0 };
    break :blk arr;
};

var serial: serial_mod.Serial = serial_mod.DISABLED;

// Page count of the staged libz image, populated by stageLibzPf at
// startup. Cached so spawnOne can build the PassedHandle without
// re-querying the cap table.
var libz_pf_handle: caps.HandleId = 0;

// Test-fixture device_region handles in the runner's own cap table,
// minted by the kernel at boot under -Dprofile=test (see
// kernel/boot/userspace_init.zig grantTestFixtureDevices). The runner
// scans for them at startup and forwards them to every test child via
// passed_handles so spec tests targeting `device_region` / IRQ / DMA
// surfaces have something to scan for.
//
//   fixture_dma_irq_handle: caps={move,copy,dma,irq} — exercises
//                            §[create_vmar] tests 22/15 (success path
//                            on dma create_vmar) and §[ack] / §[map_pf]
//                            paths that need a dma+irq cap on [5].
//   fixture_plain_handle:    caps={move,copy} — bare device_region
//                            without dma or irq, needed by §[create_vmar]
//                            test 15 to observe E_PERM (caps.dma=1
//                            requested but device lacks dma cap).
//
// Both are zero (= SLOT_SELF id) when the fixtures are absent (e.g.
// production build without -Dtests_fixture_devices=true). The runner's
// findFixtureMmio scan returns null in that case and spawnOne forwards
// only the result-port + ELF + libz triple.
var fixture_dma_irq_handle: caps.HandleId = 0;
var fixture_plain_handle: caps.HandleId = 0;

pub fn main(cap_table_base: u64) void {
    serial = serial_mod.init(cap_table_base);

    // Spec §[thread].priority — bump self to `.high` (=2)
    // so the receiver preempts test Threads the moment a result lands. Two
    // effects matter for the L4 fast path: (a) when a child suspends,
    // primary is already parked in `recv` and `port.waiter_kind ==
    // .receivers`, so the asm rendezvous matches its predicate and
    // bypasses the slow Zig path entirely; (b) primary's reply →
    // recv → next-suspend cycle stays head-of-queue so the next child
    // also finds primary parked. Without this nudge, primary and
    // children all tie at `.normal` and the round-robin scheduler
    // gives children a chance to suspend before primary parks — the
    // fast path predicate then fails 100% of the time.
    _ = syscall.priority(caps.SLOT_INITIAL_THREAD, 2);

    // §[port] / §[create_port] — mint a single shared result port.
    const port_caps = caps.PortCap{
        .move = true,
        .copy = true,
        .xfer = true,
        .recv = true,
        .bind = true,
        .@"suspend" = true,
    };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    const port_handle: caps.HandleId = @truncate(cp.v1 & 0xFFF);

    serial.print("[runner] starting ");
    serial.printU64(embedded_tests.manifest.len);
    if (embedded_tests.repeat > 1) {
        serial.print(" tests x ");
        serial.printU64(embedded_tests.repeat);
        serial.print(" runs\n");
    } else {
        serial.print(" tests\n");
    }

    // Stage libz.elf into a page_frame at startup. Each child spawned
    // below receives this pf in its passed_handles array; its _start
    // mapPfs it at LIBZ_SLIDE and patches own GOT/PLT against it via
    // libz_loader.relocateSelf before app.main runs.
    libz_pf_handle = stageLibzPf();

    // Scan the runner's own cap_table for the boot-minted test-fixture
    // device_regions (kernel/boot/userspace_init.zig
    // grantTestFixtureDevices, gated on -Dtests_fixture_devices).
    // Two synthetic mmio device_regions are minted on the runner's
    // table:
    //   - phys_base = 0xCAFE_0000, caps = {move,copy,dma,irq}
    //   - phys_base = 0xBABE_0000, caps = {move,copy}
    // We pin them by phys_base because the table also holds COM1 (port_io)
    // and on bare-metal boots may hold a framebuffer (mmio with caps
    // {move,copy,dma,irq} too) and PCI BAR mmio — distinguishing by
    // phys_base avoids forwarding any real-hardware mmio region to the
    // child by accident.
    fixture_dma_irq_handle = findFixtureMmio(cap_table_base, FIXTURE_DMA_IRQ_PHYS_BASE) orelse 0;
    fixture_plain_handle = findFixtureMmio(cap_table_base, FIXTURE_PLAIN_PHYS_BASE) orelse 0;

    // Phase 1+2 interleaved. Spawn `BATCH` tests, then drain `BATCH`
    // results before spawning the next batch. Bounded in-flight test
    // count keeps simultaneous thread/process/PageFrame slab usage well below
    // the per-class capacities and avoids running every test child to
    // peak concurrency in a 4-core scheduler — the kernel's debug
    // accounting (lockdep stacks, IRQ-handler depth tables, slab
    // randomized-cursor BSS) compounds with per-thread kernel-stack frames
    // and pushes total stack pressure over the budget on full-475
    // bursts. Spec doesn't forbid batched orchestration; the kernel
    // sees identical per-test syscalls regardless of batching.
    //
    // Default 4. Historically 4 was required to clear the spawn loop
    // past iter ~432: at 16 the runner wedged in the spawn-loop body
    // before recv ever drained the batch, surfacing as no
    // `spawned 16/16` print after `[runner] batch 416..432` with the
    // kernel still ticking and the runner thread parked (stygia-utf). The
    // contention was never pinpointed, and it is independent of the
    // per-process resource leak fixed by `disarmTimerHandlesInProcess`.
    //
    // Now set by `-Dbatch=N` so the wall can be re-tested without
    // editing test code. Note "runner thread parked, kernel still ticking"
    // is the exact signature `parkSelfFaulted` leaves behind on an
    // unrouted fault — which `[UNHANDLED]` reporting in sched/port.zig
    // now announces, so a re-run should say directly whether that is
    // what happens.
    const BATCH: usize = embedded_tests.batch;

    // Cores to spread test processes over; see `-Dspread_cores`.
    //
    // The suite's expected core count comes from its boot configuration.
    // `-Dspread_cores=false` retains single-core initial placement.
    const spread_cores: u64 = if (embedded_tests.spread_cores)
        embedded_tests.expected_cores
    else
        1;
    if (embedded_tests.runner_diag) {
        serial.print("[runner] spreading tests over ");
        serial.printU64(spread_cores);
        serial.print(" core(s)\n");
    }

    // Aggregate counters across all repeats — used by the final
    // multi-run summary at end. Per-run summaries print after each.
    var agg_pass: usize = 0;
    var agg_fail: usize = 0;
    var agg_miss: usize = 0;
    var run_idx: u32 = 0;
    while (run_idx < embedded_tests.repeat) : (run_idx += 1) {
        if (embedded_tests.repeat > 1) {
            serial.print("[runner] === run ");
            serial.printU64(run_idx + 1);
            serial.print("/");
            serial.printU64(embedded_tests.repeat);
            serial.print(" ===\n");
            // Reset the per-tag table so the next run's MISS / FAIL /
            // PASS reflects only that run.
            for (&results) |*r| r.* = .{ .code = .not_run, .assertion_id = 0 };
        }

        var successful_spawns: usize = 0;
        var collected: usize = 0;
        var batch_idx: usize = 0;
        while (batch_idx < embedded_tests.manifest.len) {
            const batch_end = @min(batch_idx + BATCH, embedded_tests.manifest.len);
            if (embedded_tests.runner_diag) {
                // Per-batch progress so a stalled batch isn't ambiguous
                // with a stalled test ELF or a stalled spawn syscall.
                serial.print("[runner] batch ");
                serial.printU64(batch_idx);
                serial.print("..");
                serial.printU64(batch_end);
                serial.print("\n");
            }
            var batch_started: usize = 0;
            var i = batch_idx;
            while (i < batch_end) : (i += 1) {
                // Round-robin on the *manifest* index, not the in-batch
                // index, so the spread stays even across batch boundaries
                // (BATCH is 16 and cores is typically 4, so both would work
                // here — but only the manifest index survives a -Dbatch
                // change that is not a multiple of the core count).
                const affinity: u64 = @as(u64, 1) << @truncate(i % spread_cores);
                if (spawnOne(i, embedded_tests.manifest[i], port_handle, affinity)) {
                    successful_spawns += 1;
                    batch_started += 1;
                }
            }
            if (embedded_tests.runner_diag) {
                serial.print("[runner]   spawned ");
                serial.printU64(batch_started);
                serial.print("/");
                serial.printU64(batch_end - batch_idx);
                serial.print("\n");
            }
            // Drain this batch's events before staging the next.
            var batch_collected: usize = 0;
            var batch_recv_timed_out = false;
            while (batch_collected < batch_started) {
                const got = syscall.recv(port_handle, RECV_TIMEOUT_NS);

                // E_TIMEOUT lands in vreg 1 because no reply handle was minted.
                // Drop the batch on the floor (its survivors stay `.not_run` =
                // MISS in summarize). Hung sender Threads are reaped at process
                // teardown when the runner returns and drops its self-handle.
                if (got.regs.v1 == @intFromEnum(errors.Error.E_TIMEOUT)) {
                    serial.print("[runner] recv timeout after ");
                    serial.printU64(RECV_TIMEOUT_NS / 1_000_000_000);
                    serial.print("s with ");
                    serial.printU64(collected);
                    serial.print(" / ");
                    serial.printU64(successful_spawns);
                    serial.print(" results — skipping rest of batch\n");
                    // Name the tests that are still outstanding at the
                    // timeout instant. `summarize` reports these later as
                    // MISS anyway, but by then the batch boundary is lost,
                    // and it is the batch shape that discriminates the two
                    // stygia-ojs severities: exactly one outstanding (a
                    // single thread's result lost) versus the whole batch
                    // outstanding (nothing delivered at all, which is not
                    // BATCH independent losses).
                    serial.print("[runner]   outstanding in batch ");
                    serial.printU64(batch_idx);
                    serial.print("..");
                    serial.printU64(batch_end);
                    serial.print(":");
                    var oi = batch_idx;
                    while (oi < batch_end) : (oi += 1) {
                        if (results[oi].code == .not_run) {
                            serial.print(" ");
                            serial.printU64(oi);
                            serial.print(":");
                            serial.print(embedded_tests.manifest[oi].name);
                        }
                    }
                    serial.print("\n");
                    // Classify the timeout before abandoning the batch.
                    // Three outcomes are possible and they point at three
                    // different bugs, so guessing is not good enough:
                    //
                    //   fast=N (N > 0)  The result was already queued on the
                    //     port when the 30 s recv returned E_TIMEOUT. A 1 ms
                    //     recv cannot have waited for a test to finish, so
                    //     this is a KERNEL bug on the receive side — a lost
                    //     wake or a spurious timeout — not a stuck test.
                    //   slow=N          The sender Threads were merely late;
                    //     something starved them past 30 s.
                    //   both zero       The sender Threads never produced a
                    //     result at all (dead, parked, or faulted silently).
                    //
                    // Probed events are deliberately NOT recorded: they stay
                    // MISS in the summary. This is instrumentation, and it
                    // must not turn a real failure into a pass.
                    var probe_fast: usize = 0;
                    var probe_slow: usize = 0;
                    {
                        const want = batch_started - batch_collected;
                        while (probe_fast + probe_slow < want) {
                            const p = syscall.recv(port_handle, PROBE_FAST_NS);
                            if (p.regs.v1 != @intFromEnum(errors.Error.E_TIMEOUT)) {
                                probe_fast += 1;
                                drainProbeEvent("fast", probe_fast + probe_slow, p);
                                continue;
                            }
                            break;
                        }
                        var round: usize = 0;
                        while (round < PROBE_SLOW_ROUNDS and
                            probe_fast + probe_slow < want) : (round += 1)
                        {
                            const p = syscall.recv(port_handle, PROBE_SLOW_NS);
                            if (p.regs.v1 != @intFromEnum(errors.Error.E_TIMEOUT)) {
                                probe_slow += 1;
                                drainProbeEvent("slow", probe_fast + probe_slow, p);
                            }
                        }
                    }
                    serial.print("[runner]   probe: fast=");
                    serial.printU64(probe_fast);
                    serial.print(" slow=");
                    serial.printU64(probe_slow);
                    serial.print(" of ");
                    serial.printU64(batch_started - batch_collected);
                    serial.print(" outstanding\n");
                    if (embedded_tests.halt_on_miss) {
                        // Freeze so the corpse stays inspectable — see the
                        // -Dhalt_on_miss rationale in build.zig. Spin in
                        // user mode rather than exiting: the kernel keeps
                        // the lost thread, its port state and the per-core
                        // scheduler state exactly as they are, and the
                        // qemu gdb stub stays attachable. The harness sees
                        // "no summary" and preserves the VM.
                        serial.print("[runner] halt_on_miss — freezing for inspection (gdb stub)\n");
                        while (true) {
                            std.atomic.spinLoopHint();
                        }
                    }
                    batch_recv_timed_out = true;
                    break;
                }

                // §[event_state] return word — composed by sched.port.deliverEvent
                // and written to the receiver's `[user_rsp + 0]` (vreg 0,
                // captured into `got.word` by issueRawCaptureWord). vreg 1
                // (rax) carries the syscall success/error code (0 on a
                // delivered event, E_TIMEOUT on the deadline path).
                // Previous code read vreg 1 here, so `reply_handle_id`
                // came back as 0 and every reply syscall hit
                // `resolveHandleOnProcess(...) == null` → E_BADCAP. The
                // sender Threads stayed parked on the result port and their processes
                // lived indefinitely, preventing the runner from draining
                // those test batches.
                //
                // Layout: pair_count [12..19], tstart [20..31],
                // reply_handle_id [32..43], event_type [44..].
                const event = decodeEvent(got);

                _ = record(event.tag, .{
                    .code = event.result_code,
                    .assertion_id = event.assertion_id,
                }, event.reply_handle_id);

                // Resume the child so it can return out of testing.report,
                // fall through to start.zig, and tear down its self-handle.
                //
                // Use the discard variant of issueReg directly. The plain
                // `_ = syscall.reply(…)` chain (issueRawNoStack with 13
                // output operands → Regs return → discard) is provably
                // dead from LLVM's POV: every output operand traces to a
                // discarded slot, which lets ReleaseSmall strip the entire
                // chain INCLUDING the inner `asm volatile`. The visible
                // failure was the runner emitting ~10 of ~420 expected
                // reply syscalls, every elided reply leaving a test thread
                // parked on the result port and the test's process live
                // indefinitely. Accumulated parked children starved the
                // runner and produced a cascade-MISS tail.
                //
                // Spec §[reply]: reply_handle_id rides in syscall-word bits
                // 20-31 — pass it through `extraReplyHandle`, leave vregs
                // 1..13 untouched. (Pre-spec-update this slotted reply_handle
                // into vreg 1 / rax, which conflicted with the §[vm_exit_state]
                // GPR layout and broke the L4-style fast path.)
                syscall.issueRegDiscard(.reply, syscall.extraReplyHandle(event.reply_handle_id), .{});

                collected += 1;
                batch_collected += 1;
            }
            batch_idx = batch_end;
        }

        const counts = summarize();
        agg_pass += counts.pass;
        agg_fail += counts.fail;
        agg_miss += counts.miss;
    }

    if (embedded_tests.repeat > 1) {
        serial.print("[runner] === aggregate over ");
        serial.printU64(embedded_tests.repeat);
        serial.print(" runs: ");
        serial.printU64(agg_pass);
        serial.print(" pass / ");
        serial.printU64(agg_fail);
        serial.print(" fail / ");
        serial.printU64(agg_miss);
        serial.print(" miss ===\n");
    }

    // Return to _start after the final verdict. It drops the boot root
    // self-handle; the test-profile kernel recognizes that one exit and
    // reboots through its existing internal platform path. QEMU -no-reboot
    // exits, while Pi tryboot returns to Pi OS.
}

// Spawns a single test process bound to the shared result
// port. Returns true on success, false if create_process
// reported an error in vreg 1 — the caller skips queueing a recv for
// failed spawns so the recv loop's iteration count stays accurate.
fn spawnOne(index: usize, entry: embedded_tests.Entry, port_handle: caps.HandleId, affinity: u64) bool {
    const pf_handle = stageElfIntoPageFrame(entry.bytes);

    // Grant the child:
    //   slot 3 (SLOT_FIRST_PASSED + 0) — result port with bind+xfer.
    //   slot 4 (SLOT_FIRST_PASSED + 1) — its own ELF page_frame
    //                                    (R-only). Tests that re-
    //                                    spawn themselves into a
    //                                    sub-process (e.g.
    //                                    create_thread_03)
    //                                    reach for it via this slot.
    //   slot 5 (SLOT_FIRST_PASSED + 2 = LIBZ_PF_SLOT) — the staged
    //                                    libz.elf page_frame, R+X
    //                                    cap so the child's _start
    //                                    can mapPf it at LIBZ_SLIDE.
    //   slot 6 (SLOT_FIRST_PASSED + 3) — boot-minted test-fixture
    //                                    device_region with
    //                                    {move,copy,dma,irq} caps
    //                                    (sentinel phys_base
    //                                    0xCAFE_0000). Forwarded
    //                                    only when present in the
    //                                    runner's table (i.e. the
    //                                    kernel was built with
    //                                    -Dtests_fixture_devices=true).
    //   slot 7 (SLOT_FIRST_PASSED + 4) — boot-minted bare
    //                                    device_region with
    //                                    {move,copy} caps (sentinel
    //                                    phys_base 0xBABE_0000).
    //                                    Used by §[create_vmar]
    //                                    test 15 to observe E_PERM
    //                                    (caps.dma=1 requested but
    //                                    [5] handle lacks dma cap).
    const child_port_caps = caps.PortCap{
        .move = false,
        .copy = false,
        .xfer = true,
        .bind = true,
        .@"suspend" = true,
    };
    const child_pf_caps = caps.PfCap{
        .move = false,
        .r = true,
        .w = false,
    };
    const child_libz_caps = caps.PfCap{
        .move = false,
        .r = true,
        // x86 still uses a shared .bss scratch window for high-vreg
        // syscalls. aarch64 uses caller-stack storage instead, so keep
        // the shared libz image non-writable there.
        .w = builtin.target.cpu.arch == .x86_64,
        .x = true,
    };
    // Per §[create_process] passed-handle entry encoding
    // (libz/caps.zig:PassedHandle) the new caps word in the child
    // is `entry.caps`, NOT subset-checked against any ceiling — the
    // kernel forwards verbatim for passed handles. So the dma+irq
    // device_region forwarded here lands on the child with the same
    // caps the runner asks for.
    const child_dma_irq_caps = caps.DeviceCap{
        .move = false,
        .copy = false,
        .dma = true,
        .irq = true,
    };
    const child_plain_caps = caps.DeviceCap{
        .move = false,
        .copy = false,
    };

    var passed_buf: [5]u64 = undefined;
    passed_buf[0] = (caps.PassedHandle{
        .id = port_handle,
        .caps = child_port_caps.toU16(),
        .move = false,
    }).toU64();
    passed_buf[1] = (caps.PassedHandle{
        .id = pf_handle,
        .caps = child_pf_caps.toU16(),
        .move = false,
    }).toU64();
    passed_buf[2] = (caps.PassedHandle{
        .id = libz_pf_handle,
        .caps = child_libz_caps.toU16(),
        .move = false,
    }).toU64();
    var passed_len: usize = 3;
    // Order matters: spec test files scan their own cap_table from
    // slot 0 upward and stop at the first device_region. ack_02
    // (E_PERM if [1] lacks `irq`) and create_vmar_15 (E_PERM if
    // [5] lacks `dma`) need the "no-cap" device to land at the
    // lower slot id. ack_03 / map_pf_13 / ack_05 / ack_08 /
    // create_vmar_22 explicitly tolerate E_PERM as a degraded
    // outcome and otherwise drive the success path through any
    // device they find — so the plain fixture comes first, the
    // dma+irq fixture second. This wires both classes of test to
    // their full path under one runner config.
    if (fixture_plain_handle != 0) {
        passed_buf[passed_len] = (caps.PassedHandle{
            .id = fixture_plain_handle,
            .caps = child_plain_caps.toU16(),
            .move = false,
        }).toU64();
        passed_len += 1;
    }
    if (fixture_dma_irq_handle != 0) {
        passed_buf[passed_len] = (caps.PassedHandle{
            .id = fixture_dma_irq_handle,
            .caps = child_dma_irq_caps.toU16(),
            .move = false,
        }).toU64();
        passed_len += 1;
    }
    const passed: []const u64 = passed_buf[0..passed_len];

    // Spec §[create_process] [2] ceilings_inner field layout:
    //   bits  0-7   thread_inner_ceiling   = 0xFF
    //   bits  8-23  vmar_inner_ceiling  = 0x01FF
    //   bits 24-31  cripc_ceiling      = 0x27
    //   bits 32-39  pf_ceiling         = 0x1F   (max_rwx | max_sz)
    //   bits 40-47  vm_ceiling         = 0x01   (policy bit)
    //   bits 48-55  port_ceiling       = 0x5C   (xfer | recv | bind | suspend)
    //   bits 56-63  _reserved          = 0
    // Most tests use baseline 0x005C_011F_2701_FFFF. Test 12 gets
    // 0x001C_011F_2701_FFFF so it can request the valid suspend right
    // outside its caller's port ceiling and exercise E_PERM.
    // Test 12 needs a documented right absent from its caller's ceiling
    // so its E_PERM assertion does not depend on reserved-bit validation.
    const port_ceiling: u64 = if (std.mem.eql(u8, entry.name, "create_process_12")) 0x1C else 0x5C;
    const ceilings_inner: u64 =
        @as(u64, 0xFF) |
        (@as(u64, 0x01FF) << 8) |
        (@as(u64, 0x27) << 24) |
        (@as(u64, 0x1F) << 32) |
        (@as(u64, 0x01) << 40) |
        (port_ceiling << 48);

    const ceilings_outer: u64 = 0x0000_003F_01FE_FFFF;

    const child_self = caps.SelfCap{
        .crproc = true,
        .crec = true,
        .crvr = true,
        .crpf = true,
        .crvm = true,
        .crpt = true,
        // The restart behavior test must be able to mint a restart-cap
        // child. It drops its own restart right before reporting.
        .restart = std.mem.eql(u8, entry.name, "process_restart_01"),
        .fut_wake = true,
        .pri = 3,
    };
    const self_caps: u64 = @as(u64, child_self.toU16());

    // Spec §[create_process] [5] initial_thread_affinity — a
    // single-core mask under `-Dspread_cores` (the default), else 1,
    // which pins runner-created test processes to core 0. We keep this
    // deterministic even though affinity-0 ready Threads can now be
    // pull-stolen on x64.
    //
    // Worker Threads the tests create for themselves still pass whatever
    // affinity the test requests. Affinity 0 remains local-biased at
    // creation time but is steal-admissible on x64, so tests that need
    // simple local contender placement should pin explicitly.
    const r = syscall.createProcess(
        self_caps,
        ceilings_inner,
        ceilings_outer,
        pf_handle,
        affinity,
        passed[0..],
    );

    if (lib.testing.isHandleError(r.v1)) {
        serial.print("[runner] spawn FAILED ");
        serial.printU64(index);
        serial.print(":");
        serial.print(entry.name);
        serial.print("\n");
        // Even on failure, drop the per-spawn ELF page_frame handle the
        // runner staged in its own table — otherwise the runner's 4096
        // handle slots fill up over many reps and the next spawn loop
        // iteration creates handles whose error returns get interpreted
        // as pointers (var_base = E_BADCAP/E_FULL), faulting the runner
        // in user mode at addr=0x3 / 0x6.
        syscall.issueRegDiscard(.delete, 0, .{ .v1 = pf_handle });
        return false;
    }

    // Drop the runner-side per-spawn handles that aren't needed anymore:
    //   - pf_handle: the staged ELF page_frame. The child got an alias
    //     in its own table during create_process; with
    //     `incHandleRef` on alias the PF refcount is 2 here, so dropping
    //     the runner side leaves the child's reference at 1 and the PF
    //     stays alive until the child's process destroys.
    //   - ipc_handle (returned slot in r.v1 low 12 bits): the runner
    //     never sends IPCs to children, so it doesn't need this handle
    //     past spawn. Reclaiming the slot is required for N>>1 reps to
    //     avoid filling the runner's 4096-entry table after ~5 reps.
    syscall.issueRegDiscard(.delete, 0, .{ .v1 = pf_handle });
    const ipc_slot: caps.HandleId = @truncate(r.v1 & 0xFFF);
    syscall.issueRegDiscard(.delete, 0, .{ .v1 = ipc_slot });
    if (embedded_tests.runner_diag) {
        serial.print("[runner] spawn ");
        serial.printU64(index);
        serial.print(":");
        serial.print(entry.name);
        serial.print(" aff=0x");
        serial.printHex(affinity);
        serial.print("\n");
    }
    return true;
}

// Stage libz.elf into a single page_frame at startup:
//   1. Compute the laid-out image size from libz.elf's PT_LOADs.
//   2. Allocate a pf big enough to hold the full image.
//   3. Create a temp Var with R+W (writable view), mapPf the pf into
//      it, copy the libz_bytes into the laid-out positions, apply
//      R_*_RELATIVE relocs against image_runtime_base = LIBZ_SLIDE.
//      `libz_loader.layoutAndPrelink` does steps 3 in one shot once
//      we hand it a writable byte slice.
//   4. Delete the temp Var. The pf survives independently and its
//      bytes are now position-frozen for LIBZ_SLIDE.
//
// Returns the libz pf handle. Each child receives this same handle
// in its passed_handles, mapPfs it at LIBZ_SLIDE with R+X.
fn stageLibzPf() caps.HandleId {
    const libz_bytes = embedded_tests.libz_elf;
    const image_bytes = libz_loader.computeImageSize(libz_bytes);
    const page_size: u64 = 4096;
    const pages = (image_bytes + page_size - 1) / page_size;

    // Pf caps: r+w+x so children can later map it executable. The
    // pf itself is just memory; the child's Var owns the runtime
    // perm narrowing (R+X for libz.elf).
    const pf_caps = caps.PfCap{ .move = true, .r = true, .w = true, .x = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0,
        pages,
    );
    const pf_handle: caps.HandleId = @truncate(cpf.v1 & 0xFFF);

    // Temp Var for the runner's own writable view of the pf. We
    // create it R+W (no X needed) just long enough to populate the
    // image bytes; then delete it. The pf keeps the data.
    const var_caps_word = caps.VmarCap{ .r = true, .w = true };
    const cvar = syscall.createVmar(
        @as(u64, var_caps_word.toU16()),
        0b011, // cur_rwx = r|w
        pages,
        0, // preferred_base = 0 → kernel picks
        0,
    );
    const vmar_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);
    const var_base: u64 = cvar.v2;

    _ = syscall.mapPf(vmar_handle, &.{ 0, pf_handle });

    // Lay out PT_LOADs into the writable image and apply RELATIVE
    // relocs targeting `image_runtime_base = LIBZ_SLIDE`. The
    // resulting pf is a position-frozen image: any child mapPf'ing
    // it at exactly LIBZ_SLIDE sees correct internal pointers
    // without re-relocation.
    const image: [*]u8 = @ptrFromInt(var_base);
    libz_loader.layoutAndPrelink(
        libz_bytes,
        image[0..image_bytes],
        libz_loader.LIBZ_SLIDE,
    );

    // Drop the temp Var. The pf keeps the data; the runner holds
    // the pf handle in `libz_pf_handle` for spawnOne's
    // passed_handles.
    syscall.issueRegDiscard(.delete, 0, .{ .v1 = vmar_handle });

    return pf_handle;
}

// Scan the runner's own cap_table for an mmio device_region whose
// `phys_base` matches `target_phys_base`. Returns the slot id or null
// if no matching handle is present. Used at startup to discover the
// boot-minted test-fixture device_regions (see
// kernel/boot/userspace_init.zig:grantTestFixtureDevices).
//
// Spec §[device_region] field0 layout (mmio): bits 4-51 carry
// paddr>>12; we shift back up by 12 to compare against the sentinel.
fn findFixtureMmio(cap_table_base: u64, target_phys_base: u64) ?caps.HandleId {
    var slot: u32 = 0;
    while (slot < caps.HANDLE_TABLE_MAX) {
        const c = caps.readCap(cap_table_base, slot);
        if (c.handleType() == .device_region) {
            const dev_type: u4 = @truncate(c.field0 & 0xF);
            // mmio = 0
            if (dev_type == 0) {
                const base_paddr: u64 = ((c.field0 >> 4) & 0x0000_FFFF_FFFF_FFFF) << 12;
                if (base_paddr == target_phys_base) {
                    return @truncate(slot);
                }
            }
        }
        slot += 1;
    }
    return null;
}

fn stageElfIntoPageFrame(bytes: []const u8) caps.HandleId {
    const page_size: usize = 4096;
    const pages = (bytes.len + page_size - 1) / page_size;

    const pf_caps = caps.PfCap{ .move = true, .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0,
        @intCast(pages),
    );
    const pf_handle: caps.HandleId = @truncate(cpf.v1 & 0xFFF);

    const var_caps_word = caps.VmarCap{
        .r = true,
        .w = true,
    };
    const cvar = syscall.createVmar(
        @as(u64, var_caps_word.toU16()),
        0b011,
        @intCast(pages),
        0,
        0,
    );
    const vmar_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);
    const var_base: u64 = cvar.v2;

    _ = syscall.mapPf(vmar_handle, &.{ 0, pf_handle });

    const dst: [*]volatile u8 = @ptrFromInt(var_base);
    var i: usize = 0;
    while (i < bytes.len) {
        dst[i] = bytes[i];
        i += 1;
    }

    syscall.issueRegDiscard(.delete, 0, .{ .v1 = vmar_handle });

    return pf_handle;
}

fn decodeEvent(got: syscall.RecvReturn) EventFields {
    return .{
        .recv_status = got.regs.v1,
        .pair_count = (got.word >> 12) & 0xFF,
        .tstart = (got.word >> 20) & 0xFFF,
        .reply_handle_id = @truncate((got.word >> 32) & 0xFFF),
        .event_type = got.word >> 44,
        .result_code = @enumFromInt(got.regs.v3),
        .assertion_id = got.regs.v4,
        .tag = got.regs.v5,
    };
}

fn drainProbeEvent(kind: []const u8, ordinal: usize, got: syscall.RecvReturn) void {
    const event = decodeEvent(got);
    if (embedded_tests.runner_diag) {
        serial.print("[runner]   probe ");
        serial.print(kind);
        serial.print(" #");
        serial.printU64(ordinal);
        serial.print(" recv_v1=");
        serial.printU64(event.recv_status);
        serial.print(" word=0x");
        serial.printHex(got.word);
        serial.print(" event=");
        serial.printU64(event.event_type);
        serial.print(" pairs=");
        serial.printU64(event.pair_count);
        serial.print(" tstart=");
        serial.printU64(event.tstart);
        serial.print(" reply=");
        serial.printU64(event.reply_handle_id);
        serial.print(" tag=0x");
        serial.printHex(event.tag);
        serial.print(" code=");
        serial.printU64(@intFromEnum(event.result_code));
        serial.print(" aid=");
        serial.printU64(event.assertion_id);

        if ((event.tag & TAG_MAGIC) != 0) {
            const index = event.tag & TAG_INDEX_MASK;
            if (index < TOTAL_TESTS) {
                serial.print(" name=");
                serial.print(embedded_tests.manifest[@intCast(index)].name);
            }
        }

        serial.print(" -> probe-only");
    }

    if (event.reply_handle_id == 0) {
        if (embedded_tests.runner_diag) {
            serial.print(" reply=skip-zero-handle\n");
        }
        return;
    }

    const rr = syscall.reply(event.reply_handle_id);
    if (embedded_tests.runner_diag) {
        serial.print(" reply_v1=");
        serial.printU64(rr.v1);
        serial.print("\n");
    }
}

// Writes the result for a tag into the table. Events whose tag does
// not carry `TAG_MAGIC` are silently dropped — they come from
// suspensions that landed on the result port outside of
// `testing.report` (e.g. tests that build their own `suspend`-on-
// port-3 syscall frames, or sentinel-libz consumers — TAG = 0xFFFF
// — both include the magic bit but the latter falls out via the
// out-of-range check). Out-of-range real tags after stripping the
// magic are dropped with a diagnostic so unexpected build/runtime
// drift surfaces immediately.
fn record(tag: u64, r: TestResult, reply_handle_id: caps.HandleId) bool {
    if ((tag & TAG_MAGIC) == 0) {
        if (embedded_tests.runner_diag) {
            serial.print("[runner] deliver tag=0x");
            serial.printHex(tag);
            serial.print(" reply=");
            serial.printU64(reply_handle_id);
            serial.print(" code=");
            serial.printU64(@intFromEnum(r.code));
            serial.print(" aid=");
            serial.printU64(r.assertion_id);
            serial.print(" -> drop missing-magic\n");
        }
        return false;
    }
    const index = tag & TAG_INDEX_MASK;
    if (index >= TOTAL_TESTS) {
        // Sentinel TAG = 0x7FFF (post-strip from 0xFFFF) lands here for
        // any libz consumer that imports the sentinel test_tag module
        // and then somehow ends up suspending on the result port. The
        // runner-internal primary uses the sentinel so we don't print
        // for it, but anything else gets a diagnostic.
        if (index == TAG_INDEX_MASK) {
            if (embedded_tests.runner_diag) {
                serial.print("[runner] deliver tag=0x");
                serial.printHex(tag);
                serial.print(" reply=");
                serial.printU64(reply_handle_id);
                serial.print(" -> drop sentinel\n");
            }
            return false;
        }
        if (embedded_tests.runner_diag) {
            serial.print("[runner] OOB tag=");
            serial.printU64(index);
            serial.print(" raw=0x");
            serial.printHex(tag);
            serial.print(" reply=");
            serial.printU64(reply_handle_id);
            serial.print(" -> drop\n");
        }
        return false;
    }
    results[@intCast(index)] = r;
    if (embedded_tests.runner_diag) {
        serial.print("[runner] deliver ");
        serial.printU64(index);
        serial.print(":");
        serial.print(embedded_tests.manifest[@intCast(index)].name);
        serial.print(" tag=0x");
        serial.printHex(tag);
        serial.print(" reply=");
        serial.printU64(reply_handle_id);
        serial.print(" code=");
        serial.printU64(@intFromEnum(r.code));
        serial.print(" aid=");
        serial.printU64(r.assertion_id);
        serial.print(" -> record\n");
    }
    return true;
}

const RunCounts = struct { pass: usize, fail: usize, miss: usize };

fn summarize() RunCounts {
    var passed: usize = 0;
    var failed: usize = 0;
    var not_run: usize = 0;

    var i: usize = 0;
    while (i < TOTAL_TESTS) {
        const r = results[i];
        const name = embedded_tests.manifest[i].name;
        switch (r.code) {
            .pass => {
                passed += 1;
                serial.print("[runner] PASS ");
                serial.print(name);
                serial.print("\n");
            },
            .not_run => {
                not_run += 1;
                serial.print("[runner] MISS ");
                serial.print(name);
                serial.print(" (no result delivered)\n");
            },
            else => {
                failed += 1;
                serial.print("[runner] FAIL ");
                serial.print(name);
                serial.print(" aid=");
                serial.printU64(r.assertion_id);
                serial.print(" code=");
                serial.printU64(@intFromEnum(r.code));
                serial.print("\n");
            },
        }
        i += 1;
    }

    serial.print("[runner] ");
    serial.printU64(TOTAL_TESTS);
    serial.print(" total / ");
    serial.printU64(passed);
    serial.print(" pass / ");
    serial.printU64(failed);
    serial.print(" fail / ");
    serial.printU64(not_run);
    serial.print(" miss\n");
    return .{ .pass = passed, .fail = failed, .miss = not_run };
}
