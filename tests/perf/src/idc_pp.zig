// Synthetic IDC ping-pong workload — measures roundtrip cycles for
// the L4 fast-suspend path under controlled, single-core conditions.
//
// Topology (one capability domain, two ECs, one port):
//   pinger = initial EC, runs the measurement loop
//   ponger = worker EC at higher priority, recv → reply forever
//   port   = bind+recv, both ECs hold via the shared cap table
//
// Per round the pinger emits one syscall — `suspend(self, port)` —
// and stops the timer when the kernel returns from that suspend. The
// kernel work covered by that delta is:
//   1. pinger's suspend (FAST PATH if ponger is recv-waiting)
//   2. ponger's recv → returns with reply_handle in word bits 32-43
//   3. ponger's reply(reply_handle) → unblocks pinger
//   4. context switch back to pinger
// Only step 1 takes the L4 zero-copy register-transfer path. Steps 2-4
// are the slow-path baseline. A/B-ing `-Dkernel_fastpath=true|false`
// isolates the suspend-side delta.
//
// Priority arrangement: pinger keeps .normal (default for the initial
// EC). Ponger is bumped to .high so that on smp=1 the scheduler runs
// ponger to its recv() before resuming pinger — guaranteeing the
// fast-path predicate (`port has receiver waiting`) is satisfied on
// every round after warmup.

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;

// Marker read by libz/start.zig at comptime: skip the libz_loader
// bootstrap (the prof root CD does not get a libz pf passed in by
// userspace_init.zig — there is no slot 5 to map). All syscall wrappers
// resolve to the static-asm bodies in libz/syscall.zig via the
// `static_syscall` import chain in tests/perf/libz/lib.zig.
pub const RUNNER_STATIC = true;

// Spec layout: recv's returned syscall word
//   bits 0-11   syscall_num echo
//   bits 12-19  pair_count
//   bits 20-31  tstart
//   bits 32-43  reply_handle_id
//   bits 44-48  event_type
// (Mirrors REPLY_HANDLE_SHIFT in kernel/sched/port.zig.)
const REPLY_HANDLE_SHIFT: u6 = 32;
const REPLY_HANDLE_MASK: u64 = 0xFFF;

// COM1 serial — inline subset of tests/tests/runner/serial.zig
const COM1_BASE_PORT: u16 = 0x3F8;
const COM1_PORT_COUNT: u16 = 8;

const Serial = struct {
    base: ?[*]volatile u8,

    fn print(self: *const Serial, s: []const u8) void {
        const b = self.base orelse return;
        var i: usize = 0;
        while (i < s.len) {
            b[0] = s[i];
            i += 1;
        }
    }

    fn printU64(self: *const Serial, n: u64) void {
        const b = self.base orelse return;
        var buf: [20]u8 = undefined;
        if (n == 0) {
            b[0] = '0';
            return;
        }
        var v: u64 = n;
        var i: usize = 0;
        while (v != 0) {
            buf[i] = @intCast('0' + (v % 10));
            v /= 10;
            i += 1;
        }
        while (i > 0) {
            i -= 1;
            b[0] = buf[i];
        }
    }
};

fn findCom1(cap_table_base: u64) ?caps.HandleId {
    var slot: u32 = caps.SLOT_FIRST_PASSED;
    while (slot < caps.HANDLE_TABLE_MAX) {
        const c = caps.readCap(cap_table_base, slot);
        if (c.handleType() == .device_region) {
            const dr = caps.deviceRegionFields(c);
            if (dr.dev_type == .port_io and
                dr.base_port == COM1_BASE_PORT and
                dr.port_count == COM1_PORT_COUNT)
            {
                return @truncate(slot);
            }
        }
        slot += 1;
    }
    return null;
}

fn initSerial(cap_table_base: u64) Serial {
    const dev = findCom1(cap_table_base) orelse return .{ .base = null };
    const var_caps_word = caps.VmarCap{ .r = true, .w = true, .mmio = true };
    const props: u64 = (1 << 5) | 0b011; // cch=uc, cur_rwx=r|w
    const cvar = syscall.createVmar(@as(u64, var_caps_word.toU16()), props, 1, 0, 0);
    if (cvar.v1 < 16) return .{ .base = null };
    const vmar_handle: caps.HandleId = @truncate(cvar.v1 & 0xFFF);
    const var_base: u64 = cvar.v2;
    const mm = syscall.mapMmio(vmar_handle, dev);
    if (mm.v1 != 0) return .{ .base = null };
    return .{ .base = @ptrFromInt(var_base) };
}

inline fn cycles() u64 {
    return switch (builtin.cpu.arch) {
        .x86_64 => blk: {
            var lo: u32 = undefined;
            var hi: u32 = undefined;
            asm volatile ("rdtsc"
                : [lo] "={eax}" (lo),
                  [hi] "={edx}" (hi),
            );
            break :blk (@as(u64, hi) << 32) | @as(u64, lo);
        },
        .aarch64 => blk: {
            var c: u64 = undefined;
            asm volatile ("mrs %[c], cntvct_el0"
                : [c] "=r" (c),
            );
            break :blk c;
        },
        else => @compileError("unsupported arch"),
    };
}

// pinger and ponger live in the same CD/address space, so the port
// handle is just a global that the ponger entry function reads.
var g_port: u12 = 0;

fn pongerLoop() noreturn {
    // Bootstrap: bare recv to wait for the first ping. After that,
    // collapse the recv→reply→recv loop into a single replyRecv per
    // round so the round-trip stays in the L4 fast path: ponger's
    // replyRecv parks ponger on the port directly (no run-queue
    // detour), so the pinger's next suspend hits the suspend fast
    // path predicate (port has a recv waiter) every round.
    var rr = syscall.recv(g_port, 0);
    while (true) {
        const reply_h: u12 = @truncate((rr.word >> REPLY_HANDLE_SHIFT) & REPLY_HANDLE_MASK);
        rr = syscall.replyRecv(reply_h, g_port);
    }
}

const N_ROUNDS: usize = 5_000;
var samples: [N_ROUNDS]u64 = .{0} ** N_ROUNDS;

pub fn main(cap_table_base: u64) void {
    const ser = initSerial(cap_table_base);
    ser.print("[idc_pp] init\n");

    const port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (cp.v1 < 16) {
        ser.print("[idc_pp] FAIL createPort v1=");
        ser.printU64(cp.v1);
        ser.print("\n");
        return;
    }
    g_port = @truncate(cp.v1 & 0xFFF);

    // Mint ponger EC. spri so we can elevate priority; susp+read+write
    // so the fast-path target-cap check (susp+read+write all set on
    // pinger's self handle, see interrupts.zig) has a matching peer
    // when pinger calls suspend(self). restart_policy=0 (kill) keeps
    // us out of the restart-ceiling code path.
    const ec_caps = caps.EcCap{
        .spri = true,
        .susp = true,
        .read = true,
        .write = true,
        .restart_policy = 0,
    };
    const ent: u64 = @intFromPtr(&pongerLoop);
    const cec = syscall.createExecutionContext(
        @as(u64, ec_caps.toU16()),
        ent,
        4, // stack_pages
        0, // target = self CD
        0, // affinity = any core
    );
    if (cec.v1 < 16) {
        ser.print("[idc_pp] FAIL createEc v1=");
        ser.printU64(cec.v1);
        ser.print("\n");
        return;
    }
    const ponger_ec: u12 = @truncate(cec.v1 & 0xFFF);

    // 2 = .high in kernel/sched/execution_context.zig Priority enum;
    // bumps ponger above pinger so on smp=1 it preempts and reaches
    // recv() before pinger calls suspend, satisfying the fast-path
    // predicate (port has a recv-waiter) on every round after warmup.
    const pri_r = syscall.priority(ponger_ec, 2);
    if (pri_r.v1 != @intFromEnum(errors.Error.OK)) {
        ser.print("[idc_pp] FAIL priority v1=");
        ser.printU64(pri_r.v1);
        ser.print("\n");
        return;
    }

    // Drain first-iteration slow-path miss while ponger is still
    // bringing up its recv state.
    var w: usize = 0;
    while (w < 200) {
        _ = syscall.suspendEc(caps.SLOT_INITIAL_EC, g_port, &.{});
        w += 1;
    }

    ser.print("[idc_pp] start N=");
    ser.printU64(N_ROUNDS);
    ser.print("\n");

    var i: usize = 0;
    while (i < N_ROUNDS) {
        const t0 = cycles();
        _ = syscall.suspendEc(caps.SLOT_INITIAL_EC, g_port, &.{});
        const t1 = cycles();
        samples[i] = t1 - t0;
        i += 1;
    }

    var k: usize = 0;
    while (k < N_ROUNDS) {
        ser.print("[idc_pp] sample ");
        ser.printU64(k);
        ser.print(" ");
        ser.printU64(samples[k]);
        ser.print("\n");
        k += 1;
    }
    ser.print("[idc_pp] done\n");
}
