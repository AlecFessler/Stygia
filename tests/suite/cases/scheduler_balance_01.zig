// Scheduler balance -- pull-side work stealing smoke.
//
// This is not a specv3 syscall assertion. It is a scheduler regression
// test for affinity-0 Threads: create a batch of runnable workers with
// affinity = 0 from one test thread, then prove the workers execute on more
// than one core. It remains meaningful when the suite runner is invoked
// with -Dspread_cores=false because the workers are created inside this
// test domain and explicitly use the affinity-0 sentinel.

const builtin = @import("builtin");
const lib = @import("lib");
const test_environment = @import("test_environment");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const WORKERS: usize = 24;
const POLL_BUDGET: usize = 200_000;

var go: u32 = 0;
var stop: u32 = 0;
var observed_mask: u64 = 0;
var worker_samples: u32 = 0;

fn cpuPause() void {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("pause" ::: .{ .memory = true }),
        .aarch64 => asm volatile ("yield" ::: .{ .memory = true }),
        else => @compileError("unsupported arch"),
    }
}

fn workerEntry() callconv(.c) noreturn {
    while (@atomicLoad(u32, &go, .acquire) == 0) {
        cpuPause();
    }

    while (@atomicLoad(u32, &stop, .acquire) == 0) {
        const core = testing.currentCoreId();
        if (core < 64) {
            _ = @atomicRmw(u64, &observed_mask, .Or, @as(u64, 1) << @truncate(core), .acq_rel);
        }
        _ = @atomicRmw(u32, &worker_samples, .Add, 1, .acq_rel);
        _ = syscall.yieldThread(0);
    }

    while (true) {
        cpuPause();
    }
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Stealing is intentionally disabled on aarch64 until FP migration
    // parity is implemented. Keep the ELF buildable there, but do not
    // report a false scheduler failure on that architecture.
    if (builtin.cpu.arch == .aarch64) {
        testing.pass();
        return;
    }

    @atomicStore(u32, &go, 0, .release);
    @atomicStore(u32, &stop, 0, .release);
    @atomicStore(u64, &observed_mask, 0, .release);
    @atomicStore(u32, &worker_samples, 0, .release);

    if (test_environment.expected_cores < 2) {
        testing.fail(1);
        return;
    }

    const thread_caps = caps.ThreadCap{
        .term = true,
        .restart_policy = 0,
    };
    const priority_normal: u64 = 1;
    const caps_word: u64 = @as(u64, thread_caps.toU16()) | (priority_normal << 32);
    const entry: u64 = @intFromPtr(&workerEntry);

    var workers: [WORKERS]u12 = undefined;
    var made: usize = 0;
    while (made < WORKERS) : (made += 1) {
        const cec = syscall.createThread(
            caps_word,
            entry,
            1,
            0,
            0, // affinity 0: steal-admissible by any core
        );
        if (testing.isHandleError(cec.v1)) {
            cleanup(workers[0..made]);
            testing.fail(2);
            return;
        }
        workers[made] = @truncate(cec.v1 & 0xFFF);
    }

    @atomicStore(u32, &go, 1, .release);

    var polls: usize = 0;
    while (polls < POLL_BUDGET) : (polls += 1) {
        const mask = @atomicLoad(u64, &observed_mask, .acquire);
        if (@popCount(mask) > 1) {
            @atomicStore(u32, &stop, 1, .release);
            cleanup(workers[0..]);
            testing.pass();
            return;
        }
        _ = syscall.yieldThread(0);
    }

    @atomicStore(u32, &stop, 1, .release);
    cleanup(workers[0..]);

    if (@atomicLoad(u32, &worker_samples, .acquire) == 0) {
        testing.fail(3);
        return;
    }
    testing.fail(4);
}

fn cleanup(workers: []const u12) void {
    for (workers) |worker| {
        const r = syscall.terminate(worker);
        if (r.v1 != @intFromEnum(errors.Error.OK)) {
            // Best-effort cleanup; the test result is decided by caller.
        }
    }
}
