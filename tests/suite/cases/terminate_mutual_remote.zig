// Two pinned Threads enter terminate on one another at the same barrier.
// A retired caller must leave the remote-eviction wait, allowing both cores
// to schedule a fresh Thread. Repeat in one boot to vary the syscall race.
// The runner's recv deadline and the harness's VM timeout bound a regression.
const lib = @import("lib");
const test_environment = @import("test_environment");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

const ROUNDS = 32;
const POLLS = 20_000;

var ready: u32 = 0;
var attempting: u32 = 0;
var go: u32 = 0;
var target_a: u32 = 0;
var target_b: u32 = 0;
var seen_cores: u64 = 0;

fn spin() void {
    std.atomic.spinLoopHint();
}

const std = @import("std");

fn terminatorA() callconv(.c) noreturn {
    _ = @atomicRmw(u32, &ready, .Add, 1, .acq_rel);
    while (@atomicLoad(u32, &go, .acquire) == 0) spin();
    _ = @atomicRmw(u32, &attempting, .Add, 1, .acq_rel);
    while (@atomicLoad(u32, &attempting, .acquire) != 2) spin();
    _ = syscall.terminate(@truncate(@atomicLoad(u32, &target_a, .acquire)));
    // The peer may have retired first. In that legal one-sided case this
    // caller remains live; retire it before the next round.
    _ = syscall.terminate(@truncate(@atomicLoad(u32, &target_b, .acquire)));
    while (true) spin();
}

fn terminatorB() callconv(.c) noreturn {
    _ = @atomicRmw(u32, &ready, .Add, 1, .acq_rel);
    while (@atomicLoad(u32, &go, .acquire) == 0) spin();
    _ = @atomicRmw(u32, &attempting, .Add, 1, .acq_rel);
    while (@atomicLoad(u32, &attempting, .acquire) != 2) spin();
    _ = syscall.terminate(@truncate(@atomicLoad(u32, &target_b, .acquire)));
    _ = syscall.terminate(@truncate(@atomicLoad(u32, &target_a, .acquire)));
    while (true) spin();
}

fn probe() callconv(.c) noreturn {
    const core = testing.currentCoreId();
    _ = @atomicRmw(u64, &seen_cores, .Or, @as(u64, 1) << @truncate(core), .acq_rel);
    while (true) {
        _ = syscall.yieldThread(0);
    }
}

fn create(entry: u64, core: u64) ?u12 {
    const word: u64 = @as(u64, (caps.ThreadCap{ .term = true }).toU16());
    const result = syscall.createThread(word, entry, 1, 0, @as(u64, 1) << @truncate(core));
    if (testing.isHandleError(result.v1)) return null;
    return @truncate(result.v1 & 0xfff);
}

pub fn main(_: u64) void {
    if (test_environment.expected_cores < 3) return testing.fail(1);
    const own = testing.currentCoreId();
    const core_a = (own + 1) % test_environment.expected_cores;
    const core_b = (own + 2) % test_environment.expected_cores;
    const want = (@as(u64, 1) << @truncate(core_a)) | (@as(u64, 1) << @truncate(core_b));

    for (0..ROUNDS) |_| {
        @atomicStore(u32, &ready, 0, .release);
        @atomicStore(u32, &attempting, 0, .release);
        @atomicStore(u32, &go, 0, .release);
        @atomicStore(u64, &seen_cores, 0, .release);

        const a = create(@intFromPtr(&terminatorA), core_a) orelse return testing.fail(2);
        const b = create(@intFromPtr(&terminatorB), core_b) orelse return testing.fail(3);
        @atomicStore(u32, &target_a, b, .release);
        @atomicStore(u32, &target_b, a, .release);

        var polls: usize = 0;
        while (@atomicLoad(u32, &ready, .acquire) != 2 and polls < POLLS) : (polls += 1) {
            _ = syscall.yieldThread(0);
        }
        if (polls == POLLS) return testing.fail(4);
        @atomicStore(u32, &go, 1, .release);

        polls = 0;
        while (@atomicLoad(u32, &attempting, .acquire) != 2 and polls < POLLS) : (polls += 1) {
            _ = syscall.yieldThread(0);
        }
        if (polls == POLLS) return testing.fail(11);

        // Created after release: a probe cannot run on a core whose
        // terminator is stuck in the kernel with IRQs disabled.
        const probe_a = create(@intFromPtr(&probe), core_a) orelse return testing.fail(5);
        const probe_b = create(@intFromPtr(&probe), core_b) orelse return testing.fail(6);
        polls = 0;
        while ((@atomicLoad(u64, &seen_cores, .acquire) & want) != want and polls < POLLS) : (polls += 1) {
            _ = syscall.yieldThread(0);
        }
        if (polls == POLLS) return testing.fail(7);
        if (syscall.terminate(probe_a).v1 != @intFromEnum(errors.Error.OK)) return testing.fail(9);
        if (syscall.terminate(probe_b).v1 != @intFromEnum(errors.Error.OK)) return testing.fail(10);
    }
    testing.pass();
}
