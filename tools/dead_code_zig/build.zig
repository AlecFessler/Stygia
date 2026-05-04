const std = @import("std");

// Workaround for gcc 16.1's crt1.o carrying an .sframe section with
// R_X86_64_PC64 relocations that zig 0.15.2's bundled lld/zld don't
// understand yet (lands in zig 0.16+). We compile the analyzer to a
// freestanding object via `zig build-obj`, then hand it to the system
// `cc` so binutils ld (which handles the relocation type) does the
// final link against libsqlite3 / libc / crt*.o. The artifact still
// installs to `zig-out/bin/dead_code_zig` so existing callers
// (tests/precommit.sh) work unchanged.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseFast,
    });

    const obj = b.addObject(.{
        .name = "dead_code_zig",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });

    const link = b.addSystemCommand(&.{ "cc", "-o" });
    const exe_path = link.addOutputFileArg("dead_code_zig");
    link.addFileArg(obj.getEmittedBin());
    link.addArg("-lsqlite3");

    const install = b.addInstallBinFile(exe_path, "dead_code_zig");
    b.getInstallStep().dependOn(&install.step);

    const run_cmd = std.Build.Step.Run.create(b, "run dead_code_zig");
    run_cmd.addFileArg(exe_path);
    run_cmd.step.dependOn(&install.step);
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the dead-code analyzer");
    run_step.dependOn(&run_cmd.step);
}
