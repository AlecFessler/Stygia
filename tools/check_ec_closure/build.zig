const std = @import("std");

// Same two-step link as tools/check_gen_lock/build.zig: gcc 16.1's crt1.o
// carries an .sframe section with R_X86_64_PC64 relocations that zig
// 0.15.2's bundled lld doesn't understand, so we emit a freestanding
// object and hand it to the system `cc` for the final link against
// libsqlite3.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseFast,
    });

    const obj = b.addObject(.{
        .name = "check_ec_closure",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });

    const link = b.addSystemCommand(&.{ "cc", "-o" });
    const exe_path = link.addOutputFileArg("check_ec_closure");
    link.addFileArg(obj.getEmittedBin());
    link.addArg("-lsqlite3");

    const install = b.addInstallBinFile(exe_path, "check_ec_closure");
    b.getInstallStep().dependOn(&install.step);

    const run_cmd = std.Build.Step.Run.create(b, "run check_ec_closure");
    run_cmd.addFileArg(exe_path);
    run_cmd.step.dependOn(&install.step);
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the EC-closure analyzer");
    run_step.dependOn(&run_cmd.step);
}
