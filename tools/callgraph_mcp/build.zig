const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseFast,
    });

    // GCC 16 crt objects contain .sframe relocations unsupported by Zig
    // 0.15.2's bundled linker. Emit the Zig object, then link with system cc.
    const obj = b.addObject(.{
        .name = "callgraph_mcp",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });

    const link = b.addSystemCommand(&.{ "cc", "-o" });
    const exe_path = link.addOutputFileArg("callgraph_mcp");
    link.addFileArg(obj.getEmittedBin());
    link.addArg("-lsqlite3");

    const install = b.addInstallBinFile(exe_path, "callgraph_mcp");
    b.getInstallStep().dependOn(&install.step);

    const run_cmd = std.Build.Step.Run.create(b, "run callgraph_mcp");
    run_cmd.addFileArg(exe_path);
    run_cmd.step.dependOn(&install.step);
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the callgraph MCP daemon");
    run_step.dependOn(&run_cmd.step);
}
