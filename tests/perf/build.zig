const std = @import("std");

pub fn build(b: *std.Build) void {
    const target_arch_str = b.option([]const u8, "arch", "Target architecture (x64 or arm)") orelse "x64";
    const workload = b.option([]const u8, "workload", "kprof workload (default: idc_pp)") orelse "idc_pp";

    const workload_src = blk: {
        if (std.mem.eql(u8, workload, "idc_pp")) break :blk "src/idc_pp.zig";
        @panic("-Dworkload must be: idc_pp");
    };

    const cpu_arch: std.Target.Cpu.Arch = blk: {
        break :blk if (std.mem.eql(u8, target_arch_str, "x64"))
            .x86_64
        else if (std.mem.eql(u8, target_arch_str, "arm"))
            .aarch64
        else
            @panic("Unsupported target architecture");
    };
    const cpu_model: std.Target.Query.CpuModel = if (cpu_arch == .aarch64)
        .{ .explicit = &std.Target.aarch64.cpu.cortex_a72 }
    else
        .determined_by_arch_os;
    const target = b.resolveTargetQuery(.{
        .cpu_arch = cpu_arch,
        .os_tag = .freestanding,
        .cpu_model = cpu_model,
    });

    // Static-libz path: lib_static.zig routes `syscall` / `caps` /
    // `errors` to the top-level libz/ tree (full inline-asm bodies,
    // no externs). Mirrors the runner's setup in tests/suite/build.zig —
    // the prof root service runs as the root CD with no libz pf to map,
    // so the dynamic .so load path is unusable.
    const runner_syscall_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../../libz/syscall.zig" },
        .target = target,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
    });
    const caps_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../../libz/caps.zig" },
        .target = target,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
    });
    const errors_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../../libz/errors.zig" },
        .target = target,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
    });
    const lib_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../suite/runner/lib_static.zig" },
        .target = target,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
    });
    lib_mod.addImport("lib", lib_mod);
    lib_mod.addImport("syscall", runner_syscall_mod);
    lib_mod.addImport("caps", caps_mod);
    lib_mod.addImport("errors", errors_mod);
    // lib_static.zig does not import test_tag, but testing.zig (also
    // re-exported from lib_static.zig) does — even unused, the
    // import must resolve at compile time.
    const sentinel_tag_mod = b.createModule(.{
        .root_source_file = b.addWriteFiles().add(
            "test_tag.zig",
            "pub const TAG: u16 = 0xFFFF;\n",
        ),
        .target = target,
        .optimize = .ReleaseSmall,
    });
    lib_mod.addImport("test_tag", sentinel_tag_mod);

    // libz/start.zig imports libz_loader unconditionally; the
    // RUNNER_STATIC gate only skips its bootstrap call site.
    const libz_loader_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../../libz/loader.zig" },
        .target = target,
        .optimize = .ReleaseSmall,
        .pic = true,
        .single_threaded = true,
    });

    const app_mod = b.createModule(.{
        .root_source_file = b.path(workload_src),
        .target = target,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
    });
    app_mod.addImport("lib", lib_mod);
    app_mod.addImport("libz_loader", libz_loader_mod);

    const start_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../suite/runner/start.zig" },
        .target = target,
        .optimize = .ReleaseSmall,
        .pic = true,
        .omit_frame_pointer = true,
    });
    start_mod.addImport("lib", lib_mod);
    start_mod.addImport("app", app_mod);
    start_mod.addImport("libz_loader", libz_loader_mod);

    const exe = b.addExecutable(.{
        .name = "root_service",
        .root_module = start_mod,
        .linkage = .static,
    });
    exe.pie = true;
    exe.entry = .{ .symbol_name = "_start" };

    const install = b.addInstallFile(exe.getEmittedBin(), "../bin/root_service.elf");
    b.getInstallStep().dependOn(&install.step);
}
