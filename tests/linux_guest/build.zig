const std = @import("std");

pub fn build(b: *std.Build) void {
    const arch_opt = b.option([]const u8, "arch", "Target architecture: x64 (default) or arm") orelse "x64";
    const is_arm = std.mem.eql(u8, arch_opt, "arm");

    const target = if (is_arm)
        b.resolveTargetQuery(.{
            .cpu_arch = .aarch64,
            .os_tag = .freestanding,
        })
    else
        b.resolveTargetQuery(.{
            .cpu_arch = .x86_64,
            .os_tag = .freestanding,
        });

    const lib_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../../libz/lib.zig" },
        .target = target,
        .optimize = .ReleaseSafe,
        .pic = true,
        .omit_frame_pointer = true,
    });
    lib_mod.addImport("lib", lib_mod);

    const app_root = if (is_arm) "vmm/aarch64/main.zig" else "vmm/main.zig";

    const app_mod = b.createModule(.{
        .root_source_file = b.path(app_root),
        .target = target,
        .optimize = .ReleaseSafe,
        .pic = true,
        .omit_frame_pointer = true,
    });
    app_mod.addImport("lib", lib_mod);

    // Embedded guest assets for QEMU fallback (NVMe may not work in
    // emulation). assets/assets.zig dispatches on target arch: bzImage +
    // initramfs.cpio.gz for x64, raw arm64 Image + rootfs.cpio.gz for arm.
    const assets_mod = b.createModule(.{
        .root_source_file = b.path("assets/assets.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
        .pic = true,
        .omit_frame_pointer = true,
    });
    app_mod.addImport("assets", assets_mod);

    const start_mod = b.createModule(.{
        .root_source_file = b.path("start.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
        .pic = true,
        .omit_frame_pointer = true,
    });
    start_mod.addImport("lib", lib_mod);
    start_mod.addImport("app", app_mod);

    const exe_name = if (is_arm) "linux_guest-arm" else "linux_guest";
    const exe = b.addExecutable(.{
        .name = exe_name,
        .root_module = start_mod,
        .linkage = .static,
    });
    exe.pie = true;
    exe.entry = .{ .symbol_name = "_start" };
    exe.root_module.strip = false;

    const install_name = if (is_arm) "../bin/linux_guest-arm.elf" else "../bin/linux_guest.elf";
    const install = b.addInstallFile(exe.getEmittedBin(), install_name);
    b.getInstallStep().dependOn(&install.step);
}
