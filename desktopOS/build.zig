// desktopOS — small Zag userspace exercising the v3 spec end-to-end.
//
// Build layout:
//   1. block_device.elf — interim mock-storage service (page_frame
//                          backed). Same wire protocol the eventual
//                          NVMe driver will speak, so fs is portable.
//   2. fs.elf            — filesystem service (phase 1: smoke
//                          read/write roundtrip; SQLite VFS lands later).
//   3. nvme_driver.elf   — real NVMe driver. Built but not spawned by
//                          root_service today; awaits IOMMU restoration.
//   4. desktopOS.elf     — root service. Embeds block_device.elf and
//                          fs.elf, spawns each as a child cap domain
//                          with shared port + scratch page_frame.
//
// Every binary is statically linked against libz and produces an
// ET_DYN PIE ELF. The kernel's userspace bringup loads the staged
// root ELF the same way it loads the test runner; the root then
// stages the embedded sub-ELFs into page_frames and createCapability
// Domain's against them.

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

    const optimize: std.builtin.OptimizeMode = .ReleaseSafe;

    // ── Shared modules ──────────────────────────────────────────────

    const lib_mod = b.createModule(.{
        .root_source_file = .{ .cwd_relative = "../libz/lib.zig" },
        .target = target,
        .optimize = optimize,
        .pic = true,
        .omit_frame_pointer = true,
    });
    lib_mod.addImport("lib", lib_mod);

    const log_mod = b.createModule(.{
        .root_source_file = b.path("log/log.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true,
        .omit_frame_pointer = true,
    });
    log_mod.addImport("lib", lib_mod);

    const blockdev_mod = b.createModule(.{
        .root_source_file = b.path("protocols/blockdev.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true,
        .omit_frame_pointer = true,
    });

    const fs_ops_mod = b.createModule(.{
        .root_source_file = b.path("protocols/fs_ops.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true,
        .omit_frame_pointer = true,
    });

    const fs_client_mod = b.createModule(.{
        .root_source_file = b.path("fs_client/lib.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true,
        .omit_frame_pointer = true,
    });
    fs_client_mod.addImport("lib", lib_mod);
    fs_client_mod.addImport("fs_ops", fs_ops_mod);

    const start_src: std.Build.LazyPath = b.path("start.zig");

    // Helper wrapper closure isn't possible in build.zig at top level,
    // so inline each child build below.

    // ── nvme_driver.elf (built; not spawned in phase 1) ─────────────
    const nvme_app_mod = b.createModule(.{
        .root_source_file = b.path("nvme_driver/main.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true,
        .omit_frame_pointer = true,
    });
    nvme_app_mod.addImport("lib", lib_mod);
    nvme_app_mod.addImport("log", log_mod);
    nvme_app_mod.addImport("blockdev", blockdev_mod);

    const nvme_start_mod = b.createModule(.{
        .root_source_file = start_src,
        .target = target,
        .optimize = optimize,
        .pic = true,
        .omit_frame_pointer = true,
    });
    nvme_start_mod.addImport("lib", lib_mod);
    nvme_start_mod.addImport("app", nvme_app_mod);

    const nvme_exe = b.addExecutable(.{
        .name = "nvme_driver",
        .root_module = nvme_start_mod,
        .linkage = .static,
    });
    nvme_exe.pie = true;
    nvme_exe.entry = .{ .symbol_name = "_start" };
    nvme_exe.root_module.strip = false;

    const nvme_install = b.addInstallFile(nvme_exe.getEmittedBin(), "../bin/nvme_driver.elf");
    b.getInstallStep().dependOn(&nvme_install.step);

    // ── block_device.elf ────────────────────────────────────────────
    const blkdev_app_mod = b.createModule(.{
        .root_source_file = b.path("block_device/main.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true,
        .omit_frame_pointer = true,
    });
    blkdev_app_mod.addImport("lib", lib_mod);
    blkdev_app_mod.addImport("log", log_mod);
    blkdev_app_mod.addImport("blockdev", blockdev_mod);

    const blkdev_start_mod = b.createModule(.{
        .root_source_file = start_src,
        .target = target,
        .optimize = optimize,
        .pic = true,
        .omit_frame_pointer = true,
    });
    blkdev_start_mod.addImport("lib", lib_mod);
    blkdev_start_mod.addImport("app", blkdev_app_mod);

    const blkdev_exe = b.addExecutable(.{
        .name = "block_device",
        .root_module = blkdev_start_mod,
        .linkage = .static,
    });
    blkdev_exe.pie = true;
    blkdev_exe.entry = .{ .symbol_name = "_start" };
    blkdev_exe.root_module.strip = false;

    const blkdev_install = b.addInstallFile(blkdev_exe.getEmittedBin(), "../bin/block_device.elf");
    b.getInstallStep().dependOn(&blkdev_install.step);

    // ── fs.elf ──────────────────────────────────────────────────────
    const fs_app_mod = b.createModule(.{
        .root_source_file = b.path("fs/main.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true,
        .omit_frame_pointer = true,
    });
    fs_app_mod.addImport("lib", lib_mod);
    fs_app_mod.addImport("log", log_mod);
    fs_app_mod.addImport("blockdev", blockdev_mod);
    fs_app_mod.addImport("fs_ops", fs_ops_mod);

    const libc_shim_mod = b.createModule(.{
        .root_source_file = b.path("fs/sqlite/libc_shim.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true,
        .omit_frame_pointer = true,
    });
    libc_shim_mod.addImport("lib", lib_mod);
    libc_shim_mod.addImport("log", log_mod);
    fs_app_mod.addImport("libc_shim", libc_shim_mod);

    const sqlite_glue_mod = b.createModule(.{
        .root_source_file = b.path("fs/sqlite/glue.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true,
        .omit_frame_pointer = true,
    });
    sqlite_glue_mod.addImport("lib", lib_mod);
    sqlite_glue_mod.addImport("log", log_mod);
    sqlite_glue_mod.addImport("blockdev", blockdev_mod);
    sqlite_glue_mod.addIncludePath(b.path("fs/sqlite/include"));
    sqlite_glue_mod.addIncludePath(b.path("fs/sqlite"));
    fs_app_mod.addImport("sqlite", sqlite_glue_mod);

    const fs_start_mod = b.createModule(.{
        .root_source_file = start_src,
        .target = target,
        .optimize = optimize,
        .pic = true,
        .omit_frame_pointer = true,
    });
    fs_start_mod.addImport("lib", lib_mod);
    fs_start_mod.addImport("app", fs_app_mod);

    const fs_exe = b.addExecutable(.{
        .name = "fs",
        .root_module = fs_start_mod,
        .linkage = .static,
    });
    fs_exe.pie = true;
    fs_exe.entry = .{ .symbol_name = "_start" };
    fs_exe.root_module.strip = false;

    // SQLite amalgamation, configured for a freestanding embed:
    //   - OS_OTHER=1: kernel never receives a libc syscall; we
    //     install a Zig-side sqlite3_vfs at startup that proxies
    //     xRead/xWrite to block_device.
    //   - THREADSAFE=0: single-threaded fs service.
    //   - ZERO_MALLOC + ENABLE_MEMSYS5: SQLite's built-in fixed-
    //     buffer allocator over a heap we hand it via SQLITE_CONFIG_HEAP.
    //   - OMIT_LOAD_EXTENSION: no dlopen.
    //   - OMIT_AUTOINIT: we call sqlite3_initialize manually after VFS
    //     registration.
    //   - OMIT_DEPRECATED, DEFAULT_MEMSTATUS=0: trim surface.
    //   - HAVE_MALLOC_USABLE_SIZE=0, USE_ALLOCA=0: keep allocator path
    //     deterministic and shim-free.
    fs_exe.addCSourceFile(.{
        .file = b.path("fs/sqlite/sqlite3.c"),
        .flags = &.{
            "-DSQLITE_OS_OTHER=1",
            "-DSQLITE_THREADSAFE=0",
            "-DSQLITE_ZERO_MALLOC",
            "-DSQLITE_ENABLE_MEMSYS5",
            "-DSQLITE_OMIT_LOAD_EXTENSION",
            "-DSQLITE_OMIT_AUTOINIT",
            "-DSQLITE_OMIT_DEPRECATED",
            "-DSQLITE_DEFAULT_MEMSTATUS=0",
            "-DSQLITE_DEFAULT_LOCKING_MODE=1",
            // Don't pass -DSQLITE_USE_ALLOCA — sqlite3.c uses
            // `#ifdef SQLITE_USE_ALLOCA` so any definition (even =0)
            // triggers the alloca path. Omitting the flag entirely
            // makes sqlite3StackAllocRaw fall back to sqlite3DbMallocRaw.
            "-DSQLITE_HAVE_MALLOC_USABLE_SIZE=0",
            "-DSQLITE_NO_SYNC=1",
            "-DSQLITE_TEMP_STORE=2",
            "-DSQLITE_OMIT_SHARED_CACHE",
            "-DSQLITE_OMIT_PROGRESS_CALLBACK",
            "-DSQLITE_OMIT_AUTHORIZATION",
            "-DSQLITE_OMIT_TRACE",
            "-DSQLITE_DISABLE_LFS",
            "-DSQLITE_DEFAULT_PAGE_SIZE=512",
            "-fno-stack-protector",
            "-fno-builtin",
        },
    });
    // Custom freestanding headers (string.h, stdio.h stubs, etc.)
    // win over any system path because addIncludePath inserts at the
    // front of the search list.
    fs_exe.addIncludePath(b.path("fs/sqlite/include"));
    fs_exe.addIncludePath(b.path("fs/sqlite"));

    const fs_install = b.addInstallFile(fs_exe.getEmittedBin(), "../bin/fs.elf");
    b.getInstallStep().dependOn(&fs_install.step);

    // ── verify_fs.elf (smoke harness) ───────────────────────────────
    const verify_app_mod = b.createModule(.{
        .root_source_file = b.path("verify_fs/main.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true,
        .omit_frame_pointer = true,
    });
    verify_app_mod.addImport("lib", lib_mod);
    verify_app_mod.addImport("log", log_mod);
    verify_app_mod.addImport("fs_client", fs_client_mod);
    verify_app_mod.addImport("fs_ops", fs_ops_mod);

    const verify_start_mod = b.createModule(.{
        .root_source_file = start_src,
        .target = target,
        .optimize = optimize,
        .pic = true,
        .omit_frame_pointer = true,
    });
    verify_start_mod.addImport("lib", lib_mod);
    verify_start_mod.addImport("app", verify_app_mod);

    const verify_exe = b.addExecutable(.{
        .name = "verify_fs",
        .root_module = verify_start_mod,
        .linkage = .static,
    });
    verify_exe.pie = true;
    verify_exe.entry = .{ .symbol_name = "_start" };
    verify_exe.root_module.strip = false;

    const verify_install = b.addInstallFile(verify_exe.getEmittedBin(), "../bin/verify_fs.elf");
    b.getInstallStep().dependOn(&verify_install.step);

    // ── Embedded services for root_service ──────────────────────────
    const services_wf = b.addWriteFiles();
    _ = services_wf.addCopyFile(nvme_exe.getEmittedBin(), "nvme_driver.elf");
    _ = services_wf.addCopyFile(blkdev_exe.getEmittedBin(), "block_device.elf");
    _ = services_wf.addCopyFile(fs_exe.getEmittedBin(), "fs.elf");
    _ = services_wf.addCopyFile(verify_exe.getEmittedBin(), "verify_fs.elf");
    const services_src = services_wf.add(
        "embedded_services.zig",
        \\pub const nvme_driver_elf = @embedFile("nvme_driver.elf");
        \\pub const block_device_elf = @embedFile("block_device.elf");
        \\pub const fs_elf = @embedFile("fs.elf");
        \\pub const verify_fs_elf = @embedFile("verify_fs.elf");
        \\
    );
    const services_mod = b.createModule(.{
        .root_source_file = services_src,
        .target = target,
        .optimize = optimize,
    });

    // ── desktopOS.elf (root service) ────────────────────────────────
    const root_app_mod = b.createModule(.{
        .root_source_file = b.path("root_service/main.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true,
        .omit_frame_pointer = true,
    });
    root_app_mod.addImport("lib", lib_mod);
    root_app_mod.addImport("log", log_mod);
    root_app_mod.addImport("services", services_mod);

    const root_start_mod = b.createModule(.{
        .root_source_file = start_src,
        .target = target,
        .optimize = optimize,
        .pic = true,
        .omit_frame_pointer = true,
    });
    root_start_mod.addImport("lib", lib_mod);
    root_start_mod.addImport("app", root_app_mod);

    const root_exe = b.addExecutable(.{
        .name = "desktopOS",
        .root_module = root_start_mod,
        .linkage = .static,
    });
    root_exe.pie = true;
    root_exe.entry = .{ .symbol_name = "_start" };
    root_exe.root_module.strip = false;

    const root_install = b.addInstallFile(root_exe.getEmittedBin(), "../bin/desktopOS.elf");
    b.getInstallStep().dependOn(&root_install.step);
}
