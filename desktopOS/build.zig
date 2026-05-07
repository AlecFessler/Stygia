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

    const usb_input_mod = b.createModule(.{
        .root_source_file = b.path("protocols/usb_input.zig"),
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

    const serial_mod = b.createModule(.{
        .root_source_file = b.path("protocols/serial.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true,
        .omit_frame_pointer = true,
    });

    const serial_client_mod = b.createModule(.{
        .root_source_file = b.path("serial_client/lib.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true,
        .omit_frame_pointer = true,
    });
    serial_client_mod.addImport("lib", lib_mod);
    serial_client_mod.addImport("serial", serial_mod);

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

    // ── serial_server.elf ───────────────────────────────────────────
    const serial_app_mod = b.createModule(.{
        .root_source_file = b.path("serial_server/main.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true,
        .omit_frame_pointer = true,
    });
    serial_app_mod.addImport("lib", lib_mod);
    serial_app_mod.addImport("log", log_mod);
    serial_app_mod.addImport("serial", serial_mod);

    const serial_start_mod = b.createModule(.{
        .root_source_file = start_src,
        .target = target,
        .optimize = optimize,
        .pic = true,
        .omit_frame_pointer = true,
    });
    serial_start_mod.addImport("lib", lib_mod);
    serial_start_mod.addImport("app", serial_app_mod);

    const serial_exe = b.addExecutable(.{
        .name = "serial_server",
        .root_module = serial_start_mod,
        .linkage = .static,
    });
    serial_exe.pie = true;
    serial_exe.entry = .{ .symbol_name = "_start" };
    serial_exe.root_module.strip = false;

    const serial_install = b.addInstallFile(serial_exe.getEmittedBin(), "../bin/serial_server.elf");
    b.getInstallStep().dependOn(&serial_install.step);

    // ── zig_hello.elf — built by the patched no-LLVM Zig compiler ───
    //
    // Phase-0 demo: a Zig program targeting `x86_64-zag-none` (the .zag
    // Os.Tag we added to the patched stdlib at
    // ~/.local/zag-toolchains/zig-0.15.2-src). The patched compiler is
    // invoked as a subprocess; addPrefixedOutputFileArg captures the
    // emitted binary as a build-graph LazyPath we can embed below.
    const zag_zig = b.option(
        []const u8,
        "zag-zig",
        "Patched zig compiler with .zag target (default: ~/.local/zag-toolchains/zig-0.15.2-src/zig-out/bin/zig)",
    ) orelse "/home/alec/.local/zag-toolchains/zig-0.15.2-src/zig-out/bin/zig";
    const zag_zig_lib = b.option(
        []const u8,
        "zag-zig-lib",
        "Path to the patched zig std lib (default: ~/.local/zag-toolchains/zig-0.15.2-src/lib)",
    ) orelse "/home/alec/.local/zag-toolchains/zig-0.15.2-src/lib";

    // Common build flags for any Zag-target ELF compiled by the
    // patched no-LLVM Zig compiler.
    const zag_args = [_][]const u8{
        "-target",         "x86_64-zag-none",
        "-fno-llvm",       "-fno-lld",
        "-fsingle-threaded",
        "-fstrip",         "-OReleaseSmall",
        "-fPIC",           "-fPIE",
        // spec-v3 syscall ABI uses %rbp as vreg 4; the no-LLVM backend
        // currently ignores -fomit-frame-pointer, so each Zag-target
        // binary's syscall asm must use the stack-resident scratch-slot
        // pattern (see zig_hello/main.zig issueRaw) regardless.
        "-fomit-frame-pointer",
    };

    // ── zig_hello2.elf — Phase 4a spawn target. Built like zig_hello
    //    via the patched compiler; embedded into root_service.elf
    //    alongside the other services and written to disk on first
    //    boot so zig_hello can load + spawn it from /hello2.elf.
    const hello2_run = b.addSystemCommand(&.{ zag_zig, "build-exe" });
    hello2_run.addArgs(&.{ "--zig-lib-dir", zag_zig_lib });
    hello2_run.addArgs(&zag_args);
    hello2_run.addFileArg(b.path("zig_hello2/main.zig"));
    const hello2_elf = hello2_run.addPrefixedOutputFileArg("-femit-bin=", "zig_hello2.elf");

    const hello_run = b.addSystemCommand(&.{ zag_zig, "build-exe" });
    hello_run.addArgs(&.{ "--zig-lib-dir", zag_zig_lib });
    hello_run.addArgs(&zag_args);
    hello_run.addFileArg(b.path("zig_hello/main.zig"));
    const hello_elf = hello_run.addPrefixedOutputFileArg("-femit-bin=", "zig_hello.elf");

    // ── zig_hello_std.elf — Phase 4b: imports `std` and prints via
    //    std.io.getStdErr().writeAll. Routes through std.os.zag's
    //    extern bridges (zag_write_console / zag_exit / fs/mmap stubs).
    //    First Zag-target binary that ACTUALLY uses the std-on-Zag
    //    layer instead of inlining its own syscall asm.
    const hello_std_run = b.addSystemCommand(&.{ zag_zig, "build-exe" });
    hello_std_run.addArgs(&.{ "--zig-lib-dir", zag_zig_lib });
    hello_std_run.addArgs(&zag_args);
    hello_std_run.addFileArg(b.path("zig_hello_std/main.zig"));
    const hello_std_elf = hello_std_run.addPrefixedOutputFileArg("-femit-bin=", "zig_hello_std.elf");

    // ── fs_smoke.elf — exercises the libc.a → runtime.o → fs IPC chain.
    //    The patched no-LLVM zig can't take two source files in a single
    //    build-exe, so build each as build-obj, then link with libc.a.
    //
    //    libc.a is pre-built at libz/libc/zig-out/lib/libc.a — see
    //    libz/libc/PORT_CHECKLIST.md. Rebuilt manually after edits to
    //    libz/libc/src/.
    const libc_a = b.option(
        []const u8,
        "libc-a",
        "Path to libz/libc.a (default: ../libz/libc/zig-out/lib/libc.a)",
    ) orelse "/home/alec/Zag/libz/libc/zig-out/lib/libc.a";

    const fs_smoke_obj_run = b.addSystemCommand(&.{ zag_zig, "build-obj" });
    fs_smoke_obj_run.addArgs(&.{ "--zig-lib-dir", zag_zig_lib });
    fs_smoke_obj_run.addArgs(&zag_args);
    fs_smoke_obj_run.addArgs(&.{ "--name", "fs_smoke" });
    fs_smoke_obj_run.addFileArg(b.path("libc_smoke/fs_smoke.zig"));
    const fs_smoke_obj = fs_smoke_obj_run.addPrefixedOutputFileArg("-femit-bin=", "fs_smoke.o");

    const runtime_obj_run = b.addSystemCommand(&.{ zag_zig, "build-obj" });
    runtime_obj_run.addArgs(&.{ "--zig-lib-dir", zag_zig_lib });
    runtime_obj_run.addArgs(&zag_args);
    runtime_obj_run.addArgs(&.{ "--name", "runtime" });
    runtime_obj_run.addFileArg(b.path("libc_smoke/runtime.zig"));
    const runtime_obj = runtime_obj_run.addPrefixedOutputFileArg("-femit-bin=", "runtime.o");

    const fs_smoke_run = b.addSystemCommand(&.{ zag_zig, "build-exe" });
    fs_smoke_run.addArgs(&.{ "--zig-lib-dir", zag_zig_lib });
    fs_smoke_run.addArgs(&zag_args);
    fs_smoke_run.addArgs(&.{ "--name", "fs_smoke" });
    fs_smoke_run.addFileArg(fs_smoke_obj);
    fs_smoke_run.addFileArg(runtime_obj);
    fs_smoke_run.addArg(libc_a);
    const fs_smoke_elf = fs_smoke_run.addPrefixedOutputFileArg("-femit-bin=", "fs_smoke.elf");

    // ── usb_driver.elf ──────────────────────────────────────────────
    const usb_app_mod = b.createModule(.{
        .root_source_file = b.path("usb_driver/main.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true,
        .omit_frame_pointer = true,
    });
    usb_app_mod.addImport("lib", lib_mod);
    usb_app_mod.addImport("log", log_mod);
    usb_app_mod.addImport("usb_input", usb_input_mod);

    const usb_start_mod = b.createModule(.{
        .root_source_file = start_src,
        .target = target,
        .optimize = optimize,
        .pic = true,
        .omit_frame_pointer = true,
    });
    usb_start_mod.addImport("lib", lib_mod);
    usb_start_mod.addImport("app", usb_app_mod);

    const usb_exe = b.addExecutable(.{
        .name = "usb_driver",
        .root_module = usb_start_mod,
        .linkage = .static,
    });
    usb_exe.pie = true;
    usb_exe.entry = .{ .symbol_name = "_start" };
    usb_exe.root_module.strip = false;

    const usb_install = b.addInstallFile(usb_exe.getEmittedBin(), "../bin/usb_driver.elf");
    b.getInstallStep().dependOn(&usb_install.step);

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

    // ── doom.elf ────────────────────────────────────────────────────
    //
    // Vendored doomgeneric Doom port (87 .c files in doom/src) compiled
    // against the freestanding libc surface in doom/libc_shim.zig and
    // linked with a tiny C platform shim (doom/dg_platform.c) that
    // forwards the DG_* hooks to Zig externs in doom/main.zig. The
    // shareware WAD is @embedFile-d directly into the ELF.
    const doom_app_mod = b.createModule(.{
        .root_source_file = b.path("doom/main.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true,
        .omit_frame_pointer = true,
    });
    doom_app_mod.addImport("lib", lib_mod);
    doom_app_mod.addImport("log", log_mod);
    doom_app_mod.addImport("usb_input", usb_input_mod);

    const doom_libc_mod = b.createModule(.{
        .root_source_file = b.path("doom/libc_shim.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true,
        .omit_frame_pointer = true,
    });
    doom_libc_mod.addImport("lib", lib_mod);
    doom_libc_mod.addImport("log", log_mod);
    doom_app_mod.addImport("libc_shim", doom_libc_mod);

    const doom_start_mod = b.createModule(.{
        .root_source_file = start_src,
        .target = target,
        .optimize = optimize,
        .pic = true,
        .omit_frame_pointer = true,
    });
    doom_start_mod.addImport("lib", lib_mod);
    doom_start_mod.addImport("app", doom_app_mod);

    const doom_exe = b.addExecutable(.{
        .name = "doom",
        .root_module = doom_start_mod,
        .linkage = .static,
    });
    doom_exe.pie = true;
    doom_exe.entry = .{ .symbol_name = "_start" };
    doom_exe.root_module.strip = false;

    const doom_c_flags = [_][]const u8{
        "-std=gnu99",
        "-fno-stack-protector",
        "-fno-builtin",
        "-fno-strict-aliasing",
        "-fno-sanitize=undefined", // doom predates UBSan-clean expectations
        "-fno-pic",
        "-fPIE",
        "-DDOOMGENERIC",
        "-DNORMALUNIX",
        "-DLINUX", // toggles the unix-y ifdef paths we want over the win32 ones
        "-DNO_SCREENSHOT",
        "-Wno-implicit-function-declaration",
        "-Wno-incompatible-pointer-types",
        "-Wno-pointer-sign",
        "-Wno-unused-result",
        "-Wno-format",
        "-Wno-deprecated-non-prototype",
        "-Wno-int-conversion",
        "-Wno-unused-but-set-variable",
        "-Wno-parentheses",
    };

    // Enumerate every .c file in doom/src/ at configure time, skipping
    // a small set of source files that hard-depend on host audio /
    // graphics SDKs we don't have (SDL, allegro). Doom can run silent
    // and headless audio-wise; only the rendering path matters.
    const doom_skip_sources = [_][]const u8{
        "i_sdlmusic.c",
        "i_sdlsound.c",
        "i_allegromusic.c",
        "i_allegrosound.c",
    };

    var doom_src_dir = std.fs.cwd().openDir("doom/src", .{ .iterate = true }) catch unreachable;
    defer doom_src_dir.close();
    var iter = doom_src_dir.iterate();
    while (iter.next() catch unreachable) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".c")) continue;
        var skip = false;
        for (doom_skip_sources) |s| {
            if (std.mem.eql(u8, entry.name, s)) {
                skip = true;
                break;
            }
        }
        if (skip) continue;
        const path = b.fmt("doom/src/{s}", .{entry.name});
        doom_exe.addCSourceFile(.{
            .file = b.path(path),
            .flags = &doom_c_flags,
        });
    }

    // The tiny platform shim that forwards DG_* into Zig externs.
    doom_exe.addCSourceFile(.{
        .file = b.path("doom/dg_platform.c"),
        .flags = &doom_c_flags,
    });

    // Custom freestanding headers (ctype, stdio, stdlib, string, …) at
    // the front of the include list shadow any system ones.
    doom_exe.addIncludePath(b.path("doom/include"));
    doom_exe.addIncludePath(b.path("doom/src"));
    doom_exe.addIncludePath(b.path("doom"));

    const doom_install = b.addInstallFile(doom_exe.getEmittedBin(), "../bin/doom.elf");
    b.getInstallStep().dependOn(&doom_install.step);

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
    _ = services_wf.addCopyFile(usb_exe.getEmittedBin(), "usb_driver.elf");
    _ = services_wf.addCopyFile(serial_exe.getEmittedBin(), "serial_server.elf");
    _ = services_wf.addCopyFile(blkdev_exe.getEmittedBin(), "block_device.elf");
    _ = services_wf.addCopyFile(fs_exe.getEmittedBin(), "fs.elf");
    _ = services_wf.addCopyFile(verify_exe.getEmittedBin(), "verify_fs.elf");
    _ = services_wf.addCopyFile(doom_exe.getEmittedBin(), "doom.elf");
    _ = services_wf.addCopyFile(hello_elf, "zig_hello.elf");
    _ = services_wf.addCopyFile(hello2_elf, "zig_hello2.elf");
    _ = services_wf.addCopyFile(hello_std_elf, "zig_hello_std.elf");
    _ = services_wf.addCopyFile(fs_smoke_elf, "fs_smoke.elf");
    // Phase 4c.5: the cross-compiled real Zig compiler binary (165 MB).
    // Built once outside the tree at /tmp/zig-for-zag/bin/zig, then
    // copied to desktopOS/zig_compiler/zig.elf (gitignored) so the build
    // system has a stable path. Embedding it makes desktopOS.elf large
    // but the kernel/bootloader can handle it.
    _ = services_wf.addCopyFile(b.path("zig_compiler/zig.elf"), "zig_compiler.elf");
    const services_src = services_wf.add(
        "embedded_services.zig",
        \\pub const nvme_driver_elf = @embedFile("nvme_driver.elf");
        \\pub const usb_driver_elf = @embedFile("usb_driver.elf");
        \\pub const serial_server_elf = @embedFile("serial_server.elf");
        \\pub const block_device_elf = @embedFile("block_device.elf");
        \\pub const fs_elf = @embedFile("fs.elf");
        \\pub const verify_fs_elf = @embedFile("verify_fs.elf");
        \\pub const doom_elf = @embedFile("doom.elf");
        \\pub const zig_hello_elf = @embedFile("zig_hello.elf");
        \\pub const zig_hello2_elf = @embedFile("zig_hello2.elf");
        \\pub const zig_hello_std_elf = @embedFile("zig_hello_std.elf");
        \\pub const fs_smoke_elf = @embedFile("fs_smoke.elf");
        \\pub const zig_compiler_elf = @embedFile("zig_compiler.elf");
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
