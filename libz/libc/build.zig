const std = @import("std");

// libz/libc/build.zig — produces libc.a for x86_64-stygia-none.
//
// Invoked by the patched zig (~/.local/stygia-toolchains/zig-0.15.2-src/
// zig-out/bin/zig) pointed at the patched stdlib (--zig-lib-dir
// ~/.local/stygia-toolchains/zig-0.15.2-src/lib), which has Os.Tag.stygia.
//
// The resulting libc.a is the minimal C-ABI compatibility layer the
// cross-compiled Zig+LLVM compiler links against (Phase 4c.4). Single-
// threaded for the first cut: errno is a global, pthread is a no-op
// shim, no FS-base TLS work needed.
//
//     ~/.local/stygia-toolchains/zig-0.15.2-src/zig-out/bin/zig build \
//         --build-file libz/libc/build.zig \
//         --zig-lib-dir ~/.local/stygia-toolchains/zig-0.15.2-src/lib

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});

    const target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .stygia,
        .abi = .none,
        .ofmt = .elf,
    });

    const libc_mod = b.createModule(.{
        .root_source_file = b.path("src/libc.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true,
        .single_threaded = true,
        .strip = false,
        .red_zone = false,
        .omit_frame_pointer = true,
    });

    const libc = b.addLibrary(.{
        .name = "c",
        .linkage = .static,
        .root_module = libc_mod,
    });

    b.installArtifact(libc);
}
