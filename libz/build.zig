const std = @import("std");

// libz/build.zig — produces libz.elf, the kernel-shipped userspace
// shared library that dynamic libz consumers (test ELFs, hyprvOS apps)
// link against. Static consumers (the test runner, root_service) skip
// this build entirely and import libz/lib.zig directly.

pub fn build(b: *std.Build) void {
    const target_arch = b.option([]const u8, "arch", "Target architecture (x64 or arm)") orelse "x64";
    const optimize = b.standardOptimizeOption(.{});

    const arch: std.Target.Cpu.Arch = if (std.mem.eql(u8, target_arch, "x64"))
        .x86_64
    else if (std.mem.eql(u8, target_arch, "arm"))
        .aarch64
    else
        @panic("Unsupported target architecture (expected x64 or arm)");

    // Drop SIMD features so the inline-asm syscall wrappers don't have
    // to preserve XMM/Q-register state across the kernel boundary, and
    // pull in soft_float on x86 so compiler-rt's float helpers stay
    // SSE-free.
    const cpu_features_sub: std.Target.Cpu.Feature.Set = blk: {
        var s = std.Target.Cpu.Feature.Set.empty;
        if (arch == .x86_64) {
            const F = std.Target.x86.Feature;
            s.addFeature(@intFromEnum(F.mmx));
            s.addFeature(@intFromEnum(F.sse));
            s.addFeature(@intFromEnum(F.sse2));
            s.addFeature(@intFromEnum(F.avx));
            s.addFeature(@intFromEnum(F.avx2));
        }
        break :blk s;
    };
    const cpu_features_add: std.Target.Cpu.Feature.Set = blk: {
        var s = std.Target.Cpu.Feature.Set.empty;
        if (arch == .x86_64) {
            s.addFeature(@intFromEnum(std.Target.x86.Feature.soft_float));
        }
        break :blk s;
    };

    // os_tag = .linux + abi = .none — Zig refuses dynamic linkage on
    // .freestanding, but we don't link any Linux runtime: libz uses
    // no libc, no syscalls into Linux. The .linux tag is purely the
    // gate that lets addLibrary(.linkage = .dynamic) emit a real ELF
    // shared object with .dynsym / .rela.dyn / etc. Apps load it via
    // libz_loader's userspace rtld, never through Linux's ld.so.
    const target = b.resolveTargetQuery(.{
        .cpu_arch = arch,
        .os_tag = .linux,
        .abi = .none,
        .ofmt = .elf,
        .cpu_features_sub = cpu_features_sub,
        .cpu_features_add = cpu_features_add,
    });

    const abi_mod = b.createModule(.{
        .root_source_file = b.path("abi.zig"),
        .target = target,
        .optimize = optimize,
        .pic = true,
        // single_threaded keeps Zig's std lib from emitting TLS
        // references (__tls_get_addr) that would otherwise show up as
        // unresolved externals — we don't have a userspace TLS runtime
        // in Zag, and libz wrappers don't need any thread-local state.
        .single_threaded = true,
    });

    const libz = b.addLibrary(.{
        .name = "z",
        .linkage = .dynamic,
        .root_module = abi_mod,
    });
    libz.root_module.red_zone = false;
    libz.root_module.omit_frame_pointer = false;

    // Force LLVM + LLD: Zig 0.15's self-hosted x86_64 backend chokes
    // on the inline-asm wrappers in syscall_x64.zig (replyTransferAsm
    // hits "ran out of registers") and on naked-callconv functions
    // pulled in transitively by the linux target. LLVM compiles them
    // cleanly.
    libz.use_llvm = true;
    libz.use_lld = true;

    b.installArtifact(libz);

    // Stage at libz/bin/libz.elf to match the convention used by
    // routerOS/bin and hyprvOS/bin.
    const install_libz = b.addInstallFile(
        libz.getEmittedBin(),
        "../bin/libz.elf",
    );
    install_libz.step.dependOn(&libz.step);
    b.getInstallStep().dependOn(&install_libz.step);
}
