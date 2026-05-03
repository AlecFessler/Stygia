//! Embedded guest assets for QEMU fallback when NVMe is unavailable.
//!
//! The VMM loads a Linux kernel + initramfs into guest RAM. On x86_64 that
//! means a bzImage + gzipped cpio; on aarch64 a raw arm64 Image + gzipped
//! cpio built by the recipes under `assets/guest/`. Both arches expose the
//! same `image` / `initramfs` slices so the VMM code stays uniform.

const builtin = @import("builtin");

pub const image = switch (builtin.cpu.arch) {
    .x86_64 => @embedFile("bzImage"),
    .aarch64 => @embedFile("guest/out/linux-arm64-Image"),
    else => @compileError("unsupported guest arch"),
};

pub const initramfs = switch (builtin.cpu.arch) {
    .x86_64 => @embedFile("initramfs.cpio.gz"),
    .aarch64 => @embedFile("guest/out/rootfs.cpio.gz"),
    else => @compileError("unsupported guest arch"),
};

pub const bzimage = image;
