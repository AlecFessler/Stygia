const std = @import("std");

const Profile = struct {
    root_service: []const u8,
    net: []const u8,
    kvm: bool,
    use_llvm: bool,
    iommu: []const u8,
    display: []const u8 = "none",
};

const profiles = struct {
    const router = Profile{
        .root_service = "routerOS/bin/routerOS.elf",
        .net = "tap",
        .kvm = true,
        .use_llvm = true,
        .iommu = "intel",
    };
    const test_ = Profile{
        .root_service = "tests/tests/bin/root_service.elf",
        .net = "none",
        .kvm = true,
        .use_llvm = true,
        .iommu = "intel",
    };
    const bench = Profile{
        .root_service = "tests/tests/bin/bench.elf",
        .net = "none",
        .kvm = true,
        .use_llvm = true,
        .iommu = "intel",
    };
    const desktop = Profile{
        .root_service = "desktopOS/bin/desktopOS.elf",
        .net = "none",
        .kvm = true,
        .use_llvm = true,
        .iommu = "intel",
        .display = "gtk",
    };
    const hyprvos = Profile{
        .root_service = "hyprvOS/bin/hyprvOS.elf",
        .net = "none",
        .kvm = true,
        .use_llvm = true,
        .iommu = "intel",
    };
    const prof = Profile{
        .root_service = "tests/prof/bin/root_service.elf",
        .net = "none",
        .kvm = true,
        .use_llvm = true,
        .iommu = "intel",
    };
};

fn getProfile(name: []const u8) ?Profile {
    if (std.mem.eql(u8, name, "router")) return profiles.router;
    if (std.mem.eql(u8, name, "test")) return profiles.test_;
    if (std.mem.eql(u8, name, "bench")) return profiles.bench;
    if (std.mem.eql(u8, name, "desktop")) return profiles.desktop;
    if (std.mem.eql(u8, name, "hyprvos")) return profiles.hyprvos;
    if (std.mem.eql(u8, name, "prof")) return profiles.prof;

    return null;
}

pub fn build(b: *std.Build) void {
    const profile_name = b.option([]const u8, "profile", "Build profile: router, test, bench (sets defaults for other flags)");
    const profile = if (profile_name) |name| getProfile(name) else null;

    const kvm = b.option(bool, "kvm", "Enable KVM acceleration (default: on)") orelse
        if (profile) |p| p.kvm else true;
    const use_llvm = b.option(bool, "use-llvm", "Force LLVM+LLD backend") orelse
        if (profile) |p| p.use_llvm else false;
    const target_arch = b.option([]const u8, "arch", "Target architecture (x64 or arm)") orelse "x64";
    const root_service_path = b.option([]const u8, "root-service", "Path to root service ELF") orelse
        if (profile) |p| p.root_service else "tests/tests/bin/root_service.elf";
    const iommu_type = b.option([]const u8, "iommu", "IOMMU type: intel or amd (default: intel)") orelse
        if (profile) |p| p.iommu else "intel";
    const display_type = b.option([]const u8, "display", "QEMU display: none, gtk, sdl (default: none)") orelse
        if (profile) |p| p.display else "none";
    const net_type = b.option([]const u8, "net", "Network: tap, user, or none (default: user)") orelse
        if (profile) |p| p.net else "user";
    const emit_ir = b.option(bool, "emit_ir", "Emit kernel LLVM IR to zig-out/kernel.ll (consumed by tools/indexer)") orelse false;
    const emit_index = b.option(bool, "emit_index", "Build the per-(arch, commit_sha) callgraph SQLite DB to tools/callgraph_http/test/dbs/ (implies -Demit_ir=true)") orelse false;
    const commit_sha = b.option([]const u8, "commit_sha", "Commit SHA recorded in the callgraph DB when -Demit_index=true (default: 'DEV')") orelse "DEV";
    const kernel_profile = b.option([]const u8, "kernel_profile", "Kernel profiling mode: none, trace, or sample (default: none)") orelse "none";
    if (!std.mem.eql(u8, kernel_profile, "none") and
        !std.mem.eql(u8, kernel_profile, "trace") and
        !std.mem.eql(u8, kernel_profile, "sample"))
    {
        @panic("-Dkernel_profile must be one of: none, trace, sample");
    }
    const kprof_enabled = !std.mem.eql(u8, kernel_profile, "none");
    // Lazy-FPU on/off switch. Default on. With -Dlazy_fpu=false the
    // kernel arms no FP-disable trap and unconditionally save/restores
    // FPU state on every context switch — exposes the eager baseline
    // for A/B perf comparison.
    const lazy_fpu = b.option(bool, "lazy_fpu", "Lazy FPU save/restore (default: on)") orelse true;

    const arch: std.Target.Cpu.Arch = blk: {
        break :blk if (std.mem.eql(u8, target_arch, "x64"))
            .x86_64
        else if (std.mem.eql(u8, target_arch, "arm"))
            .aarch64
        else
            @panic("Unsupported target architecture");
    };
    // When kprof is compiled in, prefer ReleaseFast so the measured
    // kernel matches production code generation, and retain debug info
    // on the kernel.elf so parse_kprof.py can symbolize trace/sample
    // IPs directly against the built binary. Plain Debug remains the
    // default when kprof is disabled so normal builds aren't bloated.
    // We register `-Doptimize` directly (not via standardOptimizeOption)
    // because standardOptimizeOption hides -Doptimize whenever
    // preferred_optimize_mode is set, and we still want users to be
    // able to override the kprof default explicitly.
    const user_optimize = b.option(
        std.builtin.OptimizeMode,
        "optimize",
        "Prioritize performance, safety, or binary size",
    );
    const optimize: std.builtin.OptimizeMode = user_optimize orelse
        (if (kprof_enabled) .ReleaseFast else .Debug);
    const cpu_model: std.Target.Query.CpuModel = if (arch == .aarch64)
        .{ .explicit = &std.Target.aarch64.cpu.cortex_a72 }
    else
        .determined_by_arch_os;
    // Lazy-FPU requires the kernel itself to never emit FP/SIMD
    // instructions, so userspace FP state survives across kernel
    // entries untouched in registers. LLVM otherwise auto-vectorises
    // 16-byte struct copies into XMM/Q-reg moves throughout the
    // kernel. Subtract the SIMD feature bits per arch and add
    // soft_float (x64) so compiler-rt uses software-emulated FP for
    // its own float-converting builtins (otherwise their SSE-register
    // return ABIs fail to compile against the reduced target).
    const cpu_features_sub: std.Target.Cpu.Feature.Set = blk: {
        var s = std.Target.Cpu.Feature.Set.empty;
        if (arch == .x86_64) {
            const F = std.Target.x86.Feature;
            s.addFeature(@intFromEnum(F.mmx));
            s.addFeature(@intFromEnum(F.sse));
            s.addFeature(@intFromEnum(F.sse2));
            s.addFeature(@intFromEnum(F.avx));
            s.addFeature(@intFromEnum(F.avx2));
        } else if (arch == .aarch64) {
            // TODO: also drop neon for aarch64 — needs the bootloader
            // path debugged first (initial attempt boot-faults in
            // firmware between [ZAG] stack and [ZAG] exit BS). For now
            // leave NEON enabled on aarch64 so the bootloader still
            // works; lazy-FPU correctness still holds because the
            // kernel save/restore asm runs unconditionally and the
            // CPACR_EL1 trap arms regardless of whether the kernel
            // *could* clobber V regs.
            _ = std.Target.aarch64.Feature; // keep import shape stable
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
    const zag_mod = b.addModule("zag", .{
        .root_source_file = b.path("kernel/zag.zig"),
        .target = b.resolveTargetQuery(.{
            .cpu_arch = arch,
            .os_tag = .freestanding,
            .cpu_model = cpu_model,
            .cpu_features_sub = cpu_features_sub,
            .cpu_features_add = cpu_features_add,
        }),
        .optimize = optimize,
    });
    zag_mod.omit_frame_pointer = false;
    zag_mod.red_zone = false;
    zag_mod.addImport("zag", zag_mod);

    const build_opts = b.addOptions();
    build_opts.addOption([]const u8, "kernel_profile", kernel_profile);
    build_opts.addOption(bool, "lazy_fpu", lazy_fpu);
    const build_opts_mod = build_opts.createModule();
    zag_mod.addImport("build_options", build_opts_mod);

    const kprof_mod = b.createModule(.{
        .root_source_file = b.path("kernel/kprof/kprof.zig"),
        .target = b.resolveTargetQuery(.{
            .cpu_arch = arch,
            .os_tag = .freestanding,
            .cpu_model = cpu_model,
            .cpu_features_sub = cpu_features_sub,
            .cpu_features_add = cpu_features_add,
        }),
        .optimize = optimize,
    });
    kprof_mod.omit_frame_pointer = false;
    kprof_mod.red_zone = false;
    kprof_mod.addImport("zag", zag_mod);
    kprof_mod.addImport("build_options", build_opts_mod);
    zag_mod.addImport("kprof", kprof_mod);

    // ── SMP trampoline (x86-only; aarch64 uses PSCI CPU_ON) ────────────
    const embedded_wf = b.addWriteFiles();
    if (arch == .x86_64) {
        const nasm_step = b.addSystemCommand(&.{
            "nasm",                    "-f", "bin",
            "kernel/arch/x64/smp.asm", "-o",
        });
        const trampoline_output = nasm_step.addOutputFileArg("trampoline.bin");
        _ = embedded_wf.addCopyFile(trampoline_output, "trampoline.bin");
    }
    const embedded_bins_mod = b.createModule(.{
        .root_source_file = embedded_wf.add("embedded_bins.zig", if (arch == .x86_64)
            \\pub const trampoline = @embedFile("trampoline.bin");
            \\pub const root_service: []const u8 = &.{};
            \\
        else
            \\pub const trampoline: []const u8 = &.{};
            \\pub const root_service: []const u8 = &.{};
            \\
        ),
        .target = b.resolveTargetQuery(.{
            .cpu_arch = arch,
            .os_tag = .freestanding,
            .cpu_model = cpu_model,
            .cpu_features_sub = cpu_features_sub,
            .cpu_features_add = cpu_features_add,
        }),
        .optimize = optimize,
    });
    zag_mod.addImport("embedded_bins", embedded_bins_mod);

    // ── Bootloader ──────────────────────────────────────────────────────
    const loader_name = if (arch == .x86_64) "BOOTX64.EFI" else "BOOTAA64.EFI";
    const loader = b.addExecutable(.{
        .name = loader_name,
        .root_module = b.createModule(.{
            .root_source_file = b.path("bootloader/main.zig"),
            .target = b.resolveTargetQuery(.{
                .cpu_arch = arch,
                .os_tag = .uefi,
                .cpu_model = cpu_model,
            }),
            .optimize = optimize,
        }),
        .linkage = .static,
    });
    b.installArtifact(loader);
    const out_dir = "img";
    const install_loader = b.addInstallFile(
        loader.getEmittedBin(),
        b.fmt("{s}/efi/boot/{s}", .{
            out_dir,
            loader.name,
        }),
    );
    loader.root_module.addImport("zag", zag_mod);
    install_loader.step.dependOn(&loader.step);
    b.getInstallStep().dependOn(&install_loader.step);

    // ── Kernel ──────────────────────────────────────────────────────────
    const kernel = b.addExecutable(.{
        .name = "kernel.elf",
        .root_module = b.createModule(.{
            .root_source_file = b.path("kernel/main.zig"),
            .target = b.resolveTargetQuery(.{
                .cpu_arch = arch,
                .os_tag = .freestanding,
                .ofmt = .elf,
                .cpu_model = cpu_model,
                .cpu_features_sub = cpu_features_sub,
                .cpu_features_add = cpu_features_add,
            }),
            .optimize = optimize,
            .code_model = if (arch == .x86_64) .kernel else .small,
            // Keep debug info in the kernel ELF under kprof so that
            // parse_kprof.py (task #12) can resolve trace/sample IPs
            // to source locations without a separate symbol bundle.
            // null leaves Zig's default behavior for non-kprof builds.
            .strip = if (kprof_enabled) false else null,
        }),
        .linkage = .static,
    });
    if (use_llvm or emit_ir) {
        kernel.use_llvm = true;
        kernel.use_lld = true;
    }
    kernel.entry = .{ .symbol_name = "kEntry" };
    kernel.root_module.omit_frame_pointer = false;
    kernel.root_module.red_zone = false;
    kernel.root_module.addImport("zag", zag_mod);
    const linker_script = if (arch == .x86_64)
        "kernel/linker-x86.ld"
    else
        "kernel/linker-aarch64.ld";
    kernel.setLinkerScript(b.path(linker_script));
    // Preserve relocation info so the bootloader can apply a random KASLR
    // slide to kernel text/rodata/data at load time. Without --emit-relocs
    // the .rela.* sections are stripped and absolute references bake in
    // the link-time base address.
    kernel.link_emit_relocs = true;
    b.installArtifact(kernel);
    const install_kernel = b.addInstallFile(
        kernel.getEmittedBin(),
        b.fmt("{s}/{s}", .{
            out_dir,
            kernel.name,
        }),
    );
    install_kernel.step.dependOn(&kernel.step);
    b.getInstallStep().dependOn(&install_kernel.step);

    var maybe_install_ir: ?*std.Build.Step.InstallFile = null;
    if (emit_ir or emit_index) {
        const ir_name = b.fmt("kernel.{s}.ll", .{@tagName(arch)});
        const install_ir = b.addInstallFile(kernel.getEmittedLlvmIr(), ir_name);
        install_ir.step.dependOn(&kernel.step);
        b.getInstallStep().dependOn(&install_ir.step);
        maybe_install_ir = install_ir;
    }

    if (emit_index) {
        // Run the indexer (must already be built — `cd tools/indexer && zig
        // build` once before invoking this) against the just-installed
        // kernel ELF + IR. Output `.db` lands in tools/callgraph_http/test/dbs/
        // where the callgraph daemons auto-discover it.
        //
        // We can't bootstrap the indexer's own zig build from here without
        // tripping option-forwarding (the parent `-Dprofile=test
        // -Demit_index=true` flags get inherited by the sub-build, where
        // they're invalid). Keep them as separate, explicit zig invocations.
        const installed_ir = b.fmt("{s}/kernel.{s}.ll", .{ b.install_path, @tagName(arch) });
        const installed_elf = b.fmt("{s}/{s}/{s}", .{ b.install_path, out_dir, kernel.name });
        const db_dir = b.path("tools/callgraph_http/test/dbs").getPath(b);
        const db_filename = b.fmt("{s}-{s}.db", .{ @tagName(arch), commit_sha });
        const db_out = b.fmt("{s}/{s}", .{ db_dir, db_filename });
        const run_indexer = b.addSystemCommand(&.{
            "tools/indexer/zig-out/bin/indexer",
            "--kernel-root",      "kernel",
            "--extra-source-root", "routerOS",
            "--extra-source-root", "hyprvOS",
            "--extra-source-root", "bootloader",
            "--extra-source-root", "tools",
            "--extra-source-root", "tests",
            "--out",              db_out,
            "--arch",             @tagName(arch),
            "--commit-sha",       commit_sha,
            "--ir",               installed_ir,
            "--elf",              installed_elf,
        });
        run_indexer.step.dependOn(&install_kernel.step);
        if (maybe_install_ir) |ir| run_indexer.step.dependOn(&ir.step);
        const index_step = b.step("index", "Run the callgraph DB indexer after the kernel build (requires `cd tools/indexer && zig build` and -Demit_index=true)");
        index_step.dependOn(&run_indexer.step);
    }

    // ── Root service (copied into FAT image, loaded by bootloader) ─────
    const install_root_service = b.addInstallFile(
        .{ .cwd_relative = root_service_path },
        b.fmt("{s}/root_service.elf", .{out_dir}),
    );
    b.getInstallStep().dependOn(&install_root_service.step);

    // ── QEMU ────────────────────────────────────────────────────────────
    const qemu_cmdline = if (arch == .aarch64) blk: {
        const accel = if (kvm)
            "-enable-kvm -cpu host,pmu=on"
        else
            "-machine accel=tcg -cpu cortex-a72,pmu=on -d int,cpu_reset -no-shutdown -D qemu.log";
        break :blk b.fmt(
            \\exec qemu-system-aarch64 \
            \\ -M virt,gic-version=3 \
            \\ -m 1G \
            \\ -bios /usr/share/AAVMF/AAVMF_CODE.fd \
            \\ -drive file=fat:rw:{s}/{s},format=raw \
            \\ -serial mon:stdio \
            \\ -display {s} \
            \\ -no-reboot \
            \\ {s} \
            \\ -smp cores=4
        , .{ b.install_path, out_dir, display_type, accel });
    } else blk: {
        const qemu_accel_args: []const u8 = if (kvm)
            \\-enable-kvm \
            \\-cpu host,+invtsc
        else
            \\-machine accel=tcg \
            \\-cpu qemu64,+invtsc \
            \\-d int,cpu_reset \
            \\-no-shutdown \
            \\-D qemu.log
        ;
        const qemu_machine_args: []const u8 =
            \\-machine q35
        ;
        const qemu_iommu_args: []const u8 = if (std.mem.eql(u8, iommu_type, "intel"))
            "-device intel-iommu,intremap=off"
        else
            "-device amd-iommu";
        const qemu_usb_args: []const u8 = if (profile_name != null and std.mem.eql(u8, profile_name.?, "desktop"))
            \\-device qemu-xhci,id=xhci \
            \\-device usb-kbd,bus=xhci.0 \
            \\-device usb-mouse,bus=xhci.0
        else
            "";
        const qemu_nvme_args: []const u8 = if (profile_name != null and
            (std.mem.eql(u8, profile_name.?, "desktop") or std.mem.eql(u8, profile_name.?, "hyprvos")))
            \\-drive file=nvme.img,format=raw,if=none,id=nvme0 \
            \\-device nvme,drive=nvme0,serial=zagdisk0
        else
            "";
        const qemu_net_args: []const u8 = if (std.mem.eql(u8, net_type, "tap"))
            \\-netdev tap,id=net0,ifname=tap0,script=no,downscript=no,vhost=off \
            \\-device e1000e,netdev=net0,mac=52:54:00:12:34:56 \
            \\-netdev tap,id=net1,ifname=tap1,script=no,downscript=no,vhost=off \
            \\-device e1000e,netdev=net1,mac=52:54:00:12:34:57
        else if (std.mem.eql(u8, net_type, "passthrough"))
            \\-net none \
            \\-device pcie-root-port,id=rp1,slot=1 \
            \\-device pcie-pci-bridge,id=br1,bus=rp1 \
            \\-device vfio-pci,host=05:00.0,bus=br1,addr=1.0 \
            \\-device vfio-pci,host=05:00.1,bus=br1,addr=2.0
        else if (std.mem.eql(u8, net_type, "user"))
            \\-netdev user,id=net0 \
            \\-device e1000e,netdev=net0,mac=52:54:00:12:34:56 \
            \\-netdev user,id=net1 \
            \\-device e1000e,netdev=net1,mac=52:54:00:12:34:57
        else
            \\-net none
        ;
        break :blk b.fmt(
            \\exec qemu-system-x86_64 \
            \\ -m 4G \
            \\ -bios /usr/share/ovmf/x64/OVMF.4m.fd \
            \\ -drive file=fat:rw:{s}/{s},format=raw \
            \\ -serial mon:stdio \
            \\ -display {s} \
            \\ -no-reboot \
            \\ {s} \
            \\ {s} \
            \\ {s} \
            \\ {s} \
            \\ {s} \
            \\ {s} \
            \\ -smp cores=4
        , .{ b.install_path, out_dir, display_type, qemu_accel_args, qemu_machine_args, qemu_iommu_args, qemu_net_args, qemu_usb_args, qemu_nvme_args });
    };
    // Create NVMe disk image if it doesn't exist
    const create_nvme_img = b.addSystemCommand(&[_][]const u8{
        "sh", "-c", "test -f nvme.img || dd if=/dev/zero of=nvme.img bs=1M count=64 2>/dev/null",
    });

    const qemu_cmd = b.addSystemCommand(&[_][]const u8{
        "sh", "-lc", qemu_cmdline,
    });
    qemu_cmd.step.dependOn(b.getInstallStep());
    qemu_cmd.step.dependOn(&create_nvme_img.step);
    const run_qemu_cmd = b.step("run", "Run QEMU");
    run_qemu_cmd.dependOn(&qemu_cmd.step);
}
