const std = @import("std");

const Profile = struct {
    /// Path to the root service ELF. `null` means the profile is
    /// generic and the caller must supply `-Droot-service=<path>`.
    root_service: ?[]const u8,
    net: []const u8,
    kvm: bool,
    use_llvm: bool,
    iommu: []const u8,
    display: []const u8 = "none",
};

const profiles = struct {
    const test_ = Profile{
        .root_service = "tests/suite/bin/root_service.elf",
        .net = "none",
        .kvm = true,
        .use_llvm = true,
        .iommu = "intel",
    };
    const linux_guest = Profile{
        .root_service = "tests/linux_guest/bin/linux_guest.elf",
        .net = "none",
        .kvm = true,
        .use_llvm = true,
        .iommu = "intel",
    };
    /// Generic profile for booting an external root service. Caller
    /// MUST pass `-Droot-service=<path>`; the profile only supplies
    /// the other defaults (LLVM backend on, KVM on, intel IOMMU,
    /// user-mode networking, headless display).
    const app = Profile{
        .root_service = null,
        .net = "user",
        .kvm = true,
        .use_llvm = true,
        .iommu = "intel",
    };
};

fn getProfile(name: []const u8) ?Profile {
    if (std.mem.eql(u8, name, "test")) return profiles.test_;
    if (std.mem.eql(u8, name, "linux_guest")) return profiles.linux_guest;
    if (std.mem.eql(u8, name, "app")) return profiles.app;

    return null;
}

pub fn build(b: *std.Build) void {
    const profile_name = b.option([]const u8, "profile", "Build profile: test, linux_guest, app (sets defaults for other flags; app requires -Droot-service)");
    const profile = if (profile_name) |name| getProfile(name) else null;

    const kvm = b.option(bool, "kvm", "Enable KVM acceleration (default: on)") orelse
        if (profile) |p| p.kvm else true;
    const use_llvm = b.option(bool, "use-llvm", "Force LLVM+LLD backend") orelse
        if (profile) |p| p.use_llvm else false;
    const target_arch = b.option([]const u8, "arch", "Target architecture (x64 or arm)") orelse "x64";
    // The linux_guest sub-project emits an arch-suffixed ELF
    // (`linux_guest-arm.elf` for aarch64 vs. plain `linux_guest.elf` for
    // x86_64). The profile struct can only hold one literal, so for
    // `-Darch=arm -Dprofile=linux_guest` swap in the arm-suffixed path.
    const root_service_path = b.option([]const u8, "root-service", "Path to root service ELF") orelse
        if (profile) |p|
            (if (std.mem.eql(u8, target_arch, "arm") and std.mem.eql(u8, profile_name orelse "", "linux_guest"))
                "tests/linux_guest/bin/linux_guest-arm.elf"
            else
                p.root_service orelse @panic("-Dprofile=app requires -Droot-service=<path>"))
        else
            "tests/suite/bin/root_service.elf";
    const iommu_type = b.option([]const u8, "iommu", "IOMMU type: intel or amd (default: intel)") orelse
        if (profile) |p| p.iommu else "intel";
    const display_type = b.option([]const u8, "display", "QEMU display: none, gtk, sdl (default: none)") orelse
        if (profile) |p| p.display else "none";
    const net_type = b.option([]const u8, "net", "Network: tap, user, or none (default: user)") orelse
        if (profile) |p| p.net else "user";
    const gdbstub = b.option(bool, "gdbstub", "Enable QEMU gdbstub on port 1234 (-s) for `zig build run` (default: off; off avoids port collisions when multiple qemu instances run concurrently)") orelse false;
    const emit_ir = b.option(bool, "emit_ir", "Emit kernel LLVM IR to zig-out/kernel.ll (consumed by tools/indexer)") orelse false;
    const emit_index = b.option(bool, "emit_index", "Build the per-(arch, commit_sha) callgraph SQLite DB to tools/callgraph_http/test/dbs/ (implies -Demit_ir=true)") orelse false;
    const commit_sha = b.option([]const u8, "commit_sha", "Commit SHA recorded in the callgraph DB when -Demit_index=true (default: 'DEV')") orelse "DEV";
    // L4 IPC fast-path classifier on/off switch. Default on. With
    // -Dkernel_fastpath=false the classifier in `syscallEntry` skips
    // the `cmpq $13 / jbe .Lsyscall_suspend_fast` test, so every
    // syscall (including suspend) takes the slow Zig dispatch path —
    // exposes the slow-path baseline for A/B perf comparison.
    const kernel_fastpath = b.option(bool, "kernel_fastpath", "L4 IPC fast-path classifier (default: on)") orelse true;
    const kernel_fastpath_suspend = b.option(bool, "kernel_fastpath_suspend", "L4 fast-path suspend arm (default: kernel_fastpath)") orelse kernel_fastpath;
    const kernel_fastpath_reply = b.option(bool, "kernel_fastpath_reply", "L4 fast-path reply arm (default: kernel_fastpath)") orelse kernel_fastpath;
    // Per-EC kstack-corruption snapshot ring with dump-on-panic. Off by
    // default; CI runs with the flag absent. Each `mark` site captures
    // tsc + ec.ctx {cs, ss, rsp, rip} into a 32-entry ring keyed by EC
    // slab index; the panic path walks every EC ring and dumps the
    // contents over serial. Used to debug the smp=4 iret-frame
    // corruption that surfaces as #GP at iretq with kernel-pointer
    // fragments in ctx.cs (offset 144 in cpu.Context).
    const kernel_ctx_trace = b.option(bool, "ctx_trace", "Enable per-EC ctx-snapshot ring + dump-on-panic (default: off)") orelse false;
    // Per-core current_ec transition log + dump-on-panic. Records every
    // setCurrentEc / clearCurrentEc and every IPC fast-path Step 14 / R14
    // gs:32 write; panic-handler dumps each core's ring over serial. Used
    // to debug the smp=4 race that surfaces as "kernel page fault on user
    // VA with no current EC" in memory/fault.zig — distinguishes a
    // missing-set-after-clear from a kernel-mode fault masquerading as
    // user-mode.
    const kernel_ec_log = b.option(bool, "ec_log", "Enable per-core current_ec transition log + dump-on-panic (default: off)") orelse false;
    // Per-PF-handler outcome ring with dump-on-panic. Off by default.
    // Records ENTER + decision-branch outcome + RESUME for every page
    // fault; the panic path dumps the global 256-entry ring over serial.
    // Used to debug the smp=4 PF-loop bug where a fault repeatedly
    // re-fires after the handler claims success.
    const kernel_pf_log = b.option(bool, "pf_log", "Enable per-PF outcome ring + dump-on-panic (default: off)") orelse false;
    // HPET-driven NMI hang watchdog. Off by default. When enabled the BSP
    // programs HPET timer 0 in periodic FSB-deliver mode → NMI (~500ms
    // period) targeting all cores; the NMI handler calls
    // `hang_detector.tickCheck()` so the dump still fires when the LAPIC
    // scheduler tick + every other periodic kernel-side IRQ source has
    // stalled (the smp=4 lost-wakeup signature: all cores idle hlt with
    // current_ec=null and run-queues empty).
    const kernel_hang_watchdog = b.option(bool, "kernel_hang_watchdog", "Enable HPET-NMI hang watchdog (default: off)") orelse false;
    const kernel_spawn_diag = b.option(
        bool,
        "spawn_diag",
        "Enable test-child spawn/terminal attribution diagnostics (default: on under -Dprofile=test)",
    ) orelse (profile_name != null and std.mem.eql(u8, profile_name.?, "test"));
    // Per-core kernel-entry counter feeding `spin_diag.entries` / the hang
    // dump's liveness probe. Gated SEPARATELY from `spin_diag.note`, which
    // is unconditional: `note` only ever runs inside an already-spinning
    // wait loop, where one relaxed RMW is lost in the noise of the `pause`
    // beside it, but `noteEntry` sits on the bare preemption tick and on
    // every cross-core wake IPI with no surrounding spin to hide in. It is
    // the one site where "free next to the pause" is not an argument, so
    // production builds do not carry it. Default on under -Dprofile=test,
    // which is where the hang detector that consumes it lives.
    const kernel_spin_entry_diag = b.option(
        bool,
        "spin_entry_diag",
        "Count kernel entries per core for the hang dump's liveness probe (default: on under -Dprofile=test)",
    ) orelse (profile_name != null and std.mem.eql(u8, profile_name.?, "test"));
    // Test-only fixture devices (synthetic device_regions handed to the
    // root service so spec tests targeting `device_region` / IRQ / DMA
    // surfaces have something to scan for). Defaults on under
    // -Dprofile=test, off elsewhere. The fixture path is dead-stripped
    // when the option is false, so production builds carry no test
    // surface in the boot path.
    const tests_fixture_devices = b.option(
        bool,
        "tests_fixture_devices",
        "Mint synthetic test-only fixture device_regions in the boot path (default: on under -Dprofile=test)",
    ) orelse (profile_name != null and std.mem.eql(u8, profile_name.?, "test"));
    // The suite runner returns after printing its final result and its
    // _start deletes the boot root self-handle. Reboot that one test root
    // at the syscall boundary so QEMU exits and Pi tryboot returns to Pi OS.
    const test_root_reboot_on_exit = profile_name != null and std.mem.eql(u8, profile_name.?, "test");

    const arch: std.Target.Cpu.Arch = blk: {
        break :blk if (std.mem.eql(u8, target_arch, "x64"))
            .x86_64
        else if (std.mem.eql(u8, target_arch, "arm"))
            .aarch64
        else
            @panic("Unsupported target architecture");
    };
    const optimize = b.option(std.builtin.OptimizeMode, "optimize", "Prioritize performance, safety, or binary size") orelse .Debug;
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
            // Drop NEON *and* fp_armv8 (`ldr q`/`str q` are FP-gated, not
            // NEON-gated — same rationale as the Pi 5 EL2 loader below).
            //
            // This is load-bearing for lazy-FPU correctness, not just
            // codegen hygiene. With these features present, LLVM lowers
            // 16-byte struct copies to `ldr q0`/`str q0` throughout the
            // kernel (666 Debug-mode functions measured, including
            // allocExecutionContext / destroyExecutionContextLocked /
            // detachForDelete), and ReleaseSafe vectorizes whole loops
            // (main.zig's exported memset became `dup v0.16b` +
            // `stp q0,q0`). The lazy-FPU design gives kernel V-regs NO
            // owner: an IRQ that preempts a kernel q-reg copy mid-flight
            // context-switches without saving kernel V state, and the
            // copy later resumes spraying another context's V0 into
            // kernel structures. Autopsied live on the linux_guest
            // ReleaseSafe boot: growOne's zeroing memset wrote
            // v0={0xffffff80bd238280,0xffff000000008e9c} (a physmap ptr
            // + its own return address) instead of zeros into the first
            // CD slab slot, and the next create() read the garbage as a
            // gen word.
            //
            // The old TODO here feared the EFI bootloader (it imports
            // stygia_mod); the loader keeps its own full-featured target
            // below, and NEON-free module code is valid everywhere.
            // Hand-written V-reg asm (fpuSave/fpuRestore, hyp guest FP
            // swap) re-enables the assembler locally via
            // `.arch_extension fp` + `.arch_extension simd`.
            const F = std.Target.aarch64.Feature;
            s.addFeature(@intFromEnum(F.neon));
            s.addFeature(@intFromEnum(F.fp_armv8));
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
    const stygia_mod = b.addModule("stygia", .{
        .root_source_file = b.path("kernel/stygia.zig"),
        .target = b.resolveTargetQuery(.{
            .cpu_arch = arch,
            .os_tag = .freestanding,
            .cpu_model = cpu_model,
            .cpu_features_sub = cpu_features_sub,
            .cpu_features_add = cpu_features_add,
        }),
        .optimize = optimize,
    });
    stygia_mod.omit_frame_pointer = false;
    stygia_mod.red_zone = false;
    stygia_mod.addImport("stygia", stygia_mod);

    const build_opts = b.addOptions();
    build_opts.addOption(bool, "kernel_fastpath", kernel_fastpath);
    build_opts.addOption(bool, "kernel_fastpath_suspend", kernel_fastpath_suspend);
    build_opts.addOption(bool, "kernel_fastpath_reply", kernel_fastpath_reply);
    build_opts.addOption(bool, "kernel_ctx_trace", kernel_ctx_trace);
    build_opts.addOption(bool, "kernel_ec_log", kernel_ec_log);
    build_opts.addOption(bool, "kernel_pf_log", kernel_pf_log);
    build_opts.addOption(bool, "kernel_hang_watchdog", kernel_hang_watchdog);
    build_opts.addOption(bool, "kernel_spawn_diag", kernel_spawn_diag);
    build_opts.addOption(bool, "kernel_spin_entry_diag", kernel_spin_entry_diag);
    build_opts.addOption(bool, "tests_fixture_devices", tests_fixture_devices);
    build_opts.addOption(bool, "test_root_reboot_on_exit", test_root_reboot_on_exit);
    const build_opts_mod = build_opts.createModule();
    stygia_mod.addImport("build_options", build_opts_mod);

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
    stygia_mod.addImport("embedded_bins", embedded_bins_mod);

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
    loader.root_module.addImport("stygia", stygia_mod);
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
            // Always false: link_emit_relocs (set below) is incompatible
            // with --strip-all, which ReleaseSmall enables by default.
            .strip = false,
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
    kernel.root_module.addImport("stygia", stygia_mod);
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

    // ── Raspberry Pi 5 native loader (opt-in, aarch64 only) ─────────────
    //
    // A second bootloader for a board with no UEFI, so the kernel can be
    // exercised on real silicon at EL2 — the only configuration in which
    // aarch64 virtualization is actually testable (under Pi KVM the guest is
    // pinned at EL1 and the hv tests short-circuit on E_NODEV).
    //
    // Deliberately NOT wired into b.getInstallStep(): it is built only by
    // `zig build pi5 -Darch=arm`. That keeps default builds, the FAT image,
    // and every precommit gate byte-identical to before this existed. It also
    // means the mixed-arch image guards do not have to reason about a
    // bare-metal artifact that never belongs in zig-out/img.
    if (arch == .aarch64) {
        const pi5_target = b.resolveTargetQuery(.{
            .cpu_arch = .aarch64,
            .os_tag = .freestanding,
            .ofmt = .elf,
            // Pi 5 is a BCM2712 (Cortex-A76). `el3` is required for the `smc`
            // instruction used to call PSCI — without the feature LLVM rejects
            // it outright with "instruction requires: el3". We never execute at
            // EL3; the feature flag only gates the encoding.
            .cpu_model = .{ .explicit = &std.Target.aarch64.cpu.cortex_a76 },
            .cpu_features_add = blk: {
                var s = std.Target.Cpu.Feature.Set.empty;
                s.addFeature(@intFromEnum(std.Target.aarch64.Feature.el3));
                break :blk s;
            },
            // Drop FP and NEON. This is a correctness requirement, not an
            // optimization choice, and it was measured rather than guessed.
            //
            // The loader runs with the MMU OFF (firmware hands us
            // SCTLR_EL2 = 0x30c50830, so M=0). When stage 1 translation is
            // disabled, data accesses are Device-nGnRnE, and an access to Device
            // memory that is not naturally aligned raises an Alignment fault
            // regardless of SCTLR_EL2.A.
            //
            // LLVM compiles 16-byte struct copies (`dtb.Range` is two u64s) into
            // `ldr q0` / `str q0`. Those are 16-byte accesses, but Range has only
            // 8-byte alignment, so against an 8-byte-aligned array element they
            // are UNALIGNED Device accesses and fault as EC=0x25 / DFSC=0x21.
            // Measured: 4 such instructions survived in the image, two of them in
            // normalizeReservations' insertion sort.
            //
            // Subtracting `neon` alone is NOT sufficient — `ldr q`/`str q` are FP
            // instructions gated on `fp_armv8`, so both features must go.
            //
            // Same family of hazard as the `memset` override in kernel/main.zig
            // (compiler-rt's aarch64 memset uses `dup`/`stp q0,q0`) and the NEON
            // TODO in the aarch64 `cpu_features_sub` above. Here it is free to
            // fix properly: nothing in this loader wants FP or SIMD, so we remove
            // the ability to emit either and let it use ldp/stp of x-registers,
            // whose 8-byte constituent accesses are naturally aligned.
            .cpu_features_sub = blk: {
                var s = std.Target.Cpu.Feature.Set.empty;
                s.addFeature(@intFromEnum(std.Target.aarch64.Feature.neon));
                s.addFeature(@intFromEnum(std.Target.aarch64.Feature.fp_armv8));
                break :blk s;
            },
        });
        // ReleaseSmall, not ReleaseFast: this is a flat binary the firmware loads
        // whole, and there is no hot path in it.
        const pi5_optimize: std.builtin.OptimizeMode = .ReleaseSmall;

        // The loader calls into the kernel's own paging code (mapPageBoot and
        // friends) rather than reimplementing VMSAv8-64 table construction. That
        // means kernel code executes MMU-OFF inside this image, so it must be
        // built for the LOADER's target, not the kernel's — a separate instance
        // of the same source, not the shared `stygia_mod`.
        //
        // This is not tidiness. `stygia_mod` resolves to `cortex_a72` with FP and
        // NEON present, and the whole reason `pi5_target` subtracts them is that
        // 16-byte FP accesses fault when translation is disabled (see the long
        // comment above). Linking the shared module in would silently reintroduce
        // exactly the hazard the target flags exist to prevent, in code that is
        // harder to audit than the loader's own. Separately, FP at EL2 depends on
        // CPTR_EL2.TFP, whose reset value is not architecturally guaranteed, so
        // an FP instruction here could trap before it could fault.
        //
        // Consequence worth stating: at ReleaseSmall the `std.debug.assert` calls
        // inside mapPageBoot compile away, so they check nothing here. The
        // software table walk in bootloader/pi5/paging.zig is what actually
        // verifies the tables, and it is strictly stronger — it checks the
        // resulting translations rather than the arguments.
        const pi5_stygia_mod = b.createModule(.{
            .root_source_file = b.path("kernel/stygia.zig"),
            .target = pi5_target,
            .optimize = pi5_optimize,
        });
        pi5_stygia_mod.omit_frame_pointer = false;
        pi5_stygia_mod.red_zone = false;
        pi5_stygia_mod.addImport("stygia", pi5_stygia_mod);
        pi5_stygia_mod.addImport("build_options", build_opts_mod);

        // Same generated file as the kernel's, recompiled for this target. On
        // aarch64 both members are empty slices today; when root_service starts
        // being embedded, this is where the loader picks it up.
        const pi5_embedded_bins_mod = b.createModule(.{
            .root_source_file = embedded_bins_mod.root_source_file.?,
            .target = pi5_target,
            .optimize = pi5_optimize,
        });
        pi5_stygia_mod.addImport("embedded_bins", pi5_embedded_bins_mod);

        // The kernel and root service, carried INSIDE the loader image.
        //
        // The UEFI loader opens `kernel.elf` and `root_service.elf` off the FAT
        // volume. Pi firmware loads exactly one file and hands over with no
        // storage stack at all, so both blobs have to be part of that one file.
        //
        // `align(4096)` is load-bearing, not cosmetic. `@embedFile` yields
        // alignment 1, and the ELF parser reaches the header through
        // `std.mem.bytesAsValue(Elf64_Ehdr, ...)`, which assumes natural
        // alignment. With the MMU off every access is Device-nGnRnE and an
        // unaligned one raises an Alignment fault — the same failure class that
        // the FP/NEON subtraction above exists to prevent, arriving by a
        // different route. Page alignment also makes `e_shoff`/`e_phoff`
        // naturally aligned, since those are file-offset aligned already.
        const pi5_blobs_wf = b.addWriteFiles();
        _ = pi5_blobs_wf.addCopyFile(kernel.getEmittedBin(), "kernel.elf");
        _ = pi5_blobs_wf.addCopyFile(
            .{ .cwd_relative = root_service_path },
            "root_service.elf",
        );
        const pi5_blobs_mod = b.createModule(.{
            .root_source_file = pi5_blobs_wf.add("pi5_blobs.zig",
                \\const kernel_raw = @embedFile("kernel.elf");
                \\const rs_raw = @embedFile("root_service.elf");
                \\
                \\pub const kernel_elf: [kernel_raw.len]u8 align(4096) = kernel_raw.*;
                \\pub const root_service_elf: [rs_raw.len]u8 align(4096) = rs_raw.*;
                \\
            ),
            .target = pi5_target,
            .optimize = pi5_optimize,
        });

        const pi5 = b.addExecutable(.{
            .name = "pi5_loader.elf",
            .root_module = b.createModule(.{
                .root_source_file = b.path("bootloader/pi5/entry.zig"),
                .target = pi5_target,
                .optimize = pi5_optimize,
            }),
        });
        pi5.setLinkerScript(b.path("bootloader/pi5/link.ld"));
        pi5.root_module.addImport("stygia", pi5_stygia_mod);
        pi5.root_module.addImport("pi5_blobs", pi5_blobs_mod);

        // The EL2->EL1 drop, shared with the UEFI loader.
        //
        // Given as a named module rather than imported by relative path: the pi5
        // module root is `bootloader/pi5/`, so `@import("../aarch64_el2_drop.zig")`
        // is rejected as an import outside the module path. A module declaration is
        // the supported way to reach a sibling file, and it also gets the file
        // compiled for `pi5_target` — which matters here for the same reason
        // `pi5_stygia_mod` exists, since this code executes inside the loader.
        //
        // Sharing rather than copying is deliberate: `hyp_vectors_bytes` is
        // comptime-assembled and position-independent, and a second copy of the
        // drop's asm would be a second thing to keep correct.
        const pi5_el2_drop_mod = b.createModule(.{
            .root_source_file = b.path("bootloader/aarch64_el2_drop.zig"),
            .target = pi5_target,
            .optimize = pi5_optimize,
        });
        pi5_el2_drop_mod.omit_frame_pointer = false;
        pi5_el2_drop_mod.red_zone = false;
        pi5_el2_drop_mod.addImport("stygia", pi5_stygia_mod);
        pi5.root_module.addImport("el2_drop", pi5_el2_drop_mod);

        // The firmware loads a RAW binary, not an ELF.
        const pi5_bin = b.addObjCopy(pi5.getEmittedBin(), .{ .format = .bin });
        const install_pi5 = b.addInstallFile(
            pi5_bin.getOutput(),
            "pi5/kernel_stygia.img",
        );
        const pi5_step = b.step(
            "pi5",
            "Build the Raspberry Pi 5 bare-metal loader image (aarch64 only)",
        );
        pi5_step.dependOn(&install_pi5.step);
    }

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
            "--kernel-root",
            "kernel",
            "--extra-source-root",
            "bootloader",
            "--extra-source-root",
            "tools",
            "--extra-source-root",
            "tests",
            "--extra-source-root",
            "libz",
            "--out",
            db_out,
            "--arch",
            @tagName(arch),
            "--commit-sha",
            commit_sha,
            "--ir",
            installed_ir,
            "--elf",
            installed_elf,
        });
        run_indexer.step.dependOn(&install_kernel.step);
        if (maybe_install_ir) |ir| run_indexer.step.dependOn(&ir.step);
        const index_step = b.step("index", "Run the callgraph DB indexer after the kernel build (requires `cd tools/indexer && zig build` and -Demit_index=true)");
        index_step.dependOn(&run_indexer.step);
    }

    // ── Root service (copied into FAT image, loaded by bootloader) ─────
    //
    // The root service is a PREBUILT input: this build copies it verbatim
    // and never re-derives it. `tests/suite/bin/root_service.elf` is
    // arch-specific and is produced by a separate `cd tests/suite &&
    // zig build [-Darch=arm]`, so building the kernel for one arch after
    // building the suite for the other silently pairs an x86-64
    // kernel.elf with an aarch64 root_service.elf (or vice versa).
    //
    // That mismatch used to exit 0 and boot. The bootloader maps the
    // foreign ELF and jumps to its "entry", which lands in a zeroed page;
    // on x86 the leading 00 00 decodes as `add %al,(%rax)` with rax = 0,
    // producing a boot-time USR-PF write to address 0 followed by a
    // single-live-EC [HANG] — a signature indistinguishable from a
    // scheduler regression, and the leading explanation for stygia-gms.
    // Verify it at configure time instead. See also
    // `zig-out` staleness below.
    //
    // `-Dimage_check=false` waives both guards, for builds that consume only
    // `kernel.elf` / `kernel.{arch}.ll` and never boot the image — the
    // callgraph indexer's two back-to-back cross-arch builds in
    // tests/precommit.sh are the only such caller. Anything that boots must
    // leave the guards on.
    const image_check = b.option(
        bool,
        "image_check",
        "Reject an arch-mixed boot image at configure time (default: on; off only for builds that consume kernel.elf/.ll and never boot)",
    ) orelse true;
    if (image_check) verifyRootServiceArch(root_service_path, arch);

    const install_root_service = b.addInstallFile(
        .{ .cwd_relative = root_service_path },
        b.fmt("{s}/root_service.elf", .{out_dir}),
    );
    b.getInstallStep().dependOn(&install_root_service.step);

    // `zig-out/` is not cleaned on an arch switch, so the previous arch's
    // EFI loader survives beside the new one and the firmware may pick
    // either. The install step writes only the matching loader, so a
    // foreign one present here is always stale.
    if (image_check) verifyNoStaleLoader(b, out_dir, arch);

    // ── QEMU ────────────────────────────────────────────────────────────
    // NVMe is on by default under -Dprofile=linux_guest (guest needs a
    // backing disk); other profiles must opt in via -Dnvme=true. The
    // sibling Stygia-desktopOS repo's `run` step passes -Dnvme=true.
    const wants_nvme = b.option(bool, "nvme", "Attach an NVMe drive (default: on under -Dprofile=linux_guest)") orelse
        (profile_name != null and std.mem.eql(u8, profile_name.?, "linux_guest"));
    // qemu-xhci + usb-kbd/usb-mouse so a guest USB driver has a
    // controller to enumerate and a HID device to bind. Off by default;
    // the sibling Stygia-desktopOS repo's `run` step passes -Dusb=true.
    const wants_usb = b.option(bool, "usb", "Attach a qemu-xhci controller + HID devices (default: off)") orelse false;

    const qemu_cmdline = if (arch == .aarch64) blk: {
        const accel = if (kvm)
            "-enable-kvm -cpu host,pmu=on"
        else if (test_root_reboot_on_exit)
            // QEMU must exit on the test-root reboot after the verdict.
            "-machine accel=tcg -cpu cortex-a72,pmu=on -d int,cpu_reset -D qemu.log"
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
        else if (test_root_reboot_on_exit)
            \\-machine accel=tcg \
            \\-cpu qemu64,+invtsc \
            \\-d int,cpu_reset \
            \\-D qemu.log
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
        // cache=writethrough makes write completions wait until the
        // host has flushed to nvme.img. Without it QEMU buffers writes
        // in-process and a SIGTERM (e.g. from `timeout`) loses pages
        // that haven't been written through. fs needs writes to
        // survive QEMU exit so the LBA-0 superblock + SQLite pages
        // both reach disk for the next boot.
        const qemu_nvme_args: []const u8 = if (wants_nvme)
            b.fmt(
                \\-drive file={s}/nvme.img,format=raw,if=none,id=nvme0,cache=writethrough \
                \\-device nvme,drive=nvme0,serial=stygiadisk0
            , .{b.install_path})
        else
            "";
        const qemu_usb_args: []const u8 = if (wants_usb)
            \\-device qemu-xhci,id=xhci0 \
            \\-device usb-kbd,bus=xhci0.0 \
            \\-device usb-mouse,bus=xhci0.0
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
        const qemu_gdbstub_args: []const u8 = if (gdbstub) "-s" else "";
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
            \\ {s} \
            \\ -smp cores=4
        , .{ b.install_path, out_dir, display_type, qemu_gdbstub_args, qemu_accel_args, qemu_machine_args, qemu_iommu_args, qemu_net_args, qemu_nvme_args, qemu_usb_args });
    };

    const qemu_cmd = b.addSystemCommand(&[_][]const u8{
        "sh", "-lc", qemu_cmdline,
    });
    qemu_cmd.step.dependOn(b.getInstallStep());

    if (wants_nvme) {
        const create_nvme_img = b.addSystemCommand(&[_][]const u8{
            "sh", "-c",
            b.fmt(
                "mkdir -p {s} && test -f {s}/nvme.img || dd if=/dev/zero of={s}/nvme.img bs=1M count=64 2>/dev/null",
                .{ b.install_path, b.install_path, b.install_path },
            ),
        });
        qemu_cmd.step.dependOn(&create_nvme_img.step);
    }
    const run_qemu_cmd = b.step("run", "Run QEMU");
    run_qemu_cmd.dependOn(&qemu_cmd.step);
}

/// ELF `e_machine` values for the two architectures this kernel targets.
/// (`std.elf.EM` exists, but reading the two bytes directly keeps this
/// guard independent of the host toolchain's ELF definitions.)
const EM_X86_64: u16 = 0x3E;
const EM_AARCH64: u16 = 0xB7;

fn archMachineName(machine: u16) []const u8 {
    return switch (machine) {
        EM_X86_64 => "x86-64",
        EM_AARCH64 => "aarch64",
        else => "unknown",
    };
}

/// Fail the build if the prebuilt root service ELF was compiled for a
/// different architecture than the kernel we are about to pair it with.
///
/// Runs at configure time and deliberately stays silent when the file is
/// absent or unreadable: a missing root service already fails later, at
/// the install step, with a clearer message than anything we could emit.
fn verifyRootServiceArch(path: []const u8, arch: std.Target.Cpu.Arch) void {
    const want: u16 = switch (arch) {
        .x86_64 => EM_X86_64,
        .aarch64 => EM_AARCH64,
        else => return,
    };

    const file = std.fs.cwd().openFile(path, .{}) catch return;
    defer file.close();

    // e_ident[16] then e_type (u16) then e_machine (u16) — machine is at
    // offset 18 in both ELF32 and ELF64.
    var hdr: [20]u8 = undefined;
    const n = file.readAll(&hdr) catch return;
    if (n < hdr.len) return;
    if (!std.mem.eql(u8, hdr[0..4], "\x7fELF")) return;

    const got = std.mem.readInt(u16, hdr[18..20], .little);
    if (got == want) return;

    std.debug.print(
        \\
        \\error: root service arch mismatch — refusing to build a mixed image.
        \\
        \\  kernel target : {s}
        \\  {s} : {s} (e_machine = 0x{X:0>2})
        \\
        \\This file is a prebuilt input; the kernel build copies it verbatim and
        \\never re-derives it. Rebuild it for this arch, then rebuild the kernel:
        \\
        \\  cd tests/suite && rm -rf bin/ .zig-cache && zig build{s}
        \\  cd - && rm -rf zig-out && zig build -Dprofile=test{s}
        \\
        \\Booting the mismatched pair would jump into a zeroed page and produce a
        \\boot-time USR-PF write to address 0 plus a single-live-EC [HANG], which
        \\looks exactly like a scheduler regression and is not one (stygia-gms).
        \\
    , .{
        archMachineName(want),
        path,
        archMachineName(got),
        got,
        if (arch == .aarch64) " -Darch=arm" else "",
        if (arch == .aarch64) " -Darch=arm" else "",
    });
    std.process.exit(1);
}

/// Fail the build if `zig-out` still holds the other architecture's EFI
/// loader. The install step writes only the matching loader and nothing
/// prunes the output tree on an arch switch, so a foreign loader here is
/// always a leftover — and the firmware may boot it instead.
fn verifyNoStaleLoader(b: *std.Build, out_dir: []const u8, arch: std.Target.Cpu.Arch) void {
    const stale_name = switch (arch) {
        .x86_64 => "BOOTAA64.EFI",
        .aarch64 => "BOOTX64.EFI",
        else => return,
    };
    const stale_path = b.fmt("{s}/{s}/efi/boot/{s}", .{ b.install_path, out_dir, stale_name });
    std.fs.cwd().access(stale_path, .{}) catch return;

    std.debug.print(
        \\
        \\error: stale EFI loader in the output tree — refusing to build a mixed image.
        \\
        \\  found : {s}
        \\  but this is a {s} build, which installs {s}
        \\
        \\`zig-out` is not pruned on an arch switch, so both loaders would sit in
        \\the FAT image and the firmware may pick either one. Clear it first:
        \\
        \\  rm -rf zig-out
        \\
    , .{
        stale_path,
        archMachineName(switch (arch) {
            .x86_64 => EM_X86_64,
            else => EM_AARCH64,
        }),
        if (arch == .x86_64) "BOOTX64.EFI" else "BOOTAA64.EFI",
    });
    std.process.exit(1);
}
