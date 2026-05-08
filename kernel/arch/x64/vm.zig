/// x64 VM interface — runtime dispatch between Intel VT-x and AMD-V/SVM.
///
/// Detects CPU vendor at boot via CPUID and dispatches all VM operations
/// to the appropriate backend. Follows the same pattern as iommu.zig
/// (Intel VT-d vs AMD-Vi runtime dispatch).
const zag = @import("zag");

const cpu = zag.arch.x64.cpu;
const svm = zag.arch.x64.amd.svm;
const vmx = zag.arch.x64.intel.vmx;

const PAddr = zag.memory.address.PAddr;

/// Full x64 guest register state snapshot.
pub const GuestState = extern struct {
    // General-purpose registers
    rax: u64 = 0,
    rbx: u64 = 0,
    rcx: u64 = 0,
    rdx: u64 = 0,
    rsi: u64 = 0,
    rdi: u64 = 0,
    rbp: u64 = 0,
    rsp: u64 = 0,
    r8: u64 = 0,
    r9: u64 = 0,
    r10: u64 = 0,
    r11: u64 = 0,
    r12: u64 = 0,
    r13: u64 = 0,
    r14: u64 = 0,
    r15: u64 = 0,

    // Instruction pointer and flags
    rip: u64 = 0,
    rflags: u64 = 0x2, // bit 1 always set

    // Control registers
    cr0: u64 = 0,
    cr2: u64 = 0,
    cr3: u64 = 0,
    cr4: u64 = 0,

    // Segment registers (base, limit, selector, access rights)
    cs: SegmentReg = .{},
    ds: SegmentReg = .{},
    es: SegmentReg = .{},
    fs: SegmentReg = .{},
    gs: SegmentReg = .{},
    ss: SegmentReg = .{},
    tr: SegmentReg = .{},
    ldtr: SegmentReg = .{},

    // Descriptor table registers
    gdtr_base: u64 = 0,
    gdtr_limit: u32 = 0,
    idtr_base: u64 = 0,
    idtr_limit: u32 = 0,

    // Key MSRs that must be saved/restored across VM transitions
    efer: u64 = 0,
    star: u64 = 0,
    lstar: u64 = 0,
    cstar: u64 = 0,
    sfmask: u64 = 0,
    kernel_gs_base: u64 = 0,
    sysenter_cs: u64 = 0,
    sysenter_esp: u64 = 0,
    sysenter_eip: u64 = 0,
    pat: u64 = 0,
    dr6: u64 = 0,
    dr7: u64 = 0x400, // bit 10 always set per x86 spec

    // Pending event injection for SVM (VMCB EVENTINJ format).
    // Written by svm.injectInterrupt/injectException, consumed by svm.vmResume.
    // Not used by VMX (which writes directly to the VMCS).
    pending_eventinj: u64 = 0,

    pub const SegmentReg = extern struct {
        base: u64 = 0,
        limit: u32 = 0,
        selector: u16 = 0,
        access_rights: u16 = 0,
    };
};

/// Tagged union of x64 VM exit reasons.
pub const VmExitInfo = union(enum) {
    cpuid: CpuidExit,
    io: IoExit,
    mmio: MmioExit,
    cr_access: CrAccessExit,
    msr_read: MsrExit,
    msr_write: MsrExit,
    ept_violation: EptViolationExit,
    exception: ExceptionExit,
    interrupt_window: void,
    hlt: void,
    shutdown: void,
    triple_fault: void,
    unknown: u64,

    pub const CpuidExit = struct {
        leaf: u32,
        subleaf: u32,
        /// Guest RIP of the next sequential instruction past the
        /// trapping CPUID (for RIP advance after inline policy
        /// resolution). Intel sources this from VM_EXIT_INSTRUCTION_LEN
        /// (SDM Vol 3C §28.2.5); AMD sources it from VMCB nRIP at offset
        /// 0xC8 (APM Vol 2 §15.7.1).
        next_rip: u64,
    };

    pub const IoExit = struct {
        port: u16,
        size: u8,
        is_write: bool,
        value: u32,
        next_rip: u64,
    };

    pub const MmioExit = struct {
        addr: u64,
        size: u8,
        is_write: bool,
        value: u64,
    };

    pub const CrAccessExit = struct {
        cr_num: u4,
        is_write: bool,
        gpr: u4,
        value: u64,
        /// Guest RIP of the next sequential instruction past the
        /// trapping mov-to/from-CR (for RIP advance after inline
        /// policy resolution). Same sources as CpuidExit.next_rip.
        next_rip: u64,
    };

    pub const MsrExit = struct {
        msr: u32,
        value: u64,
    };

    pub const EptViolationExit = struct {
        guest_phys: u64,
        is_read: bool,
        is_write: bool,
        is_exec: bool,
    };

    pub const ExceptionExit = struct {
        vector: u8,
        error_code: u64,
    };
};

/// FXSAVE area (512 bytes, 16-byte aligned) for guest FP/SIMD save/restore.
pub const FxsaveArea = [512]u8;

/// Return an FxsaveArea initialized with default x87/SSE state:
/// FCW=0x037F (x87 default), MXCSR=0x1F80 (SSE default, all exceptions masked).
pub fn fxsaveInit() FxsaveArea {
    var area: FxsaveArea = .{0} ** 512;
    // FCW at offset 0 (2 bytes, little-endian)
    area[0] = 0x7F;
    area[1] = 0x03;
    // MXCSR at offset 24 (4 bytes, little-endian)
    area[24] = 0x80;
    area[25] = 0x1F;
    return area;
}

/// Interrupt to inject into a guest vCPU.
pub const GuestInterrupt = extern struct {
    vector: u8,
    interrupt_type: u8, // 0=external, 4=NMI, 5=exception, 6=software
    error_code_valid: bool,
    _pad: [5]u8 = .{0} ** 5,
    error_code: u32 = 0,
    _pad2: [4]u8 = .{0} ** 4,
};

/// Exception to inject into a guest vCPU.
pub const GuestException = extern struct {
    vector: u8,
    _pad: [3]u8 = .{0} ** 3,
    error_code: u32 = 0,
    fault_addr: u64 = 0,
};

/// Static policy table for inline exit handling.
/// Set at vm_create time and never changes.
pub const VmPolicy = extern struct {
    /// Pre-configured CPUID leaf responses. If a guest CPUID exit matches
    /// a leaf here, the kernel returns the configured response inline.
    cpuid_responses: [MAX_CPUID_POLICIES]CpuidPolicy = .{CpuidPolicy{}} ** MAX_CPUID_POLICIES,
    num_cpuid_responses: u32 = 0,
    _pad0: u32 = 0,

    /// CR access policies. If a guest CR read/write matches an entry here,
    /// the kernel handles it inline per the configured action.
    cr_policies: [MAX_CR_POLICIES]CrPolicy = .{CrPolicy{}} ** MAX_CR_POLICIES,
    num_cr_policies: u32 = 0,
    _pad1: u32 = 0,

    pub const MAX_CPUID_POLICIES = 32;
    pub const MAX_CR_POLICIES = 8;

    pub const CpuidPolicy = extern struct {
        leaf: u32 = 0,
        subleaf: u32 = 0,
        eax: u32 = 0,
        ebx: u32 = 0,
        ecx: u32 = 0,
        edx: u32 = 0,
    };

    pub const CrPolicy = extern struct {
        cr_num: u8 = 0,
        _pad: [7]u8 = .{0} ** 7,
        read_value: u64 = 0,
        write_mask: u64 = 0, // bits the guest is allowed to set
    };
};

const VmBackend = enum {
    none,
    intel_vmx,
    amd_svm,
};

var active_backend: VmBackend = .none;

/// Detect hardware virtualization support and initialize the global VM subsystem.
/// Called once at boot from arch.vmInit().
pub fn vmInit() void {
    const vendor = detectVendor();
    switch (vendor) {
        .intel => {
            if (vmx.init()) {
                active_backend = .intel_vmx;
            }
        },
        .amd => {
            if (svm.init()) {
                active_backend = .amd_svm;
            }
        },
        .unknown => {},
    }
}

/// Per-core VM initialization. Called from sched.perCoreInit().
pub fn vmPerCoreInit() void {
    switch (active_backend) {
        .intel_vmx => vmx.perCoreInit(),
        .amd_svm => svm.perCoreInit(),
        .none => {},
    }
}

/// Returns whether hardware virtualization is available.
pub fn vmSupported() bool {
    return active_backend != .none;
}

/// Enter the guest. Called from the vCPU thread entry point.
/// Returns the exit info when the guest exits.
pub fn vmResume(guest_state: *GuestState, vmcs_paddr: PAddr, guest_fxsave: *align(16) FxsaveArea) VmExitInfo {
    return switch (active_backend) {
        .intel_vmx => vmx.vmResume(guest_state, vmcs_paddr),
        .amd_svm => svm.vmResume(guest_state, vmcs_paddr, guest_fxsave),
        .none => .{ .unknown = 0 },
    };
}

/// Inject a virtual interrupt into the guest.
pub fn injectInterrupt(guest_state: *GuestState, interrupt: GuestInterrupt) void {
    switch (active_backend) {
        .intel_vmx => vmx.injectInterrupt(guest_state, interrupt),
        .amd_svm => svm.injectInterrupt(guest_state, interrupt),
        .none => {},
    }
}

/// Inject an exception into the guest.
pub fn injectException(guest_state: *GuestState, exception: GuestException) void {
    switch (active_backend) {
        .intel_vmx => vmx.injectException(guest_state, exception),
        .amd_svm => svm.injectException(guest_state, exception),
        .none => {},
    }
}

/// Modify system-register passthrough bits in the VM's MSRPM. On x86 a
/// "sysreg" is an MSR; `sysreg_id` is the 32-bit MSR address.
pub fn sysregPassthrough(vm_structures: PAddr, sysreg_id: u32, allow_read: bool, allow_write: bool) void {
    switch (active_backend) {
        .amd_svm => svm.msrPassthrough(vm_structures, sysreg_id, allow_read, allow_write),
        // Intel VMX MSR bitmap support is configured via VMCS bits at
        // initVmcs time; per-MSR runtime mutation is not yet wired here.
        .intel_vmx => {},
        .none => {},
    }
}

/// Free arch-specific per-VM structures.
///
/// Spec-v3 split: this frees only the per-VM control state (VMCS on
/// Intel, VMCB+IOPM+MSRPM on AMD). The stage-2 root is freed separately
/// via `freeStage2RootPage`, so callers walking the spec-v3 dispatch
/// path don't double-free the EPT/NPT root.
pub fn vmFreeStructures(paddr: PAddr) void {
    switch (active_backend) {
        .intel_vmx => vmx.freeVmStructures(paddr),
        .amd_svm => svm.freeVmcbOnly(paddr),
        .none => {},
    }
}

/// Allocate the stage-2 nested-paging root page (EPT PML4 / NPT PML4).
/// Spec-v3 dispatch primitive — backs `hv.vm.allocStage2Root`.
pub fn allocStage2RootPage() ?PAddr {
    return switch (active_backend) {
        .intel_vmx => vmx.allocEptRoot(),
        .amd_svm => svm.allocNptRoot(),
        .none => null,
    };
}

/// Free a stage-2 nested-paging root page allocated by
/// `allocStage2RootPage`. TODO: walk and free intermediate tables.
pub fn freeStage2RootPage(paddr: PAddr) void {
    switch (active_backend) {
        .intel_vmx => vmx.freeEptRoot(paddr),
        .amd_svm => svm.freeNptRoot(paddr),
        .none => {},
    }
}

/// Allocate per-VM control state (VMCS / VMCB) wired to a pre-allocated
/// stage-2 root. On Intel this returns the VMCS PAddr after VMCLEAR +
/// VMPTRLD + `initVmcs(ept_root)`. On AMD this is not yet split out and
/// returns null so the caller surfaces `error.NoDevice`.
pub fn allocVmCtrlState(stage2_root: PAddr) ?PAddr {
    return switch (active_backend) {
        .intel_vmx => vmx.allocVmcsWithEpt(stage2_root),
        .amd_svm => svm.allocVmcbWithNpt(stage2_root),
        .none => null,
    };
}

/// Map a guest physical page in the arch-specific guest memory translation structures.
pub fn mapGuestPage(vm_structures: PAddr, guest_phys: u64, host_phys: PAddr, rights: u8) !void {
    switch (active_backend) {
        .intel_vmx => try vmx.mapEptPage(vm_structures, guest_phys, host_phys, rights),
        .amd_svm => try svm.mapNptPage(vm_structures, guest_phys, host_phys, rights),
        .none => return error.NoVmSupport,
    }
}

/// Unmap a guest physical page from the arch-specific guest memory translation structures.
pub fn unmapGuestPage(vm_structures: PAddr, guest_phys: u64) void {
    switch (active_backend) {
        .intel_vmx => vmx.unmapEptPage(vm_structures, guest_phys),
        .amd_svm => svm.unmapNptPage(vm_structures, guest_phys),
        .none => {},
    }
}

const Vendor = enum { intel, amd, unknown };

fn detectVendor() Vendor {
    const result = cpu.cpuid(.basic_max, 0);
    // "GenuineIntel" = EBX:EDX:ECX
    if (result.ebx == 0x756e6547 and result.edx == 0x49656e69 and result.ecx == 0x6c65746e)
        return .intel;
    // "AuthenticAMD" = EBX:EDX:ECX
    if (result.ebx == 0x68747541 and result.edx == 0x69746e65 and result.ecx == 0x444d4163)
        return .amd;
    return .unknown;
}
