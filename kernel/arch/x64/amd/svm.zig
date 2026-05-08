/// AMD-V/SVM (Secure Virtual Machine) implementation.
///
/// Handles SVM enable, VMCB allocation, VMRUN/#VMEXIT, NPT (Nested Page Tables),
/// and event injection per AMD APM Vol 2, Chapter 15.
const std = @import("std");
const zag = @import("zag");

const apic = zag.arch.x64.apic;
const cpu = zag.arch.x64.cpu;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const vm_mod = zag.arch.x64.vm;

const GuestException = vm_mod.GuestException;
const GuestInterrupt = vm_mod.GuestInterrupt;
const GuestState = vm_mod.GuestState;
const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;
const VmExitInfo = vm_mod.VmExitInfo;

// ---------------------------------------------------------------------------
// MSR addresses — AMD APM Vol 2, Section 15.28, Table 15-9
// ---------------------------------------------------------------------------

/// EFER MSR — bit 12 (SVME) enables SVM instructions.
/// AMD APM Vol 2, Section 15.4.
const IA32_EFER: u32 = 0xC0000080;

/// VM_HSAVE_PA MSR — physical address of host state-save area.
/// AMD APM Vol 2, Section 15.28.
const VM_HSAVE_PA: u32 = 0xC0010117;

const EFER_SVME: u64 = 1 << 12;

/// Default PAT MSR value as configured by BIOS/hardware reset.
/// AMD APM Vol 2, Section 7.8.1, Table 7-8.
/// PA0=WB(6), PA1=WT(4), PA2=UC-(7), PA3=UC(0), PA4=WB(6), PA5=WT(4), PA6=UC-(7), PA7=UC(0).
const DEFAULT_PAT: u64 = 0x0007040600070406;

// ---------------------------------------------------------------------------
// SVM exit codes — AMD APM Vol 2, Section 15.9, Appendix C
// ---------------------------------------------------------------------------

const VMEXIT_CR0_READ: u64 = 0x000;
const VMEXIT_CR0_WRITE: u64 = 0x010;
const VMEXIT_EXCP_BASE: u64 = 0x040;
const VMEXIT_INTR: u64 = 0x060;
const VMEXIT_NMI: u64 = 0x061;
const VMEXIT_SMI: u64 = 0x062;
const VMEXIT_INIT: u64 = 0x063;
const VMEXIT_VINTR: u64 = 0x064;
const VMEXIT_CPUID: u64 = 0x072;
const VMEXIT_HLT: u64 = 0x078;
const VMEXIT_INVLPG: u64 = 0x079;
const VMEXIT_IOIO: u64 = 0x07B;
const VMEXIT_MSR: u64 = 0x07C;
const VMEXIT_SHUTDOWN: u64 = 0x07F;
const VMEXIT_VMRUN: u64 = 0x080;
const VMEXIT_NPF: u64 = 0x400;
const VMEXIT_INVALID: u64 = @as(u64, @bitCast(@as(i64, -1)));

// ---------------------------------------------------------------------------
// VMCB layout — AMD APM Vol 2, Appendix B, Tables B-1 and B-2
// ---------------------------------------------------------------------------

/// VMCB Control Area offsets (relative to VMCB base).
/// AMD APM Vol 2, Appendix B, Table B-1.
const Vmcb = struct {
    // Control area (0x000 - 0x3FF)
    const INTERCEPT_CR_RW: usize = 0x000; // CR read/write intercepts
    const INTERCEPT_DR_RW: usize = 0x004; // DR read/write intercepts
    const INTERCEPT_EXCP: usize = 0x008; // Exception intercepts (bits 0-31)
    const INTERCEPT_CTRL1: usize = 0x00C; // Misc intercepts word 1
    const INTERCEPT_CTRL2: usize = 0x010; // Misc intercepts word 2
    const IOPM_BASE_PA: usize = 0x040; // I/O permission map phys addr
    const MSRPM_BASE_PA: usize = 0x048; // MSR permission map phys addr
    const TSC_OFFSET: usize = 0x050; // TSC offset
    const GUEST_ASID: usize = 0x058; // Guest ASID (bits 31:0), TLB_CONTROL (bits 39:32)
    const V_INTR: usize = 0x060; // Virtual interrupt control
    const EXITCODE: usize = 0x070; // Exit code
    const EXITINFO1: usize = 0x078; // Exit info 1
    const EXITINFO2: usize = 0x080; // Exit info 2
    const EXITINTINFO: usize = 0x088; // Exit interrupt info
    const NP_ENABLE: usize = 0x090; // Nested paging enable (bit 0)
    const EVENTINJ: usize = 0x0A8; // Event injection
    const N_CR3: usize = 0x0B0; // Nested page table CR3 (host CR3 for NPT)
    const VMCB_CLEAN: usize = 0x0C0; // VMCB clean bits (AMD APM Vol 2, Section 15.15.3)
    const NRIP_SAVE: usize = 0x0C8; // Next sequential instruction pointer (AMD APM Vol 2, Section 15.7.1)

    // State save area offsets (relative to VMCB + 0x400)
    // AMD APM Vol 2, Appendix B, Table B-2.
    const STATE_BASE: usize = 0x400;

    // Segment registers: each is selector(2) + attrib(2) + limit(4) + base(8) = 16 bytes
    const ES: usize = STATE_BASE + 0x000;
    const CS: usize = STATE_BASE + 0x010;
    const SS: usize = STATE_BASE + 0x020;
    const DS: usize = STATE_BASE + 0x030;
    const FS: usize = STATE_BASE + 0x040;
    const GS: usize = STATE_BASE + 0x050;
    const GDTR: usize = STATE_BASE + 0x060;
    const LDTR: usize = STATE_BASE + 0x070;
    const IDTR: usize = STATE_BASE + 0x080;
    const TR: usize = STATE_BASE + 0x090;

    const CPL: usize = STATE_BASE + 0x0CB;
    const EFER: usize = STATE_BASE + 0x0D0;
    const CR4: usize = STATE_BASE + 0x148;
    const CR3: usize = STATE_BASE + 0x150;
    const CR0: usize = STATE_BASE + 0x158;
    const DR7: usize = STATE_BASE + 0x160;
    const DR6: usize = STATE_BASE + 0x168;
    const RFLAGS: usize = STATE_BASE + 0x170;
    const RIP: usize = STATE_BASE + 0x178;
    const RSP: usize = STATE_BASE + 0x1D8;
    const RAX: usize = STATE_BASE + 0x1F8;
    const STAR: usize = STATE_BASE + 0x200;
    const LSTAR: usize = STATE_BASE + 0x208;
    const CSTAR: usize = STATE_BASE + 0x210;
    const SFMASK: usize = STATE_BASE + 0x218;
    const KERNEL_GS_BASE: usize = STATE_BASE + 0x220;
    const SYSENTER_CS: usize = STATE_BASE + 0x228;
    const SYSENTER_ESP: usize = STATE_BASE + 0x230;
    const SYSENTER_EIP: usize = STATE_BASE + 0x238;
    const CR2: usize = STATE_BASE + 0x240;
    const PAT: usize = STATE_BASE + 0x268;
};

/// Intercept bits for INTERCEPT_CTRL1 (offset 0x00C).
/// AMD APM Vol 2, Appendix B, Table B-1.
const CTRL1_INTERCEPT_INTR: u32 = 1 << 0;
const CTRL1_INTERCEPT_NMI: u32 = 1 << 1;
const CTRL1_INTERCEPT_SMI: u32 = 1 << 2;
const CTRL1_INTERCEPT_INIT: u32 = 1 << 3;
const CTRL1_INTERCEPT_VINTR: u32 = 1 << 4; // AMD APM Vol 2, Table B-1: virtual interrupt
const CTRL1_INTERCEPT_CPUID: u32 = 1 << 18;
const CTRL1_INTERCEPT_HLT: u32 = 1 << 24;
const CTRL1_INTERCEPT_IOIO: u32 = 1 << 27;
const CTRL1_INTERCEPT_MSR: u32 = 1 << 28;
const CTRL1_INTERCEPT_SHUTDOWN: u32 = 1 << 31;

/// Intercept bits for INTERCEPT_CTRL2 (offset 0x010).
/// AMD APM Vol 2, Appendix B, Table B-1.
const CTRL2_INTERCEPT_VMRUN: u32 = 1 << 0;

// ---------------------------------------------------------------------------
// Module state
// ---------------------------------------------------------------------------

var svm_supported_flag: bool = false;

/// Maximum guest ASID value (from CPUID Fn8000_000A EBX).
/// AMD APM Vol 2, Section 15.30.1: NASID = max ASID + 1.
var max_asid: u32 = 1;

/// Atomic counter for ASID allocation. Starts at 1 (ASID 0 is reserved
/// for the host). AMD APM Vol 2, Section 15.5.1.
var next_asid: std.atomic.Value(u32) = std.atomic.Value(u32).init(1);

/// Per-core host VMCB physical addresses for VMSAVE/VMLOAD.
/// AMD APM Vol 2, Section 15.14: VMSAVE/VMLOAD use the VMCB-format page
/// addressed by RAX to save/restore FS/GS/TR/LDTR bases, KernelGsBase,
/// STAR, LSTAR, CSTAR, SFMASK, and SYSENTER MSRs. This is separate from
/// VM_HSAVE_PA (Section 15.5.1) which has implementation-specific format.
const MAX_CORES = 64;
var host_vmcb_pa: [MAX_CORES]u64 = .{0} ** MAX_CORES;
// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

/// Detect SVM support via CPUID.
/// AMD APM Vol 2, Section 15.4: check CPUID Fn 8000_0001h ECX bit 2.
pub fn init() bool {
    const ext_features = cpu.cpuid(.ext_features, 0);
    if ((ext_features.ecx & (1 << 2)) == 0) {
        svm_supported_flag = false;
        return false;
    }

    // Check SVM revision and NPT support.
    // AMD APM Vol 2, Section 15.30.1: CPUID Fn 8000_000Ah.
    // EBX = NASID (number of ASIDs, i.e. max ASID + 1).
    const svm_info = cpu.cpuid(.svm_features, 0);
    max_asid = if (svm_info.ebx > 1) svm_info.ebx - 1 else 1;

    svm_supported_flag = true;
    return true;
}

/// Per-core SVM initialization.
/// AMD APM Vol 2, Section 15.4: set EFER.SVME, allocate host save area.
pub fn perCoreInit() void {
    if (!svm_supported_flag) return;

    // Set EFER.SVME (bit 12) to enable SVM instructions.
    var efer = cpu.rdmsr(IA32_EFER);
    efer |= EFER_SVME;
    cpu.wrmsr(IA32_EFER, efer);

    // Allocate host state-save area (4KB aligned page).
    // AMD APM Vol 2, Section 15.28: VM_HSAVE_PA MSR holds the physical
    // address of the host save area used by VMRUN/#VMEXIT.
    const pmm_mgr = &pmm.global_pmm.?;
    const hsa_page = pmm_mgr.create(paging.PageMem(.page4k)) catch return;
    @memset(std.mem.asBytes(hsa_page), 0);
    const hsa_phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(hsa_page)), null);
    cpu.wrmsr(VM_HSAVE_PA, hsa_phys.addr);

    // Allocate per-core host VMCB page for VMSAVE/VMLOAD (Section 15.14).
    // VMSAVE/VMLOAD use a standard VMCB-format page (unlike VM_HSAVE_PA
    // which is implementation-specific). Holds host FS/GS bases, TR/LDTR
    // hidden state, KernelGsBase, STAR/LSTAR/CSTAR/SFMASK, and SYSENTER
    // CS/ESP/EIP across guest entry/exit.
    const host_vmcb_page = pmm_mgr.create(paging.PageMem(.page4k)) catch return;
    @memset(std.mem.asBytes(host_vmcb_page), 0);
    const core_id = apic.coreID();
    host_vmcb_pa[core_id] = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(host_vmcb_page)), null).addr;
}

/// Allocate and zero a 4K page to serve as the NPT PML4 root.
/// Spec-v3 split: caller (`arch.x64.hv.vm.allocStage2Root`) holds this
/// PAddr in `VirtualMachine.guest_pt_root`. On AMD the NPT root has to
/// be patched into the VMCB (`N_CR3`) by per-VM control state setup.
pub fn allocNptRoot() ?PAddr {
    const pmm_mgr = &pmm.global_pmm.?;
    const npt_page = pmm_mgr.create(paging.PageMem(.page4k)) catch return null;
    return PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(npt_page)), null);
}

/// Free an NPT PML4 page allocated by `allocNptRoot`.
pub fn freeNptRoot(paddr: PAddr) void {
    const pmm_mgr = &pmm.global_pmm.?;
    const vaddr = VAddr.fromPAddr(paddr, null).addr;
    const page: *paging.PageMem(.page4k) = @ptrFromInt(vaddr);
    pmm_mgr.destroy(page);
}

/// Allocate a VMCB + IOPM + MSRPM and wire it to an externally-allocated
/// NPT root. Mirrors `vmx.allocVmcsWithEpt` so the spec-v3 split (one
/// dispatch slot for the stage-2 root, another for per-VM control state)
/// can mint AMD VMs as well.
///
/// AMD APM Vol 2, Section 15.5.1: VMCB is a 4KB-aligned page.
/// Returns physical address of the VMCB page. The caller's pre-allocated
/// NPT PML4 physical address is patched into the VMCB at offset N_CR3
/// (0x0B0). The NPT root is NOT freed by `freeVmcbOnly` — its lifetime
/// is governed by the spec-v3 `freeStage2Root` dispatch.
pub fn allocVmcbWithNpt(npt_root_phys: PAddr) ?PAddr {
    const pmm_mgr = &pmm.global_pmm.?;

    // Allocate VMCB page — returns zeroed.
    const vmcb_page = pmm_mgr.create(paging.PageMem(.page4k)) catch return null;
    const vmcb_vaddr = @intFromPtr(vmcb_page);
    const vmcb_phys = PAddr.fromVAddr(VAddr.fromInt(vmcb_vaddr), null);

    // Allocate IOPM (3 contiguous pages = 12KB, 4KB-aligned).
    // AMD APM Vol 2, Section 15.10.1: I/O permission map is 12KB.
    // Must be physically contiguous. Allocate 4 pages (order-2) from the
    // buddy allocator to guarantee contiguity, then use the first 3.
    const iopm_ptr = pmm_mgr.allocBlock(4 * paging.PAGE4K) orelse {
        pmm_mgr.destroy(vmcb_page);
        return null;
    };
    @memset(iopm_ptr[0 .. 3 * paging.PAGE4K], 0xFF);
    const iopm_phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(iopm_ptr)), null);

    // Allocate MSRPM (2 contiguous pages = 8KB, 4KB-aligned).
    // AMD APM Vol 2, Section 15.10.2: MSR permission map is 8KB.
    const msrpm_ptr = pmm_mgr.allocBlock(2 * paging.PAGE4K) orelse {
        pmm_mgr.freeBlock(iopm_ptr[0 .. 4 * paging.PAGE4K]);
        pmm_mgr.destroy(vmcb_page);
        return null;
    };
    @memset(msrpm_ptr[0 .. 2 * paging.PAGE4K], 0xFF);

    // Allow passthrough for MSRs that are saved/restored by VMSAVE/VMLOAD.
    clearMsrpmBits(msrpm_ptr, 0x10); // TSC
    clearMsrpmBits(msrpm_ptr, 0x174); // SYSENTER_CS
    clearMsrpmBits(msrpm_ptr, 0x175); // SYSENTER_ESP
    clearMsrpmBits(msrpm_ptr, 0x176); // SYSENTER_EIP
    clearMsrpmBits(msrpm_ptr, 0xC0000080); // EFER
    clearMsrpmBits(msrpm_ptr, 0xC0000081); // STAR
    clearMsrpmBits(msrpm_ptr, 0xC0000082); // LSTAR
    clearMsrpmBits(msrpm_ptr, 0xC0000083); // CSTAR
    clearMsrpmBits(msrpm_ptr, 0xC0000084); // SFMASK
    clearMsrpmBits(msrpm_ptr, 0xC0000100); // FS_BASE
    clearMsrpmBits(msrpm_ptr, 0xC0000101); // GS_BASE
    clearMsrpmBits(msrpm_ptr, 0xC0000102); // KERNEL_GS_BASE

    const msrpm_phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(msrpm_ptr)), null);

    // MINIMAL VMCB SETUP — bare minimum to test if VMRUN returns at all.
    // AMD APM Vol 2, Appendix B, Table B-1.
    const vmcb: [*]u8 = @ptrFromInt(vmcb_vaddr);

    // Intercept HLT and VMRUN only. VMRUN intercept is mandatory (AMD APM
    // Vol 2, Section 15.5.1).
    const ctrl1: u32 = CTRL1_INTERCEPT_INTR | CTRL1_INTERCEPT_NMI |
        CTRL1_INTERCEPT_VINTR |
        CTRL1_INTERCEPT_HLT | CTRL1_INTERCEPT_SHUTDOWN |
        CTRL1_INTERCEPT_CPUID | CTRL1_INTERCEPT_MSR |
        CTRL1_INTERCEPT_IOIO;
    writeVmcb32(vmcb, Vmcb.INTERCEPT_CTRL1, ctrl1);
    writeVmcb32(vmcb, Vmcb.INTERCEPT_CTRL2, CTRL2_INTERCEPT_VMRUN);

    // Intercept only exceptions the hypervisor needs.
    // #DB (1)  — debug
    // #MC (18) — machine check, must always be intercepted
    writeVmcb32(vmcb, Vmcb.INTERCEPT_EXCP, (1 << 1) | (1 << 18));

    writeVmcb64(vmcb, Vmcb.IOPM_BASE_PA, iopm_phys.addr);
    writeVmcb64(vmcb, Vmcb.MSRPM_BASE_PA, msrpm_phys.addr);

    // Guest ASID must be non-zero (ASID 0 is reserved for the host).
    var asid = next_asid.fetchAdd(1, .monotonic);
    var tlb_control: u32 = 0;
    if (asid > max_asid) {
        next_asid.store(2, .monotonic);
        asid = 1;
        tlb_control = 1;
    }
    const asid_field: u64 = @as(u64, asid) | (@as(u64, tlb_control) << 32);
    writeVmcb64(vmcb, Vmcb.GUEST_ASID, asid_field);

    // Enable virtual interrupt masking.
    writeVmcb64(vmcb, Vmcb.V_INTR, @as(u64, 1) << 24);

    // Enable nested paging.
    writeVmcb64(vmcb, Vmcb.NP_ENABLE, 1);

    // Patch the externally-allocated NPT PML4 into the VMCB.
    // AMD APM Vol 2, Section 15.24.3: offset 0x0B0.
    writeVmcb64(vmcb, Vmcb.N_CR3, npt_root_phys.addr);

    return vmcb_phys;
}

/// Free a VMCB allocated by `allocVmcbWithNpt`. Frees IOPM, MSRPM, and
/// the VMCB page; leaves the NPT root alone (its lifetime is owned by
/// the spec-v3 `freeStage2Root` dispatch).
pub fn freeVmcbOnly(vmcb_phys: PAddr) void {
    const pmm_mgr = &pmm.global_pmm.?;
    const vmcb_vaddr = VAddr.fromPAddr(vmcb_phys, null).addr;
    const vmcb: [*]u8 = @ptrFromInt(vmcb_vaddr);

    const iopm_phys_addr = readVmcb64(vmcb, Vmcb.IOPM_BASE_PA);
    if (iopm_phys_addr != 0) {
        const iopm_vaddr = VAddr.fromPAddr(PAddr.fromInt(iopm_phys_addr), null).addr;
        const iopm_slice: [*]u8 = @ptrFromInt(iopm_vaddr);
        pmm_mgr.freeBlock(iopm_slice[0 .. 4 * paging.PAGE4K]);
    }

    const msrpm_phys_addr = readVmcb64(vmcb, Vmcb.MSRPM_BASE_PA);
    if (msrpm_phys_addr != 0) {
        const msrpm_vaddr = VAddr.fromPAddr(PAddr.fromInt(msrpm_phys_addr), null).addr;
        const msrpm_slice: [*]u8 = @ptrFromInt(msrpm_vaddr);
        pmm_mgr.freeBlock(msrpm_slice[0 .. 2 * paging.PAGE4K]);
    }

    const vmcb_page: *paging.PageMem(.page4k) = @ptrFromInt(vmcb_vaddr);
    pmm_mgr.destroy(vmcb_page);
}

/// Allocate VMCB + NPT PML4 for a new VM.
/// AMD APM Vol 2, Section 15.5.1: VMCB is a 4KB-aligned page.
/// Returns physical address of the VMCB page. The NPT PML4 physical
/// address is stored at VMCB offset N_CR3 (0x0B0).

/// Free VMCB and associated structures.

/// Recursively walk the NPT page table tree and free all intermediate pages
/// (PDPT, PD, PT) plus the PML4 itself. Leaf entries point to guest-backing
/// host pages which are NOT freed here (they belong to the host process).

/// Execute guest via VMRUN, handle #VMEXIT.
/// AMD APM Vol 2, Section 15.5.1: VMRUN takes VMCB physical address in RAX.
/// On #VMEXIT, processor writes exit info to VMCB control area and resumes
/// host at the instruction following VMRUN.
pub fn vmResume(guest_state: *GuestState, vmcb_phys: PAddr, guest_fxsave: *align(16) [512]u8) VmExitInfo {
    const vmcb_vaddr = VAddr.fromPAddr(vmcb_phys, null).addr;
    const vmcb: [*]u8 = @ptrFromInt(vmcb_vaddr);

    // Write guest state into VMCB state save area.
    // AMD APM Vol 2, Appendix B, Table B-2.
    writeGuestToVmcb(vmcb, guest_state);

    // Clear VMCB clean bits to force the processor to reload all fields
    // from the VMCB. Required after modifying guest state, and essential
    // under nested virtualization (KVM) where cached state may be stale.
    // AMD APM Vol 2, Section 15.15.3.
    writeVmcb32(vmcb, Vmcb.VMCB_CLEAN, 0);

    // Event injection and virtual interrupt management.
    // AMD APM Vol 2, Section 15.20: EVENTINJ at offset 0x0A8.
    // Section 15.21.1: V_IRQ/V_INTR for interrupt window notification.
    if (guest_state.pending_eventinj != 0) {
        // Check if the pending event is an external interrupt (type bits 10:8 == 0)
        const event_type = (guest_state.pending_eventinj >> 8) & 0x7;
        const guest_if = guest_state.rflags & (1 << 9);
        if (event_type == 0 and guest_if == 0) {
            // External interrupt but guest has IF=0 — can't deliver now.
            // Arm V_IRQ to get VMEXIT_VINTR when guest enables IF.
            // Keep pending_eventinj for later delivery.
            writeVmcb64(vmcb, Vmcb.V_INTR, (@as(u64, 1) << 24) | (@as(u64, 1) << 8) | (@as(u64, 1) << 16) | (@as(u64, 0xF) << 12));
        } else {
            // Can deliver: either IF=1 or non-external-interrupt event.
            writeVmcb64(vmcb, Vmcb.EVENTINJ, guest_state.pending_eventinj);
            guest_state.pending_eventinj = 0;
            writeVmcb64(vmcb, Vmcb.V_INTR, @as(u64, 1) << 24);
        }
    } else {
        writeVmcb64(vmcb, Vmcb.V_INTR, @as(u64, 1) << 24);
    }

    // Save host FPU/SSE state and load guest FPU/SSE state.
    // FXSAVE/FXRSTOR are always available on x86-64 (required by AMD64 spec).
    var host_fxsave: [512]u8 align(16) = undefined;
    asm volatile ("fxsave (%[addr])"
        :
        : [addr] "r" (&host_fxsave),
        : .{ .memory = true });
    asm volatile ("fxrstor (%[addr])"
        :
        : [addr] "r" (guest_fxsave),
        : .{ .memory = true });

    // Look up per-core host VMCB physical address for VMSAVE/VMLOAD.
    const host_pa = host_vmcb_pa[apic.coreID()];

    // Execute VMRUN with full SVM entry/exit sequence per AMD APM Vol 2.
    //
    // Section 15.5.1: VMRUN only saves/restores minimal host state.
    // Section 15.14: VMSAVE/VMLOAD save/restore FS/GS bases (GS base is
    //   per-CPU data), TR/LDTR hidden state, KernelGsBase, STAR, LSTAR,
    //   CSTAR, SFMASK, and SYSENTER_CS/ESP/EIP — none of which VMRUN
    //   handles.
    // Section 15.5.1, 15.16: CLGI/STGI disable/enable global interrupts
    //   to ensure atomic state switch. Without CLGI, physical interrupts
    //   can corrupt the VMCB state load under nested KVM.
    //
    // Sequence:
    //   CLGI                        — disable global interrupts
    //   VMSAVE [host_vmcb_pa]       — save host FS/GS/TR/LDTR/syscall MSRs
    //   VMLOAD [guest_vmcb_pa]      — load guest FS/GS/TR/LDTR/syscall MSRs
    //   VMRUN  [guest_vmcb_pa]      — enter guest
    //   ; ... #VMEXIT returns here ...
    //   VMSAVE [guest_vmcb_pa]      — save guest FS/GS/TR/LDTR/syscall MSRs
    //   VMLOAD [host_vmcb_pa]       — restore host FS/GS/TR/LDTR/syscall MSRs
    //   STGI                        — re-enable global interrupts
    //
    // VMRUN clobbers all GPRs except RAX, so both PAs are pushed onto the
    // stack before entry and recovered via RSP-relative addressing after
    // VMEXIT.
    const gs_ptr = @intFromPtr(guest_state);

    asm volatile (
    // Save host callee-saved registers (VMRUN clobbers them per AMD spec)
        \\pushq %%rbx
        \\pushq %%r12
        \\pushq %%r13
        \\pushq %%r14
        \\pushq %%r15
        \\pushq %%rbp
        // Push host_pa, guest_pa, and GuestState pointer for recovery after
        // VMEXIT. Stack layout: [rsp]=gs_ptr, [rsp+8]=guest_pa, [rsp+16]=host_pa
        \\pushq %%rdi
        \\pushq %%rsi
        \\pushq %%rdx
        //
        // AMD APM Vol 2, Section 15.16: CLGI clears GIF, preventing
        // physical interrupts from arriving during the state switch.
        \\clgi
        //
        // AMD APM Vol 2, Section 15.14: VMSAVE saves host FS/GS/TR/LDTR
        // bases and syscall MSRs to the VMCB-format page in RAX.
        \\movq 16(%%rsp), %%rax
        \\vmsave %%rax
        //
        // VMLOAD loads guest FS/GS/TR/LDTR bases and syscall MSRs from
        // the guest VMCB.
        \\movq 8(%%rsp), %%rax
        \\vmload %%rax
        //
        // Load guest GPRs from GuestState before VMRUN.
        // GuestState layout (extern struct, 8 bytes each):
        //   0x00=rax, 0x08=rbx, 0x10=rcx, 0x18=rdx, 0x20=rsi, 0x28=rdi,
        //   0x30=rbp, 0x38=rsp(unused), 0x40=r8..0x78=r15
        // RAX is loaded from VMCB by VMRUN, so we skip it here.
        \\movq (%%rsp), %%rax
        \\movq 0x08(%%rax), %%rbx
        \\movq 0x10(%%rax), %%rcx
        \\movq 0x18(%%rax), %%rdx
        \\movq 0x20(%%rax), %%rsi
        \\movq 0x28(%%rax), %%rdi
        \\movq 0x30(%%rax), %%rbp
        \\movq 0x40(%%rax), %%r8
        \\movq 0x48(%%rax), %%r9
        \\movq 0x50(%%rax), %%r10
        \\movq 0x58(%%rax), %%r11
        \\movq 0x60(%%rax), %%r12
        \\movq 0x68(%%rax), %%r13
        \\movq 0x70(%%rax), %%r14
        \\movq 0x78(%%rax), %%r15
        //
        // VMRUN: RAX = VMCB physical address.
        // AMD APM Vol 2, Section 15.5: VMRUN saves host state, loads guest
        // state from VMCB, enters guest. On #VMEXIT, host state is restored
        // and execution continues at the next instruction.
        \\movq 8(%%rsp), %%rax
        \\vmrun %%rax
        //
        // #VMEXIT returns here. RSP is restored by the processor.
        // Save guest GPRs back to GuestState. Recover GuestState pointer
        // from the stack (push rax first since we need rax as the base).
        \\pushq %%rax
        \\movq 8(%%rsp), %%rax
        \\popq 0x00(%%rax)
        \\movq %%rbx, 0x08(%%rax)
        \\movq %%rcx, 0x10(%%rax)
        \\movq %%rdx, 0x18(%%rax)
        \\movq %%rsi, 0x20(%%rax)
        \\movq %%rdi, 0x28(%%rax)
        \\movq %%rbp, 0x30(%%rax)
        \\movq %%r8,  0x40(%%rax)
        \\movq %%r9,  0x48(%%rax)
        \\movq %%r10, 0x50(%%rax)
        \\movq %%r11, 0x58(%%rax)
        \\movq %%r12, 0x60(%%rax)
        \\movq %%r13, 0x68(%%rax)
        \\movq %%r14, 0x70(%%rax)
        \\movq %%r15, 0x78(%%rax)
        //
        // Save guest FS/GS/TR/LDTR/syscall MSRs back to the guest VMCB.
        \\movq 8(%%rsp), %%rax
        \\vmsave %%rax
        //
        // Restore host FS/GS/TR/LDTR/syscall MSRs from host VMCB.
        \\movq 16(%%rsp), %%rax
        \\vmload %%rax
        //
        // AMD APM Vol 2, Section 15.16: STGI sets GIF, re-enabling
        // physical interrupt delivery.
        \\stgi
        //
        // Pop gs_ptr, guest_pa, host_pa and restore callee-saved registers.
        \\addq $24, %%rsp
        \\popq %%rbp
        \\popq %%r15
        \\popq %%r14
        \\popq %%r13
        \\popq %%r12
        \\popq %%rbx
        :
        : [guest_pa] "{rsi}" (vmcb_phys.addr),
          [host_pa] "{rdi}" (host_pa),
          [gs_ptr] "{rdx}" (gs_ptr),
        : .{ .memory = true, .rax = true, .rcx = true, .rdx = true, .rsi = true, .rdi = true, .r8 = true, .r9 = true, .r10 = true, .r11 = true });

    // Save guest FPU/SSE state and restore host FPU/SSE state.
    asm volatile ("fxsave (%[addr])"
        :
        : [addr] "r" (guest_fxsave),
        : .{ .memory = true });
    asm volatile ("fxrstor (%[addr])"
        :
        : [addr] "r" (&host_fxsave),
        : .{ .memory = true });

    // RAX is saved/restored by VMRUN/#VMEXIT in the VMCB state save area
    // (AMD APM Vol 2, Section 15.5.1 and 15.6). Read it from VMCB for the
    // canonical copy.
    guest_state.rax = readVmcb64(vmcb, Vmcb.RAX);

    // Read back guest architectural state from VMCB.
    readGuestFromVmcb(vmcb, guest_state);

    // Decode exit reason from VMCB control area.
    // AMD APM Vol 2, Section 15.9: EXITCODE at offset 0x070.
    return decodeExitReason(vmcb, guest_state);
}

/// Map a guest physical page in NPT (Nested Page Tables).
/// AMD APM Vol 2, Section 15.24.5: NPT uses the same page table format
/// as standard AMD64 long-mode paging (4-level, 4KB pages).
///
/// `vmcb_phys` is the VMCB physical address (same as vm.arch_structures).
/// The NPT PML4 root is read from the VMCB at N_CR3 (offset 0x0B0).
pub fn mapNptPage(vmcb_phys: PAddr, guest_phys: u64, host_phys: PAddr, rights: u8) !void {
    const pmm_mgr = &pmm.global_pmm.?;

    // Extract NPT PML4 root from VMCB N_CR3 field.
    const vmcb: [*]const u8 = @ptrFromInt(VAddr.fromPAddr(vmcb_phys, null).addr);
    const npt_root = PAddr.fromInt(readVmcb64(vmcb, Vmcb.N_CR3));

    // NPT entry format is identical to regular AMD64 PTE:
    // Bits 0=present, 1=writable, 2=user, 51:12=physical address.
    // AMD APM Vol 2, Section 15.24.5.
    const pml4_vaddr = VAddr.fromPAddr(npt_root, null).addr;
    const pml4: *[512]u64 = @ptrFromInt(pml4_vaddr);

    const pml4_idx = (guest_phys >> 39) & 0x1FF;
    const pdpt_idx = (guest_phys >> 30) & 0x1FF;
    const pd_idx = (guest_phys >> 21) & 0x1FF;
    const pt_idx = (guest_phys >> 12) & 0x1FF;

    // Walk/allocate PML4 → PDPT
    if (pml4[pml4_idx] == 0) {
        const page = pmm_mgr.create(paging.PageMem(.page4k)) catch return error.OutOfMemory;
        const phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
        pml4[pml4_idx] = phys.addr | 0x7; // present + writable + user
    }
    const pdpt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pml4[pml4_idx] & 0x000F_FFFF_FFFF_F000), null).addr);

    // Walk/allocate PDPT → PD
    if (pdpt[pdpt_idx] == 0) {
        const page = pmm_mgr.create(paging.PageMem(.page4k)) catch return error.OutOfMemory;
        const phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
        pdpt[pdpt_idx] = phys.addr | 0x7;
    }
    const pd: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pdpt[pdpt_idx] & 0x000F_FFFF_FFFF_F000), null).addr);

    // Walk/allocate PD → PT
    if (pd[pd_idx] == 0) {
        const page = pmm_mgr.create(paging.PageMem(.page4k)) catch return error.OutOfMemory;
        const phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
        pd[pd_idx] = phys.addr | 0x7;
    }
    const pt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pd[pd_idx] & 0x000F_FFFF_FFFF_F000), null).addr);

    // Insert leaf entry with host physical address and rights.
    // AMD NPT uses standard AMD64 PTE format (AMD APM Vol 2, Section 15.24.5):
    //   Bit 0 = present (readable), Bit 1 = writable, Bit 2 = user,
    //   Bit 63 = NX (no-execute).
    var entry: u64 = host_phys.addr & 0x000F_FFFF_FFFF_F000;
    entry |= 0x1; // present
    if ((rights & 0x2) != 0) entry |= 0x2; // writable
    entry |= 0x4; // user (NPT entries need user bit for guest access)
    if ((rights & 0x4) == 0) entry |= (@as(u64, 1) << 63); // NX if no execute permission
    pt[pt_idx] = entry;
}

/// Unmap a guest physical page from NPT.
/// `vmcb_phys` is the VMCB physical address. NPT root is read from N_CR3.
pub fn unmapNptPage(vmcb_phys: PAddr, guest_phys: u64) void {
    const vmcb: [*]const u8 = @ptrFromInt(VAddr.fromPAddr(vmcb_phys, null).addr);
    const npt_root = PAddr.fromInt(readVmcb64(vmcb, Vmcb.N_CR3));
    const pml4_vaddr = VAddr.fromPAddr(npt_root, null).addr;
    const pml4: *[512]u64 = @ptrFromInt(pml4_vaddr);

    const pml4_idx = (guest_phys >> 39) & 0x1FF;
    if (pml4[pml4_idx] == 0) return;
    const pdpt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pml4[pml4_idx] & 0x000F_FFFF_FFFF_F000), null).addr);

    const pdpt_idx = (guest_phys >> 30) & 0x1FF;
    if (pdpt[pdpt_idx] == 0) return;
    const pd: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pdpt[pdpt_idx] & 0x000F_FFFF_FFFF_F000), null).addr);

    const pd_idx = (guest_phys >> 21) & 0x1FF;
    if (pd[pd_idx] == 0) return;
    const pt: *[512]u64 = @ptrFromInt(VAddr.fromPAddr(PAddr.fromInt(pd[pd_idx] & 0x000F_FFFF_FFFF_F000), null).addr);

    const pt_idx = (guest_phys >> 12) & 0x1FF;
    pt[pt_idx] = 0;

    // Set TLB_CONTROL=1 in the VMCB to flush all TLB entries for this
    // ASID on the next VMRUN. AMD APM Vol 2, Section 15.17.
    // TLB_CONTROL is at GUEST_ASID offset bits 39:32 (byte offset +4).
    const vmcb_rw: [*]u8 = @ptrFromInt(VAddr.fromPAddr(vmcb_phys, null).addr);
    const current_asid = readVmcb32(vmcb_rw, Vmcb.GUEST_ASID);
    const asid_with_flush: u64 = @as(u64, current_asid) | (@as(u64, 1) << 32);
    writeVmcb64(vmcb_rw, Vmcb.GUEST_ASID, asid_with_flush);
}

/// Inject a virtual interrupt into the guest.
/// AMD APM Vol 2, Section 15.20, Figure 15-4: EVENTINJ field at VMCB offset 0x0A8.
pub fn injectInterrupt(guest_state: *GuestState, interrupt: GuestInterrupt) void {
    // Build EVENTINJ value per AMD APM Vol 2, Section 15.20, Figure 15-4:
    //   bits 7:0   = vector
    //   bits 10:8  = type (0=INTR, 2=NMI, 3=exception, 4=software interrupt)
    //   bit 11     = error code valid
    //   bit 31     = valid
    //   bits 63:32 = error code
    var eventinj: u64 = @as(u64, interrupt.vector);
    eventinj |= @as(u64, interrupt.interrupt_type) << 8;
    if (interrupt.error_code_valid) {
        eventinj |= (1 << 11);
        eventinj |= @as(u64, interrupt.error_code) << 32;
    }
    eventinj |= (1 << 31); // valid bit
    guest_state.pending_eventinj = eventinj;
}

/// Inject an exception into the guest.
/// AMD APM Vol 2, Section 15.20, Figure 15-4: EVENTINJ with TYPE=3 (exception).
pub fn injectException(guest_state: *GuestState, exception: GuestException) void {
    if (exception.vector == 14) {
        guest_state.cr2 = exception.fault_addr;
    }

    var eventinj: u64 = @as(u64, exception.vector);
    eventinj |= (3 << 8); // exception type

    // Exceptions that deliver an error code: #DF(8), #TS(10), #NP(11),
    // #SS(12), #GP(13), #PF(14), #AC(17).
    const has_error_code = switch (exception.vector) {
        8, 10, 11, 12, 13, 14, 17 => true,
        else => false,
    };
    if (has_error_code) {
        eventinj |= (1 << 11);
        eventinj |= @as(u64, exception.error_code) << 32;
    }
    eventinj |= (1 << 31); // valid bit
    guest_state.pending_eventinj = eventinj;
}

/// Modify MSR passthrough bits in the VM's MSRPM.
/// AMD APM Vol 2, Section 15.10: MSRPM format.
pub fn msrPassthrough(vmcb_phys: PAddr, msr_num: u32, allow_read: bool, allow_write: bool) void {
    const vmcb_vaddr = VAddr.fromPAddr(vmcb_phys, null).addr;
    const vmcb: [*]const u8 = @ptrFromInt(vmcb_vaddr);
    const msrpm_phys_addr = readVmcb64(vmcb, Vmcb.MSRPM_BASE_PA);
    if (msrpm_phys_addr == 0) return;
    const msrpm_vaddr = VAddr.fromPAddr(PAddr.fromInt(msrpm_phys_addr), null).addr;
    const msrpm: [*]u8 = @ptrFromInt(msrpm_vaddr);

    var base_offset: usize = 0;
    var msr_offset: u32 = msr_num;
    if (msr_num >= 0xC0000000 and msr_num <= 0xC0001FFF) {
        base_offset = 0x0800;
        msr_offset = msr_num - 0xC0000000;
    } else if (msr_num > 0x1FFF) {
        return;
    }
    const bit_pos = @as(usize, msr_offset) * 2;
    const byte_idx = base_offset + bit_pos / 8;
    const bit_idx: u3 = @truncate(bit_pos % 8);

    if (allow_read) {
        msrpm[byte_idx] &= ~(@as(u8, 1) << bit_idx);
    } else {
        msrpm[byte_idx] |= @as(u8, 1) << bit_idx;
    }
    const write_bit: u3 = @truncate((@as(usize, bit_idx) + 1) % 8);
    const write_byte = byte_idx + (@as(usize, bit_idx) + 1) / 8;
    if (allow_write) {
        msrpm[write_byte] &= ~(@as(u8, 1) << write_bit);
    } else {
        msrpm[write_byte] |= @as(u8, 1) << write_bit;
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Write guest state from GuestState into VMCB state save area.
/// AMD APM Vol 2, Appendix B, Table B-2.
///
/// Applies fixups for fields that require specific values per the AMD spec
/// but which GuestState may leave at zero/default. These are essential for
/// nested KVM (L0) VMCB consistency checks.
fn writeGuestToVmcb(vmcb: [*]u8, gs: *const GuestState) void {
    writeVmcb64(vmcb, Vmcb.RIP, gs.rip);
    writeVmcb64(vmcb, Vmcb.RSP, gs.rsp);
    // RFLAGS bit 1 is reserved-set per x86 spec.
    writeVmcb64(vmcb, Vmcb.RFLAGS, gs.rflags | 0x2);
    writeVmcb64(vmcb, Vmcb.RAX, gs.rax);

    // CR0: ET (bit 4) is hardwired to 1 on all x86 processors.
    writeVmcb64(vmcb, Vmcb.CR0, gs.cr0 | 0x10);
    writeVmcb64(vmcb, Vmcb.CR3, gs.cr3);
    writeVmcb64(vmcb, Vmcb.CR4, gs.cr4);

    // Segment registers — AMD APM Vol 2, Appendix B, Table B-2.
    writeSegment(vmcb, Vmcb.CS, gs.cs);
    writeSegment(vmcb, Vmcb.DS, gs.ds);
    writeSegment(vmcb, Vmcb.ES, gs.es);
    writeSegment(vmcb, Vmcb.FS, gs.fs);
    writeSegment(vmcb, Vmcb.GS, gs.gs);
    writeSegment(vmcb, Vmcb.SS, gs.ss);

    // TR: must have a valid busy-TSS type or the processor may reject the
    // VMCB. Default to a 32-bit busy TSS when the guest hasn't configured one.
    if (gs.tr.access_rights == 0) {
        writeSegment(vmcb, Vmcb.TR, .{
            .selector = 0,
            .access_rights = 0x008B,
            .limit = 0xFFFF,
            .base = 0,
        });
    } else {
        writeSegment(vmcb, Vmcb.TR, gs.tr);
    }

    // LDTR: an all-zero LDTR may fail consistency checks under KVM.
    if (gs.ldtr.access_rights == 0) {
        writeSegment(vmcb, Vmcb.LDTR, .{
            .selector = 0,
            .access_rights = 0x0082,
            .limit = 0,
            .base = 0,
        });
    } else {
        writeSegment(vmcb, Vmcb.LDTR, gs.ldtr);
    }

    // GDTR/IDTR — same layout but selector/attrib are reserved.
    writeVmcb32(vmcb, Vmcb.GDTR + 4, gs.gdtr_limit);
    writeVmcb64(vmcb, Vmcb.GDTR + 8, gs.gdtr_base);
    writeVmcb32(vmcb, Vmcb.IDTR + 4, gs.idtr_limit);
    writeVmcb64(vmcb, Vmcb.IDTR + 8, gs.idtr_base);

    // CPL is a 1-byte field at VMCB offset 0x4CB. Writing it as a u64 would
    // clobber the EFER field at 0x4D0; write a single byte instead.
    vmcb[Vmcb.CPL] = 0;

    // EFER.SVME (bit 12) must be set in VMCB or VMRUN exits with VMEXIT_INVALID.
    writeVmcb64(vmcb, Vmcb.EFER, gs.efer | EFER_SVME);

    writeVmcb64(vmcb, Vmcb.STAR, gs.star);
    writeVmcb64(vmcb, Vmcb.LSTAR, gs.lstar);
    writeVmcb64(vmcb, Vmcb.CSTAR, gs.cstar);
    writeVmcb64(vmcb, Vmcb.SFMASK, gs.sfmask);
    writeVmcb64(vmcb, Vmcb.KERNEL_GS_BASE, gs.kernel_gs_base);
    writeVmcb64(vmcb, Vmcb.SYSENTER_CS, gs.sysenter_cs);
    writeVmcb64(vmcb, Vmcb.SYSENTER_ESP, gs.sysenter_esp);
    writeVmcb64(vmcb, Vmcb.SYSENTER_EIP, gs.sysenter_eip);

    // PAT: must be a valid PAT value. Zero is invalid (all UC entries with
    // reserved encoding). Use the hardware default if not set.
    const pat_val = if (gs.pat == 0) DEFAULT_PAT else gs.pat;
    writeVmcb64(vmcb, Vmcb.PAT, pat_val);

    writeVmcb64(vmcb, Vmcb.CR2, gs.cr2);
    writeVmcb64(vmcb, Vmcb.DR6, gs.dr6);
    // DR7 bit 10 is reserved-set per x86 spec.
    writeVmcb64(vmcb, Vmcb.DR7, gs.dr7 | 0x400);
}

/// Read guest state from VMCB state save area back into GuestState.
fn readGuestFromVmcb(vmcb: [*]const u8, gs: *GuestState) void {
    gs.rip = readVmcb64(vmcb, Vmcb.RIP);
    gs.rsp = readVmcb64(vmcb, Vmcb.RSP);
    gs.rflags = readVmcb64(vmcb, Vmcb.RFLAGS);
    // RAX already read separately (from VMCB after VMRUN).
    gs.cr0 = readVmcb64(vmcb, Vmcb.CR0);
    gs.cr3 = readVmcb64(vmcb, Vmcb.CR3);
    gs.cr4 = readVmcb64(vmcb, Vmcb.CR4);
    gs.efer = readVmcb64(vmcb, Vmcb.EFER);

    gs.cs = readSegment(vmcb, Vmcb.CS);
    gs.ds = readSegment(vmcb, Vmcb.DS);
    gs.es = readSegment(vmcb, Vmcb.ES);
    gs.fs = readSegment(vmcb, Vmcb.FS);
    gs.gs = readSegment(vmcb, Vmcb.GS);
    gs.ss = readSegment(vmcb, Vmcb.SS);
    gs.tr = readSegment(vmcb, Vmcb.TR);
    gs.ldtr = readSegment(vmcb, Vmcb.LDTR);

    gs.gdtr_limit = readVmcb32(vmcb, Vmcb.GDTR + 4);
    gs.gdtr_base = readVmcb64(vmcb, Vmcb.GDTR + 8);
    gs.idtr_limit = readVmcb32(vmcb, Vmcb.IDTR + 4);
    gs.idtr_base = readVmcb64(vmcb, Vmcb.IDTR + 8);

    gs.star = readVmcb64(vmcb, Vmcb.STAR);
    gs.lstar = readVmcb64(vmcb, Vmcb.LSTAR);
    gs.cstar = readVmcb64(vmcb, Vmcb.CSTAR);
    gs.sfmask = readVmcb64(vmcb, Vmcb.SFMASK);
    gs.kernel_gs_base = readVmcb64(vmcb, Vmcb.KERNEL_GS_BASE);
    gs.sysenter_cs = readVmcb64(vmcb, Vmcb.SYSENTER_CS);
    gs.sysenter_esp = readVmcb64(vmcb, Vmcb.SYSENTER_ESP);
    gs.sysenter_eip = readVmcb64(vmcb, Vmcb.SYSENTER_EIP);
    gs.pat = readVmcb64(vmcb, Vmcb.PAT);
    gs.cr2 = readVmcb64(vmcb, Vmcb.CR2);
    gs.dr6 = readVmcb64(vmcb, Vmcb.DR6);
    gs.dr7 = readVmcb64(vmcb, Vmcb.DR7);
}

/// Decode #VMEXIT reason from VMCB control area.
/// AMD APM Vol 2, Section 15.9: EXITCODE at offset 0x070,
/// EXITINFO1 at 0x078, EXITINFO2 at 0x080.
fn decodeExitReason(vmcb: [*]const u8, guest_state: *const GuestState) VmExitInfo {
    const exitcode = readVmcb64(vmcb, Vmcb.EXITCODE);
    const exitinfo1 = readVmcb64(vmcb, Vmcb.EXITINFO1);
    const exitinfo2 = readVmcb64(vmcb, Vmcb.EXITINFO2);

    if (exitcode == VMEXIT_CPUID) {
        return .{ .cpuid = .{
            .leaf = @truncate(guest_state.rax),
            .subleaf = @truncate(guest_state.rcx),
            .next_rip = readVmcb64(vmcb, Vmcb.NRIP_SAVE),
        } };
    }

    if (exitcode == VMEXIT_IOIO) {
        // AMD APM Vol 2, Section 15.10.2, Figure 15-2: EXITINFO1 format.
        const port: u16 = @truncate(exitinfo1 >> 16);
        const is_write = (exitinfo1 & 1) == 0; // TYPE bit: 0 = OUT, 1 = IN
        var size: u8 = 1;
        if ((exitinfo1 & (1 << 5)) != 0) size = 2;
        if ((exitinfo1 & (1 << 6)) != 0) size = 4;
        return .{ .io = .{
            .port = port,
            .size = size,
            .is_write = is_write,
            .value = @truncate(guest_state.rax),
            .next_rip = exitinfo2,
        } };
    }

    if (exitcode == VMEXIT_HLT) {
        return .hlt;
    }

    if (exitcode == VMEXIT_NPF) {
        return .{ .ept_violation = .{
            .guest_phys = exitinfo2,
            .is_read = (exitinfo1 & 1) == 0,
            .is_write = (exitinfo1 & 2) != 0,
            .is_exec = (exitinfo1 & 4) != 0,
        } };
    }

    if (exitcode == VMEXIT_MSR) {
        const msr_index: u32 = @truncate(guest_state.rcx);
        const msr_value: u64 = (@as(u64, @truncate(guest_state.rdx)) << 32) | @as(u64, @as(u32, @truncate(guest_state.rax)));
        if (exitinfo1 != 0) {
            return .{ .msr_write = .{ .msr = msr_index, .value = msr_value } };
        } else {
            return .{ .msr_read = .{ .msr = msr_index, .value = msr_value } };
        }
    }

    if (exitcode >= VMEXIT_CR0_READ and exitcode < VMEXIT_CR0_READ + 16) {
        const gpr_num: u4 = @truncate(exitinfo1);
        return .{ .cr_access = .{
            .cr_num = @truncate(exitcode - VMEXIT_CR0_READ),
            .is_write = false,
            .gpr = gpr_num,
            .value = readGpr(guest_state, gpr_num),
            .next_rip = readVmcb64(vmcb, Vmcb.NRIP_SAVE),
        } };
    }

    if (exitcode >= VMEXIT_CR0_WRITE and exitcode < VMEXIT_CR0_WRITE + 16) {
        const gpr_num: u4 = @truncate(exitinfo1);
        return .{ .cr_access = .{
            .cr_num = @truncate(exitcode - VMEXIT_CR0_WRITE),
            .is_write = true,
            .gpr = gpr_num,
            .value = readGpr(guest_state, gpr_num),
            .next_rip = readVmcb64(vmcb, Vmcb.NRIP_SAVE),
        } };
    }

    if (exitcode == VMEXIT_SHUTDOWN) {
        return .triple_fault;
    }

    // VMEXIT_INTR: a host IRQ fired while the guest was running. We need
    // to (a) crack the IRQ window so the host IDT services the latched
    // IRQ (otherwise VMRUN re-exits immediately on the same pending
    // IRQ, an infinite loop), AND (b) yield back through fireVmExit so
    // the VMM gets scheduled to drive PIT/serial polling — without that
    // round trip the VMM is starved and Linux's check_timer fails.
    // Reporting as `.unknown` triggers the VMM round trip; the inline
    // `sti; nop; cli` arm in vm_runloop's `.interrupt_window` case is
    // also entered for the same exit code via the Intel side.
    //
    // VMEXIT_VINTR (guest became interruptible) is a different signal:
    // pure interrupt-window, no host IRQ to drain. Stay inline so the
    // next iteration's deliverPendingInterrupts can fire the queued
    // LAPIC vector.
    if (exitcode == VMEXIT_INTR) {
        return .{ .unknown = VMEXIT_INTR };
    }
    if (exitcode == VMEXIT_VINTR) {
        return .{ .interrupt_window = {} };
    }

    if (exitcode == VMEXIT_NMI) {
        return .{ .unknown = VMEXIT_NMI };
    }

    // Exception intercepts are exit codes 0x040-0x05F (EXCP_BASE + vector).
    if (exitcode >= VMEXIT_EXCP_BASE and exitcode < VMEXIT_EXCP_BASE + 0x20) {
        return .{ .exception = .{
            .vector = @truncate(exitcode - VMEXIT_EXCP_BASE),
            .error_code = exitinfo1,
        } };
    }

    if (exitcode == VMEXIT_INVALID) {
        return .{ .unknown = VMEXIT_INVALID };
    }

    return .{ .unknown = exitcode };
}

/// Read a GPR value from GuestState by register number (0=RAX..15=R15).
/// Used to decode CR access exits where EXITINFO1 encodes the GPR number.
fn readGpr(gs: *const GuestState, gpr_num: u4) u64 {
    return switch (gpr_num) {
        0 => gs.rax,
        1 => gs.rcx,
        2 => gs.rdx,
        3 => gs.rbx,
        4 => gs.rsp,
        5 => gs.rbp,
        6 => gs.rsi,
        7 => gs.rdi,
        8 => gs.r8,
        9 => gs.r9,
        10 => gs.r10,
        11 => gs.r11,
        12 => gs.r12,
        13 => gs.r13,
        14 => gs.r14,
        15 => gs.r15,
    };
}

/// Write a segment register to VMCB state save area.
/// AMD APM Vol 2, Appendix B, Table B-2: selector(u16) + attrib(u16) + limit(u32) + base(u64).
fn writeSegment(vmcb: [*]u8, offset: usize, seg: GuestState.SegmentReg) void {
    writeVmcb16(vmcb, offset + 0, seg.selector);
    writeVmcb16(vmcb, offset + 2, seg.access_rights);
    writeVmcb32(vmcb, offset + 4, seg.limit);
    writeVmcb64(vmcb, offset + 8, seg.base);
}

/// Read a segment register from VMCB state save area.
fn readSegment(vmcb: [*]const u8, offset: usize) GuestState.SegmentReg {
    return .{
        .selector = readVmcb16(vmcb, offset + 0),
        .access_rights = readVmcb16(vmcb, offset + 2),
        .limit = readVmcb32(vmcb, offset + 4),
        .base = readVmcb64(vmcb, offset + 8),
    };
}

/// Clear read and write intercept bits for an MSR in the MSRPM.
/// AMD APM Vol 2, Section 15.10: MSRPM format.
/// MSRs 0x0000-0x1FFF: byte offset = (msr * 2) / 8, bit = (msr * 2) % 8.
/// MSRs 0xC0000000-0xC0001FFF: same formula but starting at byte 0x0800.
fn clearMsrpmBits(msrpm: [*]u8, msr: u32) void {
    var base_offset: usize = 0;
    var msr_offset: u32 = msr;
    if (msr >= 0xC0000000 and msr <= 0xC0001FFF) {
        base_offset = 0x0800;
        msr_offset = msr - 0xC0000000;
    } else if (msr > 0x1FFF) {
        return; // MSR not covered by MSRPM ranges we handle
    }
    const bit_pos = @as(usize, msr_offset) * 2;
    const byte_idx = base_offset + bit_pos / 8;
    const bit_idx: u3 = @truncate(bit_pos % 8);
    // Clear both read (bit_idx) and write (bit_idx+1) intercept bits.
    msrpm[byte_idx] &= ~(@as(u8, 0x3) << bit_idx);
}

// VMCB read/write helpers — little-endian memory-mapped access.

fn writeVmcb16(vmcb: [*]u8, offset: usize, value: u16) void {
    const ptr: *align(1) volatile u16 = @ptrCast(vmcb + offset);
    ptr.* = value;
}

fn readVmcb16(vmcb: [*]const u8, offset: usize) u16 {
    const ptr: *align(1) const volatile u16 = @ptrCast(vmcb + offset);
    return ptr.*;
}

fn writeVmcb32(vmcb: [*]u8, offset: usize, value: u32) void {
    const ptr: *align(1) volatile u32 = @ptrCast(vmcb + offset);
    ptr.* = value;
}

fn writeVmcb64(vmcb: [*]u8, offset: usize, value: u64) void {
    const ptr: *align(1) volatile u64 = @ptrCast(vmcb + offset);
    ptr.* = value;
}

fn readVmcb32(vmcb: [*]const u8, offset: usize) u32 {
    const ptr: *align(1) const volatile u32 = @ptrCast(vmcb + offset);
    return ptr.*;
}

fn readVmcb64(vmcb: [*]const u8, offset: usize) u64 {
    const ptr: *align(1) const volatile u64 = @ptrCast(vmcb + offset);
    return ptr.*;
}
