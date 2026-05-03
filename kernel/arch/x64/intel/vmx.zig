/// Intel VT-x (VMX) implementation per the Intel SDM, Vol 3C (Order
/// Number 326019-081US, September 2023).
///
/// Handles VMXON/VMXOFF, VMCS allocation and management, VM entry/exit,
/// and EPT (Extended Page Tables) setup.
const std = @import("std");
const zag = @import("zag");

const cpu = zag.arch.x64.cpu;
const gdt = zag.arch.x64.gdt;
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
// MSR addresses (SDM Vol 3C, Appendix A.1 — VMX Capability Reporting MSRs)
// ---------------------------------------------------------------------------
const IA32_VMX_BASIC: u32 = 0x480;
const IA32_VMX_PINBASED_CTLS: u32 = 0x481;
const IA32_VMX_PROCBASED_CTLS: u32 = 0x482;
const IA32_VMX_EXIT_CTLS: u32 = 0x483;
const IA32_VMX_ENTRY_CTLS: u32 = 0x484;
const IA32_VMX_PROCBASED_CTLS2: u32 = 0x48B;
const IA32_VMX_EPT_VPID_CAP: u32 = 0x48C;
const IA32_VMX_TRUE_PINBASED_CTLS: u32 = 0x48D;
const IA32_VMX_TRUE_PROCBASED_CTLS: u32 = 0x48E;
const IA32_VMX_TRUE_EXIT_CTLS: u32 = 0x48F;
const IA32_VMX_TRUE_ENTRY_CTLS: u32 = 0x490;
const IA32_FEATURE_CONTROL: u32 = 0x3A;
const IA32_EFER: u32 = 0xC0000080;
const IA32_PAT: u32 = 0x277;
const IA32_SYSENTER_CS: u32 = 0x174;
const IA32_SYSENTER_ESP: u32 = 0x175;
const IA32_SYSENTER_EIP: u32 = 0x176;
const IA32_FS_BASE: u32 = 0xC0000100;
const IA32_GS_BASE: u32 = 0xC0000101;

// ---------------------------------------------------------------------------
// VMCS field encodings (SDM Vol 3C, Appendix B; encoding format in
// Table 25-21: bits 14:13 = width, 11:10 = type, 9:1 = index, 0 = access)
// ---------------------------------------------------------------------------

// 16-bit guest state
const GUEST_CS_SELECTOR: u32 = 0x0802;
const GUEST_DS_SELECTOR: u32 = 0x0806;
const GUEST_ES_SELECTOR: u32 = 0x0800;
const GUEST_FS_SELECTOR: u32 = 0x0808;
const GUEST_GS_SELECTOR: u32 = 0x080A;
const GUEST_SS_SELECTOR: u32 = 0x0804;
const GUEST_TR_SELECTOR: u32 = 0x080E;
const GUEST_LDTR_SELECTOR: u32 = 0x080C;

// 16-bit host state
const HOST_CS_SELECTOR: u32 = 0x0C02;
const HOST_DS_SELECTOR: u32 = 0x0C06;
const HOST_ES_SELECTOR: u32 = 0x0C00;
const HOST_FS_SELECTOR: u32 = 0x0C08;
const HOST_GS_SELECTOR: u32 = 0x0C0A;
const HOST_SS_SELECTOR: u32 = 0x0C04;
const HOST_TR_SELECTOR: u32 = 0x0C0C;

// 32-bit control fields
const PIN_BASED_CONTROLS: u32 = 0x4000;
const PRIMARY_PROC_CONTROLS: u32 = 0x4002;
const EXCEPTION_BITMAP: u32 = 0x4004;
const VM_EXIT_CONTROLS: u32 = 0x400C;
const VM_ENTRY_CONTROLS: u32 = 0x4012;
const VM_ENTRY_INTR_INFO: u32 = 0x4016;
const VM_ENTRY_EXCEPTION_ERROR_CODE: u32 = 0x4018;
const VM_ENTRY_INSTRUCTION_LEN: u32 = 0x401A;
const SECONDARY_PROC_CONTROLS: u32 = 0x401E;

// 32-bit guest state
const GUEST_CS_LIMIT: u32 = 0x4802;
const GUEST_DS_LIMIT: u32 = 0x4806;
const GUEST_ES_LIMIT: u32 = 0x4800;
const GUEST_FS_LIMIT: u32 = 0x4808;
const GUEST_GS_LIMIT: u32 = 0x480A;
const GUEST_SS_LIMIT: u32 = 0x4804;
const GUEST_TR_LIMIT: u32 = 0x480E;
const GUEST_LDTR_LIMIT: u32 = 0x480C;
const GUEST_GDTR_LIMIT: u32 = 0x4810;
const GUEST_IDTR_LIMIT: u32 = 0x4812;
const GUEST_CS_ACCESS: u32 = 0x4816;
const GUEST_DS_ACCESS: u32 = 0x481A;
const GUEST_ES_ACCESS: u32 = 0x4814;
const GUEST_FS_ACCESS: u32 = 0x481C;
const GUEST_GS_ACCESS: u32 = 0x481E;
const GUEST_SS_ACCESS: u32 = 0x4818;
const GUEST_TR_ACCESS: u32 = 0x4822;
const GUEST_LDTR_ACCESS: u32 = 0x4820;
const GUEST_INTERRUPTIBILITY: u32 = 0x4824;
const GUEST_ACTIVITY_STATE: u32 = 0x4826;
const GUEST_SYSENTER_CS: u32 = 0x482A;

// 32-bit exit info
const VM_INSTRUCTION_ERROR: u32 = 0x4400;
const EXIT_REASON: u32 = 0x4402;
const EXIT_INTR_INFO: u32 = 0x4404;
const EXIT_INTR_ERROR_CODE: u32 = 0x4406;
const IDT_VECTORING_INFO: u32 = 0x4408;
const VM_EXIT_INSTRUCTION_LEN: u32 = 0x440C;

// 64-bit control fields
const EPT_POINTER: u32 = 0x201A;

// 64-bit exit info
const GUEST_PHYSICAL_ADDR: u32 = 0x2400;

// Natural-width guest state
const GUEST_CR0: u32 = 0x6800;
const GUEST_CR3: u32 = 0x6802;
const GUEST_CR4: u32 = 0x6804;
const GUEST_CS_BASE: u32 = 0x6808;
const GUEST_DS_BASE: u32 = 0x680C;
const GUEST_ES_BASE: u32 = 0x6806;
const GUEST_FS_BASE: u32 = 0x680E;
const GUEST_GS_BASE: u32 = 0x6810;
const GUEST_SS_BASE: u32 = 0x680A;
const GUEST_TR_BASE: u32 = 0x6814;
const GUEST_LDTR_BASE: u32 = 0x6812;
const GUEST_GDTR_BASE: u32 = 0x6816;
const GUEST_IDTR_BASE: u32 = 0x6818;
const GUEST_DR7: u32 = 0x681A;
const GUEST_RSP: u32 = 0x681C;
const GUEST_RIP: u32 = 0x681E;
const GUEST_RFLAGS: u32 = 0x6820;
const GUEST_SYSENTER_ESP: u32 = 0x6824;
const GUEST_SYSENTER_EIP: u32 = 0x6826;

// Natural-width host state
const HOST_CR0: u32 = 0x6C00;
const HOST_CR3: u32 = 0x6C02;
const HOST_CR4: u32 = 0x6C04;
const HOST_FS_BASE: u32 = 0x6C06;
const HOST_GS_BASE: u32 = 0x6C08;
const HOST_TR_BASE: u32 = 0x6C0A;
const HOST_GDTR_BASE: u32 = 0x6C0C;
const HOST_IDTR_BASE: u32 = 0x6C0E;
const HOST_SYSENTER_ESP: u32 = 0x6C10;
const HOST_SYSENTER_EIP: u32 = 0x6C12;
const HOST_RSP: u32 = 0x6C14;
const HOST_RIP: u32 = 0x6C16;

// Natural-width control fields
const CR0_GUEST_HOST_MASK: u32 = 0x6000;
const CR0_READ_SHADOW: u32 = 0x6004;
const CR4_GUEST_HOST_MASK: u32 = 0x6002;
const CR4_READ_SHADOW: u32 = 0x6006;

// Natural-width exit info
const EXIT_QUALIFICATION: u32 = 0x6400;
const GUEST_LINEAR_ADDR: u32 = 0x640A;

// 64-bit guest state
const VMCS_LINK_POINTER: u32 = 0x2800;
const GUEST_EFER: u32 = 0x2806;

// 64-bit host state
const HOST_EFER: u32 = 0x2C02;

// ---------------------------------------------------------------------------
// VM exit reasons (SDM Vol 3C, Appendix C, Table C-1 — Basic Exit Reasons)
// ---------------------------------------------------------------------------
const EXIT_REASON_EXCEPTION_NMI: u16 = 0;
const EXIT_REASON_EXTERNAL_INT: u16 = 1;
const EXIT_REASON_TRIPLE_FAULT: u16 = 2;
const EXIT_REASON_CPUID: u16 = 10;
const EXIT_REASON_HLT: u16 = 12;
const EXIT_REASON_INVLPG: u16 = 14;
const EXIT_REASON_RDTSC: u16 = 16;
const EXIT_REASON_VMCALL: u16 = 18;
const EXIT_REASON_CR_ACCESS: u16 = 28;
const EXIT_REASON_IO: u16 = 30;
const EXIT_REASON_MSR_READ: u16 = 31;
const EXIT_REASON_MSR_WRITE: u16 = 32;
const EXIT_REASON_INVALID_GUEST: u16 = 33;
const EXIT_REASON_EPT_VIOLATION: u16 = 48;
const EXIT_REASON_EPT_MISCONFIG: u16 = 49;
const EXIT_REASON_INVEPT: u16 = 50;
const EXIT_REASON_RDTSCP: u16 = 51;
const EXIT_REASON_PREEMPT_TIMER: u16 = 52;
const EXIT_REASON_INVVPID: u16 = 53;
const EXIT_REASON_XSETBV: u16 = 55;

// ---------------------------------------------------------------------------
// Pin-based VM-execution controls (SDM Vol 3C, Table 25-5)
// ---------------------------------------------------------------------------
const PIN_EXTERNAL_INT_EXIT: u32 = 1 << 0;
const PIN_NMI_EXIT: u32 = 1 << 3;
const PIN_VIRTUAL_NMI: u32 = 1 << 5;
const PIN_PREEMPTION_TIMER: u32 = 1 << 6;

// ---------------------------------------------------------------------------
// Primary processor-based VM-execution controls (SDM Vol 3C, Table 25-6)
// ---------------------------------------------------------------------------
const PROC_INTERRUPT_WINDOW_EXIT: u32 = 1 << 2;
const PROC_USE_TSC_OFFSETTING: u32 = 1 << 3;
const PROC_HLT_EXIT: u32 = 1 << 7;
const PROC_INVLPG_EXIT: u32 = 1 << 9;
const PROC_MWAIT_EXIT: u32 = 1 << 10;
const PROC_RDPMC_EXIT: u32 = 1 << 11;
const PROC_RDTSC_EXIT: u32 = 1 << 12;
const PROC_CR3_LOAD_EXIT: u32 = 1 << 15;
const PROC_CR3_STORE_EXIT: u32 = 1 << 16;
const PROC_CR8_LOAD_EXIT: u32 = 1 << 19;
const PROC_CR8_STORE_EXIT: u32 = 1 << 20;
const PROC_USE_TPR_SHADOW: u32 = 1 << 21;
const PROC_NMI_WINDOW_EXIT: u32 = 1 << 22;
const PROC_MOV_DR_EXIT: u32 = 1 << 23;
const PROC_UNCONDITIONAL_IO_EXIT: u32 = 1 << 24;
const PROC_USE_IO_BITMAPS: u32 = 1 << 25;
const PROC_USE_MSR_BITMAPS: u32 = 1 << 28;
const PROC_MONITOR_EXIT: u32 = 1 << 29;
const PROC_PAUSE_EXIT: u32 = 1 << 30;
const PROC_ACTIVATE_SECONDARY: u32 = 1 << 31;

// ---------------------------------------------------------------------------
// Secondary processor-based VM-execution controls (SDM Vol 3C, Table 25-7)
// ---------------------------------------------------------------------------
const PROC2_VIRTUALIZE_APIC: u32 = 1 << 0;
const PROC2_ENABLE_EPT: u32 = 1 << 1;
const PROC2_DESCRIPTOR_TABLE_EXIT: u32 = 1 << 2;
const PROC2_ENABLE_RDTSCP: u32 = 1 << 3;
const PROC2_VIRTUALIZE_X2APIC: u32 = 1 << 4;
const PROC2_ENABLE_VPID: u32 = 1 << 5;
const PROC2_WBINVD_EXIT: u32 = 1 << 6;
const PROC2_UNRESTRICTED_GUEST: u32 = 1 << 7;
const PROC2_APIC_REGISTER_VIRT: u32 = 1 << 8;
const PROC2_VIRTUAL_INTERRUPT_DELIVERY: u32 = 1 << 9;
const PROC2_ENABLE_INVPCID: u32 = 1 << 12;
const PROC2_ENABLE_XSAVES: u32 = 1 << 20;

// ---------------------------------------------------------------------------
// VM-exit controls (SDM Vol 3C, Table 25-13)
// ---------------------------------------------------------------------------
const EXIT_SAVE_DEBUG_CTLS: u32 = 1 << 2;
const EXIT_HOST_ADDR_SPACE_SIZE: u32 = 1 << 9;
const EXIT_LOAD_PERF_GLOBAL_CTRL: u32 = 1 << 12;
const EXIT_ACK_INTERRUPT_ON_EXIT: u32 = 1 << 15;
const EXIT_SAVE_PAT: u32 = 1 << 18;
const EXIT_LOAD_PAT: u32 = 1 << 19;
const EXIT_SAVE_EFER: u32 = 1 << 20;
const EXIT_LOAD_EFER: u32 = 1 << 21;

// ---------------------------------------------------------------------------
// VM-entry controls (SDM Vol 3C, Table 25-15)
// ---------------------------------------------------------------------------
const ENTRY_LOAD_DEBUG_CTLS: u32 = 1 << 2;
const ENTRY_IA32E_GUEST: u32 = 1 << 9;
const ENTRY_LOAD_PAT: u32 = 1 << 14;
const ENTRY_LOAD_EFER: u32 = 1 << 15;

// ---------------------------------------------------------------------------
// EPT constants (SDM Vol 3C, Section 29.3.2, Tables 29-1 through 29-7)
// ---------------------------------------------------------------------------
const EPT_READ: u64 = 1 << 0;
const EPT_WRITE: u64 = 1 << 1;
const EPT_EXECUTE: u64 = 1 << 2;
const EPT_MEM_TYPE_WB: u64 = 6 << 3; // for leaf entries: memory type in bits 5:3
const EPT_IGNORE_PAT: u64 = 1 << 6;

// EPT pointer format (SDM Vol 3C, Table 25-9): bits 2:0 = memory type, bits 5:3 = walk length - 1
const EPTP_MEM_TYPE_WB: u64 = 6;
const EPTP_WALK_LENGTH_4: u64 = 3 << 3;

// Page table index shift amounts
const EPT_L4SH: u6 = 39;
const EPT_L3SH: u6 = 30;
const EPT_L2SH: u6 = 21;
const EPT_L1SH: u6 = 12;
const EPT_INDEX_MASK: u64 = 0x1FF;
const EPT_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// ---------------------------------------------------------------------------
// Module state
// ---------------------------------------------------------------------------

/// VMX revision ID read from IA32_VMX_BASIC MSR.
var vmx_revision_id: u32 = 0;

/// Whether VMX is available on this CPU.
var vmx_available: bool = false;

/// Whether IA32_VMX_BASIC bit 55 is set (use TRUE controls MSRs).
var use_true_ctls: bool = false;

/// Per-core VMXON region physical addresses.
const MAX_CORES = 64;
var vmxon_regions: [MAX_CORES]PAddr = [_]PAddr{PAddr.fromInt(0)} ** MAX_CORES;

// ---------------------------------------------------------------------------
// Low-level VMCS read/write
// ---------------------------------------------------------------------------

fn vmcsRead(field: u32) u64 {
    var value: u64 = 0;
    var success: u8 = 0;
    asm volatile (
        \\vmread %[field], %[value]
        \\seta %[success]
        : [value] "=r" (value),
          [success] "=r" (success),
        : [field] "r" (@as(u64, field)),
    );
    return value;
}

fn vmcsWrite(field: u32, value: u64) void {
    asm volatile (
        \\vmwrite %[value], %[field]
        :
        : [field] "r" (@as(u64, field)),
          [value] "r" (value),
    );
}

// ---------------------------------------------------------------------------
// Control field adjustment
// ---------------------------------------------------------------------------

/// Adjust a VM-execution control value per the allowed-0 and allowed-1 MSR
/// (SDM Vol 3C, Appendix A.3.1). Low 32 bits = must-be-1, high 32 bits =
/// allowed-to-be-1.
fn adjustControls(desired: u32, msr: u32) u32 {
    const msr_val = cpu.rdmsr(msr);
    const must_be_one: u32 = @truncate(msr_val);
    const may_be_one: u32 = @truncate(msr_val >> 32);
    return (desired | must_be_one) & may_be_one;
}

// ---------------------------------------------------------------------------
// Page allocation helpers
// ---------------------------------------------------------------------------

fn allocPage() ?*paging.PageMem(.page4k) {
    const pmm_mgr = &pmm.global_pmm.?;
    return pmm_mgr.create(paging.PageMem(.page4k)) catch null;
}

fn freePage(page: *paging.PageMem(.page4k)) void {
    const pmm_mgr = &pmm.global_pmm.?;
    pmm_mgr.destroy(page);
}

fn pageToPhys(page: *paging.PageMem(.page4k)) PAddr {
    return PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
}

// ---------------------------------------------------------------------------
// Global VMX initialization
// ---------------------------------------------------------------------------

/// Global VMX initialization (SDM Vol 3C, Section 24.6 "Discovering Support
/// for VMX"). Detects VT-x support via CPUID.1:ECX[bit 5] and reads the
/// VMX revision ID and TRUE controls flag from IA32_VMX_BASIC (Appendix A.1).
/// Returns true if VMX is available.
pub fn init() bool {
    const features = cpu.cpuid(.basic_features, 0);
    // ECX bit 5 = VMX
    if (features.ecx & (1 << 5) == 0) return false;

    // Read VMX revision ID from IA32_VMX_BASIC
    const vmx_basic = cpu.rdmsr(IA32_VMX_BASIC);
    vmx_revision_id = @truncate(vmx_basic & 0x7FFF_FFFF);

    // Bit 55: if set, use TRUE control MSRs for default1 settings
    use_true_ctls = (vmx_basic & (1 << 55)) != 0;

    vmx_available = true;
    return true;
}

/// Per-core VMX initialization (SDM Vol 3C, Section 24.7 "Enabling and
/// Entering VMX Operation"). Locks IA32_FEATURE_CONTROL with VMX-outside-SMX
/// enabled, sets CR4.VMXE[bit 13], allocates the VMXON region with the
/// revision ID in the first 4 bytes, and executes VMXON.
pub fn perCoreInit() void {
    if (!vmx_available) return;

    // Ensure IA32_FEATURE_CONTROL is locked with VMX-outside-SMX enabled.
    var feature_ctl = cpu.rdmsr(IA32_FEATURE_CONTROL);
    const LOCK_BIT: u64 = 1 << 0;
    const VMX_OUTSIDE_SMX: u64 = 1 << 2;
    if (feature_ctl & LOCK_BIT == 0) {
        feature_ctl |= VMX_OUTSIDE_SMX | LOCK_BIT;
        cpu.wrmsr(IA32_FEATURE_CONTROL, feature_ctl);
    } else if (feature_ctl & VMX_OUTSIDE_SMX == 0) {
        // Locked without VMX — cannot enable.
        return;
    }

    // Set CR4.VMXE (bit 13)
    var cr4: u64 = 0;
    asm volatile ("mov %%cr4, %[out]"
        : [out] "=r" (cr4),
    );
    cr4 |= (1 << 13);
    asm volatile ("mov %[val], %%cr4"
        :
        : [val] "r" (cr4),
    );

    // Allocate VMXON region (4KB aligned, zeroed).
    const page = allocPage() orelse return;
    @memset(&page.mem, 0);

    // Write revision ID into first 4 bytes (SDM Vol 3C, Table 25-1).
    const rev_ptr: *u32 = @ptrCast(@alignCast(&page.mem));
    rev_ptr.* = vmx_revision_id;

    const phys = pageToPhys(page);
    const core_id = zag.arch.x64.apic.coreID();
    vmxon_regions[core_id] = phys;

    asm volatile (
        \\vmxon (%[addr])
        :
        : [addr] "r" (&phys.addr),
        : .{ .memory = true, .cc = true });
}

// ---------------------------------------------------------------------------
// VMCS and EPT allocation
// ---------------------------------------------------------------------------

/// Layout of what allocVmStructures returns:
/// The returned PAddr points to a 4KB page that holds the VMCS.
/// We store the EPT root PAddr in a separate per-VMCS tracking structure.
/// For simplicity, we use the VMCS page itself — the EPT root physical
/// address is stored at offset 4092 (last 8 bytes won't overlap VMCS data
/// since Intel limits VMCS to at most 4KB and the writeable region is smaller).
///
/// Actually, we allocate TWO pages: one for the VMCS, one for the EPT PML4.
/// We pack the EPT root PAddr into the VMCS region at a known offset after
/// VMCLEAR. Instead, we use a simpler approach: the VMCS is one page, the
/// EPT root is another. We store the EPT root phys into VMCS field (EPTP)
/// during initVmcs. The caller only needs the VMCS PAddr.
///
/// The EPT PML4 page phys gets written into the EPTP VMCS field during
/// initVmcs. We keep a small side-table mapping VMCS PAddr -> EPT root PAddr
/// so that mapEptPage/unmapEptPage can find the EPT root.
///
/// Revised approach: vm.zig passes vm_structures (a PAddr) to both vmResume
/// and mapEptPage. Looking at the dispatch, mapGuestPage receives
/// vm_structures. So vm_structures IS the EPT root, not the VMCS.
///
/// But vmResume also receives vm_structures as vmcs_paddr. Looking at
/// vcpu.zig line 262: both vmResume and mapGuestPage use vm_obj.arch_structures.
/// So arch_structures is ONE PAddr used for everything.
///
/// Solution: allocate a "VM control block" — a page containing:
///   bytes 0..3: VMCS revision ID (this IS the VMCS)
///   The EPT root is a separate allocation whose phys addr we store in the
///   VMCS EPTP field during init.
///
/// Simplest correct approach: arch_structures = VMCS PAddr. The EPT root
/// PAddr is written into the VMCS EPTP field. mapEptPage needs the EPT root.
/// Since mapEptPage receives arch_structures (= VMCS PAddr), we need to
/// VMPTRLD the VMCS, read the EPTP field, extract the EPT root PAddr.
/// This is clean and avoids side tables.
/// Allocate and initialize a VMCS and EPT root for a new VM (SDM Vol 3C,
/// Section 25.2 "Format of the VMCS Region", Table 25-1; Section 25.11.3
/// for VMCLEAR/VMPTRLD lifecycle). The VMCS revision ID is written into
/// the first 4 bytes per Table 25-1.
/// Returns the physical address of the VMCS, or null on failure.
/// Allocate and zero a single 4K page to serve as the EPT PML4 root.
/// Spec-v3 split: caller (`arch.x64.hv.vm.allocStage2Root`) holds this
/// PAddr in `VirtualMachine.guest_pt_root` and feeds it into
/// `allocVmcsWithEpt` when the per-VM control state is allocated.
pub fn allocEptRoot() ?PAddr {
    const ept_page = allocPage() orelse return null;
    @memset(&ept_page.mem, 0);
    return pageToPhys(ept_page);
}

/// Free an EPT PML4 page allocated by `allocEptRoot`. Caller has
/// already torn down any intermediate tables (TODO: stage-2 mapping
/// teardown lives elsewhere).
pub fn freeEptRoot(paddr: PAddr) void {
    const virt = VAddr.fromPAddr(paddr, null);
    const page: *paging.PageMem(.page4k) = @ptrFromInt(virt.addr);
    freePage(page);
}

/// Allocate a VMCS page initialized against a pre-allocated EPT root.
/// Mirrors the VMCLEAR + VMPTRLD + `initVmcs` sequence from the legacy
/// `allocVmStructures` so callers (spec-v3 `allocVmArchState`) can keep
/// the EPT root and per-VM control state in distinct dispatch slots.
pub fn allocVmcsWithEpt(ept_root_phys: PAddr) ?PAddr {
    const vmcs_page = allocPage() orelse return null;
    @memset(&vmcs_page.mem, 0);

    const rev_ptr: *u32 = @ptrCast(@alignCast(&vmcs_page.mem));
    rev_ptr.* = vmx_revision_id;

    const vmcs_phys = pageToPhys(vmcs_page);

    asm volatile (
        \\vmclear (%[addr])
        :
        : [addr] "r" (&vmcs_phys.addr),
        : .{ .memory = true, .cc = true });

    asm volatile (
        \\vmptrld (%[addr])
        :
        : [addr] "r" (&vmcs_phys.addr),
        : .{ .memory = true, .cc = true });

    initVmcs(ept_root_phys);

    return vmcs_phys;
}

/// Free a VMCS and associated EPT structures.
pub fn freeVmStructures(paddr: PAddr) void {
    // VMCLEAR to flush any cached VMCS data
    asm volatile (
        \\vmclear (%[addr])
        :
        : [addr] "r" (&paddr.addr),
        : .{ .memory = true, .cc = true });

    // Read back the EPT root from the VMCS before freeing
    // (We'd need to VMPTRLD first, but the VMCS is being freed so
    // we skip EPT teardown for now — the pages will be reclaimed
    // when the owning process is destroyed.)

    const vmcs_virt = VAddr.fromPAddr(paddr, null);
    const vmcs_page: *paging.PageMem(.page4k) = @ptrFromInt(vmcs_virt.addr);
    freePage(vmcs_page);
}

// ---------------------------------------------------------------------------
// VMCS initialization
// ---------------------------------------------------------------------------

fn initVmcs(ept_root_phys: PAddr) void {
    // -- Host state --
    // Host CR0/CR3/CR4
    var host_cr0: u64 = 0;
    asm volatile ("mov %%cr0, %[out]"
        : [out] "=r" (host_cr0),
    );
    vmcsWrite(HOST_CR0, host_cr0);
    vmcsWrite(HOST_CR3, cpu.readCr3());
    var host_cr4: u64 = 0;
    asm volatile ("mov %%cr4, %[out]"
        : [out] "=r" (host_cr4),
    );
    vmcsWrite(HOST_CR4, host_cr4);

    // Host segment selectors (RPL=0 required)
    vmcsWrite(HOST_CS_SELECTOR, gdt.KERNEL_CODE_OFFSET);
    vmcsWrite(HOST_SS_SELECTOR, gdt.KERNEL_DATA_OFFSET);
    vmcsWrite(HOST_DS_SELECTOR, gdt.KERNEL_DATA_OFFSET);
    vmcsWrite(HOST_ES_SELECTOR, gdt.KERNEL_DATA_OFFSET);
    vmcsWrite(HOST_FS_SELECTOR, 0);
    vmcsWrite(HOST_GS_SELECTOR, 0);
    vmcsWrite(HOST_TR_SELECTOR, gdt.TSS_OFFSET);

    // Host FS/GS base
    vmcsWrite(HOST_FS_BASE, cpu.rdmsr(IA32_FS_BASE));
    vmcsWrite(HOST_GS_BASE, cpu.rdmsr(IA32_GS_BASE));

    // Host TR base — read from the GDT TSS descriptor
    const core_id = zag.arch.x64.apic.coreID();
    vmcsWrite(HOST_TR_BASE, @intFromPtr(gdt.coreTss(core_id)));

    // Host GDTR/IDTR base — read via SGDT/SIDT
    var gdtr_buf: [10]u8 align(8) = undefined;
    asm volatile ("sgdt (%[buf])"
        :
        : [buf] "r" (&gdtr_buf),
        : .{ .memory = true });
    const gdtr_base = std.mem.readInt(u64, gdtr_buf[2..10], .little);
    vmcsWrite(HOST_GDTR_BASE, gdtr_base);

    var idtr_buf: [10]u8 align(8) = undefined;
    asm volatile ("sidt (%[buf])"
        :
        : [buf] "r" (&idtr_buf),
        : .{ .memory = true });
    const idtr_base = std.mem.readInt(u64, idtr_buf[2..10], .little);
    vmcsWrite(HOST_IDTR_BASE, idtr_base);

    // Host SYSENTER MSRs
    vmcsWrite(HOST_SYSENTER_ESP, cpu.rdmsr(IA32_SYSENTER_ESP));
    vmcsWrite(HOST_SYSENTER_EIP, cpu.rdmsr(IA32_SYSENTER_EIP));

    // Host RIP = address of our VM exit handler entry point (set in vmResume)
    // Host RSP = set per-entry in vmResume

    // Host EFER
    vmcsWrite(HOST_EFER, cpu.rdmsr(IA32_EFER));

    // -- VM-execution controls --
    const pin_msr = if (use_true_ctls) IA32_VMX_TRUE_PINBASED_CTLS else IA32_VMX_PINBASED_CTLS;
    const pin_desired: u32 = PIN_EXTERNAL_INT_EXIT | PIN_NMI_EXIT;
    vmcsWrite(PIN_BASED_CONTROLS, adjustControls(pin_desired, pin_msr));

    const proc_msr = if (use_true_ctls) IA32_VMX_TRUE_PROCBASED_CTLS else IA32_VMX_PROCBASED_CTLS;
    const proc_desired: u32 = PROC_HLT_EXIT |
        PROC_UNCONDITIONAL_IO_EXIT |
        PROC_ACTIVATE_SECONDARY;
    vmcsWrite(PRIMARY_PROC_CONTROLS, adjustControls(proc_desired, proc_msr));

    const proc2_desired: u32 = PROC2_ENABLE_EPT |
        PROC2_UNRESTRICTED_GUEST |
        PROC2_ENABLE_RDTSCP |
        PROC2_ENABLE_INVPCID |
        PROC2_ENABLE_XSAVES;
    vmcsWrite(SECONDARY_PROC_CONTROLS, adjustControls(proc2_desired, IA32_VMX_PROCBASED_CTLS2));

    const exit_msr = if (use_true_ctls) IA32_VMX_TRUE_EXIT_CTLS else IA32_VMX_EXIT_CTLS;
    const exit_desired: u32 = EXIT_HOST_ADDR_SPACE_SIZE |
        EXIT_SAVE_EFER |
        EXIT_LOAD_EFER |
        EXIT_ACK_INTERRUPT_ON_EXIT;
    vmcsWrite(VM_EXIT_CONTROLS, adjustControls(exit_desired, exit_msr));

    const entry_msr = if (use_true_ctls) IA32_VMX_TRUE_ENTRY_CTLS else IA32_VMX_ENTRY_CTLS;
    const entry_desired: u32 = ENTRY_LOAD_EFER;
    vmcsWrite(VM_ENTRY_CONTROLS, adjustControls(entry_desired, entry_msr));

    // Exception bitmap — intercept nothing by default (let guest handle all)
    vmcsWrite(EXCEPTION_BITMAP, 0);

    // CR0/CR4 guest/host masks — let guest control all bits
    vmcsWrite(CR0_GUEST_HOST_MASK, 0);
    vmcsWrite(CR0_READ_SHADOW, 0);
    vmcsWrite(CR4_GUEST_HOST_MASK, 0);
    vmcsWrite(CR4_READ_SHADOW, 0);

    // VMCS link pointer — required, set to -1 (no linked VMCS)
    vmcsWrite(VMCS_LINK_POINTER, 0xFFFF_FFFF_FFFF_FFFF);

    // -- EPT pointer --
    // Format: bits 2:0 = memory type (6=WB), bits 5:3 = page-walk length - 1 (3),
    // bits 63:12 = PML4 physical address
    const eptp = (ept_root_phys.addr & EPT_ADDR_MASK) | EPTP_MEM_TYPE_WB | EPTP_WALK_LENGTH_4;
    vmcsWrite(EPT_POINTER, eptp);

    // -- Guest state defaults (will be overwritten from GuestState before each entry) --
    // Set minimal valid guest state so VMCS passes consistency checks
    vmcsWrite(GUEST_CR0, 0x0000_0000_0000_0021); // PE + NE
    vmcsWrite(GUEST_CR3, 0);
    vmcsWrite(GUEST_CR4, 0x0000_0000_0000_2000); // VMXE (required in guest)
    vmcsWrite(GUEST_DR7, 0x0000_0000_0000_0400);
    vmcsWrite(GUEST_RSP, 0);
    vmcsWrite(GUEST_RIP, 0);
    vmcsWrite(GUEST_RFLAGS, 0x2); // bit 1 always set

    // Segment registers — flat protected mode defaults
    vmcsWrite(GUEST_CS_SELECTOR, 0);
    vmcsWrite(GUEST_CS_BASE, 0);
    vmcsWrite(GUEST_CS_LIMIT, 0xFFFF_FFFF);
    vmcsWrite(GUEST_CS_ACCESS, 0x209B); // present, code, read, accessed, long mode
    vmcsWrite(GUEST_DS_SELECTOR, 0);
    vmcsWrite(GUEST_DS_BASE, 0);
    vmcsWrite(GUEST_DS_LIMIT, 0xFFFF_FFFF);
    vmcsWrite(GUEST_DS_ACCESS, 0x4093); // present, data, write, accessed, 32-bit
    vmcsWrite(GUEST_ES_SELECTOR, 0);
    vmcsWrite(GUEST_ES_BASE, 0);
    vmcsWrite(GUEST_ES_LIMIT, 0xFFFF_FFFF);
    vmcsWrite(GUEST_ES_ACCESS, 0x4093);
    vmcsWrite(GUEST_FS_SELECTOR, 0);
    vmcsWrite(GUEST_FS_BASE, 0);
    vmcsWrite(GUEST_FS_LIMIT, 0xFFFF_FFFF);
    vmcsWrite(GUEST_FS_ACCESS, 0x4093);
    vmcsWrite(GUEST_GS_SELECTOR, 0);
    vmcsWrite(GUEST_GS_BASE, 0);
    vmcsWrite(GUEST_GS_LIMIT, 0xFFFF_FFFF);
    vmcsWrite(GUEST_GS_ACCESS, 0x4093);
    vmcsWrite(GUEST_SS_SELECTOR, 0);
    vmcsWrite(GUEST_SS_BASE, 0);
    vmcsWrite(GUEST_SS_LIMIT, 0xFFFF_FFFF);
    vmcsWrite(GUEST_SS_ACCESS, 0x4093);
    vmcsWrite(GUEST_TR_SELECTOR, 0);
    vmcsWrite(GUEST_TR_BASE, 0);
    vmcsWrite(GUEST_TR_LIMIT, 0x67);
    vmcsWrite(GUEST_TR_ACCESS, 0x8B); // present, 64-bit TSS busy
    vmcsWrite(GUEST_LDTR_SELECTOR, 0);
    vmcsWrite(GUEST_LDTR_BASE, 0);
    vmcsWrite(GUEST_LDTR_LIMIT, 0);
    vmcsWrite(GUEST_LDTR_ACCESS, 0x10082); // present, LDT, unusable

    // Guest GDTR/IDTR
    vmcsWrite(GUEST_GDTR_BASE, 0);
    vmcsWrite(GUEST_GDTR_LIMIT, 0);
    vmcsWrite(GUEST_IDTR_BASE, 0);
    vmcsWrite(GUEST_IDTR_LIMIT, 0);

    // Guest interruptibility / activity state
    vmcsWrite(GUEST_INTERRUPTIBILITY, 0);
    vmcsWrite(GUEST_ACTIVITY_STATE, 0);

    // Guest SYSENTER
    vmcsWrite(GUEST_SYSENTER_CS, 0);
    vmcsWrite(GUEST_SYSENTER_ESP, 0);
    vmcsWrite(GUEST_SYSENTER_EIP, 0);

    // Guest EFER
    vmcsWrite(GUEST_EFER, 0);
}

// ---------------------------------------------------------------------------
// VM entry and exit
// ---------------------------------------------------------------------------

/// Write guest register state from GuestState into the active VMCS.
fn writeGuestState(gs: *const GuestState) void {
    vmcsWrite(GUEST_RIP, gs.rip);
    vmcsWrite(GUEST_RSP, gs.rsp);
    vmcsWrite(GUEST_RFLAGS, gs.rflags);
    vmcsWrite(GUEST_CR0, gs.cr0);
    vmcsWrite(GUEST_CR3, gs.cr3);
    vmcsWrite(GUEST_CR4, gs.cr4);

    // Segments
    vmcsWrite(GUEST_CS_SELECTOR, gs.cs.selector);
    vmcsWrite(GUEST_CS_BASE, gs.cs.base);
    vmcsWrite(GUEST_CS_LIMIT, gs.cs.limit);
    vmcsWrite(GUEST_CS_ACCESS, gs.cs.access_rights);
    vmcsWrite(GUEST_DS_SELECTOR, gs.ds.selector);
    vmcsWrite(GUEST_DS_BASE, gs.ds.base);
    vmcsWrite(GUEST_DS_LIMIT, gs.ds.limit);
    vmcsWrite(GUEST_DS_ACCESS, gs.ds.access_rights);
    vmcsWrite(GUEST_ES_SELECTOR, gs.es.selector);
    vmcsWrite(GUEST_ES_BASE, gs.es.base);
    vmcsWrite(GUEST_ES_LIMIT, gs.es.limit);
    vmcsWrite(GUEST_ES_ACCESS, gs.es.access_rights);
    vmcsWrite(GUEST_FS_SELECTOR, gs.fs.selector);
    vmcsWrite(GUEST_FS_BASE, gs.fs.base);
    vmcsWrite(GUEST_FS_LIMIT, gs.fs.limit);
    vmcsWrite(GUEST_FS_ACCESS, gs.fs.access_rights);
    vmcsWrite(GUEST_GS_SELECTOR, gs.gs.selector);
    vmcsWrite(GUEST_GS_BASE, gs.gs.base);
    vmcsWrite(GUEST_GS_LIMIT, gs.gs.limit);
    vmcsWrite(GUEST_GS_ACCESS, gs.gs.access_rights);
    vmcsWrite(GUEST_SS_SELECTOR, gs.ss.selector);
    vmcsWrite(GUEST_SS_BASE, gs.ss.base);
    vmcsWrite(GUEST_SS_LIMIT, gs.ss.limit);
    vmcsWrite(GUEST_SS_ACCESS, gs.ss.access_rights);
    vmcsWrite(GUEST_TR_SELECTOR, gs.tr.selector);
    vmcsWrite(GUEST_TR_BASE, gs.tr.base);
    vmcsWrite(GUEST_TR_LIMIT, gs.tr.limit);
    vmcsWrite(GUEST_TR_ACCESS, gs.tr.access_rights);
    vmcsWrite(GUEST_LDTR_SELECTOR, gs.ldtr.selector);
    vmcsWrite(GUEST_LDTR_BASE, gs.ldtr.base);
    vmcsWrite(GUEST_LDTR_LIMIT, gs.ldtr.limit);
    vmcsWrite(GUEST_LDTR_ACCESS, gs.ldtr.access_rights);

    // Descriptor tables
    vmcsWrite(GUEST_GDTR_BASE, gs.gdtr_base);
    vmcsWrite(GUEST_GDTR_LIMIT, gs.gdtr_limit);
    vmcsWrite(GUEST_IDTR_BASE, gs.idtr_base);
    vmcsWrite(GUEST_IDTR_LIMIT, gs.idtr_limit);

    // MSRs
    vmcsWrite(GUEST_EFER, gs.efer);
    vmcsWrite(GUEST_SYSENTER_CS, gs.sysenter_cs);
    vmcsWrite(GUEST_SYSENTER_ESP, gs.sysenter_esp);
    vmcsWrite(GUEST_SYSENTER_EIP, gs.sysenter_eip);
}

/// Read guest register state from the active VMCS back into GuestState.
fn readGuestState(gs: *GuestState) void {
    gs.rip = vmcsRead(GUEST_RIP);
    gs.rsp = vmcsRead(GUEST_RSP);
    gs.rflags = vmcsRead(GUEST_RFLAGS);
    gs.cr0 = vmcsRead(GUEST_CR0);
    gs.cr3 = vmcsRead(GUEST_CR3);
    gs.cr4 = vmcsRead(GUEST_CR4);

    // Segments
    gs.cs.selector = @truncate(vmcsRead(GUEST_CS_SELECTOR));
    gs.cs.base = vmcsRead(GUEST_CS_BASE);
    gs.cs.limit = @truncate(vmcsRead(GUEST_CS_LIMIT));
    gs.cs.access_rights = @truncate(vmcsRead(GUEST_CS_ACCESS));
    gs.ds.selector = @truncate(vmcsRead(GUEST_DS_SELECTOR));
    gs.ds.base = vmcsRead(GUEST_DS_BASE);
    gs.ds.limit = @truncate(vmcsRead(GUEST_DS_LIMIT));
    gs.ds.access_rights = @truncate(vmcsRead(GUEST_DS_ACCESS));
    gs.es.selector = @truncate(vmcsRead(GUEST_ES_SELECTOR));
    gs.es.base = vmcsRead(GUEST_ES_BASE);
    gs.es.limit = @truncate(vmcsRead(GUEST_ES_LIMIT));
    gs.es.access_rights = @truncate(vmcsRead(GUEST_ES_ACCESS));
    gs.fs.selector = @truncate(vmcsRead(GUEST_FS_SELECTOR));
    gs.fs.base = vmcsRead(GUEST_FS_BASE);
    gs.fs.limit = @truncate(vmcsRead(GUEST_FS_LIMIT));
    gs.fs.access_rights = @truncate(vmcsRead(GUEST_FS_ACCESS));
    gs.gs.selector = @truncate(vmcsRead(GUEST_GS_SELECTOR));
    gs.gs.base = vmcsRead(GUEST_GS_BASE);
    gs.gs.limit = @truncate(vmcsRead(GUEST_GS_LIMIT));
    gs.gs.access_rights = @truncate(vmcsRead(GUEST_GS_ACCESS));
    gs.ss.selector = @truncate(vmcsRead(GUEST_SS_SELECTOR));
    gs.ss.base = vmcsRead(GUEST_SS_BASE);
    gs.ss.limit = @truncate(vmcsRead(GUEST_SS_LIMIT));
    gs.ss.access_rights = @truncate(vmcsRead(GUEST_SS_ACCESS));
    gs.tr.selector = @truncate(vmcsRead(GUEST_TR_SELECTOR));
    gs.tr.base = vmcsRead(GUEST_TR_BASE);
    gs.tr.limit = @truncate(vmcsRead(GUEST_TR_LIMIT));
    gs.tr.access_rights = @truncate(vmcsRead(GUEST_TR_ACCESS));
    gs.ldtr.selector = @truncate(vmcsRead(GUEST_LDTR_SELECTOR));
    gs.ldtr.base = vmcsRead(GUEST_LDTR_BASE);
    gs.ldtr.limit = @truncate(vmcsRead(GUEST_LDTR_LIMIT));
    gs.ldtr.access_rights = @truncate(vmcsRead(GUEST_LDTR_ACCESS));

    // Descriptor tables
    gs.gdtr_base = vmcsRead(GUEST_GDTR_BASE);
    gs.gdtr_limit = @truncate(vmcsRead(GUEST_GDTR_LIMIT));
    gs.idtr_base = vmcsRead(GUEST_IDTR_BASE);
    gs.idtr_limit = @truncate(vmcsRead(GUEST_IDTR_LIMIT));

    // MSRs
    gs.efer = vmcsRead(GUEST_EFER);
    gs.sysenter_cs = vmcsRead(GUEST_SYSENTER_CS);
    gs.sysenter_esp = vmcsRead(GUEST_SYSENTER_ESP);
    gs.sysenter_eip = vmcsRead(GUEST_SYSENTER_EIP);
}

/// Enter the guest via VMLAUNCH/VMRESUME (SDM Vol 3C, Section 27.2-27.4
/// for VM-entry checks and loading guest state; Section 31.3 for the
/// VMLAUNCH/VMRESUME instruction semantics). Returns exit info on VM exit.
///
/// The assembly sequence:
///   1. VMPTRLD the VMCS
///   2. Write guest VMCS state from GuestState
///   3. Write HOST_RSP and HOST_RIP
///   4. Save host callee-saved registers
///   5. Load guest GP registers from GuestState
///   6. VMLAUNCH or VMRESUME
///   7. On VM exit: save guest GP registers to GuestState
///   8. Restore host callee-saved registers
///   9. Read VMCS exit fields and decode into VmExitInfo
pub fn vmResume(guest_state: *GuestState, vmcs_paddr: PAddr) VmExitInfo {
    // Load this VMCS as current
    asm volatile (
        \\vmptrld (%[addr])
        :
        : [addr] "r" (&vmcs_paddr.addr),
        : .{ .memory = true, .cc = true });

    // Write guest architectural state into VMCS fields
    writeGuestState(guest_state);

    const gs_ptr = @intFromPtr(guest_state);

    asm volatile (
    // Save host callee-saved registers
        \\pushq %%rbx
        \\pushq %%rbp
        \\pushq %%r12
        \\pushq %%r13
        \\pushq %%r14
        \\pushq %%r15
        //
        // Write HOST_RSP = current RSP (after pushes)
        // VMWRITE field HOST_RSP (0x6C14), value = RSP
        \\movq %%rsp, %%rax
        \\movq $0x6C14, %%rdx
        \\vmwrite %%rax, %%rdx
        //
        // Write HOST_RIP = address of .Lvm_exit_point
        \\leaq .Lvm_exit_point(%%rip), %%rax
        \\movq $0x6C16, %%rdx
        \\vmwrite %%rax, %%rdx
        //
        // Load guest GP registers from GuestState.
        // GuestState layout (extern struct, 8 bytes each):
        // offset 0x00: rax, 0x08: rbx, 0x10: rcx, 0x18: rdx
        // offset 0x20: rsi, 0x28: rdi, 0x30: rbp, 0x38: rsp (not used here)
        // offset 0x40: r8,  0x48: r9,  0x50: r10, 0x58: r11
        // offset 0x60: r12, 0x68: r13, 0x70: r14, 0x78: r15
        \\movq %[gs], %%rax
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
        // Load RAX last (clobbers our pointer)
        \\movq 0x00(%%rax), %%rax
        //
        // Try VMRESUME first; if it fails (CF=1 => not launched), use VMLAUNCH.
        \\vmresume
        // If VMRESUME succeeds, we never reach here — VM exit goes to HOST_RIP.
        // If VMRESUME fails (CF=1, VMCS never launched), try VMLAUNCH.
        \\jbe .Lvm_launch
        \\jmp .Lvm_exit_point
        //
        \\.Lvm_launch:
        \\vmlaunch
        // If VMLAUNCH succeeds, VM exit goes to HOST_RIP.
        // If it fails, we fall through to the exit point with an error.
        //
        \\.Lvm_exit_point:
        // We arrive here on VM exit. The processor has:
        //   - Restored host segment registers, CR0/CR3/CR4, RSP, RIP
        //   - Guest GP registers still hold guest values
        //
        // Save guest GP registers back into GuestState.
        \\pushq %%rax
        \\movq %[gs], %%rax
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
        // Restore host callee-saved registers
        \\popq %%r15
        \\popq %%r14
        \\popq %%r13
        \\popq %%r12
        \\popq %%rbp
        \\popq %%rbx
        :
        : [gs] "r" (gs_ptr),
        : .{
            // rbx, rbp, r12-r15 are NOT clobber-listed: the asm manually
            // pushes/pops them on entry/exit. Listing a manually-saved
            // callee-saved register as a clobber forces LLVM to allocate a
            // scratch register for it — and with `omit_frame_pointer = false`
            // plus the guest-GPR constraints, register pressure aborts the
            // compile. See the matching comment on the SVM VMRUN asm.
            .rax = true,
            .rcx = true,
            .rdx = true,
            .rsi = true,
            .rdi = true,
            .r8 = true,
            .r9 = true,
            .r10 = true,
            .r11 = true,
            .memory = true,
            .cc = true,
        });

    // Read guest architectural state back from VMCS into GuestState
    readGuestState(guest_state);

    // Decode exit reason
    return decodeExitReason(guest_state);
}

// ---------------------------------------------------------------------------
// Exit reason decoding
// ---------------------------------------------------------------------------

/// Decode the VM-exit reason from VMCS fields (SDM Vol 3C, Section 28.2.1
/// "Basic VM-Exit Information"; Appendix C, Table C-1 for exit reason numbers).
fn decodeExitReason(guest_state: *const GuestState) VmExitInfo {
    const exit_reason_raw = vmcsRead(EXIT_REASON);
    const exit_reason: u16 = @truncate(exit_reason_raw & 0xFFFF);
    const qualification = vmcsRead(EXIT_QUALIFICATION);

    switch (exit_reason) {
        EXIT_REASON_CPUID => {
            return .{ .cpuid = .{
                .leaf = @truncate(guest_state.rax),
                .subleaf = @truncate(guest_state.rcx),
            } };
        },
        EXIT_REASON_IO => {
            // Exit qualification for I/O (SDM Vol 3C, Table 28-5):
            // Bit 3: direction (0=out, 1=in)
            // Bits 2:0: size (0=1, 1=2, 3=4 bytes)
            // Bits 31:16: port number
            const size_bits: u8 = @truncate(qualification & 0x7);
            const size: u8 = switch (size_bits) {
                0 => 1,
                1 => 2,
                3 => 4,
                else => 1,
            };
            const is_in = (qualification & (1 << 3)) != 0;
            const port: u16 = @truncate((qualification >> 16) & 0xFFFF);
            const instr_len = vmcsRead(VM_EXIT_INSTRUCTION_LEN);
            return .{ .io = .{
                .port = port,
                .size = size,
                .is_write = !is_in,
                .value = @truncate(guest_state.rax),
                .next_rip = guest_state.rip + instr_len,
            } };
        },
        EXIT_REASON_CR_ACCESS => {
            // Qualification (SDM Vol 3C, Table 28-3): bits 3:0 = CR number,
            // bits 5:4 = access type (0=mov to CR, 1=mov from CR), bits 11:8 = GPR.
            const cr_num: u4 = @truncate(qualification & 0xF);
            const access_type: u2 = @truncate((qualification >> 4) & 0x3);
            const gpr: u4 = @truncate((qualification >> 8) & 0xF);
            const is_write = (access_type == 0);
            const value = readGprFromGuest(guest_state, gpr);
            return .{ .cr_access = .{
                .cr_num = cr_num,
                .is_write = is_write,
                .gpr = gpr,
                .value = value,
            } };
        },
        EXIT_REASON_MSR_READ => {
            return .{ .msr_read = .{
                .msr = @truncate(guest_state.rcx),
                .value = 0,
            } };
        },
        EXIT_REASON_MSR_WRITE => {
            const value = (guest_state.rdx << 32) | (guest_state.rax & 0xFFFF_FFFF);
            return .{ .msr_write = .{
                .msr = @truncate(guest_state.rcx),
                .value = value,
            } };
        },
        EXIT_REASON_EPT_VIOLATION => {
            const guest_phys = vmcsRead(GUEST_PHYSICAL_ADDR);
            return .{ .ept_violation = .{
                .guest_phys = guest_phys,
                .is_read = (qualification & (1 << 0)) != 0,
                .is_write = (qualification & (1 << 1)) != 0,
                .is_exec = (qualification & (1 << 2)) != 0,
            } };
        },
        EXIT_REASON_HLT => {
            return .hlt;
        },
        EXIT_REASON_TRIPLE_FAULT => {
            return .triple_fault;
        },
        EXIT_REASON_EXTERNAL_INT => {
            return .{ .interrupt_window = {} };
        },
        else => {
            return .{ .unknown = exit_reason_raw };
        },
    }
}

fn readGprFromGuest(gs: *const GuestState, gpr: u4) u64 {
    return switch (gpr) {
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

// ---------------------------------------------------------------------------
// Interrupt / exception injection
// ---------------------------------------------------------------------------

/// Inject a virtual interrupt into the guest via VMCS VM-entry
/// interruption-information field (SDM Vol 3C, Section 25.8.3 "VM-Entry
/// Controls for Event Injection", Table 25-17 for field format).
pub fn injectInterrupt(guest_state: *GuestState, interrupt: GuestInterrupt) void {
    _ = guest_state;

    // VM-entry interruption-information field (0x4016):
    // Bits 7:0   = vector
    // Bits 10:8  = type (0=external interrupt, 2=NMI, 3=hardware exception,
    //              4=software interrupt, 5=privileged sw exception, 6=software exception)
    // Bit 11     = error code valid
    // Bit 31     = valid
    var info: u32 = @as(u32, interrupt.vector);
    info |= @as(u32, interrupt.interrupt_type) << 8;
    if (interrupt.error_code_valid) {
        info |= (1 << 11);
        vmcsWrite(VM_ENTRY_EXCEPTION_ERROR_CODE, interrupt.error_code);
    }
    info |= (1 << 31); // valid bit
    vmcsWrite(VM_ENTRY_INTR_INFO, info);

    // For software interrupts, also set instruction length
    if (interrupt.interrupt_type == 4 or interrupt.interrupt_type == 6) {
        vmcsWrite(VM_ENTRY_INSTRUCTION_LEN, 0);
    }
}

/// Inject an exception into the guest via VMCS interrupt-info field (SDM
/// Vol 3C, Section 25.8.3 "VM-Entry Controls for Event Injection"). Uses
/// type 3 (hardware exception) and delivers error codes for #DF, #TS, #NP,
/// #SS, #GP, #PF, and #AC per SDM Vol 3A, Table 6-1.
pub fn injectException(guest_state: *GuestState, exception: GuestException) void {
    // For #PF (vector 14), also set CR2 in guest state
    if (exception.vector == 14) {
        guest_state.cr2 = exception.fault_addr;
    }

    // Type 3 = hardware exception
    var info: u32 = @as(u32, exception.vector);
    info |= (3 << 8); // hardware exception type

    // Exceptions that deliver an error code: #DF(8), #TS(10), #NP(11),
    // #SS(12), #GP(13), #PF(14), #AC(17)
    const has_error_code = switch (exception.vector) {
        8, 10, 11, 12, 13, 14, 17 => true,
        else => false,
    };
    if (has_error_code) {
        info |= (1 << 11);
        vmcsWrite(VM_ENTRY_EXCEPTION_ERROR_CODE, exception.error_code);
    }
    info |= (1 << 31); // valid bit
    vmcsWrite(VM_ENTRY_INTR_INFO, info);
}

// ---------------------------------------------------------------------------
// EPT management
// ---------------------------------------------------------------------------

/// Map a guest physical page in EPT (SDM Vol 3C, Section 29.3.2 "EPT
/// Translation Mechanism", Tables 29-1 through 29-7 for entry formats).
/// The ept_root parameter is actually the VMCS PAddr (arch_structures).
/// We VMPTRLD, read the EPTP to get the EPT PML4, then walk/allocate.
pub fn mapEptPage(ept_root: PAddr, guest_phys: u64, host_phys: PAddr, rights: u8) !void {
    // Load the VMCS to read the EPTP
    asm volatile (
        \\vmptrld (%[addr])
        :
        : [addr] "r" (&ept_root.addr),
        : .{ .memory = true, .cc = true });

    const eptp = vmcsRead(EPT_POINTER);
    const pml4_phys = PAddr.fromInt(eptp & EPT_ADDR_MASK);

    try mapEptPageInner(pml4_phys, guest_phys, host_phys, rights);
}

fn mapEptPageInner(pml4_phys: PAddr, guest_phys: u64, host_phys: PAddr, rights: u8) !void {
    const pmm_mgr = &pmm.global_pmm.?;

    // Build EPT rights bits
    var ept_rights: u64 = 0;
    if (rights & 0x1 != 0) ept_rights |= EPT_READ;
    if (rights & 0x2 != 0) ept_rights |= EPT_WRITE;
    if (rights & 0x4 != 0) ept_rights |= EPT_EXECUTE;

    // Walk/allocate PML4 -> PDPT -> PD -> PT
    const l4_idx = (guest_phys >> EPT_L4SH) & EPT_INDEX_MASK;
    const l3_idx = (guest_phys >> EPT_L3SH) & EPT_INDEX_MASK;
    const l2_idx = (guest_phys >> EPT_L2SH) & EPT_INDEX_MASK;
    const l1_idx = (guest_phys >> EPT_L1SH) & EPT_INDEX_MASK;

    var table_virt = VAddr.fromPAddr(pml4_phys, null);
    var table: [*]u64 = @ptrFromInt(table_virt.addr);

    // Walk levels 4, 3, 2 — allocate intermediate tables as needed
    const indices = [_]u64{ l4_idx, l3_idx, l2_idx };
    for (indices) |idx| {
        const entry = &table[idx];
        if (entry.* & (EPT_READ | EPT_WRITE | EPT_EXECUTE) == 0) {
            // No valid entry — allocate a new page table page (comes back zeroed).
            const new_page = try pmm_mgr.create(paging.PageMem(.page4k));
            const new_phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(new_page)), null);
            // Intermediate entries need R/W/X set so the walk continues
            entry.* = (new_phys.addr & EPT_ADDR_MASK) | EPT_READ | EPT_WRITE | EPT_EXECUTE;
        }
        const next_phys = PAddr.fromInt(entry.* & EPT_ADDR_MASK);
        table_virt = VAddr.fromPAddr(next_phys, null);
        table = @ptrFromInt(table_virt.addr);
    }

    // Write the leaf entry at L1
    const leaf = (host_phys.addr & EPT_ADDR_MASK) | ept_rights | EPT_MEM_TYPE_WB | EPT_IGNORE_PAT;
    table[l1_idx] = leaf;
}

/// Unmap a guest physical page from EPT and invalidate stale TLB entries
/// via INVEPT (SDM Vol 3C, Section 29.4.3.4 "Guidelines for Use of the
/// INVEPT Instruction"). Uses single-context invalidation (type 1).
///
/// IMPORTANT — TLB shootdown scope: INVEPT is per-logical-processor. This
/// call only invalidates EPT TLB entries on the current core. Remote cores
/// that previously executed vCPUs of this VM may still cache guest-physical
/// EPT mappings (EPT TLB entries are tagged by EPTP and are NOT flushed on
/// VMX transitions; SDM 28.3.3.1). VPID is currently not enabled, which
/// changes linear/combined mapping invalidation but not EPT-only mappings.
///
/// Caller contract (per Zag's current hv architecture, see
/// `kernel/arch/x64/hv/vm.zig` and `guest_memory.zig`):
///
///   1. `guest_mem.deinit` teardown path — called only from `Vm.destroy`,
///      which first sets every vCPU to `.exited` and spins on
///      `thread.on_cpu` until no vCPU is executing on any core
///      (`vcpu.destroy` loop). After this, the VM is permanently dead:
///      no vCPU will ever re-enter VMX non-root with this EPTP, so stale
///      remote EPT TLB entries are never consulted again. `freeVmStructures`
///      currently leaks the EPT page tables until process-exit address-space
///      teardown, so the backing physical pages are not handed to another
///      security domain until after that process dies entirely (at which
///      point no core holds a cached EPTP matching this VM).
///
///   2. `rollbackGuestMap` partial-failure path — called synchronously
///      inside `guestMap` to undo pages this same syscall just mapped.
///      Remote vCPUs of the same VM may still cache EPT entries for those
///      pages. However, the host pages being "unmapped" here are pages
///      from the caller's OWN process address space (resolved via
///      `arch.resolveVaddr(proc.addr_space_root, ...)`) and are NOT
///      freed — only their EPT leaf is cleared. A stale remote EPT TLB
///      entry therefore only lets a vCPU of the SAME process continue to
///      read/write a host page the same process already owns. This is not
///      a cross-security-domain leak.
///
/// If a future caller needs to unmap EPT pages while other vCPUs of the
/// same VM are actively executing AND the host page must be reused across
/// security domains (e.g., an eventual `vm_guest_unmap` syscall that
/// frees the host page back to PMM), this function is NOT sufficient:
/// it must be paired with an IPI-driven INVEPT shootdown on every core
/// that may hold stale entries for this EPTP (canonical TLB shootdown),
/// or the VM must be fully quiesced (all vCPUs forced off-cpu) first.
pub fn unmapEptPage(ept_root: PAddr, guest_phys: u64) void {
    // Load the VMCS to read the EPTP
    asm volatile (
        \\vmptrld (%[addr])
        :
        : [addr] "r" (&ept_root.addr),
        : .{ .memory = true, .cc = true });

    const eptp = vmcsRead(EPT_POINTER);
    const pml4_phys = PAddr.fromInt(eptp & EPT_ADDR_MASK);

    const l4_idx = (guest_phys >> EPT_L4SH) & EPT_INDEX_MASK;
    const l3_idx = (guest_phys >> EPT_L3SH) & EPT_INDEX_MASK;
    const l2_idx = (guest_phys >> EPT_L2SH) & EPT_INDEX_MASK;
    const l1_idx = (guest_phys >> EPT_L1SH) & EPT_INDEX_MASK;

    var table_virt = VAddr.fromPAddr(pml4_phys, null);
    var table: [*]u64 = @ptrFromInt(table_virt.addr);

    // Walk to the PT level
    const indices = [_]u64{ l4_idx, l3_idx, l2_idx };
    for (indices) |idx| {
        const entry = table[idx];
        if (entry & (EPT_READ | EPT_WRITE | EPT_EXECUTE) == 0) {
            return; // Not mapped
        }
        const next_phys = PAddr.fromInt(entry & EPT_ADDR_MASK);
        table_virt = VAddr.fromPAddr(next_phys, null);
        table = @ptrFromInt(table_virt.addr);
    }

    // Clear the leaf entry
    table[l1_idx] = 0;

    // Invalidate EPT TLB for this mapping
    // INVEPT type 1 (single-context), descriptor = { EPTP, 0 }
    var descriptor: [2]u64 = .{ eptp, 0 };
    asm volatile (
        \\invept (%[desc]), %[type]
        :
        : [desc] "r" (&descriptor),
          [type] "r" (@as(u64, 1)),
        : .{ .memory = true, .cc = true });
}

