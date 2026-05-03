/// MSR read/write emulation for Linux guest boot.
/// Handles architectural MSRs that Linux reads/writes during early boot.
/// MSRs in GuestState are read/written directly; others use shadow storage.
const log = @import("log.zig");

const GuestState = @import("main.zig").GuestState;

// MSR addresses
const IA32_TSC: u32 = 0x10;
const IA32_APIC_BASE: u32 = 0x1B;
const IA32_MTRRCAP: u32 = 0xFE;
const IA32_SYSENTER_CS: u32 = 0x174;
const IA32_SYSENTER_ESP: u32 = 0x175;
const IA32_SYSENTER_EIP: u32 = 0x176;
const IA32_MISC_ENABLE: u32 = 0x1A0;
const IA32_PAT: u32 = 0x277;
const IA32_MTRR_DEF_TYPE: u32 = 0x2FF;
const IA32_EFER: u32 = 0xC0000080;
const IA32_STAR: u32 = 0xC0000081;
const IA32_LSTAR: u32 = 0xC0000082;
const IA32_CSTAR: u32 = 0xC0000083;
const IA32_SFMASK: u32 = 0xC0000084;
const IA32_FS_BASE: u32 = 0xC0000100;
const IA32_GS_BASE: u32 = 0xC0000101;
const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
const IA32_TSC_AUX: u32 = 0xC0000103;

// Shadow storage for MSRs not in GuestState
var shadow_apic_base: u64 = 0xFEE00900; // BSP + enabled + base 0xFEE00000
var shadow_misc_enable: u64 = 0x1; // Fast-string enable
var shadow_mtrr_def_type: u64 = 0;
var shadow_tsc: u64 = 0;
var shadow_tsc_aux: u64 = 0;
var shadow_fs_base: u64 = 0;
var shadow_gs_base: u64 = 0;

pub fn handleRead(msr_num: u32, state: *GuestState) void {
    const value: u64 = switch (msr_num) {
        IA32_EFER => state.efer,
        IA32_STAR => state.star,
        IA32_LSTAR => state.lstar,
        IA32_CSTAR => state.cstar,
        IA32_SFMASK => state.sfmask,
        IA32_KERNEL_GS_BASE => state.kernel_gs_base,
        IA32_SYSENTER_CS => state.sysenter_cs,
        IA32_SYSENTER_ESP => state.sysenter_esp,
        IA32_SYSENTER_EIP => state.sysenter_eip,
        IA32_PAT => state.pat,
        IA32_APIC_BASE => shadow_apic_base,
        IA32_MISC_ENABLE => shadow_misc_enable,
        IA32_MTRRCAP => 0,
        IA32_MTRR_DEF_TYPE => shadow_mtrr_def_type,
        IA32_FS_BASE => shadow_fs_base,
        IA32_GS_BASE => shadow_gs_base,
        IA32_TSC_AUX => shadow_tsc_aux,
        IA32_TSC => blk: {
            shadow_tsc += 1000;
            break :blk shadow_tsc;
        },
        else => 0, // Unknown MSRs return 0
    };

    // RDMSR returns value in EDX:EAX
    state.rax = value & 0xFFFFFFFF;
    state.rdx = value >> 32;
    // RDMSR is 2 bytes: 0F 32
    state.rip += 2;
}

pub fn handleWrite(msr_num: u32, state: *GuestState) void {

    // WRMSR reads value from EDX:EAX
    const value: u64 = (@as(u64, @as(u32, @truncate(state.rdx))) << 32) | @as(u64, @as(u32, @truncate(state.rax)));

    switch (msr_num) {
        IA32_EFER => state.efer = value,
        IA32_STAR => state.star = value,
        IA32_LSTAR => state.lstar = value,
        IA32_CSTAR => state.cstar = value,
        IA32_SFMASK => state.sfmask = value,
        IA32_KERNEL_GS_BASE => state.kernel_gs_base = value,
        IA32_SYSENTER_CS => state.sysenter_cs = value,
        IA32_SYSENTER_ESP => state.sysenter_esp = value,
        IA32_SYSENTER_EIP => state.sysenter_eip = value,
        IA32_PAT => state.pat = value,
        IA32_APIC_BASE => shadow_apic_base = value,
        IA32_MISC_ENABLE => shadow_misc_enable = value,
        IA32_MTRR_DEF_TYPE => shadow_mtrr_def_type = value,
        IA32_FS_BASE => shadow_fs_base = value,
        IA32_GS_BASE => shadow_gs_base = value,
        IA32_TSC_AUX => shadow_tsc_aux = value,
        IA32_TSC => shadow_tsc = value,
        else => {}, // Unknown MSRs silently ignored
    }

    // WRMSR is 2 bytes: 0F 30
    state.rip += 2;
}
