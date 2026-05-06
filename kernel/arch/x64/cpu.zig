const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const gdt = zag.arch.x64.gdt;
const interrupts = zag.arch.x64.interrupts;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const VAddr = zag.memory.address.VAddr;

pub const CpuidFeatureEcx = enum(u32) {
    sse3 = 1 << 0, // Supplemental SSE3
    pclmul = 1 << 1, // Carryless multiply
    dtes64 = 1 << 2, // 64-bit debug store
    monitor = 1 << 3, // MONITOR/MWAIT instructions
    ds_cpl = 1 << 4, // CPL-qualified debug store
    vmx = 1 << 5, // Hardware virtualization
    smx = 1 << 6, // Safer mode extensions
    est = 1 << 7, // Enhanced SpeedStep
    tm2 = 1 << 8, // Thermal monitor 2
    ssse3 = 1 << 9, // Supplemental SSE3
    cid = 1 << 10, // Context ID
    sdbg = 1 << 11, // Silicon debug
    fma = 1 << 12, // Fused multiply-add
    cx16 = 1 << 13, // CMPXCHG16B instruction
    xtpr = 1 << 14, // xTPR update control
    pdcm = 1 << 15, // Perf/Debug capability MSR
    pcid = 1 << 17, // Process-context identifiers
    dca = 1 << 18, // Direct Cache Access
    sse4_1 = 1 << 19, // SSE4.1: adds dot-product, blend ops, rounding control
    sse4_2 = 1 << 20, // SSE4.2: adds string compare/CRC instructions
    x2apic = 1 << 21, // x2APIC mode support
    movbe = 1 << 22, // Big-endian byte load/store
    popcnt = 1 << 23, // POPCNT instruction
    tsc_deadline = 1 << 24, // TSC deadline mode in local APIC timer
    aes = 1 << 25, // AES-NI instructions
    xsave = 1 << 26, // XSAVE/XRSTOR
    osxsave = 1 << 27, // OS has enabled XSAVE in CR4
    avx = 1 << 28, // Advanced Vector Extensions
    f16c = 1 << 29, // Half-precision float conversion
    rdrand = 1 << 30, // Hardware RNG
    hypervisor = 1 << 31, // Running under a hypervisor
};

pub const CpuidFeatureEdx = enum(u32) {
    fpu = 1 << 0, // x87 FPU
    vme = 1 << 1, // Virtual 8086 extensions
    de = 1 << 2, // Debugging extensions
    pse = 1 << 3, // Page Size Extension
    tsc = 1 << 4, // Time Stamp Counter
    msr = 1 << 5, // Model Specific Registers
    pae = 1 << 6, // Physical Address Extension
    mce = 1 << 7, // Machine Check Exception
    cx8 = 1 << 8, // CMPXCHG8B
    lapic = 1 << 9, // Local APIC present
    sep = 1 << 11, // SYSENTER/SYSEXIT
    mtrr = 1 << 12, // Memory Type Range Registers
    pge = 1 << 13, // Global pages
    mca = 1 << 14, // Machine Check Architecture
    cmov = 1 << 15, // CMOV instruction
    pat = 1 << 16, // Page Attribute Table
    pse36 = 1 << 17, // 36-bit PSE
    psn = 1 << 18, // Processor serial number
    clflush = 1 << 19, // CLFLUSH instruction
    ds = 1 << 21, // Debug store
    acpi = 1 << 22, // Thermal/APIC extensions
    mmx = 1 << 23, // MMX: early SIMD integer ops
    fxsr = 1 << 24, // FXSAVE/FXRSTOR: fast FPU/SSE context save/restore
    sse = 1 << 25, // SSE: 128-bit SIMD floating-point
    sse2 = 1 << 26, // SSE2: expands SSE to cover integer ops
    ss = 1 << 27, // Self-snoop
    htt = 1 << 28, // Hyperthreading / multiple logical CPUs
    tm = 1 << 29, // Thermal Monitor
    ia64 = 1 << 30, // IA-64
    pbe = 1 << 31, // Pending Break Enable
};

pub const CpuidLeaf = enum(u32) {
    basic_max = 0x00000000,
    basic_features = 0x00000001,
    ext_max = 0x80000000,
    /// AMD extended features — ECX bit 2 = SVM support.
    /// AMD APM Vol 2, Section 15.4, CPUID Fn 8000_0001h.
    ext_features = 0x80000001,
    brand_0 = 0x80000002,
    brand_1 = 0x80000003,
    brand_2 = 0x80000004,
    ext_power = 0x80000007,
    /// SVM revision and feature identification.
    /// AMD APM Vol 2, Section 15.30.1, CPUID Fn 8000_000Ah.
    svm_features = 0x8000000A,
};

pub const CpuidPowerEdx = enum(u32) {
    ts = 1 << 0, // Temperature sensor available
    fid = 1 << 1, // Frequency ID control
    vid = 1 << 2, // Voltage ID control
    ttp = 1 << 3, // Thermal Trip
    tm = 1 << 4, // Hardware Thermal Management
    stc = 1 << 5, // Software Thermal Control
    step_100mhz = 1 << 6, // 100 MHz bus multiplier capability
    hwp = 1 << 7, // Hardware P-State
    constant_tsc = 1 << 8, // Invariant TSC
};

pub const Context = packed struct {
    regs: Registers,
    int_num: u64,
    err_code: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
};

/// FXSAVE the local core's FP/SIMD state into the thread's lazy-FPU
/// buffer. `area` must be 16-byte aligned (Thread.fpu_state is 64-byte
/// aligned, so this is satisfied by construction).
/// Intel SDM Vol 2A "FXSAVE — Save x87 FPU, MMX, XMM, and MXCSR State".
pub inline fn fpuSave(area: *[576]u8) void {
    asm volatile (
        \\fxsave (%[a])
        :
        : [a] "r" (area),
        : .{ .memory = true });
}

/// FXRSTOR the local core's FP/SIMD state from the thread's lazy-FPU
/// buffer. Reverse of `fpuSave`. The buffer must contain a previously
/// saved FXSAVE image, or the canonical init image written by
/// `fpuStateInit` for never-before-run threads.
/// Intel SDM Vol 2A "FXRSTOR — Restore x87 FPU, MMX, XMM, and MXCSR State".
pub inline fn fpuRestore(area: *[576]u8) void {
    asm volatile (
        \\fxrstor (%[a])
        :
        : [a] "r" (area),
        : .{ .memory = true });
}

/// Initialise an FPU buffer to the architectural reset state.
/// FCW = 0x037F (mask all FPU exceptions), MXCSR = 0x1F80 (mask all
/// SSE exceptions, round-to-nearest, FZ/DAZ off). Everything else
/// zero. Called by Thread create so the first FXRSTOR on a brand-new
/// thread loads sensible defaults rather than whatever bit pattern
/// happened to be in the slab page.
pub fn fpuStateInit(area: *[576]u8) void {
    @memset(area, 0);
    @as(*align(1) u16, @ptrCast(area[0..2])).* = 0x037F; // FCW
    @as(*align(1) u32, @ptrCast(area[24..28])).* = 0x1F80; // MXCSR
}

/// Clear CR0.TS (bit 3). The next user-mode FP/SSE instruction will
/// no longer raise #NM. Called at the end of the lazy-FPU trap handler
/// after the thread's state has been restored.
/// Intel SDM Vol 2A "CLTS — Clear Task-Switched Flag in CR0".
pub inline fn fpuClearTrap() void {
    asm volatile ("clts" ::: .{ .memory = true });
}

/// Set CR0.TS (bit 3). The next user-mode FP/SSE instruction will
/// raise #NM, dispatching to the lazy-FPU trap handler. Called from
/// `switchTo` on every context switch so the new thread traps on its
/// first FP touch (unless it was already the previous owner on this
/// core, in which case the handler short-circuits).
/// Intel SDM Vol 3A §2.5 "Control Registers", CR0.TS.
pub inline fn fpuArmTrap() void {
    var cr0: u64 = undefined;
    asm volatile ("mov %%cr0, %[v]"
        : [v] "=r" (cr0),
    );
    cr0 |= 0x8;
    asm volatile ("mov %[v], %%cr0"
        :
        : [v] "r" (cr0),
    );
}

/// Per-core mailbox for the FPU-flush IPI. The requesting core writes
/// `requested_thread`, sends the IPI, then spins on `done`. The
/// receiver reads `requested_thread`, performs the FXSAVE, sets `done`.
/// One mailbox per *target* core; concurrent flushes targeting the
/// same core serialize at the IPI vector level (the receiver services
/// one IPI at a time). A thread only owns the FPU on one core at a
/// time, so a second flush of the same thread is a no-op.
pub const FpuFlushMailbox = struct {
    requested_thread: ?*anyopaque align(64) = null,
    done: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),

    pub fn ackDone(self: *FpuFlushMailbox) void {
        self.done.store(true, .release);
    }
};

pub var fpu_flush_mailbox: [64]FpuFlushMailbox align(64) = [_]FpuFlushMailbox{.{}} ** 64;

pub const Registers = packed struct {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rdi: u64,
    rsi: u64,
    rbp: u64,
    rbx: u64,
    rdx: u64,
    rcx: u64,
    rax: u64,
};

pub const PrivilegeLevel = enum(u2) {
    ring_0 = 0x0,
    ring_3 = 0x3,
};

pub fn cpuid(eax: CpuidLeaf, ecx: u32) struct {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
} {
    var a = @intFromEnum(eax);
    var b: u32 = 0;
    var c = ecx;
    var d: u32 = 0;
    asm volatile ("cpuid"
        : [a] "={eax}" (a),
          [b] "={ebx}" (b),
          [c] "={ecx}" (c),
          [d] "={edx}" (d),
        : [in_a] "{eax}" (@intFromEnum(eax)),
          [in_c] "{ecx}" (ecx),
    );
    return .{ .eax = a, .ebx = b, .ecx = c, .edx = d };
}

/// Raw CPUID for arbitrary leaf/subleaf numbers. Used by the PMU detection
/// path which needs leaf `0x0A` (architectural performance monitoring,
/// Intel SDM Vol 3 §18.2.2) — not worth broadening `CpuidLeaf` for.
pub fn cpuidRaw(leaf: u32, subleaf: u32) struct {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
} {
    var a: u32 = leaf;
    var b: u32 = 0;
    var c: u32 = subleaf;
    var d: u32 = 0;
    asm volatile ("cpuid"
        : [a] "={eax}" (a),
          [b] "={ebx}" (b),
          [c] "={ecx}" (c),
          [d] "={edx}" (d),
        : [in_a] "{eax}" (leaf),
          [in_c] "{ecx}" (subleaf),
    );
    return .{ .eax = a, .ebx = b, .ecx = c, .edx = d };
}

/// Intel SDM Vol 2B, "STI — Set Interrupt Flag" — sets RFLAGS.IF, enabling
/// maskable hardware interrupts after the next instruction completes.
pub fn enableInterrupts() void {
    asm volatile ("sti");
}

/// Intel SDM Vol 3A, Section 10.12.1 "Detecting and Enabling x2APIC Mode" —
/// sets IA32_APIC_BASE[10] (x2APIC enable) and IA32_APIC_BASE[11] (APIC global
/// enable), then programs the Spurious-Interrupt Vector Register via x2APIC MSR
/// 80FH. Intel SDM Vol 3A, Section 10.9, Figure 10-23 (SVR layout).
pub fn enableX2Apic(spurious_vector: u8) bool {
    std.debug.assert(spurious_vector >= 0x10);

    const feat = cpuid(.basic_features, 0);
    if (!hasFeatureEdx(feat.edx, .lapic)) return false;
    if (!hasFeatureEcx(feat.ecx, .x2apic)) return false;

    const ia32_apic_base: u32 = 0x1B;
    const apic_en: u64 = 1 << 11;
    const x2apic_en: u64 = 1 << 10;

    var apic_base = rdmsr(ia32_apic_base);
    apic_base |= (apic_en | x2apic_en);
    wrmsr(ia32_apic_base, apic_base);

    const x2apic_svr: u32 = 0x80F;
    const svr_apic_enable: u64 = 1 << 8;
    const svr_value: u64 = svr_apic_enable | (@as(u64, spurious_vector));
    wrmsr(x2apic_svr, svr_value);

    return true;
}

pub fn hasFeatureEcx(reg: u32, feat: CpuidFeatureEcx) bool {
    return (reg & @intFromEnum(feat)) != 0;
}

pub fn hasFeatureEdx(reg: u32, feat: CpuidFeatureEdx) bool {
    return (reg & @intFromEnum(feat)) != 0;
}

pub fn hasPowerFeatureEdx(reg: u32, feat: CpuidPowerEdx) bool {
    return (reg & @intFromEnum(feat)) != 0;
}

/// Intel SDM Vol 2B, "RDTSC — Read Time-Stamp Counter" — loads EDX:EAX with
/// the 64-bit TSC value. The preceding LFENCE serializes instruction retirement
/// so no prior load reorders past the counter read.
/// Intel SDM Vol 3B, Section 17.17 "Time-Stamp Counter"; §17.17.1 "Invariant TSC".
pub fn rdtscLFenced() u64 {
    var a: u32 = 0;
    var d: u32 = 0;
    asm volatile (
        \\ lfence
        \\ rdtsc
        : [a] "={eax}" (a),
          [d] "={edx}" (d),
        :
        : .{ .memory = true });
    return (@as(u64, d) << 32) | a;
}

/// Intel SDM Vol 2B, "RDTSCP — Read Time-Stamp Counter and Processor ID" —
/// atomically loads the TSC into EDX:EAX and the IA32_TSC_AUX MSR into ECX.
/// Acts as a partial serializing instruction: all prior instructions must retire
/// before the counter is sampled, but subsequent instructions may begin speculatively.
/// Intel SDM Vol 3B, Section 17.17 "Time-Stamp Counter".
pub fn rdtscp() u64 {
    var a: u32 = 0;
    var d: u32 = 0;
    var c: u32 = 0;
    asm volatile (
        \\ rdtscp
        : [a] "={eax}" (a),
          [d] "={edx}" (d),
          [c] "={ecx}" (c),
        :
        : .{ .memory = true });
    return (@as(u64, d) << 32) | a;
}

/// Intel SDM Vol 2B, "RDTSCP — Read Time-Stamp Counter and Processor ID" —
/// samples the TSC after all prior instructions retire; the trailing LFENCE
/// prevents subsequent loads from executing before the counter read completes.
/// Intel SDM Vol 3B, Section 17.17 "Time-Stamp Counter".
pub fn rdtscpLFenced() u64 {
    var a: u32 = 0;
    var d: u32 = 0;
    var c: u32 = 0;
    asm volatile (
        \\ rdtscp
        \\ lfence
        : [a] "={eax}" (a),
          [d] "={edx}" (d),
          [c] "={ecx}" (c),
        :
        : .{ .memory = true });
    return (@as(u64, d) << 32) | a;
}

/// Intel SDM Vol 3A, Section 2.3 "System Flags and Fields in the EFLAGS Register" —
/// CR2 holds the 64-bit linear address that caused the most recent #PF exception.
/// Intel SDM Vol 3A, Section 5.7 "Exceptions and Interrupts" — the page-fault
/// handler reads CR2 before re-enabling interrupts to capture the faulting address.
pub fn readCr2() u64 {
    var vaddr: u64 = 0;
    asm volatile ("mov %%cr2, %[addr]"
        : [addr] "=r" (vaddr),
    );
    return vaddr;
}

/// Intel SDM Vol 2A, "PUSHFQ" — saves RFLAGS to the stack; Vol 2A, "CLI/STI" —
/// clears/sets RFLAGS.IF (bit 9). Together these implement a save-and-restore
/// critical-section bracket. Intel SDM Vol 3A, Section 2.3 (RFLAGS.IF definition).
pub fn restoreInterrupts(saved_rflags: u64) void {
    const IF: u64 = 1 << 9;
    if ((saved_rflags & IF) != 0) {
        asm volatile ("sti");
    } else {
        asm volatile ("cli");
    }
}

/// Intel SDM Vol 2A, "PUSHFQ" — captures RFLAGS without modifying any state.
/// Returns true if the IF bit (bit 9) is set, i.e., maskable interrupts are
/// currently enabled on this core. Used by lockdep to detect IRQ-vs-process
/// context at lock acquire sites.
pub fn interruptsEnabled() bool {
    var rflags: u64 = 0;
    asm volatile ("pushfq; pop %[out]"
        : [out] "={rax}" (rflags),
    );
    return (rflags & (1 << 9)) != 0;
}

/// Intel SDM Vol 2A, "PUSHFQ" / "CLI" — atomically captures RFLAGS (including
/// IF bit 9) then clears the interrupt flag. Caller must pass the returned value
/// to `restoreInterrupts` to re-arm interrupts only if they were previously enabled.
/// Intel SDM Vol 3A, Section 2.3 (RFLAGS layout).
pub fn saveAndDisableInterrupts() u64 {
    var rflags: u64 = 0;
    asm volatile ("pushfq; pop %[out]"
        : [out] "={rax}" (rflags),
    );
    asm volatile ("cli");
    return rflags;
}

/// Intel SDM Vol 2A, "INVLPG — Invalidate TLB Entry" — invalidates any TLB
/// entries covering the 4-KByte page that contains `vaddr`, including global
/// entries (regardless of CR4.PGE). Also invalidates paging-structure caches.
/// Intel SDM Vol 3A, Section 5.10.4.1 "Operations that Invalidate TLBs and
/// Paging-Structure Caches".
pub fn invlpg(vaddr: u64) void {
    asm volatile (
        \\invlpg (%[a])
        :
        : [a] "r" (vaddr),
        : .{ .memory = true });
}

pub fn halt() noreturn {
    while (true) {
        asm volatile ("hlt");
    }
}

/// Align a stack pointer for the SysV x86-64 calling convention:
/// 16-byte aligned minus 8 (simulates the return-address push by `call`).
pub fn alignStack(stack_top: VAddr) VAddr {
    return VAddr.fromInt(std.mem.alignBackward(u64, stack_top.addr, 16) - 8);
}

/// Intel SDM Vol 3A, Section 2.5 "Control Registers" — CR3 holds the physical
/// base address of the top-level paging structure (PML4 with 4-level paging).
/// Intel SDM Vol 3A, Table 4-12 "Use of CR3 with 4-Level Paging and CR4.PCIDE=0".
pub fn readCr3() u64 {
    var value: u64 = 0;
    asm volatile ("mov %%cr3, %[out]"
        : [out] "=r" (value),
    );
    return value;
}

/// Intel SDM Vol 3A, Section 5.10.4.1 — MOV to CR3 invalidates all TLB entries
/// except global pages (CR4.PGE=1) and reloads the page-directory base.
/// Intel SDM Vol 3A, Table 4-12 "Use of CR3 with 4-Level Paging and CR4.PCIDE=0".
pub fn writeCr3(value: u64) void {
    asm volatile ("mov %[val], %%cr3"
        :
        : [val] "r" (value),
    );
}

/// Intel SDM Vol 2A, "IN — Input from Port" / "OUT — Output to Port" —
/// byte (8-bit), word (16-bit), and doubleword (32-bit) variants of the x86
/// port I/O instructions. Port address is supplied in DX; data in AL/AX/EAX.
pub fn inb(port: u16) u8 {
    if (builtin.cpu.arch != .x86_64) unreachable;
    return asm volatile (
        \\inb %[port], %[ret]
        : [ret] "={al}" (-> u8),
        : [port] "{dx}" (port),
        : .{ .dx = true });
}

pub fn outb(value: u8, port: u16) void {
    if (builtin.cpu.arch != .x86_64) unreachable;
    asm volatile (
        \\outb %[value], %[port]
        :
        : [value] "{al}" (value),
          [port] "{dx}" (port),
        : .{ .dx = true });
}

pub fn inw(port: u16) u16 {
    if (builtin.cpu.arch != .x86_64) unreachable;
    return asm volatile (
        \\inw %[port], %[ret]
        : [ret] "={ax}" (-> u16),
        : [port] "{dx}" (port),
        : .{ .dx = true });
}

pub fn outw(value: u16, port: u16) void {
    if (builtin.cpu.arch != .x86_64) unreachable;
    asm volatile (
        \\outw %[value], %[port]
        :
        : [value] "{ax}" (value),
          [port] "{dx}" (port),
        : .{ .dx = true });
}

pub fn ind(port: u16) u32 {
    if (builtin.cpu.arch != .x86_64) unreachable;
    return asm volatile (
        \\inl %[port], %[ret]
        : [ret] "={eax}" (-> u32),
        : [port] "{dx}" (port),
        : .{ .dx = true });
}

pub fn outd(value: u32, port: u16) void {
    if (builtin.cpu.arch != .x86_64) unreachable;
    asm volatile (
        \\outl %[value], %[port]
        :
        : [value] "{eax}" (value),
          [port] "{dx}" (port),
        : .{ .dx = true });
}

/// Intel SDM Vol 2A, "LGDT/LIDT — Load Global/Interrupt Descriptor Table Register" —
/// loads the GDTR or IDTR from a 10-byte memory operand (2-byte limit, 8-byte base).
/// Intel SDM Vol 2B, "LTR — Load Task Register" — loads the TR from a 16-bit
/// selector; marks the TSS descriptor in the GDT as busy.
/// Intel SDM Vol 3A, Section 3.5.1 "Segment Descriptor Tables" (GDTR/IDTR format).
pub fn lgdt(desc: *const anyopaque) void {
    asm volatile (
        \\lgdt (%[ptr])
        :
        : [ptr] "r" (desc),
    );
}

pub fn ltr(sel: u16) void {
    asm volatile (
        \\mov %[s], %%ax
        \\ltr %%ax
        :
        : [s] "ir" (sel),
    );
}

pub fn lidt(desc: *const anyopaque) void {
    asm volatile ("lidt (%[ptr])"
        :
        : [ptr] "r" (desc),
    );
}

/// Intel SDM Vol 2B, "WRMSR — Write to Model Specific Register" — writes EDX:EAX
/// to the MSR specified in ECX. Raises #GP(0) if the MSR is unimplemented or the
/// value violates reserved-bit constraints.
/// Intel SDM Vol 2A, "RDMSR — Read from Model Specific Register" — loads the MSR
/// in ECX into EDX:EAX. Intel SDM Vol 3A, Section 9.4 "Model-Specific Registers".
pub fn wrmsr(msr: u32, value: u64) void {
    const lo: u32 = @truncate(value);
    const hi: u32 = @truncate(value >> 32);
    asm volatile (
        \\wrmsr
        :
        : [msr] "{ecx}" (msr),
          [lo] "{eax}" (lo),
          [hi] "{edx}" (hi),
    );
}

pub fn rdmsr(msr: u32) u64 {
    var lo: u32 = 0;
    var hi: u32 = 0;
    asm volatile (
        \\rdmsr
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
        : [msr] "{ecx}" (msr),
    );
    return (@as(u64, hi) << 32) | lo;
}

const IA32_PAT: u32 = 0x277;
// PAT0=WB, PAT1=WT, PAT2=UC-, PAT3=UC, PAT4=WB, PAT5=WC, PAT6=UC-, PAT7=UC
const PAT_VALUE: u64 = 0x00070106_00070406;

/// Intel SDM Vol 3A, Section 11.12 "Page Attribute Table (PAT)" — programs
/// IA32_PAT MSR (277H) with eight 3-bit memory-type fields (PAT0–PAT7).
/// The PAT index for a page is formed by {PAT, PCD, PWT} bits in the PTE.
/// Intel SDM Vol 3A, Table 11-10 "Selection of PAT Entries with PAT, PCD, and PWT Flags".
pub fn initPat() void {
    wrmsr(IA32_PAT, PAT_VALUE);
}

/// Enable CR0.AM (bit 18) so user-mode alignment check exceptions (#AC) fire
/// when RFLAGS.AC is set and an unaligned access occurs at CPL 3.
/// Initialize SYSCALL/SYSRET MSRs. Must be called on every core.
///
/// Intel SDM Vol 3B §5.8.8; AMD APM Vol 2 §6.1.1.
///
/// STAR[47:32]  = kernel CS for SYSCALL entry (0x08).
/// STAR[63:48]  = base for SYSRET segment arithmetic. Per AMD APM Vol 2
///   §6.1.1 "the RPL bits 49–48 should be initialized to 11b" because
///   AMD's SYSRET sets SS.Sel = field+8 *literally* (no RPL=3 force,
///   unlike Intel SDM which OR's with 3 — a real divergence on Zen
///   silicon). With base=0x13, SYSRET produces CS = base+16 = 0x23 and
///   SS = base+8 = 0x1b (both with RPL=3). With the prior base=0x10
///   user mode ran with SS=0x18 (RPL=0); the next IRQ-from-user pushed
///   ss=0x18 into the saved Context, and the eventual iretq failed
///   #GP(0x18) because cs.RPL=3 ≠ ss.RPL=0.
/// LSTAR        = kernel entry point RIP (syscallEntry in interrupts.zig).
/// FMASK        = RFLAGS bits cleared on SYSCALL: IF(9), DF(10), AC(18).
/// EFER.SCE     = bit 0, enables SYSCALL/SYSRET instructions.
pub fn initSyscall(entry: u64) void {
    const ia32_star: u32 = 0xC0000081;
    const ia32_lstar: u32 = 0xC0000082;
    const ia32_fmask: u32 = 0xC0000084;
    const ia32_efer: u32 = 0xC0000080;

    const kernel_cs: u64 = 0x08;
    const sysret_base: u64 = 0x13;
    wrmsr(ia32_star, (sysret_base << 48) | (kernel_cs << 32));
    wrmsr(ia32_lstar, entry);
    wrmsr(ia32_fmask, (1 << 9) | (1 << 10) | (1 << 18)); // IF | DF | AC

    var efer = rdmsr(ia32_efer);
    efer |= (1 << 0); // SCE
    wrmsr(ia32_efer, efer);
}

/// Intel SDM Vol 3A, Section 2.5 "Control Registers" — sets CR0.AM (bit 18),
/// which enables alignment check exceptions (#AC, vector 17) when RFLAGS.AC is
/// also set and the current privilege level is 3. Without CR0.AM the RFLAGS.AC
/// bit has no effect. Intel SDM Vol 3A, Table 2-2 "System Flags and Fields in CR0".
pub fn enableAlignmentCheck() void {
    var cr0 = asm ("mov %%cr0, %[cr0]"
        : [cr0] "=r" (-> u64),
    );
    cr0 |= (1 << 18);
    asm volatile ("mov %[cr0], %%cr0"
        :
        : [cr0] "r" (cr0),
    );
}

/// Enable CR4.SMEP (bit 20) and CR4.SMAP (bit 21) when supported.
///
/// SMEP: Supervisor Mode Execution Prevention. With SMEP set, an instruction
/// fetch from a user-mode page while running at CPL 0 raises #PF, foiling
/// the classic "point RIP at user memory" exploit chain.
///
/// SMAP: Supervisor Mode Access Prevention. With SMAP set, a data access to
/// a user-mode page while running at CPL 0 raises #PF unless RFLAGS.AC is 1
/// (set/cleared via STAC/CLAC). Kernel code that intentionally touches a
/// user buffer must bracket the access with `stac()` / `clac()`.
///
/// Feature bits: CPUID.(EAX=7,ECX=0):EBX bit 7 = SMEP, bit 20 = SMAP
/// (Intel SDM Vol 2A, CPUID — Structured Extended Feature Flags).
/// CR4 bit assignments: Intel SDM Vol 3A §2.5.
pub fn enableSmapSmep() void {
    const feat = cpuidRaw(0x7, 0);
    const smep_bit: u32 = 1 << 7;
    const smap_bit: u32 = 1 << 20;
    const has_smep = (feat.ebx & smep_bit) != 0;
    const has_smap = (feat.ebx & smap_bit) != 0;

    var cr4 = asm ("mov %%cr4, %[cr4]"
        : [cr4] "=r" (-> u64),
    );
    if (has_smep) cr4 |= (1 << 20);
    if (has_smap) cr4 |= (1 << 21);
    asm volatile ("mov %[cr4], %%cr4"
        :
        : [cr4] "r" (cr4),
    );
}

/// Set when the local CPU supports CR4.PCIDE. Read by `swapAddrSpace`
/// to decide whether to write the PCID/no-flush hint into CR3 or fall
/// back to the legacy "flush on every CR3 write" path. Whole-system flag
/// — secondary cores either match the BSP's PCID capability or boot
/// fails. Some AMD parts (e.g. Ryzen 7950X3D) advertise INVPCID but not
/// PCID, so the runtime check is required.
pub var pcid_enabled: bool = false;

/// Enable global pages (CR4.PGE) and, when the CPU supports it,
/// process-context identifiers (CR4.PCIDE). PGE pins kernel-half TLB
/// entries across CR3 writes; PCIDE lets us tag the user half with a
/// per-process id so address-space switches no longer flush the user
/// TLB. Setting CR4.PCIDE on a CPU that does not support it (CPUID.1
/// ECX bit 17 = 0) raises #GP, so we CPUID-check first.
///
/// CR4.PCIDE may only transition 0→1 while CR3.PCID==0 — true at boot
/// since the bootloader leaves CR3 with all 12 low bits clear. Once
/// enabled, CR3 writes interpret bits[11:0] as PCID and bit 63 as the
/// "preserve TLB" hint (Intel SDM Vol 3A §5.10.4.1).
pub fn enablePcid() void {
    var cr4 = asm ("mov %%cr4, %[cr4]"
        : [cr4] "=r" (-> u64),
    );
    cr4 |= (1 << 7); // PGE — always safe to set in long mode.

    const feat = cpuidRaw(0x1, 0);
    const pcid_bit: u32 = 1 << 17;
    if ((feat.ecx & pcid_bit) != 0) {
        cr4 |= (1 << 17); // PCIDE
        pcid_enabled = true;
    }

    asm volatile ("mov %[cr4], %%cr4"
        :
        : [cr4] "r" (cr4),
    );
}

/// Set RFLAGS.AC so the current core may read/write user pages under SMAP.
/// Must be paired with `clac()`; keep the window as short as possible.
pub inline fn stac() void {
    asm volatile ("stac");
}

/// Clear RFLAGS.AC. Re-arms SMAP protection after a bracketed user access.
pub inline fn clac() void {
    asm volatile ("clac");
}

/// Enable speculative execution barriers (IBRS, STIBP) when supported.
///
/// IBRS (Indirect Branch Restricted Speculation): prevents indirect branch
/// predictions made at a lower privilege level from influencing execution at
/// a higher privilege level. Enhanced IBRS (eIBRS, "IBRS_ALL") is a
/// set-once-at-boot variant with zero ongoing overhead — available on
/// Coffee Lake Refresh / Zen 2 and later.
///
/// STIBP (Single Thread Indirect Branch Predictors): prevents one logical
/// processor from influencing the branch predictions of its sibling
/// hyperthread. Set alongside IBRS when supported.
///
/// Detection:
///   CPUID.(EAX=7,ECX=0):EDX bit 26 = IBRS/IBPB supported
///   CPUID.(EAX=7,ECX=0):EDX bit 27 = STIBP supported
///   IA32_ARCH_CAPABILITIES (MSR 0x10A) bit 2 = IBRS_ALL (eIBRS)
///
/// Intel SDM Vol 3A §5.10.1; AMD APM Vol 2 §3.2.8.
pub fn enableSpeculationBarriers() void {
    const feat = cpuidRaw(0x7, 0);
    const ibrs_bit: u32 = 1 << 26;
    const stibp_bit: u32 = 1 << 27;
    const has_ibrs = (feat.edx & ibrs_bit) != 0;
    const has_stibp = (feat.edx & stibp_bit) != 0;

    if (!has_ibrs and !has_stibp) return;

    const ia32_spec_ctrl: u32 = 0x48;
    var spec_ctrl: u64 = 0;
    if (has_ibrs) spec_ctrl |= (1 << 0); // IBRS
    if (has_stibp) spec_ctrl |= (1 << 1); // STIBP
    wrmsr(ia32_spec_ctrl, spec_ctrl);
}

/// Execute RDRAND and return a 64-bit hardware random value, or null if the
/// entropy source is unavailable or temporarily exhausted (CF=0).
///
/// Intel SDM Vol 1 §7.3.17; AMD APM Vol 3, RDRAND instruction reference.
pub fn rdrand() ?u64 {
    var value: u64 = 0;
    var success: u8 = 0;
    asm volatile (
        \\rdrand %[val]
        \\setc %[ok]
        : [val] "=r" (value),
          [ok] "=r" (success),
    );
    return if (success != 0) value else null;
}

/// CLZERO cache-line size and feature status. CLZERO is an AMD instruction
/// that zeroes a single cache line at the linear address in RAX without
/// first reading it (no read-for-ownership). The line size is fixed in the
/// microarchitecture and reported via CPUID Fn8000_0008_EBX[0] (feature bit)
/// and CPUID Fn8000_0008_ECX[23:16] (Zen-family line size field is not
/// standardized; AMD APM specifies CLZERO operates on a 64-byte line on
/// all implementations shipped to date, matching the standard cache line).
///
/// AMD APM Vol 3, "CLZERO — Cache Line Zero" instruction reference.
/// AMD APM Vol 3, Table E-3 — CPUID Fn8000_0008_EBX bit 0 = CLZERO.
const CLZERO_LINE: usize = 64;
var has_clzero: bool = false;

/// Probe CPUID Fn8000_0008_EBX[0] for CLZERO support and cache the result.
/// Called once from the PMM initialization path before any zeroPage4K call
/// can be issued. Safe to call multiple times (idempotent).
pub fn initZeroPageFeatures() void {
    // CPUID Fn8000_0000 returns the highest supported extended leaf in EAX.
    // Anything below 8000_0008h means CLZERO is not advertised.
    const ext_max_result = cpuidRaw(0x80000000, 0);
    if (ext_max_result.eax < 0x80000008) {
        has_clzero = false;
        return;
    }
    const ext8 = cpuidRaw(0x80000008, 0);
    has_clzero = (ext8.ebx & 0x1) != 0;
}

/// Zero a 4 KiB page at `ptr` using CLZERO when available, otherwise
/// fall back to `@memset`. The CLZERO path writes 64 zero bytes per
/// cache line with no prior read, avoiding the read-for-ownership penalty
/// that `rep stosb`/`@memset` pays on lines not already in cache.
///
/// AMD APM Vol 3, "CLZERO" — "Zeroes the cache line specified by the
/// logical address in rAX." CLZERO implicitly flushes the line from
/// all caches in the coherence domain before zeroing, so the zeros
/// reach main memory on the next writeback.
pub fn zeroPage4K(ptr: *anyopaque) void {
    if (has_clzero) {
        const base: usize = @intFromPtr(ptr);
        const end: usize = base + 4096;
        var addr: usize = base;
        while (addr < end) {
            asm volatile ("clzero"
                :
                : [a] "{rax}" (addr),
                : .{ .memory = true });
            addr += CLZERO_LINE;
        }
        return;
    }
    const bytes: [*]u8 = @ptrCast(ptr);
    @memset(bytes[0..4096], 0);
}

// ── Spec v3 EC dispatch primitives ────────────────────────────────────

/// Restore `ec.ctx` into the live register file and IRETQ to userspace.
/// Spec §[execution_context] dispatch.
pub fn loadEcContextAndReturn(ec: *ExecutionContext) noreturn {
    interrupts.switchTo(ec);
    // `switchTo` jmps to interruptStubEpilogue with rsp pointing at
    // `ec.ctx`, which iretq's into userspace and never returns to this
    // frame. Mark unreachable for the type system.
    unreachable;
}

/// Build a first-dispatch iret frame at the top of `kstack_top` so that
/// `interrupts.switchTo`'s jmp interruptStubEpilogue → iretq lands at
/// `entry` in user mode (or kernel mode when `ustack_top` is null).
/// Spec §[execution_context] first-dispatch.
pub fn prepareEcContext(
    kstack_top: VAddr,
    ustack_top: ?VAddr,
    entry: VAddr,
    arg: u64,
) *interrupts.ArchCpuContext {
    @setRuntimeSafety(false);
    const aligned = alignStack(kstack_top);
    const entry_fn: *const fn () void = @ptrFromInt(entry.addr);
    return interrupts.prepareThreadContext(
        aligned,
        ustack_top,
        entry_fn,
        arg,
    );
}

/// Re-patch an already-built kernel-mode iret frame into user-mode
/// shape. Mirrors the user-mode arm of `interrupts.prepareThreadContext`
/// (sets USER_CODE/USER_DATA selectors, applies the SysV ABI
/// `rsp%16==8` skew, writes RIP and the first-arg register). Used by
/// callers that allocate an EC without an attached user stack and wire
/// the stack in afterward.
pub fn patchUserModeIretFrame(
    ctx: *interrupts.ArchCpuContext,
    entry: VAddr,
    user_stack_top: VAddr,
    arg: u64,
) void {
    const ring_3: u64 = 3;
    ctx.cs = gdt.USER_CODE_OFFSET | ring_3;
    ctx.ss = gdt.USER_DATA_OFFSET | ring_3;
    ctx.rip = entry.addr;
    // SysV AMD64 ABI §3.4.1: at the first instruction of `_start` /
    // any function entry, `rsp % 16 == 8` (the implicit CALL pushed an
    // 8-byte return address onto a 16-byte-aligned stack). `user_stack_top`
    // is page-aligned, so subtract 8 to mimic that post-CALL skew —
    // without it, 16-byte aligned moves (movaps/movdqa for XMM spills)
    // emitted against `rsp+offset` trap with #GP at the first instruction.
    ctx.rsp = user_stack_top.addr - 8;
    ctx.regs.rdi = arg;
}

/// Halt the local core with interrupts enabled until the next IRQ.
/// Spec §[execution_context] idle EC.
pub fn idle() void {
    asm volatile (
        \\sti
        \\hlt
    );
}

/// Update per-core caches to "no EC dispatched" state ahead of an idle
/// park. Sets `kernel_rsp` and `TSS.RSP0` to the supplied per-core park
/// kstack top so subsequent kernel-mode IRQs / future syscall entries
/// land on a stack dedicated to this core (rather than on a shared
/// stale gs:0 pointing at a previously-suspended EC's kstack — see
/// `sched.scheduler.parkAndAwaitIRQ`). Clears the EC-identity caches
/// (gs:32 current_ec, gs:176 current_ec_gen, gs:40/48/56 domain ptrs)
/// to null so any FP path on this core would bail to slow path; in
/// practice no FP entry fires while this core is parked because no
/// userspace runs on it without a `switchTo` first.
pub fn parkPerCoreCaches(core_id: u64, park_top: u64) void {
    const sc = &interrupts.per_cpu_scratch[core_id];
    sc.kernel_rsp = park_top;
    sc.current_ec = 0;
    sc.current_ec_gen = 0;
    sc.current_domain = 0;
    sc.current_user_table = 0;
    sc.current_kernel_table = 0;
    gdt.coreTss(core_id).rsp0 = park_top;
}
