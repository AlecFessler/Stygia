/// CPUID emulation for Linux guest boot.
/// Returns minimal but valid responses for all leaves Linux queries during
/// early boot. Presents as AuthenticAMD with long mode, NX, SSE2, etc.
const log = @import("log.zig");

const GuestState = @import("main.zig").GuestState;

pub fn handle(state: *GuestState) void {
    const leaf: u32 = @truncate(state.rax);
    const subleaf: u32 = @truncate(state.rcx);

    switch (leaf) {
        // Basic CPUID: max leaf + "AuthenticAMD"
        0x00000000 => {
            state.rax = 0x0D;
            state.rbx = 0x68747541; // "Auth"
            state.rdx = 0x69746e65; // "enti"
            state.rcx = 0x444d4163; // "cAMD"
        },
        // Family/model/stepping + feature flags
        0x00000001 => {
            // Family 0x17 (Zen), Model 0x08, Stepping 2
            state.rax = 0x00800F82;
            // 1 logical processor, CLFLUSH 8 QWORDs, initial APIC ID 0
            state.rbx = 0x00010800;
            // ECX features: SSE3, PCLMUL, SSSE3, FMA, CX16, SSE4.1, SSE4.2,
            // x2APIC, MOVBE, POPCNT, AES, XSAVE, AVX, F16C, RDRAND
            // NOTE: OSXSAVE (bit 27) is dynamic — reflects CR4.OSXSAVE state
            var ecx: u32 = 0x76D8320B; // Same as before but OSXSAVE cleared
            if (state.cr4 & (1 << 18) != 0) {
                ecx |= (1 << 27); // Set OSXSAVE if guest has CR4.OSXSAVE=1
            }
            state.rcx = ecx;
            // EDX features: FPU, VME, DE, PSE, TSC, MSR, PAE, MCE, CX8, APIC,
            // SEP, MTRR, PGE, MCA, CMOV, PAT, PSE36, CLFSH, MMX, FXSR, SSE, SSE2
            state.rdx = 0x178BFBFF;
        },
        // Cache descriptors (Intel-style, Linux checks but tolerates zeros)
        0x00000002 => {
            state.rax = 0x00000001;
            state.rbx = 0;
            state.rcx = 0;
            state.rdx = 0;
        },
        // Monitor/MWAIT
        0x00000005 => {
            state.rax = 0;
            state.rbx = 0;
            state.rcx = 0;
            state.rdx = 0;
        },
        // Thermal and power management
        0x00000006 => {
            state.rax = 0;
            state.rbx = 0;
            state.rcx = 0;
            state.rdx = 0;
        },
        // Structured extended feature flags
        0x00000007 => {
            if (subleaf == 0) {
                state.rax = 0; // max subleaf
                state.rbx = 0x00000009; // FSGSBASE + BMI1
                state.rcx = 0;
                state.rdx = 0;
            } else {
                state.rax = 0;
                state.rbx = 0;
                state.rcx = 0;
                state.rdx = 0;
            }
        },
        // Extended topology enumeration
        0x0000000B => {
            if (subleaf == 0) {
                state.rax = 0; // bits to shift
                state.rbx = 1; // 1 logical proc at this level
                state.rcx = 0x100; // level 0 = SMT
                state.rdx = 0; // x2APIC ID
            } else {
                state.rax = 0;
                state.rbx = 0;
                state.rcx = subleaf;
                state.rdx = 0;
            }
        },
        // XSAVE features (CPUID leaf 0xD)
        // XCR0 = 0x7: bit 0 = x87, bit 1 = SSE, bit 2 = AVX
        // XSAVE area layout: [0..511] = legacy (x87+SSE via FXSAVE), [512..575] = XSAVE header, [576..831] = AVX (YMM)
        // Total = 832 bytes = 0x340
        0x0000000D => {
            if (subleaf == 0) {
                state.rax = 0x7; // XCR0 low: x87 + SSE + AVX
                state.rbx = 0x340; // current XSAVE area size (832 bytes)
                state.rcx = 0x340; // max XSAVE area size
                state.rdx = 0; // XCR0 high
            } else if (subleaf == 1) {
                // XSAVE extended features (XSAVEOPT, XSAVEC, XGETBV_ECX1, XSAVES)
                state.rax = 0x1; // XSAVEOPT supported
                state.rbx = 0; // size of XSAVE area used by all enabled features
                state.rcx = 0; // supported XSS bits low
                state.rdx = 0; // supported XSS bits high
            } else if (subleaf == 2) {
                // AVX state component (YMM high 128 bits for each of 16 regs)
                state.rax = 256; // size of AVX state = 256 bytes
                state.rbx = 576; // offset in XSAVE area = 576 (after legacy + header)
                state.rcx = 0; // flags: not in XSS, not compacted-aligned
                state.rdx = 0;
            } else {
                state.rax = 0;
                state.rbx = 0;
                state.rcx = 0;
                state.rdx = 0;
            }
        },
        // Max extended leaf
        0x80000000 => {
            state.rax = 0x8000001F;
            state.rbx = 0;
            state.rcx = 0;
            state.rdx = 0;
        },
        // Extended processor info + features
        0x80000001 => {
            state.rax = 0x00800F82; // same family/model
            state.rbx = 0;
            // ECX: LAHF/SAHF, SVM, ABM (LZCNT), SSE4A, 3DNow prefetch
            state.rcx = 0x00000121;
            // EDX: SYSCALL/SYSRET, NX, Page1GB, RDTSCP, Long Mode (LM),
            // plus base features
            state.rdx = 0x2FD3FBFF;
        },
        // Processor brand string (3 leaves)
        0x80000002 => {
            // "Zag Virtual CP"
            state.rax = 0x2067615A; // "Zag "
            state.rbx = 0x74726956; // "Virt"
            state.rcx = 0x206C6175; // "ual "
            state.rdx = 0x00005043; // "CP\0\0"
        },
        0x80000003 => {
            // "U\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
            state.rax = 0x00000055; // "U\0\0\0"
            state.rbx = 0;
            state.rcx = 0;
            state.rdx = 0;
        },
        0x80000004 => {
            state.rax = 0;
            state.rbx = 0;
            state.rcx = 0;
            state.rdx = 0;
        },
        // L1 cache and TLB (AMD)
        0x80000005 => {
            state.rax = 0;
            state.rbx = 0;
            // L1 data: 32KB, 8-way, 64B line
            state.rcx = 0x40020140;
            // L1 inst: 32KB, 8-way, 64B line
            state.rdx = 0x40020140;
        },
        // L2/L3 cache info
        0x80000006 => {
            state.rax = 0;
            state.rbx = 0;
            // L2: 512KB, 8-way, 64B line
            state.rcx = 0x02006140;
            state.rdx = 0;
        },
        // Advanced power management
        0x80000007 => {
            state.rax = 0;
            state.rbx = 0;
            state.rcx = 0;
            // Invariant TSC (bit 8)
            state.rdx = 0x00000100;
        },
        // Virtual and physical address sizes
        0x80000008 => {
            // 48-bit physical, 48-bit virtual
            state.rax = 0x00003030;
            state.rbx = 0;
            // ECX: number of physical cores - 1
            state.rcx = 0;
            state.rdx = 0;
        },
        // SVM features (leaf 0x8000000A)
        0x8000000A => {
            state.rax = 0;
            state.rbx = 0;
            state.rcx = 0;
            state.rdx = 0;
        },
        // Encrypted memory capabilities (0x8000001F) — Linux checks this
        0x8000001F => {
            state.rax = 0;
            state.rbx = 0;
            state.rcx = 0;
            state.rdx = 0;
        },
        // Unknown leaf: return zeros
        else => {
            state.rax = 0;
            state.rbx = 0;
            state.rcx = 0;
            state.rdx = 0;
        },
    }

    // CPUID is 2 bytes: 0F A2
    state.rip += 2;
}
