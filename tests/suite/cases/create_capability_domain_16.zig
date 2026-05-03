// Spec §[capability_domain] create_capability_domain — test 16.
//
// "[test 16] returns E_INVAL if `elf_page_frame` is smaller than the
//  declared ELF image size."
//
// Strategy
//   Mint a single-page (4 KiB) page frame and stage a synthetic ELF
//   into it whose program-header table declares a PT_LOAD segment
//   that extends past the end of the page frame. Specifically:
//
//     Ehdr.e_phoff   = 64 (immediately after the 64-byte Ehdr)
//     Ehdr.e_phnum   = 1
//     Phdr[0].p_type = PT_LOAD (1)
//     Phdr[0].p_offset = 0
//     Phdr[0].p_filesz = 8192  ← strictly greater than the 4096-byte
//                                  page frame the kernel was handed.
//
//   Per the line under test, the kernel must reject this with
//   E_INVAL because the ELF header declares an image that extends
//   past the bytes available in `elf_page_frame`.
//
//   To isolate test 16's failure path, every other create_capability
//   _domain check must pass:
//     - test 01-12 (all PERM checks): pass `caps = 0`,
//       `ceilings_inner = 0`, `ceilings_outer = 0`. Zero is a subset
//       of every ceiling field the caller holds, and zero in
//       `restart_policy_ceiling` / `fut_wait_max` cannot exceed the
//       caller's values.
//     - test 13 (BADCAP elf_page_frame): pass the just-minted PF.
//     - test 14 (BADCAP passed handle): pass an empty passed_handles
//       slice.
//     - test 15 (malformed ELF header): build a structurally valid
//       Ehdr — correct e_ident magic, ELFCLASS64, ELFDATA2LSB,
//       EV_CURRENT, ET_DYN, EM_X86_64, e_phentsize = 56, e_ehsize =
//       64. Test 15's "malformed header" cannot fire on a
//       well-formed Ehdr.
//     - test 17 (reserved bits): all our [1]/[2]/[3] words are 0.
//     - test 18 (duplicate passed handles): empty slice has no
//       duplicates.
//
//   That leaves test 16 (declared size > frame size) as the only
//   error path available to the kernel.
//
//   SPEC AMBIGUITY: spec §[create_capability_domain] does not pin
//   exactly how "declared ELF image size" is computed. The natural
//   reading is `max(p_offset + p_filesz)` over PT_LOAD segments, or
//   alternatively `e_phoff + e_phnum * e_phentsize` for the program
//   header table. We trip both at once: p_filesz = 8192 puts the
//   PT_LOAD's declared end at byte 8192 (>4096), which is the most
//   common implementation.
//
// Action
//   1. create_page_frame(pages=1, sz=0)              — must succeed
//   2. create_var(pages=1, cur_rwx=rw)               — must succeed
//   3. map_pf(var, offset=0, pf)                     — must succeed
//   4. write Ehdr + Phdr into the mapped VAR
//   5. delete(var) — drop the staging mapping; the page frame
//                    handle still references the underlying memory
//   6. create_capability_domain(0, 0, 0, pf, [])     — must return
//                                                      E_INVAL
//
// Assertions
//   1: create_page_frame returned an error
//   2: create_var returned an error
//   3: map_pf returned a non-OK status
//   4: delete of the staging VAR returned non-OK
//   5: create_capability_domain returned something other than E_INVAL

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Minimal ELF64 constants from the System V ABI / gABI ELF spec.
const EI_NIDENT: usize = 16;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;
const ELFOSABI_SYSV: u8 = 0;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PF_R: u32 = 0x4;
const PF_X: u32 = 0x1;

const Elf64Ehdr = extern struct {
    e_ident: [EI_NIDENT]u8,
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
};

const Elf64Phdr = extern struct {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
};

comptime {
    // §[create_capability_domain] reads the ELF from offset 0; the
    // header geometry must match the on-wire ELF64 ABI sizes (64 and
    // 56) for the kernel to find our Phdr.
    if (@sizeOf(Elf64Ehdr) != 64) @compileError("Elf64Ehdr size != 64");
    if (@sizeOf(Elf64Phdr) != 56) @compileError("Elf64Phdr size != 56");
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint a 1-page (4 KiB) page frame. props.sz = 0 selects
    // the 4 KiB size class. caps include r/w so we can stage bytes
    // through a mapped VAR; move stays so we can later hand the PF
    // off to create_capability_domain.
    const pf_caps = caps.PfCap{ .move = true, .r = true, .w = true };
    const cpf = syscall.createPageFrame(
        @as(u64, pf_caps.toU16()),
        0, // props.sz = 0 (4 KiB)
        1, // 1 page
    );
    if (testing.isHandleError(cpf.v1)) {
        testing.fail(1);
        return;
    }
    const pf_handle: u12 = @truncate(cpf.v1 & 0xFFF);

    // Step 2: mint a 1-page VAR with cur_rwx = r|w so we can write
    // the ELF bytes through it.
    const var_caps_word = caps.VarCap{ .r = true, .w = true };
    const cvar = syscall.createVar(
        @as(u64, var_caps_word.toU16()),
        0b011, // cur_rwx = r|w (bit 0 = r, bit 1 = w, bit 2 = x)
        1, // 1 page
        0, // preferred_base = kernel chooses
        0, // device_region = none
    );
    if (testing.isHandleError(cvar.v1)) {
        testing.fail(2);
        return;
    }
    const var_handle: u12 = @truncate(cvar.v1 & 0xFFF);
    const var_base: u64 = cvar.v2;

    // Step 3: install the page frame at offset 0 of the VAR.
    const map_result = syscall.mapPf(var_handle, &.{ 0, pf_handle });
    if (map_result.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Step 4: build a structurally well-formed Ehdr (so test 15
    // cannot fire) whose Phdr table claims a PT_LOAD segment that
    // extends past the page frame's 4 KiB. The page frame holds
    // 4096 bytes; declaring p_filesz = 8192 from p_offset = 0 means
    // the declared image extends to byte 8192 — strictly larger
    // than the page frame.
    const ehdr_ptr: *Elf64Ehdr = @ptrFromInt(var_base);
    ehdr_ptr.* = .{
        .e_ident = .{
            0x7F,       'E',         'L',        'F',
            ELFCLASS64, ELFDATA2LSB, EV_CURRENT, ELFOSABI_SYSV,
            0,          0,           0,          0,
            0,          0,           0,          0,
        },
        .e_type = ET_DYN,
        .e_machine = EM_X86_64,
        .e_version = EV_CURRENT,
        .e_entry = 0x1000,
        .e_phoff = 64,
        .e_shoff = 0,
        .e_flags = 0,
        .e_ehsize = 64,
        .e_phentsize = 56,
        .e_phnum = 1,
        .e_shentsize = 0,
        .e_shnum = 0,
        .e_shstrndx = 0,
    };

    const phdr_ptr: *Elf64Phdr = @ptrFromInt(var_base + 64);
    phdr_ptr.* = .{
        .p_type = PT_LOAD,
        .p_flags = PF_R | PF_X,
        .p_offset = 0,
        .p_vaddr = 0,
        .p_paddr = 0,
        .p_filesz = 8192, // > 4096 — the trigger for test 16
        .p_memsz = 8192,
        .p_align = 0x1000,
    };

    // Step 5: drop the staging VAR. The page frame still holds the
    // backing memory because PF refcount > 0 (we still hold the
    // PF handle).
    const del = syscall.delete(var_handle);
    if (del.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }

    // Step 6: invoke create_capability_domain. Every PERM/BADCAP/
    // INVAL gate other than test 16 has been suppressed by
    // construction (see Strategy). Spec line under test mandates
    // E_INVAL.
    const result = syscall.createCapabilityDomain(
        0, // [1] caps:           self_caps=0, idc_rx=0, reserved=0
        0, // [2] ceilings_inner: all subset of any caller value
        0, // [3] ceilings_outer: all subset of any caller value
        pf_handle, // [4] elf_page_frame
        0, // [5] initial_ec_affinity: any-core
        &.{}, // [6+] passed_handles: none
    );
    if (result.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(5);
        return;
    }

    testing.pass();
}
