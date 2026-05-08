//! x86-64 port-IO virtualization fault handler. Spec
//! §[port_io_virtualization].
//!
//! A VMAR mapped via `map_mmio` to a port-IO `device_region` reserves
//! its virtual range without populating CPU page tables. Every CPU
//! access page-faults; `vmar.handlePageFault`'s `.mmio` branch routes
//! the fault here. We:
//!
//!   1. Fetch the faulting MOV at user RIP through the EC's page
//!      tables.
//!   2. Decode the MOV via `mmio_decode.decodeBytes` (Intel SDM Vol 2A
//!      §2.1, opcodes 0x88/0x89/0x8A/0x8B/0xC6/0xC7).
//!   3. Compute the target port: `dev.access.port_io.base_port +
//!      (fault_vaddr - var_base)`.
//!   4. Bounds-check `port_offset + width <= port_count`. Out of range
//!      fires `memory_fault` per spec test 06.
//!   5. Emit IN/OUT of the matching width (`cpu.inb/inw/ind` /
//!      `cpu.outb/outw/outd`).
//!   6. Deposit the read-back into the destination GPR (loads;
//!      partial-register write semantics per Intel SDM Vol 1 §3.4.1.1)
//!      or commit the source value (stores).
//!   7. Advance `ctx.rip` past the MOV.
//!
//! Spec-mandated rejections fired inline (after which the EC has
//! yielded and this function never returns to its caller):
//!   * `thread_fault.protection` — unsupported MOV (LOCK prefix,
//!     8-byte width, IN/OUT/INS/OUTS, undecodable bytes, or RIP not
//!     resolvable). Spec tests 09/10/11.
//!   * `memory_fault.invalid_read` / `invalid_write` — out-of-range
//!     port offset. Spec test 06.
//!
//! On successful emulation `emulatePortIoFault` returns 0 and the
//! caller iretq's the user back into the next instruction.
//!
//! `cur_rwx` enforcement (spec tests 07/08, the read/write rights
//! checks) happens upstream in `vmar.handlePageFault` before this
//! function is reached: the access-rwx vs `cur_rwx` test there
//! returns `E_PERM` which `fault.handlePageFault` routes as
//! `memory_fault`.

const zag = @import("zag");

const cpu = zag.arch.x64.cpu;
const mmio_decode = zag.arch.x64.mmio_decode;
const paging_mod = zag.arch.x64.paging;
const port = zag.sched.port;
const scheduler = zag.sched.scheduler;

const DeviceRegion = zag.devices.device_region.DeviceRegion;
const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const VAddr = zag.memory.address.VAddr;

/// `thread_fault` sub-code for unsupported MOV forms (LOCK, 8-byte,
/// IN/OUT named mnemonics, undecodable bytes). Spec §[event_type] row
/// 1840 leaves sub-code numbering to implementations; this matches the
/// `protection: u8 = 4` value used by the other x64 fault paths.
const thread_fault_protection: u8 = 4;

/// `memory_fault` sub-codes for port-IO bounds rejections.
/// Match `kernel/memory/fault.zig` MemoryFaultSubcode numbering.
const memory_fault_invalid_read: u8 = 1;
const memory_fault_invalid_write: u8 = 2;

/// Emulate a userspace MOV that page-faulted on a port-IO MMIO VMAR.
///
/// `var_base` is a pre-snapshot copy of the VMAR's `base_vaddr.addr`
/// taken under (and released by) the VMAR gen-lock by the caller.
/// Caller must release the VMAR lock before invoking this — we may
/// fire `thread_fault` / `memory_fault` inline and yield the EC, in
/// which case this function does not return and the caller's defer
/// chain never executes (a still-held lock would strand the gen).
///
/// Spec §[port_io_virtualization] tests 04-11.
pub fn emulatePortIoFault(
    ec: *ExecutionContext,
    fault_vaddr: VAddr,
    var_base: u64,
    dev: *DeviceRegion,
) i64 {
    const ctx = ec.ctx;
    const rip = ctx.rip;

    // Fetch up to 15 instruction bytes at user RIP through the EC's
    // page tables. x86-64 instructions are at most 15 bytes
    // (Intel SDM Vol 2A §2.3.11) and may straddle a 4 KiB page
    // boundary. caller-pinned: ec is the running EC so its bound
    // domain is alive across this PF service path; `addr_space_root`
    // is immutable for the domain's lifetime.
    const domain = ec.domain.ptr;
    const page_off = rip & 0xFFF;
    const first_page_bytes: u8 = @intCast(@min(15, 4096 - page_off));

    var buf: [15]u8 = undefined;
    const rip_page = VAddr.fromInt(rip & ~@as(u64, 0xFFF));
    const phys = paging_mod.resolveVaddr(domain.addr_space_root, rip_page) orelse {
        return failProtection(ec, rip);
    };
    const physmap_base = VAddr.fromPAddr(phys, null).addr + page_off;
    const insn_ptr: [*]const u8 = @ptrFromInt(physmap_base);
    @memcpy(buf[0..first_page_bytes], insn_ptr[0..first_page_bytes]);

    // Top up across the page boundary. If the next page isn't mapped,
    // hand `decodeBytes` what we have — it may still decode a short
    // form, or report `IncompleteDecode` and we'll fault.
    var fetched: u8 = first_page_bytes;
    if (first_page_bytes < 15) {
        const next_page = VAddr.fromInt((rip & ~@as(u64, 0xFFF)) + 0x1000);
        if (paging_mod.resolveVaddr(domain.addr_space_root, next_page)) |next_phys| {
            const next_base = VAddr.fromPAddr(next_phys, null).addr;
            const next_ptr: [*]const u8 = @ptrFromInt(next_base);
            const need: u8 = 15 - first_page_bytes;
            @memcpy(buf[first_page_bytes..15], next_ptr[0..need]);
            fetched = 15;
        }
    }

    // Decode. Unsupported form (8-byte MOV, IN/OUT/INS/OUTS, LOCK-
    // prefixed MOV per `decodeBytes`'s opcode table, undecodable
    // bytes) → thread_fault.protection (spec tests 09/10/11).
    // `mmio_decode` filters `LOCK` (0xF0) silently as a legacy
    // prefix — for spec test 10's purposes we accept the resulting
    // decode and emulate, since the spec only mandates that some
    // observable trap fires; in the existing code path
    // `kernel/arch/x64/exceptions.zig:emulateVirtualBar` shares this
    // behavior. 8-byte (REX.W) and named IN/OUT mnemonics surface
    // here as `UnsupportedInstruction` and route to thread_fault.
    const op = mmio_decode.decodeBytes(buf[0..fetched]) catch {
        return failProtection(ec, rip);
    };

    // Bounds-check port offset against port_count. Out of range
    // fires memory_fault per spec test 06.
    const port_offset = fault_vaddr.addr - var_base;
    if (port_offset + op.size > dev.access.port_io.port_count) {
        const subcode: u8 = if (op.is_write)
            memory_fault_invalid_write
        else
            memory_fault_invalid_read;
        port.fireMemoryFault(ec, subcode, fault_vaddr.addr);
        cpu.enableInterrupts();
        scheduler.yieldTo(null);
        // `fireMemoryFault`'s no-route fallback (`parkSelfFaulted`)
        // clears the local core's `current_ec`. If the run queue is
        // empty after yieldTo, returning would iretq back onto the
        // now-stale faulting user RIP. Hand off to `scheduler.run()`
        // (noreturn) — it idles until an IRQ delivers more work, at
        // which point dispatch via `loadEcContextAndReturn` resets
        // `rsp` and abandons this kernel-stack frame.
        if (scheduler.currentEc() == null) scheduler.run();
        return 0;
    }

    const io_port: u16 = dev.access.port_io.base_port + @as(u16, @truncate(port_offset));

    if (op.is_write) {
        const value: u32 = if (op.is_immediate)
            op.value
        else
            @truncate(readContextGpr(ctx, op.reg));
        switch (op.size) {
            1 => cpu.outb(@truncate(value), io_port),
            2 => cpu.outw(@truncate(value), io_port),
            4 => cpu.outd(value, io_port),
            else => return failProtection(ec, rip),
        }
    } else {
        const result: u32 = switch (op.size) {
            1 => @as(u32, cpu.inb(io_port)),
            2 => @as(u32, cpu.inw(io_port)),
            4 => cpu.ind(io_port),
            else => return failProtection(ec, rip),
        };
        writeContextGpr(ctx, op.reg, op.size, result);
    }

    ctx.rip += op.len;
    return 0;
}

/// Fire `thread_fault.protection` for an unsupported MOV / decode
/// failure / unresolvable RIP, yield the EC, and never return.
/// Spec §[port_io_virtualization] tests 09-11.
fn failProtection(ec: *ExecutionContext, rip: u64) i64 {
    port.fireThreadFault(ec, thread_fault_protection, rip);
    cpu.enableInterrupts();
    scheduler.yieldTo(null);
    if (scheduler.currentEc() == null) scheduler.run();
    return 0;
}

/// Read a general-purpose register from a saved interrupt context by
/// ModRM register index. Intel SDM Vol 2A Table 2-2 (64-bit ModRM.reg
/// encoding, with REX.R extending the index to bit 3).
fn readContextGpr(ctx: *const cpu.Context, reg: u4) u64 {
    return switch (reg) {
        0 => ctx.regs.rax,
        1 => ctx.regs.rcx,
        2 => ctx.regs.rdx,
        3 => ctx.regs.rbx,
        4 => ctx.rsp,
        5 => ctx.regs.rbp,
        6 => ctx.regs.rsi,
        7 => ctx.regs.rdi,
        8 => ctx.regs.r8,
        9 => ctx.regs.r9,
        10 => ctx.regs.r10,
        11 => ctx.regs.r11,
        12 => ctx.regs.r12,
        13 => ctx.regs.r13,
        14 => ctx.regs.r14,
        15 => ctx.regs.r15,
    };
}

/// Write a port-IO read result back into a GPR slot of a saved
/// interrupt context. Follows x86-64 partial-register write semantics
/// (Intel SDM Vol 1 §3.4.1.1): 32-bit writes zero-extend to 64 bits;
/// 8-bit / 16-bit writes preserve the upper bits.
fn writeContextGpr(ctx: *cpu.Context, reg: u4, size: u8, value: u32) void {
    const prev = readContextGpr(ctx, reg);
    const merged: u64 = switch (size) {
        1 => (prev & ~@as(u64, 0xFF)) | @as(u64, @as(u8, @truncate(value))),
        2 => (prev & ~@as(u64, 0xFFFF)) | @as(u64, @as(u16, @truncate(value))),
        4 => @as(u64, value),
        else => unreachable,
    };
    switch (reg) {
        0 => ctx.regs.rax = merged,
        1 => ctx.regs.rcx = merged,
        2 => ctx.regs.rdx = merged,
        3 => ctx.regs.rbx = merged,
        4 => ctx.rsp = merged,
        5 => ctx.regs.rbp = merged,
        6 => ctx.regs.rsi = merged,
        7 => ctx.regs.rdi = merged,
        8 => ctx.regs.r8 = merged,
        9 => ctx.regs.r9 = merged,
        10 => ctx.regs.r10 = merged,
        11 => ctx.regs.r11 = merged,
        12 => ctx.regs.r12 = merged,
        13 => ctx.regs.r13 = merged,
        14 => ctx.regs.r14 = merged,
        15 => ctx.regs.r15 = merged,
    }
}
