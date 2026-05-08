// Spec §[map_pf] — test 12.
//
// "[test 12] on success, when [1].caps.dma = 0, CPU accesses to
//  `VMAR.base + offset` use effective permissions = `VMAR.cur_rwx` ∩
//  `page_frame.r/w/x` per page."
//
// This is the "exhaustive intersection" pass.
//
// Strategy
//   The spec rule is a 3-bit-by-3-bit intersection. We probe every
//   combination of `(VMAR.cur_rwx, pf.r/w/x)` from the abelian set
//   {r, r|w, r|w|x} on each axis — nine cells. For each cell we know
//   the spec-effective rwx triple at compile time, so we can attempt
//   each access type (read, write, execute) and tag it as either:
//     - allowed: the test EC issues the access directly; any fault is
//       a bug because the tested rwx bit is in the intersection.
//     - denied: a worker EC issues the access. The test EC binds
//       memory_fault on the worker's EC handle to a port, releases
//       the worker, and recv's on the port. A correct kernel raises
//       memory_fault and the recv unblocks with `event_type ==
//       memory_fault` and a subcode that matches the access type
//       (1 = invalid_read, 2 = invalid_write, 3 = invalid_execute,
//       per kernel/memory/fault.zig MemoryFaultSubcode). A buggy
//       kernel that lets the access through never fires the event;
//       the worker stores a survival sentinel and we observe E_TIMEOUT
//       on the recv.
//
// Why a worker EC for denied accesses
//   The kernel's memory_fault path either suspends the faulter on a
//   bound route's port or applies the no-route fallback. The no-route
//   fallback parks the faulter (`port.zig` `fireMemoryFault` →
//   `parkSelfFaulted`), so a self-issued denied access from the test
//   EC would terminate the test before it can report an outcome.
//   Routing memory_fault to a port the test EC owns lets the test EC
//   distinguish "kernel correctly denied" (event delivered) from
//   "kernel incorrectly allowed" (timeout + worker sentinel set).
//
// Bind cap availability
//   The runner's `ec_inner_ceiling = 0xFF` covers EcCap bits 0-7
//   only — `bind` lives at bit 10. However,
//   `kernel/syscall/execution_context.zig` only validates the low byte
//   of `caps` against `ec_inner_ceiling` (`new_caps_low: u8 =
//   @truncate(new_caps & 0xFF); if (new_caps_low & ~ec_inner_ceiling
//   != 0)`), and the file's own comment lines 137-142 document that
//   bind/rebind/unbind "are not constrained at mint time." So a
//   create_execution_context request with `caps.bind = true` minted
//   in the caller's own domain (target = 0) passes the gate and the
//   resulting EC handle carries the `bind` cap that
//   bind_event_route's [test 06] requires. (Note: an older comment in
//   bind_event_route_10.zig calls bind "structurally unreachable"
//   from a child EC; that comment is wrong about the gate behaviour
//   — the runner-side mint of slot 1 is restricted to 0xFF, but a
//   child-side `create_execution_context` is not.)
//
// Page-frame perm enforcement vs. spec
//   `kernel/memory/vmar.zig:mappingInstall` installs PTEs with
//   `perms = rwxToPerms(v.cur_rwx)` — the page-frame's r/w/x caps
//   never enter the PTE. So cells where `pf.caps` is strictly
//   narrower than `cur_rwx` (e.g. cur_rwx=r|w with pf.caps=r) get
//   PTEs with cur_rwx perms and the kernel never raises the spec-
//   required fault. This test deliberately exposes that gap —
//   tightening the assertions causes those cells to surface as
//   failures (recv times out, worker sentinel set), which is the
//   stated goal of the rewrite. Cells where `cur_rwx` is the more
//   restrictive of the two are spec-conformant under the current
//   PTE-from-cur_rwx-only impl and continue to pass.
//
// Cell layout
//   For each cell (vmar_rwx, pf_rwx) we:
//     1. Allocate a fresh page_frame with caps = pf_rwx (all
//        non-rwx caps zero). For the cell where pf has x, the
//        kernel's pf-cap encoder accepts x; the resulting PageFrame
//        slab carries x in its rwx triple.
//     2. Allocate a fresh VMAR with caps = r|w|x and cur_rwx =
//        vmar_rwx. caps must be a superset of cur_rwx (§[create_vmar]
//        test 16). caps.r/w/x = r|w|x is within
//        vmar_inner_ceiling = 0x01FF (bits 8-23 of ceilings_inner;
//        runner sets bits 10-12 = r/w/x = 1).
//     3. mapPf the page_frame at offset 0.
//     4. For the allowed leg (always at minimum `r` since both axes
//        include r in our set): read VMAR.base[0] from the test EC;
//        verify byte fidelity (page is freshly zero-filled, so we
//        write a sentinel only in cells where w is allowed).
//     5. For the write leg: if effective.w == 1, write 0xA5 from the
//        test EC and read back; if effective.w == 0, run the denied-
//        access scaffold below.
//     6. For the execute leg: if effective.x == 1, plant a `ret`
//        opcode (via the test EC's writable view from step 5) and
//        call the address; if effective.x == 0, run the denied-
//        access scaffold below.
//
// Denied-access scaffold (worker EC)
//   For an access type T and address A:
//     a. Reset shared globals: `worker_address = A`, `worker_kind =
//        T`, `worker_go = 0`, `worker_done = 0`.
//     b. Mint a port with caps = {bind, recv}. bind so
//        bind_event_route accepts the port; recv so the test EC can
//        dequeue.
//     c. Mint a worker EC with caps = {term, susp, bind} and entry =
//        &workerEntry. The EC starts on its own core and spins on
//        worker_go.
//     d. bind_event_route(worker, memory_fault=1, port). Returns OK
//        because the EC handle has bind and the port has bind.
//     e. Atomically set worker_go = 1. The worker reads worker_kind,
//        attempts the access, then either faults (kernel suspends it
//        on the route's port) or sets worker_done = 1 and halts.
//     f. recv(port, timeout). Two outcomes:
//        - regs.v1 == OK and word's event_type field == 1
//          (memory_fault): kernel correctly denied. Read the subcode
//          from regs.v2 and verify it matches T (1/2/3 for r/w/x).
//        - regs.v1 == E_TIMEOUT: kernel did NOT fire memory_fault.
//          If worker_done == 1 the worker survived the access (kernel
//          bug: PTE was permissive). If worker_done == 0 the worker
//          neither faulted nor ran past the access (e.g. kernel
//          parked it on no-route fallback because the bind didn't
//          take); either way the cell fails.
//     g. terminate(worker). Worker is either parked (memory_fault
//        suspended it on the port — terminate while parked is OK) or
//        halted post-access (we never resume it from recv reply).
//     h. delete(port).
//
// Execute-leg observation
//   Hard for two reasons:
//     1. To OBSERVE allowed execute, the test must place valid code
//        bytes at the page and call them. The test EC plants a 1-byte
//        `ret` (0xC3 on x86_64, `ret` opcode 0xD65F03C0 little-endian
//        on aarch64) into the page through a writable VMAR view. This
//        requires the cell already to have w in the test-EC-side
//        view; we leverage the cell's own r|w|x VMAR (caps = r|w|x,
//        cur_rwx = vmar_rwx) for cells where vmar_rwx includes w; for
//        cur_rwx = r the page can't be written through this VMAR, so
//        we plant code via a side VMAR opened only for the duration
//        of code-placement (caps = r|w|x, cur_rwx = r|w on a
//        SEPARATE handle that maps the SAME page_frame). map_pf
//        permits this — page_frames can be installed in multiple
//        VMARs.
//     2. To OBSERVE denied execute, we need the worker EC to fetch
//        an instruction at an address whose PTE has NX set. The
//        worker calls `(*const fn() callconv(.c) void)(@ptrFromInt(
//        addr))` — even at zero-filled bytes the CPU faults on the
//        first fetch when NX is enforced. The worker doesn't need
//        the bytes to be valid because the fault precedes decode.
//
// Faithful coverage report (printed in header comment for posterity):
//
//   |   vmar \ pf  |   r   |  r|w  | r|w|x |
//   | ------------ | ----- | ----- | ----- |
//   |       r      | R     | R     | R     |
//   |     r|w      | R W   | R W   | R W   |
//   |   r|w|x      | R W X | R W X | R W X |
//
//   R/W/X marks indicate which legs we attempt per cell. The
//   denied legs are derived from the cell's spec-effective rwx
//   complement. Legs we omit (none in this test) would be cells
//   where the spec already denies on the VMAR axis alone (e.g.
//   cur_rwx without `r` is created E_INVAL by [create_vmar] test
//   16). Our chosen set keeps cur_rwx ∈ {r, r|w, r|w|x}, all
//   accepted by the kernel.
//
// Assertion id allocation (each fail() call uses an id from this
// list so post-mortem can pin the failing cell + leg):
//
//   1   create_page_frame failed for some cell.
//   2   create_vmar failed for some cell.
//   3   map_pf failed for some cell.
//   4   allowed-read leg byte fidelity mismatch.
//   5   allowed-write leg byte fidelity mismatch.
//   6   denied-write leg: recv returned non-OK, non-E_TIMEOUT.
//   7   denied-write leg: recv returned OK with event_type !=
//       memory_fault, or subcode != invalid_write.
//   8   denied-write leg: recv timed out AND worker_done == 1
//       (kernel allowed the write where spec demands denial).
//   9   denied-write leg: recv timed out AND worker_done == 0
//       (worker neither faulted nor ran past — likely no-route
//       fallback or scheduling stall).
//   10  execute-leg setup (side-VMAR for code planting) failed.
//   11  allowed-execute leg: planted code didn't return cleanly.
//   12  denied-execute leg: recv returned non-OK, non-E_TIMEOUT.
//   13  denied-execute leg: recv returned OK with event_type !=
//       memory_fault, or subcode != invalid_execute.
//   14  denied-execute leg: recv timed out AND worker_done == 1
//       (kernel allowed execute where spec demands denial).
//   15  denied-execute leg: recv timed out AND worker_done == 0.
//   16  bind_event_route failed.
//   17  create_port failed for worker scaffold.
//   18  create_execution_context failed for worker.
//   19  terminate(worker) failed (residue from a prior cell).
//
// Read-leg note
//   The "always-allowed read" arm only fires once per cell (we test
//   from the test EC after map_pf). All cells in our 3×3 grid have
//   r in the spec-effective intersection, so no cell exercises the
//   denied-read leg. (A denied-read cell would require pf.caps with
//   r=0; that's outside our chosen pf-caps set {r, r|w, r|w|x}. We
//   omit it because the runner's vmar_inner_ceiling 0x01FF only
//   advertises r/w/x = 1/1/1, and create_vmar [test 16]
//   `cur_rwx ⊆ caps.r/w/x` constrains the VMAR axis the same way.)

const builtin = @import("builtin");
const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

// Memory-fault subcodes — kernel/memory/fault.zig MemoryFaultSubcode.
const SUBCODE_INVALID_READ: u64 = 1;
const SUBCODE_INVALID_WRITE: u64 = 2;
const SUBCODE_INVALID_EXECUTE: u64 = 3;

// EventType.memory_fault per kernel/sched/execution_context.zig.
const EVENT_MEMORY_FAULT: u64 = 1;

// recv timeout per denied-leg attempt. 100 ms is well past the
// scheduler's normal yield cadence yet short enough that 9 cells × 2
// denied legs ≈ 18 timeouts in the worst case (kernel completely
// broken) cap the test at ~2 s of real time. A correct kernel resolves
// each via memory_fault delivery in microseconds.
const RECV_TIMEOUT_NS: u64 = 100_000_000;

// Shared globals — the test EC writes the address/kind, releases the
// worker, and reads worker_done. The worker reads address/kind/go and
// writes done. Both ECs are in the same capability domain (worker is
// minted with target = 0), so .data/.bss is shared address space.
var worker_address: u64 = 0;
var worker_kind: u8 = 0; // 0 = read, 1 = write, 2 = execute
var worker_go: u32 = 0;
var worker_done: u32 = 0;

const KIND_READ: u8 = 0;
const KIND_WRITE: u8 = 1;
const KIND_EXECUTE: u8 = 2;

fn cpuPause() void {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("pause"),
        .aarch64 => asm volatile ("yield"),
        else => @compileError("unsupported arch"),
    }
}

fn cpuHalt() void {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile ("hlt"),
        .aarch64 => asm volatile ("wfi"),
        else => @compileError("unsupported arch"),
    }
}

fn workerEntry() callconv(.c) noreturn {
    // Spin until the test EC has bound the route and set the kind.
    while (@atomicLoad(u32, &worker_go, .acquire) == 0) cpuPause();

    const addr = @atomicLoad(u64, &worker_address, .acquire);
    const kind = @atomicLoad(u8, &worker_kind, .acquire);

    switch (kind) {
        KIND_READ => {
            const p: *volatile u8 = @ptrFromInt(addr);
            _ = p.*;
        },
        KIND_WRITE => {
            const p: *volatile u8 = @ptrFromInt(addr);
            p.* = 0xA5;
        },
        KIND_EXECUTE => {
            // Cast and call. NX-enforced PTE faults on instruction
            // fetch before any byte at `addr` is decoded; if the
            // kernel left the PTE executable, the bytes (zero-filled
            // on a fresh page, or 0xC3/RET if the test EC planted
            // them) decode to a benign return.
            const fp: *const fn () callconv(.c) void = @ptrFromInt(addr);
            fp();
        },
        else => {},
    }

    // Reaching here means the access did NOT fault. Mark survival so
    // the test EC's timeout branch can distinguish kernel-bug-allowed
    // from worker-stuck-elsewhere.
    @atomicStore(u32, &worker_done, 1, .release);

    while (true) cpuHalt();
}

const RWX_R: u3 = 0b001;
const RWX_RW: u3 = 0b011;
const RWX_RWX: u3 = 0b111;

fn pfCapsFor(rwx: u3) caps.PfCap {
    return .{
        .r = (rwx & 0b001) != 0,
        .w = (rwx & 0b010) != 0,
        .x = (rwx & 0b100) != 0,
    };
}

fn vmarCapsRWX() caps.VmarCap {
    // VMAR caps = full r|w|x; cur_rwx narrows below. Within
    // vmar_inner_ceiling = 0x01FF (bits 10-12 = r/w/x = 1).
    return .{ .r = true, .w = true, .x = true };
}

// Plant a `ret` instruction at `dst` so the worker's denied-execute
// leg's CPU fetch lands on benign bytes if the kernel improperly
// permits execute. The fetch faults BEFORE decode when NX is set, so
// the bytes only matter for the allowed-execute path; we plant
// unconditionally to keep both legs symmetric.
fn plantReturn(dst: [*]volatile u8) void {
    switch (builtin.cpu.arch) {
        .x86_64 => {
            // RET (near return) — single byte 0xC3.
            dst[0] = 0xC3;
        },
        .aarch64 => {
            // RET (uses x30 / lr) — encoded as 0xD65F03C0 little-
            // endian. Write 4 bytes; aarch64 instructions are
            // 32-bit aligned, and our offset 0 in a fresh page is
            // 4 KiB-aligned so the alignment is satisfied.
            dst[0] = 0xC0;
            dst[1] = 0x03;
            dst[2] = 0x5F;
            dst[3] = 0xD6;
        },
        else => @compileError("unsupported arch"),
    }
}

const RecvOutcome = enum {
    fault_delivered,
    timeout_worker_survived, // kernel allowed; spec violation
    timeout_worker_stuck, // worker neither faulted nor ran past
    other_error,
};

const RecvResult = struct {
    outcome: RecvOutcome,
    subcode: u64,
    error_v1: u64,
};

fn driveDeniedAccess(addr: u64, kind: u8, expect_subcode: u64) RecvResult {
    @atomicStore(u32, &worker_done, 0, .release);
    @atomicStore(u32, &worker_go, 0, .release);
    @atomicStore(u64, &worker_address, addr, .release);
    @atomicStore(u8, &worker_kind, kind, .release);

    // Mint port with bind + recv. xfer/suspend not needed.
    const port_caps = caps.PortCap{ .bind = true, .recv = true };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        return .{ .outcome = .other_error, .subcode = 0, .error_v1 = cp.v1 };
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Mint worker EC with bind + term + susp. restart_policy=0 keeps
    // the no-route-fallback path benign if route bind ever fails.
    const w_caps = caps.EcCap{
        .term = true,
        .susp = true,
        .bind = true,
    };
    const cec = syscall.createExecutionContext(
        @as(u64, w_caps.toU16()),
        @intFromPtr(&workerEntry),
        1, // stack_pages
        0, // target = self
        0, // affinity = any
    );
    if (testing.isHandleError(cec.v1)) {
        _ = syscall.delete(port_handle);
        return .{ .outcome = .other_error, .subcode = 0, .error_v1 = cec.v1 };
    }
    const w_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // Bind memory_fault (event_type = 1) on the worker to the port.
    const bind = syscall.bindEventRoute(w_handle, EVENT_MEMORY_FAULT, port_handle);
    if (bind.v1 != @intFromEnum(errors.Error.OK)) {
        _ = syscall.terminate(w_handle);
        _ = syscall.delete(w_handle);
        _ = syscall.delete(port_handle);
        return .{ .outcome = .other_error, .subcode = 0, .error_v1 = bind.v1 };
    }

    // Release the worker.
    @atomicStore(u32, &worker_go, 1, .release);

    // Wait for memory_fault delivery or timeout.
    const got = syscall.recv(port_handle, RECV_TIMEOUT_NS);

    var result: RecvResult = .{ .outcome = .other_error, .subcode = 0, .error_v1 = got.regs.v1 };

    if (got.regs.v1 == @intFromEnum(errors.Error.OK)) {
        const event_type: u64 = (got.word >> 44) & 0x1F;
        if (event_type == EVENT_MEMORY_FAULT and got.regs.v2 == expect_subcode) {
            result = .{ .outcome = .fault_delivered, .subcode = got.regs.v2, .error_v1 = 0 };
        } else {
            // Wrong event or wrong subcode.
            result = .{ .outcome = .other_error, .subcode = got.regs.v2, .error_v1 = event_type };
        }
    } else if (got.regs.v1 == @intFromEnum(errors.Error.E_TIMEOUT)) {
        if (@atomicLoad(u32, &worker_done, .acquire) == 1) {
            result = .{ .outcome = .timeout_worker_survived, .subcode = 0, .error_v1 = 0 };
        } else {
            result = .{ .outcome = .timeout_worker_stuck, .subcode = 0, .error_v1 = 0 };
        }
    }

    // Cleanup. terminate is OK whether the worker is parked on the
    // port (memory_fault suspended it) or halting in the post-access
    // hlt loop. delete reclaims the slots.
    _ = syscall.terminate(w_handle);
    _ = syscall.delete(w_handle);
    _ = syscall.delete(port_handle);

    return result;
}

fn buildVmarProps(cur_rwx: u3) u64 {
    // §[create_vmar] [2] props bits: cur_rwx[0..2], sz[3..4]=0 (4
    // KiB), cch[5..6]=0.
    return @as(u64, cur_rwx);
}

fn createPf(pf_rwx: u3) ?u12 {
    const pc = pfCapsFor(pf_rwx);
    const r = syscall.createPageFrame(@as(u64, pc.toU16()), 0, 1);
    if (testing.isHandleError(r.v1)) return null;
    return @as(u12, @truncate(r.v1 & 0xFFF));
}

const VmarResult = struct {
    handle: u12,
    base: u64,
};

fn createCellVmar(cur_rwx: u3) ?VmarResult {
    const vc = vmarCapsRWX();
    const cv = syscall.createVmar(
        @as(u64, vc.toU16()),
        buildVmarProps(cur_rwx),
        1,
        0,
        0,
    );
    if (testing.isHandleError(cv.v1)) return null;
    return .{
        .handle = @as(u12, @truncate(cv.v1 & 0xFFF)),
        .base = cv.v2,
    };
}

fn mapInto(vmar_handle: u12, pf_handle: u12) bool {
    const m = syscall.mapPf(vmar_handle, &.{ 0, @as(u64, pf_handle) });
    return m.v1 == 0;
}

// Run one cell. Returns true if all legs in this cell pass; sets
// `failed_assertion` on the first failure encountered.
fn runCell(vmar_rwx: u3, pf_rwx: u3, failed_assertion: *u64) bool {
    // Effective intersection per spec. eff_r is always 1 in our 3×3
    // set (both axes draw from {r, r|w, r|w|x}); we keep the read leg
    // unconditional below.
    const eff: u3 = vmar_rwx & pf_rwx;
    const eff_w: bool = (eff & 0b010) != 0;
    const eff_x: bool = (eff & 0b100) != 0;

    // Step 1: page_frame.
    const pf_handle = createPf(pf_rwx) orelse {
        failed_assertion.* = 1;
        return false;
    };

    // Step 2: cell VMAR.
    const cell = createCellVmar(vmar_rwx) orelse {
        failed_assertion.* = 2;
        _ = syscall.delete(pf_handle);
        return false;
    };

    // Step 3: install pf at offset 0 in the cell VMAR.
    if (!mapInto(cell.handle, pf_handle)) {
        failed_assertion.* = 3;
        _ = syscall.delete(cell.handle);
        _ = syscall.delete(pf_handle);
        return false;
    }

    // Side VMAR for code planting when the test EC needs to write
    // through to the page but the cell's cur_rwx isn't writable. We
    // also use it to read back the post-write byte for write-leg
    // fidelity when the cell's cur_rwx isn't readable (which never
    // happens in our 3×3 set; all cur_rwx values include r). We
    // create the side VMAR only for the cells that need to plant
    // executable bytes — i.e. cells where eff_x is true (allowed
    // execute) AND vmar_rwx.w is false (we can't plant through the
    // cell VMAR). In our set that intersection is empty: the only
    // cell with eff_x is (r|w|x, r|w|x), where vmar_rwx already
    // includes w. So we don't need a side VMAR for our set.
    //
    // Kept here for posterity if cur_rwx is later widened.

    // Step 4: read leg (always allowed in our 3×3 set).
    {
        const dst: *volatile u8 = @ptrFromInt(cell.base);
        // Read should not fault. Page is zero-filled.
        const v = dst.*;
        if (v != 0x00) {
            // Unexpected: the page should be zero on map. Some
            // earlier cell or runner staging populated it. Not a
            // strict spec violation but flag as setup error.
            failed_assertion.* = 4;
            _ = syscall.delete(cell.handle);
            _ = syscall.delete(pf_handle);
            return false;
        }
    }

    // Step 5: write leg.
    if (eff_w) {
        const dst: *volatile u8 = @ptrFromInt(cell.base);
        dst.* = 0xA5;
        if (dst.* != 0xA5) {
            failed_assertion.* = 5;
            _ = syscall.delete(cell.handle);
            _ = syscall.delete(pf_handle);
            return false;
        }
    } else {
        const r = driveDeniedAccess(cell.base, KIND_WRITE, SUBCODE_INVALID_WRITE);
        switch (r.outcome) {
            .fault_delivered => {},
            .timeout_worker_survived => {
                failed_assertion.* = 8;
                _ = syscall.delete(cell.handle);
                _ = syscall.delete(pf_handle);
                return false;
            },
            .timeout_worker_stuck => {
                failed_assertion.* = 9;
                _ = syscall.delete(cell.handle);
                _ = syscall.delete(pf_handle);
                return false;
            },
            .other_error => {
                // Distinguish "wrong event/subcode" (which surfaces
                // as outcome=.other_error with error_v1 == 0) from
                // genuine other errors (port/EC/bind setup
                // failure). The driveDeniedAccess fault path stores
                // the OK return as error_v1=event_type when it
                // mismatches; the timeout/non-OK path stores the
                // syscall error code. We use assertion 7 for
                // wrong-event, 6 for general other. error_v1 is the
                // syscall return; OK=0 means we got into the
                // wrong-event branch.
                if (r.error_v1 == 0) {
                    failed_assertion.* = 7;
                } else {
                    failed_assertion.* = 6;
                }
                _ = syscall.delete(cell.handle);
                _ = syscall.delete(pf_handle);
                return false;
            },
        }
    }

    // Step 6: execute leg. We need at least one valid instruction at
    // cell.base for the allowed-execute case. Plant a return
    // instruction. Planting requires cur_rwx.w on the cell VMAR — in
    // our 3×3 set the only cell with eff_x is (r|w|x, r|w|x), which
    // has vmar_rwx.w = 1, so we can plant directly. For other cells
    // we don't need to plant (the worker faults on fetch before
    // decode), but planting is safe as long as the test EC's view is
    // writable; if it isn't, skip planting.
    const can_plant = (vmar_rwx & 0b010) != 0;
    if (can_plant) {
        const dst: [*]volatile u8 = @ptrFromInt(cell.base);
        plantReturn(dst);
    }

    if (eff_x) {
        // Allowed execute: call into the planted RET. The function
        // returns immediately — no side effects to verify beyond
        // "didn't fault."
        const fp: *const fn () callconv(.c) void = @ptrFromInt(cell.base);
        fp();
        // If we returned, the call succeeded. (A fault would have
        // routed through the test EC's no-route fallback and parked
        // it.) Nothing else to assert here for assertion 11; the
        // sentinel is "we got past the call.".
    } else {
        const r = driveDeniedAccess(cell.base, KIND_EXECUTE, SUBCODE_INVALID_EXECUTE);
        switch (r.outcome) {
            .fault_delivered => {},
            .timeout_worker_survived => {
                failed_assertion.* = 14;
                _ = syscall.delete(cell.handle);
                _ = syscall.delete(pf_handle);
                return false;
            },
            .timeout_worker_stuck => {
                failed_assertion.* = 15;
                _ = syscall.delete(cell.handle);
                _ = syscall.delete(pf_handle);
                return false;
            },
            .other_error => {
                if (r.error_v1 == 0) {
                    failed_assertion.* = 13;
                } else {
                    failed_assertion.* = 12;
                }
                _ = syscall.delete(cell.handle);
                _ = syscall.delete(pf_handle);
                return false;
            },
        }
    }

    // Cell passed; reclaim slots so subsequent cells don't run the
    // child table out (4096 slots is generous, but cleanup keeps the
    // fingerprint per-cell stable).
    _ = syscall.delete(cell.handle);
    _ = syscall.delete(pf_handle);
    return true;
}

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const cells = [_][2]u3{
        .{ RWX_R, RWX_R },
        .{ RWX_R, RWX_RW },
        .{ RWX_R, RWX_RWX },
        .{ RWX_RW, RWX_R },
        .{ RWX_RW, RWX_RW },
        .{ RWX_RW, RWX_RWX },
        .{ RWX_RWX, RWX_R },
        .{ RWX_RWX, RWX_RW },
        .{ RWX_RWX, RWX_RWX },
    };

    var assertion: u64 = 0;
    for (cells) |cell| {
        if (!runCell(cell[0], cell[1], &assertion)) {
            testing.fail(assertion);
            return;
        }
    }

    testing.pass();
}
