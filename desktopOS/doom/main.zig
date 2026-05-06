// Doom service.
//
// Cap-table layout root_service hands us (mirrors the other services,
// starting at SLOT_FIRST_PASSED = 3):
//   [3]   COM1 port_io device_region (logging)
//   [4+]  framebuffer device_region (dev_type=2; pixel geometry in
//         field1) + the usb_port (xfer|bind) for HID input.
//
// Boot path:
//   1. log.init via COM1.
//   2. Walk the cap table for the framebuffer device_region and the
//      usb_port. Stash the framebuffer geometry in module globals.
//   3. Mint a writable VMAR over the framebuffer's MMIO region; the
//      base virt is the address we blit doomgeneric pixels into.
//   4. Allocate a 32 MiB heap VMAR (kernel demand-pages) and hand it
//      to the libc shim's FixedBufferAllocator.
//   5. Wire the embedded WAD blob into the libc shim's fopen path.
//   6. Initialise stdio / stderr placeholders.
//   7. Call doomgeneric_Create with `["doom", "-iwad", "DOOM1.WAD"]`.
//   8. Loop calling doomgeneric_Tick(); the C side calls back into
//      zag_dg_* via dg_platform.c on every frame for input, blit,
//      timing.

const std = @import("std");
const lib = @import("lib");
const log = @import("log");
const libc_shim = @import("libc_shim");
const usb_input = @import("usb_input");

const builtin = @import("builtin");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;

const HandleId = caps.HandleId;

// ── Embedded WAD ─────────────────────────────────────────────────

// The shareware WAD is roughly 4 MiB; embedFile inlines it as a
// const u8 slice. doomgeneric's fopen-on-IWAD-name resolves to the
// libc shim, which serves bytes out of this slice.
const WAD_BLOB: []const u8 = @embedFile("DOOM1.WAD");

// ── Tunables ─────────────────────────────────────────────────────

const HEAP_PAGES: u64 = 8192; // 32 MiB
const PAGE_4K: u64 = 4096;
const RECV_TIMEOUT_NS: u64 = 1_000; // 1 us — non-blocking poll for input

// doomgeneric resolution (matches DOOMGENERIC_RESX/Y in doomgeneric.h)
const DG_RESX: u32 = 640;
const DG_RESY: u32 = 400;

// ── Module state populated during init ───────────────────────────

var fb_base: u64 = 0;
var fb_width: u32 = 0;
var fb_height: u32 = 0;
var fb_stride_bytes: u32 = 0; // pixel stride × 4 (UEFI GOP reports pixels-per-scanline)
var fb_format: caps.PixelFormat = .none;

var usb_port_handle: HandleId = 0;
var have_usb: bool = false;

// Letterbox / scaling state computed at I_InitGraphics-equivalent time.
var blit_scale: u32 = 1;
var blit_x_offset: u32 = 0;
var blit_y_offset: u32 = 0;

// Doom's argv. doomgeneric_Create stores these in m_argv globals; the
// strings need to outlive the call, so they live in static storage.
var argv0_buf = "doom\x00".*;
var argv1_buf = "-iwad\x00".*;
var argv2_buf = "DOOM1.WAD\x00".*;
var argv_storage: [3][*:0]u8 = undefined;

// extern from doomgeneric.c (compiled into doom.elf)
extern fn doomgeneric_Create(argc: c_int, argv: [*][*:0]u8) void;
extern fn doomgeneric_Tick() void;

// ── DG_ScreenBuffer is *defined* by doomgeneric.c (initialized by
//    DG_Init via malloc). All the platform shim does is read it. ──

extern var DG_ScreenBuffer: ?[*]u32;

// ============================================================================
// Cap-table walks
// ============================================================================

fn findCom1(cap_table_base: u64) ?HandleId {
    var slot: u32 = caps.SLOT_FIRST_PASSED;
    while (slot < caps.HANDLE_TABLE_MAX) : (slot += 1) {
        const c = caps.readCap(cap_table_base, slot);
        if (c.handleType() != .device_region) continue;
        const dr = caps.deviceRegionFields(c);
        if (dr.dev_type == .port_io and dr.base_port == 0x3F8 and dr.port_count == 8) {
            return @truncate(slot);
        }
    }
    return null;
}

fn findFramebuffer(cap_table_base: u64) ?HandleId {
    var slot: u32 = caps.SLOT_FIRST_PASSED;
    while (slot < caps.HANDLE_TABLE_MAX) : (slot += 1) {
        const c = caps.readCap(cap_table_base, slot);
        if (c.handleType() != .device_region) continue;
        const dt: u4 = @truncate(c.field0 & 0xF);
        if (dt == @intFromEnum(caps.DevType.framebuffer)) return @truncate(slot);
    }
    return null;
}

fn findPort(cap_table_base: u64) ?HandleId {
    var slot: u32 = caps.SLOT_FIRST_PASSED;
    while (slot < caps.HANDLE_TABLE_MAX) : (slot += 1) {
        const c = caps.readCap(cap_table_base, slot);
        if (c.handleType() == .port) return @truncate(slot);
    }
    return null;
}

// ============================================================================
// Framebuffer / heap mapping
// ============================================================================

fn mapFramebuffer(fb_handle: HandleId, fb_size_pages: u64) bool {
    const var_caps_word = caps.VmarCap{
        .r = true,
        .w = true,
        .mmio = true,
    };
    const props: u64 = (1 << 5) | // cch=uc
        (0 << 3) | // sz=4K
        0b011; // cur_rwx = r|w
    const cvar = syscall.createVmar(
        @as(u64, var_caps_word.toU16()),
        props,
        fb_size_pages,
        0,
        0,
    );
    if (cvar.v1 < 16) return false;
    const vmar_handle: HandleId = @truncate(cvar.v1 & 0xFFF);
    fb_base = cvar.v2;
    if (syscall.mapMmio(vmar_handle, fb_handle).v1 != 0) return false;
    return true;
}

fn allocHeapVmar() bool {
    // RW vmar, demand-paged on first touch by the kernel page-fault
    // handler. No mapPf — the VMAR is born lazy.
    const var_caps_word = caps.VmarCap{ .r = true, .w = true };
    const props: u64 = (0 << 5) | (0 << 3) | 0b011;
    const cvar = syscall.createVmar(
        @as(u64, var_caps_word.toU16()),
        props,
        HEAP_PAGES,
        0,
        0,
    );
    if (cvar.v1 < 16) return false;
    libc_shim.setHeap(@intCast(cvar.v2), @intCast(HEAP_PAGES * PAGE_4K));
    return true;
}

// ============================================================================
// Framebuffer blit — DG_ScreenBuffer (640×400 ARGB) → mapped GOP fb
// ============================================================================

fn computeBlitGeometry() void {
    blit_scale = if (fb_width / DG_RESX < fb_height / DG_RESY)
        fb_width / DG_RESX
    else
        fb_height / DG_RESY;
    if (blit_scale == 0) blit_scale = 1;

    const draw_w = DG_RESX * blit_scale;
    const draw_h = DG_RESY * blit_scale;
    blit_x_offset = if (fb_width > draw_w) (fb_width - draw_w) / 2 else 0;
    blit_y_offset = if (fb_height > draw_h) (fb_height - draw_h) / 2 else 0;
}

// Convert one DG_ScreenBuffer pixel (ARGB packed:
// R<<16 | G<<8 | B, A<<24) to the framebuffer's native u32 pixel.
//
// UEFI GOP exposes one of two true-color formats: bgr8 (`B in low byte,
// R in third byte`) or rgb8 (`R in low byte`). The doomgeneric source
// in i_video.c packs `(R << red_off) | (G << green_off) | (B << blue_off)`
// with red_off=16, green_off=8, blue_off=0. That matches GOP's bgr8
// PixelBlueGreenRedReserved8Bit verbatim, so for bgr8 we pass the
// pixel through. For rgb8 we swap R↔B.
inline fn convertPixel(p: u32) u32 {
    return switch (fb_format) {
        .rgb8 => ((p & 0x000000FF) << 16) | (p & 0x0000FF00) | ((p & 0x00FF0000) >> 16) | (p & 0xFF000000),
        else => p, // bgr8 default
    };
}

fn blitFrame() void {
    const screen = DG_ScreenBuffer orelse return;
    if (fb_base == 0) return;

    // stride_bytes is bytes per scanline. fb is 32-bit pixels.
    const stride_pixels: u32 = fb_stride_bytes / 4;
    const scale = blit_scale;
    var sy: u32 = 0;
    while (sy < DG_RESY) : (sy += 1) {
        const src_row: [*]const u32 = screen + (sy * DG_RESX);
        var k: u32 = 0;
        while (k < scale) : (k += 1) {
            const dst_y = blit_y_offset + sy * scale + k;
            const dst_row: [*]u32 = @as([*]u32, @ptrFromInt(fb_base)) + (@as(u64, dst_y) * stride_pixels);
            var sx: u32 = 0;
            while (sx < DG_RESX) : (sx += 1) {
                const px = convertPixel(src_row[sx]);
                var j: u32 = 0;
                while (j < scale) : (j += 1) {
                    dst_row[blit_x_offset + sx * scale + j] = px;
                }
            }
        }
    }
}

// ============================================================================
// USB input poll — one fast-suspend round trip per call
// ============================================================================

const PollResult = struct {
    have_event: bool,
    tag: u64,
    a: u64,
    b: u64,
    c: u64,
};

fn pollUsb() PollResult {
    if (!have_usb) return .{ .have_event = false, .tag = 0, .a = 0, .b = 0, .c = 0 };
    const r = syscall.issueReg(.@"suspend", 0, .{
        .v1 = @as(u64, caps.SLOT_INITIAL_EC),
        .v2 = @as(u64, usb_port_handle),
        .v3 = @intFromEnum(usb_input.Op.poll),
    });
    if (r.v1 == 0) return .{ .have_event = false, .tag = 0, .a = 0, .b = 0, .c = 0 };
    return .{ .have_event = true, .tag = r.v2, .a = r.v3, .b = r.v4, .c = r.v5 };
}

// HID usage code → Doom keycode. Mirrors the doomgeneric Linux/SDL
// translation tables. Returns 0 for keys we don't map.
fn hidToDoomKey(usage: u8) u8 {
    return switch (usage) {
        0x04 => 'a',
        0x05 => 'b',
        0x06 => 'c',
        0x07 => 'd',
        0x08 => 'e',
        0x09 => 'f',
        0x0A => 'g',
        0x0B => 'h',
        0x0C => 'i',
        0x0D => 'j',
        0x0E => 'k',
        0x0F => 'l',
        0x10 => 'm',
        0x11 => 'n',
        0x12 => 'o',
        0x13 => 'p',
        0x14 => 'q',
        0x15 => 'r',
        0x16 => 's',
        0x17 => 't',
        0x18 => 'u',
        0x19 => 'v',
        0x1A => 'w',
        0x1B => 'x',
        0x1C => 'y',
        0x1D => 'z',
        0x1E => '1',
        0x1F => '2',
        0x20 => '3',
        0x21 => '4',
        0x22 => '5',
        0x23 => '6',
        0x24 => '7',
        0x25 => '8',
        0x26 => '9',
        0x27 => '0',
        0x28 => 13, // KEY_ENTER
        0x29 => 27, // KEY_ESCAPE
        0x2A => 0x7F, // KEY_BACKSPACE
        0x2B => 9, // KEY_TAB
        0x2C => ' ',
        0x2D => '-',
        0x2E => '=',
        0x2F => '[',
        0x30 => ']',
        0x31 => '\\',
        0x33 => ';',
        0x34 => '\'',
        0x35 => '`',
        0x36 => ',',
        0x37 => '.',
        0x38 => '/',
        0x4F => 0xae, // KEY_RIGHTARROW
        0x50 => 0xac, // KEY_LEFTARROW
        0x51 => 0xaf, // KEY_DOWNARROW
        0x52 => 0xad, // KEY_UPARROW
        0xE0 => 0x80 + 0x1d, // KEY_RCTRL
        0xE1 => 0x80 + 0x36, // KEY_RSHIFT
        0xE2 => 0x80 + 0x38, // KEY_LALT/RALT
        0xE4 => 0x80 + 0x1d, // RCTRL alt
        0xE5 => 0x80 + 0x36, // RSHIFT alt
        0xE6 => 0x80 + 0x38, // RALT alt
        0x3A => 0x80 + 0x3b, // KEY_F1
        0x3B => 0x80 + 0x3c, // KEY_F2
        0x3C => 0x80 + 0x3d, // KEY_F3
        0x3D => 0x80 + 0x3e, // KEY_F4
        0x3E => 0x80 + 0x3f, // KEY_F5
        0x3F => 0x80 + 0x40, // KEY_F6
        0x40 => 0x80 + 0x41, // KEY_F7
        0x41 => 0x80 + 0x42, // KEY_F8
        0x42 => 0x80 + 0x43, // KEY_F9
        0x43 => 0x80 + 0x44, // KEY_F10
        else => 0,
    };
}

// ============================================================================
// DG_* externs called from dg_platform.c
// ============================================================================

export fn zag_dg_init() void {
    log.print("[doom] DG_Init: framebuffer ");
    log.dec(@intCast(fb_width));
    log.print("x");
    log.dec(@intCast(fb_height));
    log.print(" stride_bytes=");
    log.dec(@intCast(fb_stride_bytes));
    log.print(" scale=");
    log.dec(@intCast(blit_scale));
    log.print(" letterbox=(");
    log.dec(@intCast(blit_x_offset));
    log.print(",");
    log.dec(@intCast(blit_y_offset));
    log.print(")\n");
}

export fn zag_dg_draw_frame() void {
    blitFrame();
}

export fn zag_dg_get_key(pressed: *c_int, key: *u8) c_int {
    if (!have_usb) return 0;
    const r = pollUsb();
    if (!r.have_event) return 0;
    if (r.tag != @intFromEnum(usb_input.Tag.keyboard)) return 0;
    const usage: u8 = @truncate(r.a);
    const state: u64 = r.b;
    const dk = hidToDoomKey(usage);
    if (dk == 0) return 0;
    pressed.* = if (state == @intFromEnum(usb_input.KeyState.pressed)) 1 else 0;
    key.* = dk;
    return 1;
}

export fn zag_dg_get_ticks_ms() u32 {
    const ns = syscall.timeMonotonic().v1;
    return @truncate(ns / 1_000_000);
}

export fn zag_dg_sleep_ms(ms: u32) void {
    if (ms == 0) {
        _ = syscall.yieldEc(0);
        return;
    }
    const start_ns = syscall.timeMonotonic().v1;
    const end_ns = start_ns + @as(u64, ms) * 1_000_000;
    while (true) {
        const now = syscall.timeMonotonic().v1;
        if (now >= end_ns) break;
        _ = syscall.yieldEc(0);
    }
}

export fn zag_dg_set_window_title(title_z: [*:0]const u8) void {
    var n: usize = 0;
    while (title_z[n] != 0) n += 1;
    log.print("[doom] window title: ");
    log.print(title_z[0..n]);
    log.print("\n");
}

// ============================================================================
// Entry — called from start.zig::_start
// ============================================================================

pub fn main(cap_table_base: u64) void {
    log.init(cap_table_base);
    log.print("[doom] starting\n");

    if (findCom1(cap_table_base) == null) {
        // Logging not strictly required after init succeeded, but if init
        // didn't take we have no way to surface anything. Park.
        park();
    }

    // Heap first so libc malloc works for the rest of init.
    if (!allocHeapVmar()) {
        log.print("[doom] FATAL: heap vmar create failed\n");
        park();
    }
    log.print("[doom] heap allocated (");
    log.dec(HEAP_PAGES * 4);
    log.print(" KiB)\n");

    // Framebuffer.
    const fb_handle = findFramebuffer(cap_table_base) orelse {
        log.print("[doom] FATAL: no framebuffer in cap table\n");
        park();
    };
    const fb_cap = caps.readCap(cap_table_base, fb_handle);
    const fb_fields = caps.framebufferFields(fb_cap);
    const fb_size_pages = fb_fields.size / PAGE_4K;
    fb_width = fb_fields.width;
    fb_height = fb_fields.height;
    // GOP reports stride in pixels; convert to bytes (32-bit pixels).
    fb_stride_bytes = @as(u32, fb_fields.stride) * 4;
    fb_format = fb_fields.pixel_format;

    if (!mapFramebuffer(fb_handle, fb_size_pages)) {
        log.print("[doom] FATAL: framebuffer mapMmio failed\n");
        park();
    }
    computeBlitGeometry();

    log.print("[doom] framebuffer: ");
    log.dec(@intCast(fb_width));
    log.print("x");
    log.dec(@intCast(fb_height));
    log.print(" stride_bytes=");
    log.dec(@intCast(fb_stride_bytes));
    log.print(" fmt=");
    log.dec(@intFromEnum(fb_format));
    log.print(" scale=");
    log.dec(@intCast(blit_scale));
    log.print("\n");

    // USB input port (optional — Doom can run without input, just no
    // gameplay).
    if (findPort(cap_table_base)) |p| {
        usb_port_handle = p;
        have_usb = true;
        log.print("[doom] usb_port at slot ");
        log.dec(@intCast(usb_port_handle));
        log.print("\n");
    } else {
        log.print("[doom] no usb_port; running without input\n");
    }

    // Wire embed-WAD blob into libc fopen path; init stdio sinks.
    libc_shim.setWadBlob(WAD_BLOB);
    libc_shim.initStdio();
    log.print("[doom] WAD embedded (");
    log.dec(WAD_BLOB.len);
    log.print(" bytes)\n");

    // Boot doomgeneric. argc/argv are stored statically so the strings
    // outlive doomgeneric_Create's call into D_DoomMain.
    argv_storage[0] = @ptrCast(&argv0_buf);
    argv_storage[1] = @ptrCast(&argv1_buf);
    argv_storage[2] = @ptrCast(&argv2_buf);
    log.print("[doom] entering doomgeneric_Create\n");
    doomgeneric_Create(3, @ptrCast(&argv_storage));

    // Main game loop. One Tick per frame; the C side calls back into
    // zag_dg_* for blit / input / timing.
    log.print("[doom] entering tick loop\n");
    while (true) {
        doomgeneric_Tick();
    }
}

fn park() noreturn {
    while (true) {
        switch (builtin.cpu.arch) {
            .x86_64 => asm volatile ("hlt"),
            .aarch64 => asm volatile ("wfi"),
            else => {},
        }
    }
}
