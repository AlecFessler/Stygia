// USB driver service.
//
// xHCI host-controller driver + USB-HID boot-protocol keyboard/mouse,
// retargeted from a pre-spec-v3 ABI. The xHCI register / TRB / ring
// logic and the HID parsing logic are unchanged from the original
// driver; only the userspace boundary (IPC, MMIO mapping, DMA setup,
// device discovery) has been rewritten against the v3 surface.
//
// Cap-table layout the root service hands us (mirrors nvme_driver,
// starting at SLOT_FIRST_PASSED = 3):
//   [3]      — COM1 port_io device_region (logging)
//   [4]      — usb_port (recv|bind) — server side of the input port
//   [5..]    — every PCI MMIO device_region the kernel enumerated
//              with .dma=true,.irq=true caps; we probe each looking
//              for an xHCI controller.
//
// The driver internally allocates one DMA-backed page_frame sized for
// `DMA_REGION_SIZE` and double-maps it: a regular VMAR for CPU access
// (`dma_virt_base`) and a DMA-capable VMAR bound to the xHCI device
// (`dma_phys_base` is the device-visible IOVA the kernel programs into
// the IOMMU). Both views alias the same page_frame.
//
// Input event delivery is L4-style synchronous rendezvous on
// `usb_port`: clients (Doom, etc.) suspend with a `poll` op; we reply
// with either one queued event or count=0. While no client is waiting
// we still drain the xHCI event ring on short-timeout recv loops so
// HID transfer completions are processed promptly.

const lib = @import("lib");
const log = @import("log");
const usb_input = @import("usb_input");

const builtin = @import("builtin");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;

const HandleId = caps.HandleId;

// ============================================================================
// xHCI Register Offsets (Capability Registers at MMIO base)
// ============================================================================

const CAP_CAPLENGTH = 0x00; // u8: capability register length
const CAP_HCIVERSION = 0x02; // u16: interface version
const CAP_HCSPARAMS1 = 0x04; // u32: structural parameters 1
const CAP_HCSPARAMS2 = 0x08; // u32: structural parameters 2
const CAP_HCSPARAMS3 = 0x0C; // u32: structural parameters 3
const CAP_HCCPARAMS1 = 0x10; // u32: capability parameters 1
const CAP_DBOFF = 0x14; // u32: doorbell offset
const CAP_RTSOFF = 0x18; // u32: runtime register space offset

// Operational Register offsets (relative to op_base = mmio_base + cap_length)
const OP_USBCMD = 0x00;
const OP_USBSTS = 0x04;
const OP_PAGESIZE = 0x08;
const OP_DNCTRL = 0x14;
const OP_CRCR = 0x18; // u64: command ring control register
const OP_DCBAAP = 0x30; // u64: device context base address array pointer
const OP_CONFIG = 0x38;

// USBCMD bits
const USBCMD_RS: u32 = 1 << 0; // Run/Stop
const USBCMD_HCRST: u32 = 1 << 1; // Host Controller Reset
const USBCMD_INTE: u32 = 1 << 2; // Interrupter Enable

// USBSTS bits
const USBSTS_HCH: u32 = 1 << 0; // HC Halted
const USBSTS_CNR: u32 = 1 << 11; // Controller Not Ready

// Port Status and Control Register bits
const PORTSC_CCS: u32 = 1 << 0; // Current Connect Status
const PORTSC_PED: u32 = 1 << 1; // Port Enabled/Disabled
const PORTSC_PR: u32 = 1 << 4; // Port Reset
const PORTSC_PLS_MASK: u32 = 0xF << 5; // Port Link State
const PORTSC_PP: u32 = 1 << 9; // Port Power
const PORTSC_SPEED_MASK: u32 = 0xF << 10; // Port Speed
const PORTSC_PRC: u32 = 1 << 21; // Port Reset Change
const PORTSC_WRC: u32 = 1 << 19; // Warm Port Reset Change
const PORTSC_CSC: u32 = 1 << 17; // Connect Status Change

// Port speed values (bits 13:10)
const SPEED_FULL: u32 = 1;
const SPEED_LOW: u32 = 2;
const SPEED_HIGH: u32 = 3;
const SPEED_SUPER: u32 = 4;

// Runtime Register offsets (relative to rt_base = mmio_base + rts_off)
const RT_IMAN = 0x20; // Interrupter Management (interrupter 0)
const RT_IMOD = 0x24; // Interrupter Moderation
const RT_ERSTSZ = 0x28; // Event Ring Segment Table Size
const RT_ERSTBA = 0x30; // u64: Event Ring Segment Table Base Address
const RT_ERDP = 0x38; // u64: Event Ring Dequeue Pointer

// ============================================================================
// TRB (Transfer Request Block) Types
// ============================================================================

const TRB_TYPE_NORMAL = 1;
const TRB_TYPE_SETUP = 2;
const TRB_TYPE_DATA = 3;
const TRB_TYPE_STATUS = 4;
const TRB_TYPE_LINK = 6;
const TRB_TYPE_ENABLE_SLOT = 9;
const TRB_TYPE_ADDRESS_DEVICE = 11;
const TRB_TYPE_CONFIGURE_ENDPOINT = 12;
const TRB_TYPE_EVALUATE_CONTEXT = 13;
const TRB_TYPE_NOOP = 23;
const TRB_TYPE_TRANSFER_EVENT = 32;
const TRB_TYPE_COMMAND_COMPLETION = 33;
const TRB_TYPE_PORT_STATUS_CHANGE = 34;

// TRB Completion Codes
const TRB_COMP_SUCCESS = 1;
const TRB_COMP_SHORT_PACKET = 13;

// ============================================================================
// USB Descriptor Types
// ============================================================================

const USB_DESC_DEVICE = 1;
const USB_DESC_CONFIGURATION = 2;
const USB_DESC_INTERFACE = 4;
const USB_DESC_ENDPOINT = 5;
const USB_DESC_HID = 0x21;

// USB Request Types
const USB_REQ_GET_DESCRIPTOR = 6;
const USB_REQ_SET_CONFIGURATION = 9;
const USB_REQ_SET_PROTOCOL = 0x0B;
const USB_REQ_SET_IDLE = 0x0A;

// USB HID
const USB_CLASS_HID = 3;
const HID_SUBCLASS_BOOT = 1;
const HID_PROTOCOL_KEYBOARD = 1;
const HID_PROTOCOL_MOUSE = 2;
const HID_BOOT_PROTOCOL = 0;

// ============================================================================
// TRB structure (16 bytes, 64-byte aligned rings)
// ============================================================================

const Trb = extern struct {
    param: u64 align(1),
    status: u32 align(1),
    control: u32 align(1),

    fn trbType(self: *const volatile Trb) u6 {
        return @truncate(self.control >> 10);
    }

    fn completionCode(self: *const volatile Trb) u8 {
        return @truncate(self.status >> 24);
    }

    fn slotId(self: *const volatile Trb) u8 {
        return @truncate(self.control >> 24);
    }

    fn cycle(self: *const volatile Trb) bool {
        return self.control & 1 != 0;
    }
};

// Event Ring Segment Table Entry
const ErstEntry = extern struct {
    ring_segment_base: u64 align(1),
    ring_segment_size: u16 align(1),
    _reserved: u16 align(1),
    _reserved2: u32 align(1),
};

// Slot Context (32 bytes)
const SlotContext = extern struct {
    field0: u32 align(1), // route_string[19:0], speed[23:20], mtt[25], hub[26], ctx_entries[31:27]
    field1: u32 align(1), // max_exit_latency[15:0], root_hub_port_num[23:16], num_ports[31:24]
    field2: u32 align(1), // tt_hub_slot[7:0], tt_port_num[15:8], ttt[17:16], interrupter[31:22]
    field3: u32 align(1), // device_address[7:0], slot_state[31:27]
    _reserved: [4]u32,
};

// Endpoint Context (32 bytes)
const EndpointContext = extern struct {
    field0: u32 align(1), // ep_state[2:0], mult[9:8], max_p_streams[14:10], lsa[15], interval[23:16], max_esit_hi[31:24]
    field1: u32 align(1), // cerr[2:1], ep_type[5:3], max_burst_size[15:8], max_packet_size[31:16]
    tr_dequeue: u64 align(1), // dequeue pointer (bit 0 = DCS)
    field2: u32 align(1), // average_trb_length[15:0], max_esit_lo[31:16]
    _reserved: [3]u32,
};

// Endpoint types
const EP_TYPE_ISOCH_OUT = 1;
const EP_TYPE_BULK_OUT = 2;
const EP_TYPE_INTERRUPT_OUT = 3;
const EP_TYPE_CONTROL = 4;
const EP_TYPE_ISOCH_IN = 5;
const EP_TYPE_BULK_IN = 6;
const EP_TYPE_INTERRUPT_IN = 7;

// Device Context (slot + 31 endpoints = 32 * 32 = 1024 bytes)
const DeviceContext = extern struct {
    slot: SlotContext,
    endpoints: [31]EndpointContext,
};

// Input Context has an extra Input Control Context at the front
const InputControlContext = extern struct {
    drop_flags: u32 align(1),
    add_flags: u32 align(1),
    _reserved: [5]u32,
    config_value: u32 align(1), // field7
};

// ============================================================================
// Ring sizes
// ============================================================================

const COMMAND_RING_SIZE = 64; // TRBs
const EVENT_RING_SIZE = 64;
const TRANSFER_RING_SIZE = 64;
const MAX_SLOTS = 16;
const MAX_HID_DEVICES = 4;
const DMA_REGION_SIZE: u64 = 64 * 4096; // 256 KB
const DMA_PAGES: u64 = DMA_REGION_SIZE / 4096;
const MAX_MMIO: usize = 32;
const MMIO_PROBE_PAGES: u64 = 16; // 64 KiB; xHCI BAR fits

// recv timeout while no client is parked. Short enough that xHCI events
// drain promptly; long enough that we don't burn the core.
const RECV_TIMEOUT_NS: u64 = 100_000; // 100 us

// ============================================================================
// MMIO access helpers
// ============================================================================

var mmio_base: u64 = 0;
var op_base: u64 = 0;
var rt_base: u64 = 0;
var db_base: u64 = 0;

fn readCap32(offset: u32) u32 {
    return @as(*const volatile u32, @ptrFromInt(mmio_base + offset)).*;
}

fn readOp32(offset: u32) u32 {
    return @as(*const volatile u32, @ptrFromInt(op_base + offset)).*;
}

fn writeOp32(offset: u32, val: u32) void {
    @as(*volatile u32, @ptrFromInt(op_base + offset)).* = val;
}

fn readOp64(offset: u32) u64 {
    return @as(*const volatile u64, @ptrFromInt(op_base + offset)).*;
}

fn writeOp64(offset: u32, val: u64) void {
    @as(*volatile u64, @ptrFromInt(op_base + offset)).* = val;
}

fn readRt32(offset: u32) u32 {
    return @as(*const volatile u32, @ptrFromInt(rt_base + offset)).*;
}

fn writeRt32(offset: u32, val: u32) void {
    @as(*volatile u32, @ptrFromInt(rt_base + offset)).* = val;
}

fn readRt64(offset: u32) u64 {
    return @as(*const volatile u64, @ptrFromInt(rt_base + offset)).*;
}

fn writeRt64(offset: u32, val: u64) void {
    @as(*volatile u64, @ptrFromInt(rt_base + offset)).* = val;
}

fn readPortsc(port: u32) u32 {
    return @as(*const volatile u32, @ptrFromInt(op_base + 0x400 + port * 0x10)).*;
}

fn writePortsc(port: u32, val: u32) void {
    @as(*volatile u32, @ptrFromInt(op_base + 0x400 + port * 0x10)).* = val;
}

fn ringDoorbell(slot: u8, target: u8) void {
    @as(*volatile u32, @ptrFromInt(db_base + @as(u64, slot) * 4)).* = target;
}

// ============================================================================
// DMA memory management (bump allocator within DMA region)
// ============================================================================

var dma_virt_base: u64 = 0;
var dma_phys_base: u64 = 0;
var dma_cursor: u64 = 0;

fn dmaAlloc(size: u64, alignment: u64) ?struct { virt: u64, phys: u64 } {
    const aligned_cursor = (dma_cursor + alignment - 1) & ~(alignment - 1);
    if (aligned_cursor + size > DMA_REGION_SIZE) return null;
    const virt = dma_virt_base + aligned_cursor;
    const phys = dma_phys_base + aligned_cursor;
    dma_cursor = aligned_cursor + size;
    return .{ .virt = virt, .phys = phys };
}

fn dmaVirtToPhys(virt: u64) u64 {
    return dma_phys_base + (virt - dma_virt_base);
}

// ============================================================================
// Command Ring
// ============================================================================

var cmd_ring_virt: u64 = 0;
var cmd_ring_phys: u64 = 0;
var cmd_ring_enqueue: u32 = 0;
var cmd_ring_cycle: u1 = 1;

fn cmdRingTrb(idx: u32) *volatile Trb {
    return @ptrFromInt(cmd_ring_virt + @as(u64, idx) * 16);
}

fn submitCommand(param: u64, status: u32, control_base: u32) void {
    const trb = cmdRingTrb(cmd_ring_enqueue);
    trb.param = param;
    trb.status = status;
    trb.control = control_base | @as(u32, cmd_ring_cycle);

    cmd_ring_enqueue += 1;
    if (cmd_ring_enqueue >= COMMAND_RING_SIZE - 1) {
        // Write link TRB to wrap
        const link = cmdRingTrb(cmd_ring_enqueue);
        link.param = cmd_ring_phys;
        link.status = 0;
        link.control = (@as(u32, TRB_TYPE_LINK) << 10) | @as(u32, cmd_ring_cycle) | (1 << 1); // Toggle Cycle
        cmd_ring_enqueue = 0;
        cmd_ring_cycle ^= 1;
    }

    // Ring host controller doorbell (slot 0, target 0)
    ringDoorbell(0, 0);
}

// ============================================================================
// Event Ring
// ============================================================================

var evt_ring_virt: u64 = 0;
var evt_ring_dequeue: u32 = 0;
var evt_ring_cycle: u1 = 1;

fn evtRingTrb(idx: u32) *const volatile Trb {
    return @ptrFromInt(evt_ring_virt + @as(u64, idx) * 16);
}

fn pollEvent() ?*const volatile Trb {
    const trb = evtRingTrb(evt_ring_dequeue);
    if (trb.cycle() != (evt_ring_cycle == 1)) return null;
    return trb;
}

fn advanceEventRing() void {
    evt_ring_dequeue += 1;
    if (evt_ring_dequeue >= EVENT_RING_SIZE) {
        evt_ring_dequeue = 0;
        evt_ring_cycle ^= 1;
    }
    // Update ERDP
    const phys = dmaVirtToPhys(evt_ring_virt) + @as(u64, evt_ring_dequeue) * 16;
    writeRt64(RT_ERDP, phys | (1 << 3)); // EHB bit to clear
}

fn waitForEvent(expected_type: u6, timeout_spins: u32) ?*const volatile Trb {
    var spins: u32 = 0;
    while (spins < timeout_spins) {
        if (pollEvent()) |trb| {
            if (trb.trbType() == expected_type) {
                return trb;
            }
            // Consume non-matching events
            advanceEventRing();
        }
        if (spins % 1000 == 0) _ = syscall.yieldEc(0);
        spins += 1;
    }
    return null;
}

fn waitForCommandCompletion() ?*const volatile Trb {
    return waitForEvent(TRB_TYPE_COMMAND_COMPLETION, 1_000_000);
}

// ============================================================================
// Transfer Rings (per endpoint per device)
// ============================================================================

const TransferRing = struct {
    virt: u64,
    phys: u64,
    enqueue: u32,
    cycle: u1,
};

var transfer_rings: [MAX_SLOTS][32]TransferRing = undefined;

fn initTransferRing(slot: u8, ep_index: u8) bool {
    const ring = dmaAlloc(TRANSFER_RING_SIZE * 16, 64) orelse return false;
    // Zero the ring
    const ptr: [*]u8 = @ptrFromInt(ring.virt);
    @memset(ptr[0 .. TRANSFER_RING_SIZE * 16], 0);

    transfer_rings[slot][ep_index] = .{
        .virt = ring.virt,
        .phys = ring.phys,
        .enqueue = 0,
        .cycle = 1,
    };
    return true;
}

fn queueTransferTrb(slot: u8, ep_index: u8, param: u64, status: u32, control_base: u32) void {
    var ring = &transfer_rings[slot][ep_index];
    const trb: *volatile Trb = @ptrFromInt(ring.virt + @as(u64, ring.enqueue) * 16);
    trb.param = param;
    trb.status = status;
    trb.control = control_base | @as(u32, ring.cycle);

    ring.enqueue += 1;
    if (ring.enqueue >= TRANSFER_RING_SIZE - 1) {
        // Link TRB
        const link: *volatile Trb = @ptrFromInt(ring.virt + @as(u64, ring.enqueue) * 16);
        link.param = ring.phys;
        link.status = 0;
        link.control = (@as(u32, TRB_TYPE_LINK) << 10) | @as(u32, ring.cycle) | (1 << 1);
        ring.enqueue = 0;
        ring.cycle ^= 1;
    }
}

// ============================================================================
// DCBAA and Device Contexts
// ============================================================================

var dcbaa_virt: u64 = 0;
var dcbaa_phys: u64 = 0;
var device_context_virt: [MAX_SLOTS]u64 = .{0} ** MAX_SLOTS;
var device_context_phys: [MAX_SLOTS]u64 = .{0} ** MAX_SLOTS;
var input_context_virt: u64 = 0;
var input_context_phys: u64 = 0;

// ============================================================================
// HID device tracking
// ============================================================================

const HidDevice = struct {
    slot_id: u8,
    ep_index: u8, // endpoint index in transfer ring array
    ep_dci: u8, // device context index for doorbell
    protocol: u8, // HID_PROTOCOL_KEYBOARD or HID_PROTOCOL_MOUSE
    active: bool,
    // Track previous keyboard state for key up/down detection
    prev_keys: [6]u8,
    prev_modifiers: u8,
};

var hid_devices: [MAX_HID_DEVICES]HidDevice = undefined;
var num_hid_devices: u32 = 0;

// ============================================================================
// Internal SPSC event queue (pushed by xHCI poll, popped on client poll)
// ============================================================================

const EVENT_QUEUE_CAP: usize = 64;

const QueuedEvent = struct {
    tag: usb_input.Tag,
    a: u64,
    b: u64,
    c: u64,
};

var event_queue: [EVENT_QUEUE_CAP]QueuedEvent = undefined;
var event_head: usize = 0; // next slot to read
var event_tail: usize = 0; // next slot to write
var event_count: usize = 0;

fn enqueueEvent(ev: QueuedEvent) void {
    if (event_count == EVENT_QUEUE_CAP) {
        // Drop oldest to make room — keystroke storms shouldn't lock us up.
        event_head = (event_head + 1) % EVENT_QUEUE_CAP;
        event_count -= 1;
    }
    event_queue[event_tail] = ev;
    event_tail = (event_tail + 1) % EVENT_QUEUE_CAP;
    event_count += 1;
}

fn dequeueEvent() ?QueuedEvent {
    if (event_count == 0) return null;
    const ev = event_queue[event_head];
    event_head = (event_head + 1) % EVENT_QUEUE_CAP;
    event_count -= 1;
    return ev;
}

// ============================================================================
// Controller state
// ============================================================================

var max_ports: u32 = 0;
var max_slots: u32 = 0;

// ============================================================================
// Controller initialization
// ============================================================================

fn initController() bool {
    // Read capability registers
    const cap_length: u8 = @truncate(readCap32(CAP_CAPLENGTH));
    op_base = mmio_base + cap_length;

    const rts_off = readCap32(CAP_RTSOFF) & ~@as(u32, 0x1F);
    rt_base = mmio_base + rts_off;

    const db_off = readCap32(CAP_DBOFF) & ~@as(u32, 0x3);
    db_base = mmio_base + db_off;

    const hcsparams1 = readCap32(CAP_HCSPARAMS1);
    max_slots = hcsparams1 & 0xFF;
    max_ports = (hcsparams1 >> 24) & 0xFF;

    if (max_slots > MAX_SLOTS) max_slots = MAX_SLOTS;

    const hcsparams2 = readCap32(CAP_HCSPARAMS2);
    const max_scratchpad_hi: u32 = (hcsparams2 >> 21) & 0x1F;
    const max_scratchpad_lo: u32 = (hcsparams2 >> 27) & 0x1F;
    const max_scratchpad = (max_scratchpad_hi << 5) | max_scratchpad_lo;

    log.print("[usb] xHCI caps: ");
    log.dec(max_ports);
    log.print(" ports, ");
    log.dec(max_slots);
    log.print(" slots\n");

    // Stop controller if running
    var cmd = readOp32(OP_USBCMD);
    if (cmd & USBCMD_RS != 0) {
        writeOp32(OP_USBCMD, cmd & ~USBCMD_RS);
        // Wait for halted
        var i: u32 = 0;
        while (i < 100_000) {
            if (readOp32(OP_USBSTS) & USBSTS_HCH != 0) break;
            i += 1;
        }
    }

    // Reset controller
    writeOp32(OP_USBCMD, USBCMD_HCRST);
    var i: u32 = 0;
    while (i < 1_000_000) {
        if (readOp32(OP_USBCMD) & USBCMD_HCRST == 0) break;
        i += 1;
    }
    if (readOp32(OP_USBCMD) & USBCMD_HCRST != 0) {
        log.print("[usb] reset timeout\n");
        return false;
    }

    // Wait for CNR to clear
    i = 0;
    while (i < 1_000_000) {
        if (readOp32(OP_USBSTS) & USBSTS_CNR == 0) break;
        i += 1;
    }
    if (readOp32(OP_USBSTS) & USBSTS_CNR != 0) {
        log.print("[usb] CNR timeout\n");
        return false;
    }

    // Configure max slots
    writeOp32(OP_CONFIG, max_slots);

    // Allocate DCBAA (max_slots + 1 entries, each 8 bytes, 64-byte aligned)
    const dcbaa_size = (max_slots + 1) * 8;
    const dcbaa = dmaAlloc(dcbaa_size, 64) orelse return false;
    dcbaa_virt = dcbaa.virt;
    dcbaa_phys = dcbaa.phys;
    @memset(@as([*]u8, @ptrFromInt(dcbaa.virt))[0..dcbaa_size], 0);
    writeOp64(OP_DCBAAP, dcbaa.phys);

    // Allocate scratchpad buffers if needed
    if (max_scratchpad > 0) {
        // Scratchpad buffer array
        const sp_array = dmaAlloc(max_scratchpad * 8, 64) orelse return false;
        const sp_arr_ptr: [*]volatile u64 = @ptrFromInt(sp_array.virt);

        var sp_i: u32 = 0;
        while (sp_i < max_scratchpad) {
            const sp_buf = dmaAlloc(4096, 4096) orelse return false;
            @memset(@as([*]u8, @ptrFromInt(sp_buf.virt))[0..4096], 0);
            sp_arr_ptr[sp_i] = sp_buf.phys;
            sp_i += 1;
        }

        // DCBAA[0] = scratchpad buffer array pointer
        const dcbaa_ptr: [*]volatile u64 = @ptrFromInt(dcbaa.virt);
        dcbaa_ptr[0] = sp_array.phys;
    }

    // Allocate command ring
    const cmd_ring = dmaAlloc(COMMAND_RING_SIZE * 16, 64) orelse return false;
    cmd_ring_virt = cmd_ring.virt;
    cmd_ring_phys = cmd_ring.phys;
    @memset(@as([*]u8, @ptrFromInt(cmd_ring.virt))[0 .. COMMAND_RING_SIZE * 16], 0);
    cmd_ring_enqueue = 0;
    cmd_ring_cycle = 1;
    writeOp64(OP_CRCR, cmd_ring.phys | 1); // RCS=1

    // Allocate event ring
    const evt_ring = dmaAlloc(EVENT_RING_SIZE * 16, 64) orelse return false;
    evt_ring_virt = evt_ring.virt;
    @memset(@as([*]u8, @ptrFromInt(evt_ring.virt))[0 .. EVENT_RING_SIZE * 16], 0);
    evt_ring_dequeue = 0;
    evt_ring_cycle = 1;

    // Event Ring Segment Table (1 entry)
    const erst = dmaAlloc(@sizeOf(ErstEntry), 64) orelse return false;
    const erst_entry: *volatile ErstEntry = @ptrFromInt(erst.virt);
    erst_entry.ring_segment_base = evt_ring.phys;
    erst_entry.ring_segment_size = EVENT_RING_SIZE;
    erst_entry._reserved = 0;
    erst_entry._reserved2 = 0;

    // Configure interrupter 0
    writeRt32(RT_ERSTSZ, 1);
    writeRt64(RT_ERDP, evt_ring.phys);
    writeRt64(RT_ERSTBA, erst.phys);
    // Enable interrupter
    writeRt32(RT_IMAN, readRt32(RT_IMAN) | 0x2);

    // Allocate shared input context (used for address device / configure endpoint)
    const input_ctx = dmaAlloc(33 * 32, 64) orelse return false; // input control + slot + 31 eps
    input_context_virt = input_ctx.virt;
    input_context_phys = input_ctx.phys;

    // Start controller
    cmd = readOp32(OP_USBCMD);
    writeOp32(OP_USBCMD, cmd | USBCMD_RS | USBCMD_INTE);

    // Wait for not halted
    i = 0;
    while (i < 100_000) {
        if (readOp32(OP_USBSTS) & USBSTS_HCH == 0) break;
        i += 1;
    }

    log.print("[usb] xHCI controller initialized\n");
    return true;
}

// ============================================================================
// USB Device Enumeration
// ============================================================================

fn enableSlot() ?u8 {
    submitCommand(0, 0, @as(u32, TRB_TYPE_ENABLE_SLOT) << 10);
    const evt = waitForCommandCompletion() orelse return null;
    if (evt.completionCode() != TRB_COMP_SUCCESS) return null;
    const slot = evt.slotId();
    advanceEventRing();
    return slot;
}

fn addressDevice(slot: u8, port: u32, speed: u32) bool {
    // Allocate output device context
    const dev_ctx = dmaAlloc(@sizeOf(DeviceContext), 64) orelse return false;
    @memset(@as([*]u8, @ptrFromInt(dev_ctx.virt))[0..@sizeOf(DeviceContext)], 0);
    device_context_virt[slot] = dev_ctx.virt;
    device_context_phys[slot] = dev_ctx.phys;

    // Set DCBAA entry
    const dcbaa_ptr: [*]volatile u64 = @ptrFromInt(dcbaa_virt);
    dcbaa_ptr[slot] = dev_ctx.phys;

    // Init transfer ring for default control endpoint (EP 0, DCI 1)
    if (!initTransferRing(slot, 1)) return false;

    // Build input context
    @memset(@as([*]u8, @ptrFromInt(input_context_virt))[0 .. 33 * 32], 0);

    const input_ctrl: *volatile InputControlContext = @ptrFromInt(input_context_virt);
    input_ctrl.add_flags = (1 << 0) | (1 << 1); // Slot Context + EP0

    // Slot context (at offset 32)
    const slot_ctx: *volatile SlotContext = @ptrFromInt(input_context_virt + 32);
    const speed_val: u32 = switch (speed) {
        SPEED_LOW => 2,
        SPEED_FULL => 1,
        SPEED_HIGH => 3,
        SPEED_SUPER => 4,
        else => 1,
    };
    slot_ctx.field0 = (speed_val << 20) | (1 << 27); // speed + context_entries=1
    slot_ctx.field1 = (port + 1) << 16; // root hub port number (1-based)

    // EP0 context (at offset 64 = 32 * 2)
    const ep0_ctx: *volatile EndpointContext = @ptrFromInt(input_context_virt + 64);
    const max_packet: u32 = switch (speed) {
        SPEED_LOW => 8,
        SPEED_FULL => 8,
        SPEED_HIGH => 64,
        SPEED_SUPER => 512,
        else => 8,
    };
    ep0_ctx.field1 = (EP_TYPE_CONTROL << 3) | (3 << 1) | (max_packet << 16); // CErr=3
    ep0_ctx.tr_dequeue = transfer_rings[slot][1].phys | 1; // DCS=1

    // Submit Address Device command
    submitCommand(input_context_phys, 0, (@as(u32, TRB_TYPE_ADDRESS_DEVICE) << 10) | (@as(u32, slot) << 24));
    const evt = waitForCommandCompletion() orelse return false;
    const cc = evt.completionCode();
    advanceEventRing();
    if (cc != TRB_COMP_SUCCESS) {
        log.print("[usb] address device failed\n");
        return false;
    }
    return true;
}

// ============================================================================
// Control Transfers
// ============================================================================

fn controlTransfer(
    slot: u8,
    request_type: u8,
    request: u8,
    value: u16,
    index: u16,
    length: u16,
    data_buf_phys: u64,
    data_buf_virt: u64,
    direction_in: bool,
) ?u16 {
    _ = data_buf_virt;
    const ep_index: u8 = 1; // default control endpoint

    // Setup TRB
    const setup_param: u64 = @as(u64, request_type) |
        (@as(u64, request) << 8) |
        (@as(u64, value) << 16) |
        (@as(u64, index) << 32) |
        (@as(u64, length) << 48);
    const trt: u32 = if (length > 0) (if (direction_in) @as(u32, 3) else @as(u32, 2)) else 0; // TRT field
    queueTransferTrb(slot, ep_index, setup_param, 8, (@as(u32, TRB_TYPE_SETUP) << 10) | (1 << 6) | (trt << 16)); // IDT=1

    // Data TRB (if needed)
    if (length > 0) {
        const dir_bit: u32 = if (direction_in) (1 << 16) else 0;
        queueTransferTrb(slot, ep_index, data_buf_phys, @as(u32, length), (@as(u32, TRB_TYPE_DATA) << 10) | dir_bit);
    }

    // Status TRB
    const status_dir: u32 = if (length > 0 and direction_in) 0 else (1 << 16);
    queueTransferTrb(slot, ep_index, 0, 0, (@as(u32, TRB_TYPE_STATUS) << 10) | (1 << 5) | status_dir); // IOC=1

    // Ring doorbell for EP0 (DCI=1)
    ringDoorbell(slot, 1);

    // Wait for transfer event
    const evt = waitForEvent(TRB_TYPE_TRANSFER_EVENT, 1_000_000) orelse return null;
    const cc = evt.completionCode();
    const residual: u16 = @truncate(evt.status & 0xFFFFFF);
    advanceEventRing();

    if (cc != TRB_COMP_SUCCESS and cc != TRB_COMP_SHORT_PACKET) return null;

    return length -| residual;
}

fn getDescriptor(slot: u8, desc_type: u8, desc_index: u8, length: u16, buf_phys: u64, buf_virt: u64) ?u16 {
    return controlTransfer(
        slot,
        0x80, // device-to-host, standard, device
        USB_REQ_GET_DESCRIPTOR,
        (@as(u16, desc_type) << 8) | desc_index,
        0,
        length,
        buf_phys,
        buf_virt,
        true,
    );
}

fn setConfiguration(slot: u8, config_value: u8) bool {
    const result = controlTransfer(
        slot,
        0x00, // host-to-device, standard, device
        USB_REQ_SET_CONFIGURATION,
        config_value,
        0,
        0,
        0,
        0,
        false,
    );
    return result != null;
}

fn setProtocol(slot: u8, interface: u16, protocol: u16) bool {
    const result = controlTransfer(
        slot,
        0x21, // host-to-device, class, interface
        USB_REQ_SET_PROTOCOL,
        protocol,
        interface,
        0,
        0,
        0,
        false,
    );
    return result != null;
}

fn setIdle(slot: u8, interface: u16) bool {
    const result = controlTransfer(
        slot,
        0x21,
        USB_REQ_SET_IDLE,
        0, // duration=0, report_id=0 (indefinite, all reports)
        interface,
        0,
        0,
        0,
        false,
    );
    return result != null;
}

// ============================================================================
// Endpoint Configuration
// ============================================================================

fn configureEndpoint(slot: u8, ep_addr: u8, ep_type_val: u8, max_packet: u16, interval: u8) bool {
    // EP address: bit 7 = direction (1=IN), bits 3:0 = number
    const ep_num = ep_addr & 0x0F;
    const ep_dir_in = (ep_addr & 0x80) != 0;
    const dci: u8 = ep_num * 2 + @as(u8, if (ep_dir_in) 1 else 0);

    if (!initTransferRing(slot, dci)) return false;

    // Build input context
    @memset(@as([*]u8, @ptrFromInt(input_context_virt))[0 .. 33 * 32], 0);

    const input_ctrl: *volatile InputControlContext = @ptrFromInt(input_context_virt);
    input_ctrl.add_flags = (1 << 0) | (@as(u32, 1) << @as(u5, @truncate(dci))); // Slot + this EP

    // Update slot context entries count
    const slot_ctx: *volatile SlotContext = @ptrFromInt(input_context_virt + 32);
    const out_slot: *const volatile SlotContext = @ptrFromInt(device_context_virt[slot]);
    slot_ctx.field0 = (out_slot.field0 & 0x07FFFFFF) | (@as(u32, dci) << 27);
    slot_ctx.field1 = out_slot.field1;
    slot_ctx.field2 = out_slot.field2;
    slot_ctx.field3 = out_slot.field3;

    // Endpoint context
    const ep_ctx: *volatile EndpointContext = @ptrFromInt(input_context_virt + 32 + @as(u64, dci) * 32);
    _ = ep_type_val;
    const xhci_ep_type: u32 = if (ep_dir_in) EP_TYPE_INTERRUPT_IN else EP_TYPE_INTERRUPT_OUT;
    ep_ctx.field0 = @as(u32, interval) << 16;
    ep_ctx.field1 = (3 << 1) | (xhci_ep_type << 3) | (@as(u32, max_packet) << 16); // CErr=3
    ep_ctx.tr_dequeue = transfer_rings[slot][dci].phys | 1; // DCS=1
    ep_ctx.field2 = 8; // average TRB length for interrupt

    submitCommand(input_context_phys, 0, (@as(u32, TRB_TYPE_CONFIGURE_ENDPOINT) << 10) | (@as(u32, slot) << 24));
    const evt = waitForCommandCompletion() orelse return false;
    const cc = evt.completionCode();
    advanceEventRing();
    if (cc != TRB_COMP_SUCCESS) {
        log.print("[usb] configure endpoint failed\n");
        return false;
    }
    return true;
}

// ============================================================================
// USB Enumeration (per-port)
// ============================================================================

// Scratch buffer for descriptors
var desc_buf_virt: u64 = 0;
var desc_buf_phys: u64 = 0;

fn enumeratePort(port: u32) void {
    var portsc = readPortsc(port);
    if (portsc & PORTSC_CCS == 0) return; // No device connected

    // Reset port — preserve only RW bits, clear RW1C bits by NOT setting them.
    writePortsc(port, (portsc & PORTSC_PP) | PORTSC_PR);

    // Wait for reset complete
    var i: u32 = 0;
    while (i < 500_000) {
        portsc = readPortsc(port);
        if (portsc & PORTSC_PRC != 0) break;
        if (i % 1000 == 0) _ = syscall.yieldEc(0);
        i += 1;
    }

    // Clear PRC
    writePortsc(port, (portsc & PORTSC_PP) | PORTSC_PRC);

    // Check port is enabled
    portsc = readPortsc(port);
    if (portsc & PORTSC_PED == 0) return;

    const speed = (portsc & PORTSC_SPEED_MASK) >> 10;

    log.print("[usb] device on port ");
    log.dec(port);
    log.print(", speed=");
    log.dec(speed);
    log.print("\n");

    // Enable slot
    const slot = enableSlot() orelse {
        log.print("[usb] enable slot failed\n");
        return;
    };

    // Address device
    if (!addressDevice(slot, port, speed)) return;

    log.print("[usb] addressed slot ");
    log.dec(slot);
    log.print("\n");

    // Get device descriptor (first 18 bytes)
    const dev_desc_len = getDescriptor(slot, USB_DESC_DEVICE, 0, 18, desc_buf_phys, desc_buf_virt) orelse {
        log.print("[usb] get device descriptor failed\n");
        return;
    };
    if (dev_desc_len < 18) return;

    const desc: [*]const u8 = @ptrFromInt(desc_buf_virt);

    // Get configuration descriptor (get header first to learn total length)
    _ = getDescriptor(slot, USB_DESC_CONFIGURATION, 0, 9, desc_buf_phys, desc_buf_virt) orelse return;
    const total_len: u16 = @as(u16, desc[2]) | (@as(u16, desc[3]) << 8);
    const config_value = desc[5];
    const actual_len: u16 = if (total_len > 256) 256 else total_len;

    // Get full configuration descriptor
    const full_len = getDescriptor(slot, USB_DESC_CONFIGURATION, 0, actual_len, desc_buf_phys, desc_buf_virt) orelse return;

    // Set configuration
    if (!setConfiguration(slot, config_value)) {
        log.print("[usb] set configuration failed\n");
        return;
    }

    // Parse interfaces looking for HID
    parseConfigDescriptor(slot, desc_buf_virt, full_len);
}

fn parseConfigDescriptor(slot: u8, buf_virt: u64, total_len: u16) void {
    const buf: [*]const u8 = @ptrFromInt(buf_virt);
    var offset: u16 = 0;
    var current_interface: u8 = 0;
    var current_hid_protocol: u8 = 0;
    var found_hid = false;

    while (offset + 2 <= total_len) {
        const desc_len = buf[offset];
        const desc_type = buf[offset + 1];
        if (desc_len == 0) break;
        if (offset + desc_len > total_len) break;

        if (desc_type == USB_DESC_INTERFACE and desc_len >= 9) {
            current_interface = buf[offset + 2];
            const iface_class = buf[offset + 5];
            const iface_subclass = buf[offset + 6];
            const iface_protocol = buf[offset + 7];

            if (iface_class == USB_CLASS_HID) {
                found_hid = true;
                current_hid_protocol = iface_protocol;

                const device_name: []const u8 = switch (iface_protocol) {
                    HID_PROTOCOL_KEYBOARD => "keyboard",
                    HID_PROTOCOL_MOUSE => "mouse",
                    else => "unknown HID",
                };
                log.print("[usb] found ");
                log.print(device_name);
                if (iface_subclass == HID_SUBCLASS_BOOT) {
                    log.print(" (boot protocol)");
                }
                log.print("\n");

                // Set boot protocol for keyboards and mice
                if (iface_subclass == HID_SUBCLASS_BOOT) {
                    _ = setProtocol(slot, current_interface, HID_BOOT_PROTOCOL);
                    _ = setIdle(slot, current_interface);
                }
            } else {
                found_hid = false;
            }
        } else if (desc_type == USB_DESC_ENDPOINT and desc_len >= 7 and found_hid) {
            const ep_addr = buf[offset + 2];
            const ep_attrs = buf[offset + 3];
            const ep_max_packet = @as(u16, buf[offset + 4]) | (@as(u16, buf[offset + 5]) << 8);
            const ep_interval = buf[offset + 6];

            // Only care about interrupt IN endpoints
            if ((ep_attrs & 0x03) == 0x03 and (ep_addr & 0x80) != 0) {
                if (configureEndpoint(slot, ep_addr, ep_attrs, ep_max_packet, ep_interval)) {
                    if (num_hid_devices < MAX_HID_DEVICES) {
                        const ep_num = ep_addr & 0x0F;
                        const dci = ep_num * 2 + 1; // IN endpoint DCI
                        hid_devices[num_hid_devices] = .{
                            .slot_id = slot,
                            .ep_index = dci,
                            .ep_dci = dci,
                            .protocol = current_hid_protocol,
                            .active = true,
                            .prev_keys = .{0} ** 6,
                            .prev_modifiers = 0,
                        };
                        num_hid_devices += 1;

                        // Queue initial interrupt IN transfer
                        queueInterruptIn(slot, dci);
                        ringDoorbell(slot, dci);
                    }
                }
            }
        }

        offset += desc_len;
    }
}

// ============================================================================
// HID Report Parsing
// ============================================================================

var report_buf_virt: u64 = 0;
var report_buf_phys: u64 = 0;

fn queueInterruptIn(slot: u8, dci: u8) void {
    // Each HID device gets its own section of the report buffer
    const dev_offset: u64 = @as(u64, slot) * 64; // 64 bytes per device
    queueTransferTrb(
        slot,
        dci,
        report_buf_phys + dev_offset,
        64, // max report size
        (@as(u32, TRB_TYPE_NORMAL) << 10) | (1 << 5), // IOC=1
    );
}

fn processKeyboardReport(dev: *HidDevice, data: [*]const u8) void {
    const modifiers = data[0];

    // Check modifier changes
    if (modifiers != dev.prev_modifiers) {
        var bit: u4 = 0;
        while (bit < 8) {
            const mask = @as(u8, 1) << @as(u3, @truncate(bit));
            const prev = dev.prev_modifiers & mask;
            const curr = modifiers & mask;
            if (prev != curr) {
                // Modifier keycodes are 0xE0 + bit
                const keycode: u8 = 0xE0 + @as(u8, bit);
                const state: usb_input.KeyState = if (curr != 0) .pressed else .released;
                enqueueEvent(.{
                    .tag = .keyboard,
                    .a = @as(u64, keycode),
                    .b = @intFromEnum(state),
                    .c = @as(u64, modifiers),
                });
            }
            bit += 1;
        }
        dev.prev_modifiers = modifiers;
    }

    // data[1] is reserved
    // data[2..8] are keycodes

    // Find released keys (in prev but not in current)
    for (dev.prev_keys) |prev_key| {
        if (prev_key == 0) continue;
        var still_pressed = false;
        for (data[2..8]) |curr_key| {
            if (curr_key == prev_key) {
                still_pressed = true;
                break;
            }
        }
        if (!still_pressed) {
            enqueueEvent(.{
                .tag = .keyboard,
                .a = @as(u64, prev_key),
                .b = @intFromEnum(usb_input.KeyState.released),
                .c = @as(u64, modifiers),
            });
        }
    }

    // Find newly pressed keys (in current but not in prev)
    for (data[2..8]) |curr_key| {
        if (curr_key == 0) continue;
        var was_pressed = false;
        for (dev.prev_keys) |prev_key| {
            if (prev_key == curr_key) {
                was_pressed = true;
                break;
            }
        }
        if (!was_pressed) {
            enqueueEvent(.{
                .tag = .keyboard,
                .a = @as(u64, curr_key),
                .b = @intFromEnum(usb_input.KeyState.pressed),
                .c = @as(u64, modifiers),
            });
        }
    }

    // Update state
    @memcpy(&dev.prev_keys, data[2..8]);
}

fn processMouseReport(dev: *HidDevice, data: [*]const u8) void {
    _ = dev;
    const buttons = data[0];
    const dx: i16 = @as(i16, @as(i8, @bitCast(data[1])));
    const dy: i16 = @as(i16, @as(i8, @bitCast(data[2])));

    // Only send if there's actual activity
    if (buttons != 0 or dx != 0 or dy != 0) {
        enqueueEvent(.{
            .tag = .mouse,
            .a = @as(u64, buttons),
            .b = usb_input.packI16(dx),
            .c = usb_input.packI16(dy),
        });
    }
}

// ============================================================================
// xHCI event-ring drain
// ============================================================================

fn drainXhciEvents() void {
    while (pollEvent()) |evt| {
        if (evt.trbType() == TRB_TYPE_TRANSFER_EVENT) {
            const cc = evt.completionCode();
            if (cc == TRB_COMP_SUCCESS or cc == TRB_COMP_SHORT_PACKET) {
                const slot_id = evt.slotId();
                // Find which HID device this belongs to
                for (hid_devices[0..num_hid_devices]) |*dev| {
                    if (dev.slot_id == slot_id and dev.active) {
                        const dev_offset = @as(u64, slot_id) * 64;
                        const report_data: [*]const u8 = @ptrFromInt(report_buf_virt + dev_offset);

                        if (dev.protocol == HID_PROTOCOL_KEYBOARD) {
                            processKeyboardReport(dev, report_data);
                        } else if (dev.protocol == HID_PROTOCOL_MOUSE) {
                            processMouseReport(dev, report_data);
                        }

                        // Re-queue interrupt transfer
                        queueInterruptIn(slot_id, dev.ep_dci);
                        ringDoorbell(slot_id, dev.ep_dci);
                        break;
                    }
                }
            }
        } else if (evt.trbType() == TRB_TYPE_PORT_STATUS_CHANGE) {
            // Could handle hot-plug here in the future
        }
        advanceEventRing();
    }
}

// ============================================================================
// Cap-table walks
// ============================================================================

const MmioEntry = struct {
    handle: HandleId,
    base_paddr: u64,
    size_pages: u64,
};

fn findPort(cap_table_base: u64) ?HandleId {
    var slot: u32 = caps.SLOT_FIRST_PASSED;
    while (slot < caps.HANDLE_TABLE_MAX) {
        const c = caps.readCap(cap_table_base, slot);
        if (c.handleType() == .port) return @truncate(slot);
        slot += 1;
    }
    return null;
}

fn scanMmioDeviceRegions(cap_table_base: u64, out: []MmioEntry) usize {
    var n: usize = 0;
    var slot: u32 = caps.SLOT_FIRST_PASSED;
    while (slot < caps.HANDLE_TABLE_MAX and n < out.len) {
        const c = caps.readCap(cap_table_base, slot);
        if (c.handleType() == .device_region) {
            const dev_type: u4 = @truncate(c.field0 & 0xF);
            if (dev_type == 0) {
                const paddr: u64 = ((c.field0 >> 4) & ((@as(u64, 1) << 48) - 1)) << 12;
                const size_pages: u64 = (c.field0 >> 52) & 0xFFF;
                if (size_pages != 0) {
                    out[n] = .{
                        .handle = @truncate(slot),
                        .base_paddr = paddr,
                        .size_pages = size_pages,
                    };
                    n += 1;
                }
            }
        }
        slot += 1;
    }
    return n;
}

/// Map the MMIO BAR temporarily, read xHCI HCIVERSION at offset 0x02
/// (capability-register layout starts at the BAR base; CAPLENGTH at
/// offset 0x00 and HCIVERSION at offset 0x02 form the standard xHCI
/// signature). Tears down the VMAR before returning.
fn probeXhci(m: MmioEntry) bool {
    const map_pages: u64 = if (m.size_pages > MMIO_PROBE_PAGES) MMIO_PROBE_PAGES else m.size_pages;

    const var_caps_word = caps.VmarCap{
        .r = true,
        .w = false,
        .mmio = true,
    };
    const props: u64 = (1 << 5) | // cch=1 (uc)
        (0 << 3) | // sz=0 (4 KiB)
        0b001; // cur_rwx=r
    const cvar = syscall.createVmar(
        @as(u64, var_caps_word.toU16()),
        props,
        map_pages,
        0,
        0,
    );
    if (cvar.v1 < 16) return false;
    const vmar_handle: HandleId = @truncate(cvar.v1 & 0xFFF);
    const vmar_base: u64 = cvar.v2;

    const mm = syscall.mapMmio(vmar_handle, m.handle);
    if (mm.v1 != 0) {
        _ = syscall.delete(vmar_handle);
        return false;
    }

    // CAPLENGTH at 0x00 (u8) — must be plausible (>= 0x20, <= 0xFF).
    // HCIVERSION at 0x02 (u16) — xHCI 1.0 reports 0x0100, xHCI 1.1
    // reports 0x0110, etc. Match anything in 0x0100..0x01FF.
    const cap_word: *const volatile u32 = @ptrFromInt(vmar_base + 0x00);
    const w = cap_word.*;

    _ = syscall.delete(vmar_handle);

    if (w == 0 or w == 0xFFFF_FFFF) return false;
    const cap_length: u8 = @truncate(w);
    const hci_version: u16 = @truncate(w >> 16);
    if (cap_length < 0x20) return false;
    return (hci_version & 0xFF00) == 0x0100;
}

// ============================================================================
// DMA setup (mirrors nvme.zig double-mapping pattern)
// ============================================================================

fn setupDma(device_handle: HandleId) bool {
    // Allocate the DMA-backing page_frame.
    const dma_pf_caps = caps.PfCap{ .r = true, .w = true };
    const dma_pf = syscall.createPageFrame(@as(u64, dma_pf_caps.toU16()), 0, DMA_PAGES);
    if (dma_pf.v1 < 16) {
        log.print("[usb] FATAL: DMA pf alloc failed\n");
        return false;
    }
    const dma_pf_handle: HandleId = @truncate(dma_pf.v1 & 0xFFF);

    // (1) Regular VMAR for CPU access.
    const cpu_var_caps = caps.VmarCap{ .r = true, .w = true };
    const cpu_props: u64 = (0 << 5) | (0 << 3) | 0b011; // cch=wb, sz=4K, r|w
    const cpu_cvar = syscall.createVmar(
        @as(u64, cpu_var_caps.toU16()),
        cpu_props,
        DMA_PAGES,
        0,
        0,
    );
    if (cpu_cvar.v1 < 16) {
        log.print("[usb] FATAL: DMA CPU vmar create failed\n");
        return false;
    }
    const cpu_vmar_handle: HandleId = @truncate(cpu_cvar.v1 & 0xFFF);
    dma_virt_base = cpu_cvar.v2;

    const cpu_pairs = [_]u64{ 0, dma_pf_handle };
    if (syscall.mapPf(cpu_vmar_handle, cpu_pairs[0..]).v1 != 0) {
        log.print("[usb] FATAL: DMA CPU mapPf failed\n");
        return false;
    }

    // (2) DMA VMAR bound to the xHCI device for IOMMU translation.
    const dma_var_caps = caps.VmarCap{ .r = true, .w = true, .dma = true };
    const dma_props: u64 = (0 << 5) | (0 << 3) | 0b011; // cch=wb, sz=4K, r|w
    const dma_cvar = syscall.createVmar(
        @as(u64, dma_var_caps.toU16()),
        dma_props,
        DMA_PAGES,
        0,
        device_handle,
    );
    if (dma_cvar.v1 < 16) {
        log.print("[usb] FATAL: DMA device vmar create failed\n");
        return false;
    }
    const dma_vmar_handle: HandleId = @truncate(dma_cvar.v1 & 0xFFF);
    dma_phys_base = dma_cvar.v2;

    const dma_pairs = [_]u64{ 0, dma_pf_handle };
    if (syscall.mapPf(dma_vmar_handle, dma_pairs[0..]).v1 != 0) {
        log.print("[usb] FATAL: DMA device mapPf failed\n");
        return false;
    }

    // Zero entire DMA region.
    @memset(@as([*]u8, @ptrFromInt(dma_virt_base))[0..DMA_REGION_SIZE], 0);
    dma_cursor = 0;
    return true;
}

fn mapXhciMmio(device_handle: HandleId, size_pages: u64) bool {
    const mmio_var_caps = caps.VmarCap{
        .r = true,
        .w = true,
        .mmio = true,
    };
    const mmio_props: u64 = (1 << 5) | (0 << 3) | 0b011; // cch=uc, sz=4K, r|w
    const cvar = syscall.createVmar(
        @as(u64, mmio_var_caps.toU16()),
        mmio_props,
        size_pages,
        0,
        0,
    );
    if (cvar.v1 < 16) return false;
    const vmar_handle: HandleId = @truncate(cvar.v1 & 0xFFF);
    mmio_base = cvar.v2;
    if (syscall.mapMmio(vmar_handle, device_handle).v1 != 0) return false;
    return true;
}

// ============================================================================
// Main
// ============================================================================

pub fn main(cap_table_base: u64) void {
    log.init(cap_table_base);
    log.print("[usb] starting\n");

    const port_handle = findPort(cap_table_base) orelse {
        log.print("[usb] FATAL: no port handle in cap table\n");
        park();
    };

    var mmios: [MAX_MMIO]MmioEntry = undefined;
    const n = scanMmioDeviceRegions(cap_table_base, &mmios);
    log.print("[usb] scanning ");
    log.dec(n);
    log.print(" MMIO device_region(s) for xHCI\n");

    var xhci_dev: ?HandleId = null;
    var xhci_size_pages: u64 = 0;
    var i: usize = 0;
    while (i < n) {
        const m = mmios[i];
        if (probeXhci(m)) {
            log.print("[usb]   xHCI at handle=");
            log.dec(m.handle);
            log.print(" paddr=0x");
            log.hex64(m.base_paddr);
            log.print("\n");
            xhci_dev = m.handle;
            xhci_size_pages = m.size_pages;
            break;
        }
        i += 1;
    }
    if (xhci_dev == null) {
        log.print("[usb] FATAL: no xHCI controller found\n");
        park();
    }

    if (!setupDma(xhci_dev.?)) park();
    if (!mapXhciMmio(xhci_dev.?, xhci_size_pages)) {
        log.print("[usb] FATAL: xHCI MMIO map failed\n");
        park();
    }

    // Allocate descriptor and report buffers from DMA
    const desc_alloc = dmaAlloc(512, 64) orelse {
        log.print("[usb] desc buf alloc failed\n");
        park();
    };
    desc_buf_virt = desc_alloc.virt;
    desc_buf_phys = desc_alloc.phys;

    const report_alloc = dmaAlloc(MAX_SLOTS * 64, 64) orelse {
        log.print("[usb] report buf alloc failed\n");
        park();
    };
    report_buf_virt = report_alloc.virt;
    report_buf_phys = report_alloc.phys;

    // Initialize xHCI controller
    if (!initController()) {
        log.print("[usb] controller init failed\n");
        park();
    }

    // Small delay for port state to settle
    var settle: u32 = 0;
    while (settle < 100_000) {
        _ = syscall.yieldEc(0);
        settle += 1;
    }

    // Drain any port status change events accumulated during init.
    while (pollEvent()) |evt| {
        if (evt.trbType() == TRB_TYPE_PORT_STATUS_CHANGE) {
            const port_id: u32 = @truncate(evt.param >> 24);
            if (port_id > 0) {
                const portsc = readPortsc(port_id - 1);
                writePortsc(port_id - 1, (portsc & PORTSC_PP) | PORTSC_CSC | PORTSC_PRC | PORTSC_WRC);
            }
        }
        advanceEventRing();
    }

    // Enumerate all ports.
    var port: u32 = 0;
    while (port < max_ports) {
        enumeratePort(port);
        port += 1;
    }

    if (num_hid_devices == 0) {
        log.print("[usb] no HID devices found\n");
    } else {
        log.print("[usb] ");
        log.dec(num_hid_devices);
        log.print(" HID device(s) ready\n");
    }

    serveLoop(port_handle);
}

fn serveLoop(port: HandleId) noreturn {
    log.print("[usb] entering serve loop\n");
    while (true) {
        // Drain any pending xHCI events first so the queue stays warm
        // even when no client is waiting.
        drainXhciEvents();

        const got = syscall.recv(port, RECV_TIMEOUT_NS);
        if (got.regs.v1 == @intFromEnum(errors.Error.E_TIMEOUT)) continue;

        // §[reply] reply_handle_id at returned syscall-word bits 32-43.
        const reply_handle: u12 = @truncate((got.word >> 32) & 0xFFF);

        const op_raw = got.regs.v3;
        const op: usb_input.Op = @enumFromInt(op_raw);

        var rep_v1: u64 = 0; // count
        var rep_v2: u64 = 0; // tag
        var rep_v3: u64 = 0;
        var rep_v4: u64 = 0;
        var rep_v5: u64 = 0;

        switch (op) {
            .poll => {
                // One last drain to maximise the chance we have an event
                // ready before replying — this collapses the recv-poll
                // round-trip latency for keypresses arriving just-in-time.
                drainXhciEvents();
                if (dequeueEvent()) |ev| {
                    rep_v1 = 1;
                    rep_v2 = @intFromEnum(ev.tag);
                    rep_v3 = ev.a;
                    rep_v4 = ev.b;
                    rep_v5 = ev.c;
                }
            },
            else => {
                // Unknown op — return zero events. The wire spec keeps
                // us forward-compatible with future Op additions.
            },
        }

        _ = syscall.issueReg(
            .reply,
            syscall.extraReplyHandle(reply_handle),
            .{
                .v1 = rep_v1,
                .v2 = rep_v2,
                .v3 = rep_v3,
                .v4 = rep_v4,
                .v5 = rep_v5,
            },
        );
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
