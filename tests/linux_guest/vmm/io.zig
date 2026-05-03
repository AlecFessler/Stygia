/// I/O port emulation for non-serial devices.
/// Stubs for PIC, PIT, PS/2, CMOS, PCI, VGA, etc.
/// These are needed because Linux probes many legacy devices during boot.
const lib = @import("lib");

const log = @import("log.zig");
const serial = @import("serial.zig");

const GuestState = @import("main.zig").GuestState;
const syscall = lib.syscall;

// PIC
const PIC1_CMD: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_CMD: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

// PIT
const PIT_CH0: u16 = 0x40;
const PIT_CH1: u16 = 0x41;
const PIT_CH2: u16 = 0x42;
const PIT_CMD: u16 = 0x43;

// PS/2
const PS2_DATA: u16 = 0x60;
const PS2_STATUS: u16 = 0x64;

// CMOS/RTC
const CMOS_ADDR: u16 = 0x70;
const CMOS_DATA: u16 = 0x71;

// POST diagnostic
const POST_PORT: u16 = 0x80;

// PCI config space
const PCI_CONFIG_ADDR: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

// Shadow state
var cmos_index: u8 = 0;
pub var pic1_mask: u8 = 0xFF;
var pic2_mask: u8 = 0xFF;

// PIC initialization tracking
// ICW sequence: ICW1 (cmd) → ICW2 (data, vector offset) → ICW3 (data) → ICW4 (data)
const PicPhase = enum { ready, icw2, icw3, icw4 };
var pic1_phase: PicPhase = .ready;
var pic2_phase: PicPhase = .ready;
var pci_config_addr: u32 = 0;
pub var pic1_vector_base: u8 = 0x08; // Default: IRQ0 → INT 8
pub var pic2_vector_base: u8 = 0x70; // Default: IRQ8 → INT 0x70

// PIT (8254) emulation state
// PIT frequency: 1,193,182 Hz ≈ 838.1 ns per tick
const PIT_NS_PER_TICK: u64 = 838; // ~838.1 ns

// Channel 0 state
var pit_ch0_reload: u16 = 0; // reload value (0 = 65536)
var pit_ch0_start_ns: u64 = 0; // host timestamp when counter started
var pit_ch0_last_irq_ns: u64 = 0; // last time we fired IRQ
var pit_ch0_latched: bool = false; // latch command pending
var pit_ch0_latch_val: u16 = 0; // latched count value
var pit_ch0_read_hi: bool = false; // next read is high byte (for lobyte/hibyte access)
var pit_ch0_write_hi: bool = false; // next write is high byte
var pit_ch0_mode: u8 = 0; // operating mode
var pit_ch0_access: u8 = 3; // access mode: 3 = lobyte/hibyte

// Channel 2 state (speaker/gate, used for calibration too)
var pit_ch2_reload: u16 = 0;
var pit_ch2_start_ns: u64 = 0;
var pit_ch2_latched: bool = false;
var pit_ch2_latch_val: u16 = 0;
var pit_ch2_read_hi: bool = false;
var pit_ch2_write_hi: bool = false;
var pit_ch2_mode: u8 = 0;
var pit_ch2_access: u8 = 3;
var pit_ch2_gate: bool = false; // gate input (controlled via port 0x61 bit 0), default LOW on reset
var port61_val: u8 = 0; // shadow of last value written to port 0x61

noinline fn pitGetCount(reload: u16, start_ns: u64) u16 {
    const now = syscall.timeMonotonic().v1;
    const elapsed_ns = now -% start_ns;
    const reload_val: u64 = if (reload == 0) 65536 else @as(u64, reload);
    // How many ticks elapsed
    const ticks = elapsed_ns / PIT_NS_PER_TICK;
    // Current count = reload - (ticks mod reload)
    const phase = ticks % reload_val;
    const count = reload_val - phase;
    return @truncate(if (count == reload_val) reload_val else count);
}

noinline fn handlePitCommand(value: u8) void {
    const channel: u2 = @truncate((value >> 6) & 0x3);
    const access: u2 = @truncate((value >> 4) & 0x3);
    const mode: u3 = @truncate((value >> 1) & 0x7);

    if (access == 0) {
        // Latch command
        if (channel == 0) {
            pit_ch0_latch_val = pitGetCount(pit_ch0_reload, pit_ch0_start_ns);
            pit_ch0_latched = true;
            pit_ch0_read_hi = false;
        } else if (channel == 2) {
            pit_ch2_latch_val = pitGetCount(pit_ch2_reload, pit_ch2_start_ns);
            pit_ch2_latched = true;
            pit_ch2_read_hi = false;
        }
        return;
    }

    // Mode/access command
    if (channel == 0) {
        pit_ch0_access = access;
        pit_ch0_mode = mode;
        pit_ch0_write_hi = false;
        pit_ch0_read_hi = false;
    } else if (channel == 2) {
        pit_ch2_access = access;
        pit_ch2_mode = mode;
        pit_ch2_write_hi = false;
        pit_ch2_read_hi = false;
    }
}

noinline fn handlePitWrite(channel: u2, value: u8) void {
    if (channel == 0) {
        if (pit_ch0_access == 3) {
            // lobyte/hibyte
            if (!pit_ch0_write_hi) {
                pit_ch0_reload = (pit_ch0_reload & 0xFF00) | @as(u16, value);
                pit_ch0_write_hi = true;
            } else {
                pit_ch0_reload = (pit_ch0_reload & 0x00FF) | (@as(u16, value) << 8);
                pit_ch0_write_hi = false;
                pit_ch0_start_ns = syscall.timeMonotonic().v1;
            }
        } else if (pit_ch0_access == 1) {
            // lobyte only
            pit_ch0_reload = value;
            pit_ch0_start_ns = syscall.timeMonotonic().v1;
        } else if (pit_ch0_access == 2) {
            // hibyte only
            pit_ch0_reload = @as(u16, value) << 8;
            pit_ch0_start_ns = syscall.timeMonotonic().v1;
        }
    } else if (channel == 2) {
        if (pit_ch2_access == 3) {
            if (!pit_ch2_write_hi) {
                pit_ch2_reload = (pit_ch2_reload & 0xFF00) | @as(u16, value);
                pit_ch2_write_hi = true;
            } else {
                pit_ch2_reload = (pit_ch2_reload & 0x00FF) | (@as(u16, value) << 8);
                pit_ch2_write_hi = false;
                pit_ch2_start_ns = syscall.timeMonotonic().v1;
            }
        } else if (pit_ch2_access == 1) {
            pit_ch2_reload = value;
            pit_ch2_start_ns = syscall.timeMonotonic().v1;
        } else if (pit_ch2_access == 2) {
            pit_ch2_reload = @as(u16, value) << 8;
            pit_ch2_start_ns = syscall.timeMonotonic().v1;
        }
    }
}

noinline fn handlePitRead(channel: u2) u32 {
    if (channel == 0) {
        var val: u16 = undefined;
        if (pit_ch0_latched) {
            val = pit_ch0_latch_val;
        } else {
            val = pitGetCount(pit_ch0_reload, pit_ch0_start_ns);
        }
        if (pit_ch0_access == 3) {
            if (!pit_ch0_read_hi) {
                pit_ch0_read_hi = true;
                return val & 0xFF;
            } else {
                pit_ch0_read_hi = false;
                if (pit_ch0_latched) pit_ch0_latched = false;
                return (val >> 8) & 0xFF;
            }
        } else if (pit_ch0_access == 1) {
            if (pit_ch0_latched) pit_ch0_latched = false;
            return val & 0xFF;
        } else {
            if (pit_ch0_latched) pit_ch0_latched = false;
            return (val >> 8) & 0xFF;
        }
    } else if (channel == 2) {
        var val: u16 = undefined;
        if (pit_ch2_latched) {
            val = pit_ch2_latch_val;
        } else {
            val = pitGetCount(pit_ch2_reload, pit_ch2_start_ns);
        }
        if (pit_ch2_access == 3) {
            if (!pit_ch2_read_hi) {
                pit_ch2_read_hi = true;
                return val & 0xFF;
            } else {
                pit_ch2_read_hi = false;
                if (pit_ch2_latched) pit_ch2_latched = false;
                return (val >> 8) & 0xFF;
            }
        } else if (pit_ch2_access == 1) {
            if (pit_ch2_latched) pit_ch2_latched = false;
            return val & 0xFF;
        } else {
            if (pit_ch2_latched) pit_ch2_latched = false;
            return (val >> 8) & 0xFF;
        }
    }
    return 0;
}

/// Check if PIT channel 0 has fired and assert IOAPIC IRQ if so.
/// ACPI MADT has IRQ0→GSI2 override, so we assert IOAPIC pin 2.
/// Coalesces: won't re-fire if the previous timer vector is still in the
/// LAPIC pipeline (IRR or ISR), preventing timer starvation of serial.
pub noinline fn pitCheckIrq() void {
    if (pit_ch0_reload == 0 and pit_ch0_mode == 0) return;
    if (pit_ch0_mode != 2 and pit_ch0_mode != 3 and pit_ch0_mode != 0) return;

    const reload_val: u64 = if (pit_ch0_reload == 0) 65536 else @as(u64, pit_ch0_reload);
    const period_ns = reload_val * PIT_NS_PER_TICK;
    const now = syscall.timeMonotonic().v1;

    if (pit_ch0_mode == 0) {
        if (pit_ch0_last_irq_ns == 0 and pit_ch0_start_ns > 0) {
            if (now -% pit_ch0_start_ns >= period_ns) {
                pit_ch0_last_irq_ns = now;
                _ = syscall.vmInjectIrq(@truncate(@import("main.zig").vm_handle & 0xFFF), 2, 1);
            }
        }
    } else {
        if (pit_ch0_start_ns == 0) return;
        if (now -% pit_ch0_last_irq_ns >= period_ns) {
            pit_ch0_last_irq_ns = now;
            _ = syscall.vmInjectIrq(@truncate(@import("main.zig").vm_handle & 0xFFF), 2, 1);
            _ = syscall.vmInjectIrq(@truncate(@import("main.zig").vm_handle & 0xFFF), 2, 0);
        }
    }
}

pub fn handleOut(port: u16, size: u8, value: u32, state: *GuestState) void {
    _ = state;
    _ = size;

    if (serial.isSerialPort(port)) {
        serial.handleOut(port, @truncate(value));
        return;
    }

    switch (port) {
        PIC1_CMD => {
            const v: u8 = @truncate(value);
            if (v & 0x10 != 0) { // ICW1
                pic1_phase = .icw2;
            }
            // OCW2 (EOI): ignore
        },
        PIC1_DATA => {
            const v: u8 = @truncate(value);
            switch (pic1_phase) {
                .icw2 => {
                    pic1_vector_base = v;
                    pic1_phase = .icw3;
                },
                .icw3 => {
                    pic1_phase = .icw4;
                },
                .icw4 => {
                    pic1_phase = .ready;
                },
                .ready => {
                    pic1_mask = v;
                }, // OCW1: interrupt mask
            }
        },
        PIC2_CMD => {
            const v: u8 = @truncate(value);
            if (v & 0x10 != 0) {
                pic2_phase = .icw2;
            }
        },
        PIC2_DATA => {
            const v: u8 = @truncate(value);
            switch (pic2_phase) {
                .icw2 => {
                    pic2_vector_base = v;
                    pic2_phase = .icw3;
                },
                .icw3 => {
                    pic2_phase = .icw4;
                },
                .icw4 => {
                    pic2_phase = .ready;
                },
                .ready => {
                    pic2_mask = v;
                },
            }
        },
        PIT_CMD => handlePitCommand(@truncate(value)),
        PIT_CH0 => handlePitWrite(0, @truncate(value)),
        PIT_CH2 => handlePitWrite(2, @truncate(value)),
        PIT_CH1 => {}, // Channel 1 not used
        PS2_DATA, PS2_STATUS => {},
        CMOS_ADDR => cmos_index = @truncate(value & 0x7F),
        CMOS_DATA => {},
        POST_PORT => {}, // POST codes — silently ignore
        // VGA registers
        0x3C0...0x3DA => {},
        // PCI config
        PCI_CONFIG_ADDR => {
            pci_config_addr = value;
        },
        PCI_CONFIG_DATA...PCI_CONFIG_DATA + 3 => {},
        // DMA controller
        0x00...0x0F => {},
        0xC0...0xDF => {},
        0x81...0x8F => {}, // DMA page registers (0x80 handled as POST_PORT above)
        // Port 0x61: NMI status / speaker
        // Bit 0: Gate for PIT channel 2
        // Bit 1: Speaker data enable
        0x61 => {
            const v: u8 = @truncate(value);
            const old_gate = pit_ch2_gate;
            pit_ch2_gate = (v & 1) != 0;
            port61_val = v;
            if (pit_ch2_gate and !old_gate) {
                // Rising edge on gate restarts the counter
                pit_ch2_start_ns = syscall.timeMonotonic().v1;
            }
        },
        // ELCR (edge/level control)
        0x4D0, 0x4D1 => {},
        else => {},
    }
}

pub fn handleIn(port: u16, size: u8, state: *GuestState) u32 {
    _ = state;
    _ = size;

    if (serial.isSerialPort(port)) {
        return serial.handleIn(port);
    }

    return switch (port) {
        PIC1_CMD => 0x00,
        PIC1_DATA => pic1_mask,
        PIC2_CMD => 0x00,
        PIC2_DATA => pic2_mask,
        PIT_CH0 => handlePitRead(0),
        PIT_CH2 => handlePitRead(2),
        PIT_CH1 => 0x00,
        PS2_STATUS => 0x00, // No PS/2 data
        PS2_DATA => 0x00,
        CMOS_DATA => handleCmosRead(cmos_index),
        PCI_CONFIG_ADDR...PCI_CONFIG_ADDR + 3 => 0x00, // PCI config address readback
        PCI_CONFIG_DATA...PCI_CONFIG_DATA + 3 => 0xFFFFFFFF, // No PCI devices
        // Port 0x61: NMI status / speaker control readback
        // Bit 0: Timer 2 gate status
        // Bit 5: Timer 2 output status
        0x61 => blk: {
            var v: u32 = @as(u32, port61_val) & 0x03; // Return gate bits as written
            // Timer 2 output (bit 5) depends on PIT mode
            if (pit_ch2_reload > 0 and pit_ch2_gate) {
                if (pit_ch2_mode == 0) {
                    // Mode 0 (interrupt on terminal count): output starts LOW,
                    // goes HIGH when count reaches 0.
                    const now = syscall.timeMonotonic().v1;
                    const elapsed_ns = now -% pit_ch2_start_ns;
                    const reload_u64: u64 = if (pit_ch2_reload == 0) 65536 else @as(u64, pit_ch2_reload);
                    const total_ns = reload_u64 * PIT_NS_PER_TICK;
                    if (elapsed_ns >= total_ns) {
                        v |= 0x20; // Output HIGH after terminal count
                    }
                } else if (pit_ch2_mode == 3 or pit_ch2_mode == 2) {
                    // Mode 3 (square wave): output toggles at half the reload value
                    // Mode 2 (rate generator): output is LOW for one tick, HIGH otherwise
                    const count = pitGetCount(pit_ch2_reload, pit_ch2_start_ns);
                    if (count > pit_ch2_reload / 2) v |= 0x20;
                } else {
                    // Other modes: report output high (safe default)
                    v |= 0x20;
                }
            }
            break :blk v;
        },
        // VGA
        0x3C0...0x3DA => 0x00,
        // ELCR
        0x4D0, 0x4D1 => 0x00,
        else => 0xFF,
    };
}

fn handleCmosRead(index: u8) u32 {
    return switch (index) {
        // Memory size fields
        0x15 => 0x00, // Base memory low
        0x16 => 0x02, // Base memory high (512 KB)
        0x17 => 0x00, // Extended memory low
        0x18 => 0x00, // Extended memory high
        // RTC fields — return zeros (no real clock)
        0x00...0x09 => 0x00,
        0x0A => 0x26, // Status A: divider + rate
        0x0B => 0x02, // Status B: 24hr mode
        0x0C => 0x00, // Status C
        0x0D => 0x80, // Status D: valid RAM
        else => 0x00,
    };
}
