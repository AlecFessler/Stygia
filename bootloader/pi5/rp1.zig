//! RP1 internal bring-up: `clk_uart` and the GPIO 14/15 pin mux.
//!
//! WHY this exists. `pcie.zig` trains the link and enumerates RP1, after which
//! uart0 at CPU 0x1F_0003_0000 reads as a genuine PL011 (PCellID 0xB105F00D). That
//! is necessary but not sufficient: a PL011 with no baud clock cannot shift a bit
//! out, and a TXD signal that is not routed to a pad cannot leave the package.
//! Both of those are RP1-internal state, both are wiped by the PERST# the loader
//! issues, and neither is restored by anything else in the loader. Measured at
//! handoff before this module existed: CR=0x300 (TXE|RXE but UARTEN clear),
//! IBRD=0, FBRD=0 — firmware had never touched the UART, because the link was down.
//!
//! ADDRESS TRANSLATION. RP1 BAR1 = PCI 0x0 = CPU 0x1F_0000_0000, 4 MiB (the value
//! `pcie.setupRp1Bars` programmes, confirmed against `/proc/iomem`). RP1's internal
//! bus base is 0xc0_40000000, so internal 0xc0_400X_XXXX appears at CPU
//! 0x1F_00X_XXXX. The three windows used here come from the live devicetree, read
//! off the booted Pi rather than from documentation:
//!
//!   /axi/pcie@120000/rp1/clocks@18000  reg = <0xc0 0x40018000 0x0 0x10038>
//!       -> CPU 0x1F_0001_8000
//!   /axi/pcie@120000/rp1/gpio@d0000    reg = <0xc0 0x400d0000 0x0 0xc000>,
//!                                            <0xc0 0x400e0000 0x0 0xc000>,
//!                                            <0xc0 0x400f0000 0x0 0xc000>
//!       -> CPU 0x1F_000D_0000 (io banks), 0x1F_000E_0000 (rio),
//!          0x1F_000F_0000 (pads)
//!
//! The three `reg` entries are index 0/1/2 = gpio_base / rio_base / pads_base in
//! `pinctrl-rp1.c:rp1_pinctrl_probe` (rpi-6.6.y). Only gpio_base and pads_base are
//! needed: the peripheral drives the pad through the CTRL register's OEOVER/OUTOVER
//! overrides, not through rio, and rio was measured to have OE=0 on the live system
//! with uart0 working. Note there is NO fourth `reg` entry, so `dummy_base` is NULL
//! on this board and the driver's "6 pipelined writes to the RC Slot Control
//! register" L1-wake fence (`pinctrl-rp1.c:586`) is not in play — nor could it be
//! here, since the loader never lets the link enter L1.
//!
//! WHAT HAS TO HAPPEN, and how each fact was established:
//!
//!   1. `clk_uart` must run at 50 MHz. Its parent is NOT a PLL: `clk_summary` on
//!      the booted Pi shows `clk_uart` nested directly under `xosc`, and
//!      CLK_UART_CTRL reads AUXSRC=2 which is `parents[2] = "xosc"` in
//!      `clk-rp1.c:[RP1_CLK_UART]`. xosc is RP1's 50 MHz crystal, always running.
//!      So no PLL bring-up is required at all — one divider and one mux select.
//!      This is the single most load-bearing measurement in this module: the reset
//!      default of AUXSRC is 0, which selects `pll_sys_pri_ph`, a PLL that is
//!      almost certainly powered down after PERST#. Leaving AUXSRC alone would
//!      leave the UART with no clock.
//!
//!   2. GPIO 14/15 must select FUNCSEL 4. `/sys/kernel/debug/pinctrl/...`/pins`
//!      reports `pin 14 ... function alt4 (uart0)`, and the DT group
//!      `rp1_uart0_14_15` selects function `uart0` on gpio14 (bias-disable) and
//!      gpio15 (bias-pull-up).
//!
//!   3. The pads must have their output driver enabled and input buffer enabled.
//!      This is the easy one to miss: the pad reset default measured on pins Linux
//!      never claimed is 0x96, which has OUT_DISABLE set. A perfect FUNCSEL with
//!      OUT_DISABLE still set transmits nothing.
//!
//! There is no RP1 reset controller involved: `serial@30000` has no `resets`
//! property and RP1's DT has no reset-controller node, so no peripheral reset needs
//! deasserting.
//!
//! The PL011's second clock, `apb_pclk`, is `<&clocks 6>` = RP1_PLL_SYS_PRI_PH per
//! `serial@30000`'s `clocks`/`clock-names` and `dt-bindings/clock/rp1.h`. Nothing
//! here touches it, deliberately: the loader can already read and write the PL011's
//! registers post-PERST and gets a correct PCellID back, which is direct evidence
//! that its bus clock is running. See `measureUartClock` for the check that turns
//! that inference into a number.
//!
//! VERIFICATION. Every write here is read back, because RP1's parent root complex
//! already demonstrated that this SoC will silently drop writes depending on state
//! (the RC Command register ignored writes until the link was up). Field-wise
//! comparison rather than whole-word, because several bits in these registers are
//! undocumented and read back as hardware state. On top of that, `measureUartClock`
//! uses RP1's own frequency counter to report the achieved `clk_uart` in kHz — a
//! measurement, not a read-back of what we just wrote, and the only check here that
//! can distinguish "the enable bit stuck" from "the clock generator is running".

const std = @import("std");
const stygia = @import("stygia");

const log = @import("early_log.zig");
const mmu = @import("mmu.zig");
const pcie = @import("pcie.zig");

const paging = stygia.memory.paging;

// ── Window bases ───────────────────────────────────────────────────────────

/// `clocks@18000`. The DT window is 0x10038 bytes, but every register this module
/// touches lives below 0x340 (the clock generators end at 0x1d0 and the frequency
/// counters at 0x31c), so one page is mapped rather than seventeen.
pub const CLOCKS_BASE: u64 = 0x1F_0001_8000;

/// `gpio@d0000` reg[0] — the io banks. Bank 0 (GPIO 0..27) is at offset 0, so the
/// header pins are all in the first page. Banks 1 and 2 are at 0x4000/0x8000 and
/// are not needed.
pub const GPIO_BASE: u64 = 0x1F_000D_0000;

/// `gpio@d0000` reg[2] — the pad controls. Bank 0's per-pin registers start at
/// offset 0x0004 (0x0000 is the bank voltage select, measured 0 = 3.3 V, left
/// alone), so again one page covers GPIO 0..27.
pub const PADS_BASE: u64 = 0x1F_000F_0000;

// ── Clock generator registers ──────────────────────────────────────────────
//
// Offsets from `clk-rp1.c` (raspberrypi/linux rpi-6.6.y), lines 47-175. Each of
// the ones used below was corroborated by reading the live block over /dev/mem on
// the booted Pi; the measured values are quoted at each site.

/// `clk-rp1.c:CLK_SLOW_SYS_CTRL/DIV_INT/SEL`. Only needed because it is the
/// reference for the frequency counters (`clk-rp1.c:fc0_ref_clk_name`).
const CLK_SLOW_SYS_CTRL: u64 = 0x024;
const CLK_SLOW_SYS_DIV_INT: u64 = 0x028;
const CLK_SLOW_SYS_SEL: u64 = 0x030;

/// `clk-rp1.c:CLK_UART_CTRL/DIV_INT/SEL`.
const CLK_UART_CTRL: u64 = 0x054;
const CLK_UART_DIV_INT: u64 = 0x058;
const CLK_UART_SEL: u64 = 0x060;

/// `clk-rp1.c:CLK_CTRL_ENABLE` = BIT(11).
const CLK_CTRL_ENABLE: u32 = 1 << 11;
/// `clk-rp1.c:CLK_CTRL_AUXSRC_MASK/SHIFT` — a 5-bit auxiliary source index.
const CLK_CTRL_AUXSRC_MASK: u32 = 0x0000_03E0;
const CLK_CTRL_AUXSRC_SHIFT: u5 = 5;

/// Index of "xosc" in `clk-rp1.c:[RP1_CLK_UART].parents`, which is
/// {pll_sys_pri_ph, pll_video, xosc, clksrc_gp0..gp5}. `num_std_parents` is 0 for
/// this clock, so the aux index is the whole story and the SRC field is unused
/// (measured: CLK_UART_CTRL bits 4:0 read 0 on the working system).
const AUXSRC_UART_XOSC: u32 = 2;

/// xosc is RP1's crystal: 50 MHz, per `clk_summary` (`xosc ... 50000000`).
const XOSC_HZ: u64 = 50_000_000;

/// Integer divider for a 1:1 pass-through. `clk-rp1.c:rp1_clock_recalc_rate`
/// treats a written 0 as 2^16, so 1 is not optional dressing.
const DIV_INT_PASSTHROUGH: u32 = 1;

// ── Frequency counters ─────────────────────────────────────────────────────
//
// `clk-rp1.c:FC0_*` (lines 169-178) plus `FC_SIZE`/`FC_COUNT`. There are eight
// counter blocks of 0x20 bytes starting at 0x21c, and a clock's block index and
// source number come from its `fc0_src = FC_NUM(idx, src)`.
//
// Confirmed by measurement: the live block has REF_KHZ = 0xc350 (50000 kHz) at
// 0x21c, 0x23c, 0x29c, 0x2bc and 0x2dc — i.e. at blocks 0, 1, 4, 5 and 6, exactly
// the blocks whose clocks Linux had measured, with block 6 being `clk_uart`'s
// (`[RP1_CLK_UART].fc0_src = FC_NUM(6, 7)`). Every field within block 6 read the
// value the driver writes: MAX_KHZ 0x1ffffff, DELAY 7, INTERVAL 8, SRC 0 (idle),
// STATUS 0x11.

const FC_BASE: u64 = 0x21C;
const FC_STRIDE: u64 = 0x20;
const FC_REF_KHZ: u64 = 0x00;
const FC_MIN_KHZ: u64 = 0x04;
const FC_MAX_KHZ: u64 = 0x08;
const FC_DELAY: u64 = 0x0C;
const FC_INTERVAL: u64 = 0x10;
const FC_SRC: u64 = 0x14;
const FC_STATUS: u64 = 0x18;
const FC_RESULT: u64 = 0x1C;

const FC_STATUS_DONE: u32 = 1 << 4;
const FC_STATUS_RUNNING: u32 = 1 << 8;
/// `clk-rp1.c:FC0_RESULT_FRAC_SHIFT` — the result is kHz in a fixed-point format
/// with 5 fractional bits.
const FC_RESULT_FRAC_SHIFT: u5 = 5;

/// `[RP1_CLK_UART].fc0_src = FC_NUM(6, 7)`, i.e. block 6, source 7.
const FC_IDX_UART: u64 = 6;
const FC_SRC_UART: u32 = 7;

fn fcReg(idx: u64, off: u64) u64 {
    return FC_BASE + idx * FC_STRIDE + off;
}

// ── GPIO / pad registers ───────────────────────────────────────────────────
//
// `pinctrl-rp1.c` (rpi-6.6.y). Bank 0 covers GPIO 0..27 at gpio_offset 0x0000 and
// pads_offset 0x0004 (`rp1_iobanks[0]` = { 0, 28, 0x0000, 0x011c, 0x0124, 0x0000,
// 0x0004 }), and `rp1_pinctrl_probe` lays the per-pin registers out as
//   ctrl = gpio_base + gpio_offset + n*8 + RP1_GPIO_CTRL(0x04)
//   pad  = pads_base + pads_offset + n*4

const GPIO_CTRL: u64 = 0x04;
/// `rp1_iobanks[0].pads_offset`. Bank 0's pad controls start one word in; offset 0
/// is the bank voltage select, which reads 0 (3.3 V) and is left alone.
const PADS_PIN0: u64 = 0x04;

/// `RP1_GPIO_CTRL_FUNCSEL_MASK` = 0x1f, LSB 0.
const CTRL_FUNCSEL_MASK: u32 = 0x0000_001F;
/// `RP1_GPIO_CTRL_OUTOVER_MASK` = 0x3000, LSB 12. `RP1_OUTOVER_PERI` = 0.
const CTRL_OUTOVER_MASK: u32 = 0x0000_3000;
const CTRL_OUTOVER_SHIFT: u5 = 12;
const OUTOVER_PERI: u32 = 0;
/// `RP1_GPIO_CTRL_OEOVER_MASK` = 0xc000, LSB 14. `RP1_OEOVER_PERI` = 0, which is
/// what lets the peripheral (not rio) decide when the pad drives.
const CTRL_OEOVER_MASK: u32 = 0x0000_C000;
const CTRL_OEOVER_SHIFT: u5 = 14;
const OEOVER_PERI: u32 = 0;

/// `RP1_PAD_PULL_MASK` = 0xc, LSB 2; `RP1_PUD_OFF` = 0, `RP1_PUD_UP` = 2.
const PAD_PULL_MASK: u32 = 0x0000_000C;
const PAD_PULL_SHIFT: u5 = 2;
const PUD_OFF: u32 = 0;
const PUD_UP: u32 = 2;
/// `RP1_PAD_IN_ENABLE_MASK` = 0x40, `RP1_PAD_OUT_DISABLE_MASK` = 0x80.
const PAD_IN_ENABLE: u32 = 0x0000_0040;
const PAD_OUT_DISABLE: u32 = 0x0000_0080;

/// FUNCSEL 4 = `alt4`. Both header pins want it: `pins` debugfs reports
/// `function alt4 (uart0)` for pin 14 and pin 15 on the working system.
const FSEL_ALT4: u32 = 4;

const TXD0_PIN: u64 = 14;
const RXD0_PIN: u64 = 15;

pub const Error = error{
    /// Every read from the clocks block came back as a "nothing answers" pattern,
    /// so there is no point writing anything.
    ClocksUnreachable,
};

fn rd(base: u64, off: u64) u32 {
    const p: *volatile u32 = @ptrFromInt(@as(usize, @intCast(base + off)));
    return p.*;
}

fn wr(base: u64, off: u64, v: u32) void {
    const p: *volatile u32 = @ptrFromInt(@as(usize, @intCast(base + off)));
    p.* = v;
}

/// Order the write phase against the read-back phase.
///
/// The windows are mapped Device-nGnRnE so the architecture already forbids
/// reordering, but these writes are also POSTED PCIe writes: they are complete as
/// far as the CPU is concerned long before RP1 has acted on them. A read to the
/// same device is what actually flushes them, which is exactly what the read-back
/// does — the barrier here just makes the intent explicit and matches what
/// `pinctrl-rp1.c:rp1_pin_readl` does with its `__dma_wmb()` before every read.
fn flushWrites() void {
    asm volatile ("dsb sy" ::: .{ .memory = true });
}

/// A read that came back from nothing. Same two signatures `uart.probe` documents:
/// 0xFFFFFFFF is the generic floating bus, 0xDEADDEAD is what BCM2712's root
/// complex synthesises for an address it decodes but nothing downstream answers.
fn isDead(v: u32) bool {
    return v == 0xFFFF_FFFF or v == 0xDEAD_DEAD;
}

fn field(v: u32, mask: u32, shift: u5) u32 {
    return (v & mask) >> shift;
}

fn setField(v: u32, mask: u32, shift: u5, x: u32) u32 {
    return (v & ~mask) | ((x << shift) & mask);
}

/// Enable `clk_uart` at 50 MHz off xosc.
///
/// Mirrors what the Linux clock framework does for this clock, in the same order:
/// `rp1_clock_set_rate_and_parent` writes DIV_INT and then the AUXSRC field, and
/// `rp1_clock_on` then sets ENABLE. Read-modify-write throughout, because bits
/// outside the two documented fields read back as hardware state whose meaning is
/// not established (see `verifyUartClock`) and clobbering them would be a guess.
fn enableUartClock() void {
    // clk_slow_sys is READ ONLY here, and deliberately so. It is the frequency
    // counters' reference (`clk-rp1.c:fc0_ref_clk_name`), so the tempting move is to
    // enable it before measuring — but the measurement says not to. On the booted
    // Pi, CLK_SLOW_SYS_CTRL reads 0 (ENABLE clear) and `clk_summary` shows
    // `clk_slow_sys` with prepare_count 0, i.e. Linux never enabled it; yet Linux's
    // own frequency measurements plainly completed (FC blocks 0/1/4/5/6 all read
    // back REF_KHZ 0xc350 and STATUS with DONE set). So the counter taps its
    // reference upstream of that gate, and writing it would be an unnecessary poke
    // at a clock this module has no business touching. Logged instead, because if
    // the measurement below fails this is the first register to suspect.
    const slow_ctrl = rd(CLOCKS_BASE, CLK_SLOW_SYS_CTRL);
    const slow_div = rd(CLOCKS_BASE, CLK_SLOW_SYS_DIV_INT);
    const slow_sel = rd(CLOCKS_BASE, CLK_SLOW_SYS_SEL);

    const ctrl_before = rd(CLOCKS_BASE, CLK_UART_CTRL);
    const div_before = rd(CLOCKS_BASE, CLK_UART_DIV_INT);

    wr(CLOCKS_BASE, CLK_UART_DIV_INT, DIV_INT_PASSTHROUGH);

    var ctrl = setField(ctrl_before, CLK_CTRL_AUXSRC_MASK, CLK_CTRL_AUXSRC_SHIFT, AUXSRC_UART_XOSC);
    ctrl |= CLK_CTRL_ENABLE;
    wr(CLOCKS_BASE, CLK_UART_CTRL, ctrl);

    flushWrites();

    log.str("      clk_slow_sys (untouched, FC reference): CTRL=");
    log.hex(slow_ctrl);
    log.str(" DIV_INT=");
    log.hex(slow_div);
    log.str(" SEL=");
    log.hex(slow_sel);
    log.byte('\n');

    log.str("      clk_uart CTRL ");
    log.hex(ctrl_before);
    log.str(" -> wrote ");
    log.hex(ctrl);
    log.str(", DIV_INT ");
    log.hex(div_before);
    log.str(" -> wrote ");
    log.hex(DIV_INT_PASSTHROUGH);
    log.byte('\n');

    // The aux mux is glitchless, so switching it takes a handful of source cycles
    // to propagate. 10 µs is ~500 xosc cycles: far more than enough, and free.
    pcie.delayUs(10);
}

/// Read `clk_uart` back field by field and say whether it is what was asked for.
fn verifyUartClock() bool {
    const ctrl = rd(CLOCKS_BASE, CLK_UART_CTRL);
    const div = rd(CLOCKS_BASE, CLK_UART_DIV_INT);
    const sel = rd(CLOCKS_BASE, CLK_UART_SEL);

    const enable = (ctrl & CLK_CTRL_ENABLE) != 0;
    const auxsrc = field(ctrl, CLK_CTRL_AUXSRC_MASK, CLK_CTRL_AUXSRC_SHIFT);

    log.str("      clk_uart readback: CTRL=");
    log.hex(ctrl);
    log.str(" DIV_INT=");
    log.hex(div);
    log.str(" SEL=");
    log.hex(sel);
    log.str("\n        ENABLE=");
    log.dec(@intFromBool(enable));
    log.str(" AUXSRC=");
    log.dec(auxsrc);
    log.str(" (want ");
    log.dec(AUXSRC_UART_XOSC);
    log.str(" = xosc)");
    if (div != 0) {
        log.str(" -> ");
        log.dec(XOSC_HZ / div);
        log.str(" Hz");
    }
    log.byte('\n');

    var ok = true;
    if (!enable) {
        log.str("        *** ENABLE did not stick: the clock gate is still closed\n");
        ok = false;
    }
    if (auxsrc != AUXSRC_UART_XOSC) {
        log.str("        *** AUXSRC did not stick; the UART is fed from ");
        log.str(if (auxsrc == 0) "pll_sys_pri_ph (a PLL, probably powered down)\n" else "an unintended source\n");
        ok = false;
    }
    if (div != DIV_INT_PASSTHROUGH) {
        log.str("        *** DIV_INT did not stick (a written 0 means divide by 65536)\n");
        ok = false;
    }
    // Reference, for reading the log later: on the booted Pi with this UART working
    // these read CTRL=0x10000840, DIV_INT=0x1, SEL=0x1. Bit 28 of CTRL is set on
    // every clock whose ENABLE is set and clear on every clock whose ENABLE is
    // clear, and `clk-rp1.c` never writes it, so it is very likely a hardware
    // "running" status — but that is inference, not something established from a
    // register description, so it is reported rather than asserted.
    if ((ctrl & 0x1000_0000) == 0) {
        log.str("        note: CTRL bit 28 clear (set on every running clock under Linux)\n");
    }
    return ok;
}

/// Measure `clk_uart` with RP1's own frequency counter block 6.
///
/// This is the one check here that is a measurement rather than a read-back, and
/// therefore the one that can tell "the enable bit stuck" apart from "the clock
/// generator is actually running". Sequence and parameters from
/// `clk-rp1.c:clockman_measure_clock`: park the counter, write REF_KHZ / MIN / MAX
/// / INTERVAL / DELAY, then write SRC to start it, wait for DONE, read RESULT,
/// write SRC=0 to stop.
///
/// Every wait is bounded by an explicit spin count. An unbounded poll on a counter
/// whose reference clock might not be running would hang the loader, and a hang on
/// this board costs a physical power cycle plus the log — strictly worse than
/// reporting "no measurement".
fn measureUartClock() void {
    const status_reg = fcReg(FC_IDX_UART, FC_STATUS);

    const status_before = rd(CLOCKS_BASE, status_reg);
    if ((status_before & FC_STATUS_DONE) != 0) {
        // Would make a stale RESULT indistinguishable from a fresh one. Expected to
        // be 0 after PERST#; if it is not, say so rather than trusting the number.
        log.str("      note: FC6 STATUS already has DONE set (");
        log.hex(status_before);
        log.str("); result may be stale\n");
    }

    var spins: u32 = 0;
    while ((rd(CLOCKS_BASE, status_reg) & FC_STATUS_RUNNING) != 0) {
        spins += 1;
        if (spins > 5_000) {
            log.str("      *** FC6 stuck RUNNING; no clk_uart measurement\n");
            return;
        }
        pcie.delayUs(10);
    }

    wr(CLOCKS_BASE, fcReg(FC_IDX_UART, FC_REF_KHZ), @intCast(XOSC_HZ / 1000));
    wr(CLOCKS_BASE, fcReg(FC_IDX_UART, FC_MIN_KHZ), 0);
    wr(CLOCKS_BASE, fcReg(FC_IDX_UART, FC_MAX_KHZ), 0x01FF_FFFF);
    wr(CLOCKS_BASE, fcReg(FC_IDX_UART, FC_INTERVAL), 8);
    wr(CLOCKS_BASE, fcReg(FC_IDX_UART, FC_DELAY), 7);
    wr(CLOCKS_BASE, fcReg(FC_IDX_UART, FC_SRC), FC_SRC_UART);
    flushWrites();

    spins = 0;
    while ((rd(CLOCKS_BASE, status_reg) & FC_STATUS_DONE) == 0) {
        spins += 1;
        if (spins > 5_000) {
            log.str("      *** FC6 never reported DONE (STATUS ");
            log.hex(rd(CLOCKS_BASE, status_reg));
            log.str("); no clk_uart measurement\n");
            wr(CLOCKS_BASE, fcReg(FC_IDX_UART, FC_SRC), 0);
            return;
        }
        pcie.delayUs(10);
    }

    const result = rd(CLOCKS_BASE, fcReg(FC_IDX_UART, FC_RESULT));
    const status = rd(CLOCKS_BASE, status_reg);
    wr(CLOCKS_BASE, fcReg(FC_IDX_UART, FC_SRC), 0);

    const khz = result >> FC_RESULT_FRAC_SHIFT;
    log.str("      clk_uart MEASURED ");
    log.dec(khz);
    log.str(" kHz (want ~50000)  [FC6 STATUS=");
    log.hex(status);
    log.str(" RESULT=");
    log.hex(result);
    log.str("]\n");

    // The window is 2% either way. The counter's own quantisation at INTERVAL=8 is
    // far tighter than that; this is wide enough to accept a slightly off crystal
    // and narrow enough to reject a wrong mux, whose nearest wrong answers are 0,
    // 100 MHz (pll_sys_pri_ph) and 200 MHz (pll_video).
    //
    // Checked against BOTH interpretations of RESULT, because the fixed-point
    // format is the one thing in this module that is neither measured nor used by
    // the driver: `clk-rp1.c` defines FC0_RESULT_FRAC_SHIFT = 5 and then never
    // applies it (`clockman_measure_clock`'s return value is discarded at all eight
    // call sites), so "kHz in bits 31:5, fraction in 4:0" is read off RP2040's
    // documented FC0_RESULT layout for the same clocks-block IP, by analogy. If the
    // analogy is wrong the raw word above still says 50 MHz — as 0xc350 instead of
    // 0x186a00 — and this accepts it rather than crying wolf.
    const in_window = khz >= 49_000 and khz <= 51_000;
    const in_window_unshifted = result >= 49_000 and result <= 51_000;
    if (in_window_unshifted and !in_window) {
        log.str("        clk_uart is 50 MHz, but RESULT is raw kHz: the >>5 decode is wrong\n");
    } else if (!in_window) {
        log.str("        *** clk_uart is NOT 50 MHz; 115200 baud will not come out right\n");
    }
}

/// What `muxPin` did to one pin, for logging and checking.
const PinResult = struct {
    ctrl_before: u32,
    ctrl_after: u32,
    pad_before: u32,
    pad_after: u32,
    ok: bool,
};

/// Route one pin to a peripheral function, exactly as `rp1_set_fsel` does.
///
/// Order matters and is taken from `pinctrl-rp1.c:rp1_set_fsel`: the pad's input
/// enable and output enable are set BEFORE FUNCSEL is written. The pad half is the
/// part that is easy to forget and fatal to omit — the measured pad reset value on
/// pins Linux never claimed is 0x96, which has OUT_DISABLE set, so a pin with a
/// perfect FUNCSEL would still never drive the header.
///
/// `pull` follows the DT group `rp1_uart0_14_15`: `bias-disable` on the TXD pin,
/// `bias-pull-up` on the RXD pin so an unconnected RX line idles in the mark state
/// instead of looking like a permanent break.
fn muxPin(pin: u64, pull: u32) PinResult {
    const ctrl_off = pin * 8 + GPIO_CTRL;
    const pad_off = PADS_PIN0 + pin * 4;

    const ctrl_before = rd(GPIO_BASE, ctrl_off);
    const pad_before = rd(PADS_BASE, pad_off);

    var pad = pad_before;
    pad &= ~PAD_OUT_DISABLE; // let the pad drive
    pad |= PAD_IN_ENABLE; // and receive
    pad = setField(pad, PAD_PULL_MASK, PAD_PULL_SHIFT, pull);
    // SLEWFAST, SCHMITT and DRIVE are left as found. The measured reset default
    // already carries DRIVE=4 mA, which is what Linux ends up running these two
    // pins at (pad 14 = 0x52, pad 15 = 0x5a on the working system).
    wr(PADS_BASE, pad_off, pad);

    var ctrl = ctrl_before;
    ctrl = setField(ctrl, CTRL_OUTOVER_MASK, CTRL_OUTOVER_SHIFT, OUTOVER_PERI);
    ctrl = setField(ctrl, CTRL_OEOVER_MASK, CTRL_OEOVER_SHIFT, OEOVER_PERI);
    ctrl = setField(ctrl, CTRL_FUNCSEL_MASK, 0, FSEL_ALT4);
    wr(GPIO_BASE, ctrl_off, ctrl);

    flushWrites();

    const ctrl_after = rd(GPIO_BASE, ctrl_off);
    const pad_after = rd(PADS_BASE, pad_off);

    const ok = field(ctrl_after, CTRL_FUNCSEL_MASK, 0) == FSEL_ALT4 and
        field(ctrl_after, CTRL_OUTOVER_MASK, CTRL_OUTOVER_SHIFT) == OUTOVER_PERI and
        field(ctrl_after, CTRL_OEOVER_MASK, CTRL_OEOVER_SHIFT) == OEOVER_PERI and
        (pad_after & PAD_OUT_DISABLE) == 0 and
        (pad_after & PAD_IN_ENABLE) != 0 and
        field(pad_after, PAD_PULL_MASK, PAD_PULL_SHIFT) == pull;

    return .{
        .ctrl_before = ctrl_before,
        .ctrl_after = ctrl_after,
        .pad_before = pad_before,
        .pad_after = pad_after,
        .ok = ok,
    };
}

fn dumpPin(name: []const u8, pin: u64, want_ctrl: u32, want_pad: u32, r: PinResult) void {
    log.str("      gpio");
    log.dec(pin);
    log.byte(' ');
    log.str(name);
    log.str(": CTRL ");
    log.hex(r.ctrl_before);
    log.str(" -> ");
    log.hex(r.ctrl_after);
    log.str("  PAD ");
    log.hex(r.pad_before);
    log.str(" -> ");
    log.hex(r.pad_after);
    log.byte('\n');
    if (!r.ok) {
        log.str("        *** pin did NOT take the requested mux\n");
        return;
    }
    // Not a failure if these differ — the undocumented bits in both registers read
    // back as hardware state — but a divergence from the values Linux runs is worth
    // seeing in the log, because it is the first thing to look at if the clock
    // measures right and still nothing appears on the wire.
    if (r.ctrl_after != want_ctrl or r.pad_after != want_pad) {
        log.str("        note: differs from the working Linux values CTRL=");
        log.hex(want_ctrl);
        log.str(" PAD=");
        log.hex(want_pad);
        log.byte('\n');
    }
}

/// Give RP1's uart0 a baud clock and a pair of pins.
///
/// Call this after the PCIe link is up and RP1's BARs are assigned, and before
/// `uart.configure` — the divisor writes that `configure` makes are latched against
/// UARTCLK, so the clock has to exist first.
pub fn bringUpUart0(alloc: std.mem.Allocator, ttbr0_root: u64) !void {
    log.str("    RP1 internal bring-up (clk_uart + GPIO 14/15 mux):\n");

    // Each is its own 4 KiB page. All three, plus the already-mapped uart0 page at
    // 0x1F_0003_0000, fall inside the same 1 GiB / 2 MiB slot, so they share one
    // L3 table and cost three descriptors rather than three table chains. And the
    // whole 0x1F_xxxx_xxxx window is far above RAM, so none of this can land inside
    // the identity map's coarser blocks — the split that `mmu.mapRange` refuses.
    try mmu.mapMmio(alloc, ttbr0_root, CLOCKS_BASE, paging.PAGE4K);
    try mmu.mapMmio(alloc, ttbr0_root, GPIO_BASE, paging.PAGE4K);
    try mmu.mapMmio(alloc, ttbr0_root, PADS_BASE, paging.PAGE4K);
    log.str("      mapped clocks ");
    log.hex(CLOCKS_BASE);
    log.str("  gpio ");
    log.hex(GPIO_BASE);
    log.str("  pads ");
    log.hex(PADS_BASE);
    log.byte('\n');

    // Before writing anything, establish that these windows decode at all. The
    // UART page answering does not prove the clock and GPIO pages do: they are
    // different offsets inside BAR1 and a wrong BAR programming would show up here
    // and nowhere else.
    const probe_clk = rd(CLOCKS_BASE, CLK_UART_CTRL);
    const probe_gpio = rd(GPIO_BASE, TXD0_PIN * 8 + GPIO_CTRL);
    const probe_pad = rd(PADS_BASE, PADS_PIN0 + TXD0_PIN * 4);
    log.str("      reachability: CLK_UART_CTRL=");
    log.hex(probe_clk);
    log.str(" gpio14.CTRL=");
    log.hex(probe_gpio);
    log.str(" pad14=");
    log.hex(probe_pad);
    log.byte('\n');
    if (isDead(probe_clk) and isDead(probe_gpio) and isDead(probe_pad)) {
        log.str("      *** RP1 clocks/gpio windows do not answer; nothing to program\n");
        log.commit();
        return Error.ClocksUnreachable;
    }

    enableUartClock();
    const clock_ok = verifyUartClock();
    measureUartClock();

    // 0x84 / 0x52 / 0x5a are the values read out of the working Linux system, not
    // derived: gpio14.CTRL=0x84, gpio15.CTRL=0x84, pad14=0x52, pad15=0x5a. They
    // reproduce exactly from the untouched-pin reset defaults (CTRL 0x9f, pad 0x96)
    // under the read-modify-write above, which is the strongest confirmation
    // available that this module models the registers correctly.
    const txd = muxPin(TXD0_PIN, PUD_OFF);
    dumpPin("(TXD0)", TXD0_PIN, 0x84, 0x52, txd);
    const rxd = muxPin(RXD0_PIN, PUD_UP);
    dumpPin("(RXD0)", RXD0_PIN, 0x84, 0x5A, rxd);

    if (clock_ok and txd.ok and rxd.ok) {
        log.str("      => RP1 uart0 has a 50 MHz baud clock and owns GPIO 14/15\n");
    } else {
        log.str("      *** RP1 bring-up INCOMPLETE; see the *** lines above\n");
    }
    log.commit();
}
