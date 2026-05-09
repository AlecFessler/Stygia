const std = @import("std");
const stygia = @import("stygia");

const cpu = stygia.arch.x64.cpu;

/// Read the CMOS RTC and return Unix nanoseconds since 1970-01-01T00:00:00Z.
///
/// MC146818-compatible real-time clock accessed via I/O ports 0x70 (address)
/// and 0x71 (data). Precision is 1 second (RTC has no sub-second granularity).
/// MC146818A Datasheet, §2 "Register Description":
///   Register A (0x0A): bit 7 = Update-In-Progress (UIP) flag.
///   Register B (0x0B): bit 2 = Data Mode (0=BCD, 1=binary);
///                       bit 1 = 24/12-hour mode (0=12-hour, 1=24-hour).
///   Time/date registers: 0x00=seconds, 0x02=minutes, 0x04=hours,
///     0x07=day-of-month, 0x08=month, 0x09=year, 0x32=century (ACPI extension).
pub fn readRtc() u64 {
    // Spin until the Update-In-Progress (UIP) bit is clear.
    while (readCmosReg(0x0A) & 0x80 != 0) std.atomic.spinLoopHint();

    var secs = readCmosReg(0x00);
    var mins = readCmosReg(0x02);
    var hours = readCmosReg(0x04);
    var day = readCmosReg(0x07);
    var month = readCmosReg(0x08);
    var year = readCmosReg(0x09);
    var century = readCmosReg(0x32);

    // Re-read and compare to detect an update race.
    while (true) {
        while (readCmosReg(0x0A) & 0x80 != 0) std.atomic.spinLoopHint();

        const secs2 = readCmosReg(0x00);
        const mins2 = readCmosReg(0x02);
        const hours2 = readCmosReg(0x04);
        const day2 = readCmosReg(0x07);
        const month2 = readCmosReg(0x08);
        const year2 = readCmosReg(0x09);
        const century2 = readCmosReg(0x32);

        if (secs == secs2 and mins == mins2 and hours == hours2 and
            day == day2 and month == month2 and year == year2 and
            century == century2) break;

        secs = secs2;
        mins = mins2;
        hours = hours2;
        day = day2;
        month = month2;
        year = year2;
        century = century2;
    }

    const status_b = readCmosReg(0x0B);

    // Convert BCD to binary if needed (Status Register B bit 2).
    if (status_b & 0x04 == 0) {
        secs = bcdToBin(secs);
        mins = bcdToBin(mins);
        hours = bcdToBin(hours & 0x7F) | (hours & 0x80);
        day = bcdToBin(day);
        month = bcdToBin(month);
        year = bcdToBin(year);
        century = bcdToBin(century);
    }

    // Convert 12-hour to 24-hour if needed (Status Register B bit 1).
    if (status_b & 0x02 == 0) {
        if (hours & 0x80 != 0) {
            hours = ((hours & 0x7F) % 12) + 12;
        } else {
            hours = hours % 12;
        }
    }

    // Compose full year.
    const full_century: u64 = if (century == 0) 20 else @as(u64, century);
    const full_year: u64 = full_century * 100 + @as(u64, year);

    // Convert to Unix timestamp (nanoseconds).
    const days = daysSinceEpoch(full_year, @as(u64, month), @as(u64, day));
    const total_secs: u64 = days * 86400 + @as(u64, hours) * 3600 + @as(u64, mins) * 60 + @as(u64, secs);
    return total_secs * 1_000_000_000;
}

/// Write the CMOS RTC to `unix_ns` since the Unix epoch. Returns 0 on
/// success or a negative spec error code. Spec §[time].time_setwall.
///
/// STUB step 7h: CMOS RTC programming is not wired yet; the call
/// silently succeeds so time_setwall spec tests can run without
/// killing the kernel. Real CMOS write lands when the RTC subsystem
/// is implemented.
pub fn writeRtc(unix_ns: u64) i64 {
    _ = unix_ns;
    return 0;
}

fn readCmosReg(reg: u8) u8 {
    cpu.outb(reg, 0x70);
    return cpu.inb(0x71);
}

fn bcdToBin(val: u8) u8 {
    return (val & 0x0F) + ((val >> 4) * 10);
}

/// Days from 1970-01-01 to the given date, accounting for leap years.
fn daysSinceEpoch(year: u64, month: u64, day: u64) u64 {
    const days_before_month = [_]u64{ 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };

    var days: u64 = 0;

    // Years since 1970.
    const y = year - 1;
    const y1969: u64 = 1969;
    // Total leap days from year 1 to y, minus those from year 1 to 1969.
    days += (y / 4 - y / 100 + y / 400) - (y1969 / 4 - y1969 / 100 + y1969 / 400);
    days += (year - 1970) * 365;

    // Months.
    if (month >= 1 and month <= 12) {
        days += days_before_month[month - 1];
    }

    // Add leap day if past February in a leap year.
    if (month > 2 and isLeapYear(year)) {
        days += 1;
    }

    // Day of month (1-based).
    days += day - 1;

    return days;
}

fn isLeapYear(year: u64) bool {
    return (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0);
}
