const stygia = @import("stygia");

const cpu = stygia.arch.x64.cpu;
const exceptions = stygia.arch.x64.exceptions;
const gdt = stygia.arch.x64.gdt;
const idt = stygia.arch.x64.idt;
const interrupts = stygia.arch.x64.interrupts;
const irq = stygia.arch.x64.irq;
const serial = stygia.arch.x64.serial;

pub fn init() void {
    serial.init(.com1, 115200);
    gdt.init();
    idt.init();
    exceptions.init();
    irq.init();
    cpu.initSyscall(@intFromPtr(&interrupts.syscallEntry));
    interrupts.initSyscallScratch(0);
    cpu.initPat();
    cpu.enableAlignmentCheck();
    cpu.enableSmapSmep();
    cpu.enablePcid();
    cpu.enableSpeculationBarriers();
}
