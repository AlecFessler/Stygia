/* Flat-binary layout for the Raspberry Pi 5 native loader.
 *
 * The firmware loads the file named by `kernel=` as a RAW binary at
 * `kernel_address` and branches to offset 0 with x0 = DTB phys. Two consequences
 * drive everything here:
 *
 *   1. `_start` must be the very first byte of the image. `.text.boot` is pulled
 *      first and the ASSERT at the bottom enforces it, because a wrong entry
 *      point is invisible in every build artifact and shows up only as a board
 *      that needs a physical power cycle.
 *   2. The link address must equal the load address, since a flat binary carries
 *      no relocations. 0x80000 is pinned via `kernel_address=0x80000` in
 *      tryboot.txt rather than relying on the arm64 default.
 *
 * 0x80000 is not an invented address: it is where this platform already places a
 * kernel, immediately above the ATF region at 0x0-0x7FFFF that provides PSCI.
 */
ENTRY(_start)

SECTIONS
{
    . = 0x80000;
    __image_start = .;

    .text : {
        KEEP(*(.text.boot))
        *(.text*)
    }

    .rodata : { *(.rodata*) }
    .data   : { *(.data*) }

    /* .bss is zeroed by _start using these symbols. objcopy -O binary drops it
     * from the image, so nothing on the card initializes it, and DRAM survives
     * resets on this board — it comes up dirty. 8-byte aligned so the clear loop
     * can use `str xzr`.
     */
    . = ALIGN(8);
    .bss (NOLOAD) : {
        __bss_start = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(8);
        __bss_end = .;
    }

    /* Stack sits above .bss, growing DOWN toward it. 16 KiB, matching
     * STACK_SIZE in entry.zig — the two must agree or the reservation handed to
     * the kernel covers the wrong span.
     *
     * A guard page below the stack would be better, but there is no MMU yet to
     * enforce one; the DTB parser's recursion is bounded (depth <= 16 frames)
     * so overflow is not a realistic risk at this stage.
     */
    . = ALIGN(16);
    . = . + 0x4000;
    __stack_top = .;

    /* Dedicated stack for the exception handler. The fault being reported may
     * itself be a stack problem, so the handler must not reuse the main SP —
     * doing so faults again inside the handler and produces a silent
     * double-fault loop instead of a report.
     */
    . = ALIGN(16);
    . = . + 0x1000;
    __fault_stack_top = .;

    . = ALIGN(4096);
    __image_end = .;

    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}

/* Fail the LINK, not the BOOT. */
ASSERT(_start == 0x80000, "pi5: _start must be the first byte of the flat image")
ASSERT(__stack_top > __bss_end, "pi5: stack must sit above .bss")
