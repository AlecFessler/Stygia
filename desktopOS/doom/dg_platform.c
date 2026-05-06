// doomgeneric platform shim. Each DG_* function delegates to a Zig
// extern with C linkage so all the heavy lifting (framebuffer blit,
// USB IPC poll, ticker, sleep) lives in main.zig.

#include "src/doomgeneric.h"

extern void zag_dg_init(void);
extern void zag_dg_draw_frame(void);
extern int  zag_dg_get_key(int *pressed, unsigned char *key);
extern unsigned int zag_dg_get_ticks_ms(void);
extern void zag_dg_sleep_ms(unsigned int ms);
extern void zag_dg_set_window_title(const char *title);

void DG_Init(void)
{
    zag_dg_init();
}

void DG_DrawFrame(void)
{
    zag_dg_draw_frame();
}

int DG_GetKey(int *pressed, unsigned char *key)
{
    return zag_dg_get_key(pressed, key);
}

uint32_t DG_GetTicksMs(void)
{
    return zag_dg_get_ticks_ms();
}

void DG_SleepMs(uint32_t ms)
{
    zag_dg_sleep_ms(ms);
}

void DG_SetWindowTitle(const char *title)
{
    zag_dg_set_window_title(title);
}
