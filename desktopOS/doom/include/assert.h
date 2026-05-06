/* Freestanding assert shim. Same as fs/sqlite. */
#ifndef _DESKTOPOS_DOOM_ASSERT_H
#define _DESKTOPOS_DOOM_ASSERT_H

#ifdef NDEBUG
#define assert(expr) ((void)0)
#else
extern void __desktopos_assert_fail(const char *expr, const char *file, int line) __attribute__((noreturn));
#define assert(expr) ((expr) ? (void)0 : __desktopos_assert_fail(#expr, __FILE__, __LINE__))
#endif

#endif
