/* Minimal freestanding shim for SQLite. The actual implementations
 * live in desktopOS/fs/sqlite/libc_shim.zig. */
#ifndef _DESKTOPOS_STRING_H
#define _DESKTOPOS_STRING_H

#include <stddef.h>

void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
int   memcmp(const void *a, const void *b, size_t n);
void *memchr(const void *s, int c, size_t n);

size_t strlen(const char *s);
int    strcmp(const char *a, const char *b);
int    strncmp(const char *a, const char *b, size_t n);
char  *strchr(const char *s, int c);
char  *strrchr(const char *s, int c);
char  *strstr(const char *haystack, const char *needle);

size_t strspn(const char *s, const char *accept);
size_t strcspn(const char *s, const char *reject);

char  *strpbrk(const char *s, const char *accept);

#endif
