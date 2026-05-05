/* Minimal freestanding stdlib shim for SQLite.
 * With ZERO_MALLOC + ENABLE_MEMSYS5, SQLite never calls malloc/realloc
 * /free directly — we route allocation through sqlite3_config (memsys5)
 * over a fixed buffer. Function decls below exist so the amalgamation
 * compiles; stubs in libc_shim.zig abort if ever called.
 */
#ifndef _DESKTOPOS_STDLIB_H
#define _DESKTOPOS_STDLIB_H

#include <stddef.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

void *malloc(size_t);
void *realloc(void *, size_t);
void *calloc(size_t, size_t);
void  free(void *);
void  abort(void) __attribute__((noreturn));
void  exit(int) __attribute__((noreturn));

int   atoi(const char *);
long  atol(const char *);
double strtod(const char *, char **);
long   strtol(const char *, char **, int);

void  qsort(void *, size_t, size_t, int (*)(const void *, const void *));

char *getenv(const char *);
int   system(const char *);

#endif
