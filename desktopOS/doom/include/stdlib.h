/* Freestanding stdlib shim. Real malloc/free/calloc/realloc are
 * implemented in libc_shim.zig over a FixedBufferAllocator backed by
 * a heap VMAR allocated at startup. */
#ifndef _DESKTOPOS_DOOM_STDLIB_H
#define _DESKTOPOS_DOOM_STDLIB_H

#include <stddef.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define RAND_MAX 0x7fffffff

void *malloc(size_t);
void *realloc(void *, size_t);
void *calloc(size_t, size_t);
void  free(void *);
void  abort(void) __attribute__((noreturn));
void  exit(int) __attribute__((noreturn));
void  _Exit(int) __attribute__((noreturn));

int   atoi(const char *);
long  atol(const char *);
double atof(const char *);

double strtod(const char *, char **);
long   strtol(const char *, char **, int);
unsigned long strtoul(const char *, char **, int);

void  qsort(void *, size_t, size_t, int (*)(const void *, const void *));
void *bsearch(const void *, const void *, size_t, size_t,
              int (*)(const void *, const void *));

char *getenv(const char *);
int   atexit(void (*func)(void));

int   abs(int);
long  labs(long);

int   rand(void);
void  srand(unsigned);

int   system(const char *);
int   mkstemp(char *);
int   putenv(char *);
int   setenv(const char *, const char *, int);

#endif
