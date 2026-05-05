/* Minimal freestanding stdio shim for SQLite.
 * SQLite barely uses stdio when compiled with OMIT_TRACE / OMIT_PROGRESS
 * /etc. — typically just sqlite3_snprintf which is internal. We provide
 * the FILE typedef and the few function decls SQLite references via its
 * own snprintf/fprintf wrappers but stub them out. Implementations live
 * in libc_shim.zig and mostly drop output on the floor (or redirect to
 * the COM1 log when useful). */
#ifndef _DESKTOPOS_STDIO_H
#define _DESKTOPOS_STDIO_H

#include <stddef.h>
#include <stdarg.h>

typedef struct FILE FILE;

extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;

#define EOF (-1)

int  fprintf(FILE *, const char *, ...);
int  vfprintf(FILE *, const char *, va_list);
int  fputs(const char *, FILE *);
int  fputc(int, FILE *);
int  fgetc(FILE *);
int  fclose(FILE *);
FILE *fopen(const char *, const char *);
size_t fread(void *, size_t, size_t, FILE *);
size_t fwrite(const void *, size_t, size_t, FILE *);
int  fseek(FILE *, long, int);
long ftell(FILE *);
int  fflush(FILE *);
int  printf(const char *, ...);
int  snprintf(char *, size_t, const char *, ...);
int  vsnprintf(char *, size_t, const char *, va_list);
int  sprintf(char *, const char *, ...);

#endif
