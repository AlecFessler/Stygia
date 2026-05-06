/* Freestanding stdio shim for the doomgeneric build. The FILE struct
 * is opaque to C; the actual layout (an embedded-WAD reader or a
 * RAM-file writer) lives in libc_shim.zig. printf/fprintf/sprintf/
 * snprintf format directly into a stack buffer routed through the
 * COM1 log. */
#ifndef _DESKTOPOS_DOOM_STDIO_H
#define _DESKTOPOS_DOOM_STDIO_H

#include <stddef.h>
#include <stdarg.h>

typedef struct FILE FILE;

extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;

#define EOF (-1)

#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

#define BUFSIZ 8192

int  fprintf(FILE *, const char *, ...);
int  vfprintf(FILE *, const char *, va_list);
int  fputs(const char *, FILE *);
int  fputc(int, FILE *);
int  putc(int, FILE *);
int  putchar(int);
int  puts(const char *);
int  fgetc(FILE *);
int  getc(FILE *);
char *fgets(char *, int, FILE *);
int  ungetc(int, FILE *);
int  fclose(FILE *);
FILE *fopen(const char *, const char *);
FILE *freopen(const char *, const char *, FILE *);
FILE *tmpfile(void);
size_t fread(void *, size_t, size_t, FILE *);
size_t fwrite(const void *, size_t, size_t, FILE *);
int  fseek(FILE *, long, int);
long ftell(FILE *);
void rewind(FILE *);
int  feof(FILE *);
int  ferror(FILE *);
void clearerr(FILE *);
int  fflush(FILE *);
int  fileno(FILE *);
int  setvbuf(FILE *, char *, int, size_t);

int  printf(const char *, ...);
int  vprintf(const char *, va_list);
int  snprintf(char *, size_t, const char *, ...);
int  vsnprintf(char *, size_t, const char *, va_list);
int  sprintf(char *, const char *, ...);
int  vsprintf(char *, const char *, va_list);
int  sscanf(const char *, const char *, ...);
int  vsscanf(const char *, const char *, va_list);
int  fscanf(FILE *, const char *, ...);

int  remove(const char *);
int  rename(const char *, const char *);

#endif
