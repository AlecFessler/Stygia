/* Freestanding <fcntl.h> stub. Doom uses these primarily inside
 * ORIGCODE paths. */
#ifndef _DESKTOPOS_DOOM_FCNTL_H
#define _DESKTOPOS_DOOM_FCNTL_H

#include <sys/types.h>

#define O_RDONLY  0
#define O_WRONLY  1
#define O_RDWR    2
#define O_CREAT   0x40
#define O_TRUNC   0x200
#define O_APPEND  0x400
#define O_BINARY  0
#define O_TEXT    0

int open(const char *, int, ...);
int creat(const char *, mode_t);

#endif
