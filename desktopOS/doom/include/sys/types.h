/* Freestanding <sys/types.h>. Doom uses this primarily as a transitive
 * include from other system headers; we expose just the typedefs. */
#ifndef _DESKTOPOS_DOOM_SYS_TYPES_H
#define _DESKTOPOS_DOOM_SYS_TYPES_H

#include <stddef.h>
#include <stdint.h>

typedef long           off_t;
typedef long           ssize_t;
typedef int            pid_t;
typedef unsigned int   uid_t;
typedef unsigned int   gid_t;
typedef unsigned int   mode_t;
typedef unsigned int   dev_t;
typedef unsigned long  ino_t;
typedef unsigned long  nlink_t;
typedef unsigned long  blksize_t;
typedef unsigned long  blkcnt_t;

#endif
