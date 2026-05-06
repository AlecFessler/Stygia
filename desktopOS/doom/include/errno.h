/* Freestanding errno shim. Same as fs/sqlite. */
#ifndef _DESKTOPOS_DOOM_ERRNO_H
#define _DESKTOPOS_DOOM_ERRNO_H

extern int errno_storage;
#define errno errno_storage

#define EINVAL 22
#define ENOMEM 12
#define EIO    5
#define ENOSPC 28
#define EBUSY  16
#define EAGAIN 11
#define EEXIST 17
#define ENOENT 2
#define EACCES 13
#define EBADF  9
#define EISDIR 21
#define ENOTDIR 20
#define EROFS  30
#define EPERM  1
#define EINTR  4

#endif
