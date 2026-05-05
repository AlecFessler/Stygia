/* Minimal errno shim. With OS_OTHER, SQLite reads errno only
 * defensively; we expose a single TLS-free int. */
#ifndef _DESKTOPOS_ERRNO_H
#define _DESKTOPOS_ERRNO_H

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

#endif
