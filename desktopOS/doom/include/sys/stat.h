/* Freestanding <sys/stat.h>. Doom only uses these for ORIGCODE-guarded
 * fs paths; stubs are sufficient. */
#ifndef _DESKTOPOS_DOOM_SYS_STAT_H
#define _DESKTOPOS_DOOM_SYS_STAT_H

#include <sys/types.h>

#define S_IFMT    0170000
#define S_IFREG   0100000
#define S_IFDIR   0040000
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define S_IRUSR   0400
#define S_IWUSR   0200
#define S_IRWXU   0700

struct stat {
    dev_t     st_dev;
    ino_t     st_ino;
    mode_t    st_mode;
    nlink_t   st_nlink;
    uid_t     st_uid;
    gid_t     st_gid;
    dev_t     st_rdev;
    off_t     st_size;
    blksize_t st_blksize;
    blkcnt_t  st_blocks;
    long      st_atime;
    long      st_mtime;
    long      st_ctime;
};

int stat(const char *, struct stat *);
int fstat(int, struct stat *);
int lstat(const char *, struct stat *);
int mkdir(const char *, mode_t);

#endif
