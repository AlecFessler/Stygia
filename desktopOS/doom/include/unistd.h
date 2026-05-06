/* Freestanding <unistd.h> stub. */
#ifndef _DESKTOPOS_DOOM_UNISTD_H
#define _DESKTOPOS_DOOM_UNISTD_H

#include <sys/types.h>

#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

#define F_OK 0
#define R_OK 4
#define W_OK 2
#define X_OK 1

int    access(const char *, int);
int    close(int);
ssize_t read(int, void *, size_t);
ssize_t write(int, const void *, size_t);
off_t  lseek(int, off_t, int);
int    isatty(int);
int    unlink(const char *);
int    rmdir(const char *);
int    chdir(const char *);
char  *getcwd(char *, size_t);
unsigned int sleep(unsigned int);
int    usleep(unsigned int);
pid_t  getpid(void);

#endif
