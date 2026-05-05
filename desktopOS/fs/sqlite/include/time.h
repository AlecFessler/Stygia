/* Minimal time shim. SQLite uses these for the date/time functions
 * (strftime, julianday, etc.). Our VFS xCurrentTime overrides the
 * "current time" plumbing, so most of this is unused. */
#ifndef _DESKTOPOS_TIME_H
#define _DESKTOPOS_TIME_H

#include <stddef.h>

typedef long time_t;
typedef long clock_t;

struct tm {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
    long tm_gmtoff;
    const char *tm_zone;
};

time_t time(time_t *);
struct tm *gmtime(const time_t *);
struct tm *localtime(const time_t *);
size_t strftime(char *, size_t, const char *, const struct tm *);
clock_t clock(void);

#endif
