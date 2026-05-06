/* Freestanding inttypes.h. Doom only uses PRId/PRIu printf formatters
 * and a handful of helpers. The integer typedefs come from stdint.h. */
#ifndef _DESKTOPOS_DOOM_INTTYPES_H
#define _DESKTOPOS_DOOM_INTTYPES_H

#include <stdint.h>

#define PRId8  "d"
#define PRId16 "d"
#define PRId32 "d"
#define PRId64 "lld"
#define PRIu8  "u"
#define PRIu16 "u"
#define PRIu32 "u"
#define PRIu64 "llu"
#define PRIx32 "x"
#define PRIx64 "llx"
#define PRIX64 "llX"

intmax_t strtoimax(const char *, char **, int);
uintmax_t strtoumax(const char *, char **, int);

#endif
