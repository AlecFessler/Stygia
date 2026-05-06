/* Doom uses BSD-style strings.h for strcasecmp/strncasecmp. We forward
 * to the same prototypes exposed in string.h. */
#ifndef _DESKTOPOS_DOOM_STRINGS_H
#define _DESKTOPOS_DOOM_STRINGS_H

#include <stddef.h>

int strcasecmp(const char *a, const char *b);
int strncasecmp(const char *a, const char *b, size_t n);

#endif
