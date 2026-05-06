/* Freestanding ctype shim. Same set as the SQLite shim, with toupper
 * also exposed. */
#ifndef _DESKTOPOS_DOOM_CTYPE_H
#define _DESKTOPOS_DOOM_CTYPE_H

int isalpha(int c);
int isdigit(int c);
int isalnum(int c);
int isspace(int c);
int isxdigit(int c);
int isupper(int c);
int islower(int c);
int isprint(int c);
int ispunct(int c);
int iscntrl(int c);
int isgraph(int c);
int isblank(int c);
int tolower(int c);
int toupper(int c);

#endif
