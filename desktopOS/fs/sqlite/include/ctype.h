/* Minimal ctype shim. SQLite uses isspace/isdigit/isalpha/tolower a lot
 * for SQL parsing. ASCII-only is fine; SQLite has its own UTF-8 path
 * that doesn't touch these macros. */
#ifndef _DESKTOPOS_CTYPE_H
#define _DESKTOPOS_CTYPE_H

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
int tolower(int c);
int toupper(int c);

#endif
