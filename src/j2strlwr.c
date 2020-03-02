
/*
 * 03Dec2019, Maiko, I need this all over the place, so just
 * one small nice little object file to include as I need :)
 */

#include <ctype.h>

char *j2strlwr (char *s)
{
    register char *p = s;

    while (*p) *p = tolower(*p), p++;

    return s;
}

