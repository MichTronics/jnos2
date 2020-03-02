
/*
 * 10Dec2019, Maiko, I need this all over the place, so just
 * one small nice little object file to include as I need :)
 *
 * Copy a string to a malloc'ed buffer. Turbo C has this one in its
 * library, but it doesn't call mallocw() and can therefore return NULL.
 * NOS uses of strdup() generally don't check for NULL, so they need this one.
 *
 * 03Apr2006, Maiko (VE4KLM), renamed to j2strdup () to avoid conflicts
 * with system library function of the same name.
 */

#include "global.h"

char *j2strdup (const char *s)
{
    register char *out;
    register int len;
  
    if(s == NULLCHAR)
        return NULLCHAR;
    len = strlen(s);
/*
 * 14Jan2020, Maiko, This is ridiculous, just use the damn malloc() call,
 * that's the next thing that I need to 'fix' in all of this code. There
 * will be a new j2alloc () coming to a neighbourhood near you soon :]
 *
 * All this darn redefinition of malloc to mallocw and so on.
 *
    out = mallocw(len+1);
 */

#undef	malloc

    out = malloc (len + 1);

    /* This is probably a tad faster than strcpy, since we know the len */
    memcpy(out,s,len);
    out[len] = '\0';
    return out;
}

