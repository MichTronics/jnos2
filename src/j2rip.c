
/*
 * 03Dec2019, Maiko, I need this all over the place, so just
 * one small nice little object file to include as I need :)
 */

#include <string.h>

/* replace terminating end of line marker(s) with null */

void j2rip (register char *s)
{
    register char *cp;
  
    if ((cp = strpbrk (s,"\r\n")) != NULL) /* n5knx: was "\n" */
        *cp = '\0';
}

