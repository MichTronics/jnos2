
/*
 * 01Dec2019, Maiko Langelaar (VE4KLM), Copyright 2019
 *
 * Version 2 of the JNOS 2.0 Password Management Database
 *
 */

#include <stdio.h>

void j2deluser (int type, char *username)
{
	char userpath[100];

	FILE *fp;

	j2strlwr (username);	/* 30Oct2015, Maiko (VE4KLM), force lower */

	/* 02Nov2015, Maiko, okay incorporate account type in filename */
	sprintf (userpath, "users/%s.%d.dat", username, type);

	if (unlink (userpath)) perror (NULL);
}

