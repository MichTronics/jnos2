
/*
 * 01Dec2019, Maiko Langelaar (VE4KLM), Copyright 2019
 *
 * please refer to test.c for original notes and prototype code
 *
 * Versions of JNOS 2.0m.1 (not 2.0m itself) will no longer have
 * any JNOS user passwords stored in the ftpusers file. As well,
 * the winlink password will no longer be mangled and encrypted,
 * mostly because encryption is reversible, and just not the way
 * to do things anymore - the deprecation of libcrypt helped me
 * nicely on this one anyways ... So now presenting to you :
 *
 * Version 2 of the JNOS 2.0 Password Management Database
 *
 * Encryption has been replaced with HASH / SALT pairs !
 *
 * The passwords previously kept in ftpusers will now have their
 * hash / salt pairs saved in the same database as is currently
 * used for the winlink CMS login credentials, no passwords for
 * those as well, they too will use a hash / salt pair.
 *
 * No more cleartext, no more ability to retrieve passwords !
 *
 * The MD5 code is in the j2md5bh.c source file
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

char *get_a_str_nxt_terminator (char *src, char *dst, char terminator)
{
	while (*src && *src != terminator)
		*dst++ = *src++;

	*dst = 0;	/* terminate destination string if passed */

	return src;
}

unsigned char *SHA512ByteHash (unsigned char *iBuf);

/* 15Jan2020, Maiko, MUST prototype this guys, ubuntu is unforgiving */
extern char *j2strlwr (char*);
extern void j2rip (register char*);
extern char j2hextochar (char*);
extern char *j2strdup (const char*);

/* 04Jan2020, Maiko, Adding 2 new args to j2chkuser, no more ftpusers file ! */

int j2chkuser (int type, char *username, char *password, char **dirpath, char **privs)
{
	unsigned char *hash, final[64], *fptr = final;
	char general[250], r_username[20], r_hash[64];
	char *rp_hash, r_salt[4], *rp_salt, *ptr;
	FILE *fp;
	int cnt;

	j2strlwr (username);	/* 30Oct2015, Maiko (VE4KLM), force lower */

	/* 02Nov2015, Maiko, okay incorporate account type in filename */
	sprintf (general, "users/%s.%d.dat", username, type);

	if ((fp = fopen (general, "r")))
	{
		/*
		 * let's stick with ascii representation for portability
		 *
		 * I originally started with fscanf, then decided to go the
		 * fgets route and use my own custom code to do the rest.
		 */

		fgets (general, sizeof(general)-3, fp);

		j2rip (general);	/* 11Jan2020, Maiko, Noticed in raw privs string */

		/* user TYPE */
		ptr = get_a_str_nxt_terminator (general, r_username, ':');

		ptr++;	/* skip delimiter */

		/* user NAME */
		ptr = get_a_str_nxt_terminator (ptr, r_username, ':');

		ptr++;	/* skip delimiter */

		for (cnt = 0, rp_hash = r_hash; cnt < 64; cnt++, rp_hash++, ptr++, ptr++)
			*rp_hash = j2hextochar (ptr);

		ptr++;	// skip ':' delimiter

		for (cnt = 0, rp_salt = r_salt; cnt < 4; cnt++, rp_salt++, ptr++, ptr++)
			*rp_salt = j2hextochar (ptr);
	/*
	 * 04Jan2020, Maiko (VE4KLM), Adding privs and directory previously held
	 * in the ftpusers file, dirpath and privs should be freed after use !
	 */
		{
			char tempbuf[100];	/* development only */

		ptr++;	// skip ':' delimiter

		ptr = get_a_str_nxt_terminator (ptr, tempbuf, ':');
		*dirpath = j2strdup (tempbuf);

		ptr++;	// skip ':' delimiter

		ptr = get_a_str_nxt_terminator (ptr, tempbuf, ':');
		*privs = j2strdup (tempbuf);

		}

		fclose (fp);
	}
	else
	{
		/*
		 * 11Jan2020, Maiko, Oops, should return -2 if user does not exist,
		 * so we can properly setup for 'univperm' scenarios. Kind of forgot
		 * about that right when I was ready to release this stuff.
		 *
	else perror (NULL);
		 *
		 */

		 return -2;		/* -2 means user does not exist !!! */
	}

	/* salt will take up the first 4 bytes, use the one read from the file */
	memcpy (fptr, r_salt, 4);
	fptr += 4;

	// printf ("r_salt [%.4s]\n", r_salt);

	/* using strcpy which terminates what needs to be a string */
	strcpy (fptr, password);

	// printf ("password [%s]\n", password);

	/* now create a proper 64 byte SHA512 hash of the combo above */
	hash = SHA512ByteHash (final);

	/* does the hash generated match the one read in from the file ? */
	return (memcmp (hash, r_hash, 64) == 0);
}

#include <sys/types.h>

#include <dirent.h>

static int datfile (char *ptr)
{
	int len = strlen (ptr);

	return ((len > 4) && (strcmp (ptr + len - 4, ".dat") == 0));
}

/*
 * 25Feb2020, Maiko, list all users, could have used code from smtpcli.c, but
 * then I would have had to include tons of JNOS object files, so decided to
 * try out the linux opendir(), readdir(), closedir() stuff, works nicely.
 */
int j2lsteveryone (int type)
{
	DIR *dirp;
	struct dirent *dp;
	char tempbuf[20];
	int err, retval = 0;

	if ((dirp = opendir ("users")) == NULL)
	{
		printf ("unable to open 'users' directory\n");
		return 1;
	}
	
	while ((dp = readdir (dirp)) != NULL)
	{
		/* ignore the current and parent directory entries ! */
		if (*(dp->d_name) == '.')
			continue;

		/* make sure we only process '.dat' files */
		if (!datfile (dp->d_name))
			continue;

		get_a_str_nxt_terminator (dp->d_name, tempbuf, '.');
		err = j2lstuser (type, tempbuf);
		/* OR the error values, even one entry is a success */
		if (err && (retval == 0)) retval = err;
	}

	closedir (dirp);

	return retval;
}

/* 23Feb2020, Maiko (VE4KLM), list a particular user */
int j2lstuser (int type, char *username)
{
	char general[100], tempbuf[100], *ptr = general;
	int cnt, retval = 0;
	FILE *fp;

	j2strlwr (username);	/* 30Oct2015, Maiko (VE4KLM), force lower */

	/* 02Nov2015, Maiko, okay incorporate account type in filename */
	sprintf (general, "users/%s.%d.dat", username, type);

	if ((fp = fopen (general, "r")))
	{
		/*
		 * let's stick with ascii representation for portability
		 *
		 * I originally started with fscanf, then decided to go the
		 * fgets route and use my own custom code to do the rest.
		 */

		fgets (general, sizeof(general)-3, fp);

		j2rip (general);	/* 11Jan2020, Maiko, Noticed in raw privs string */

		printf ("%s", username);

		/* skip type, name, hash, salt */
		for (cnt = 0; cnt <= 6; cnt++)
		{
			ptr = get_a_str_nxt_terminator (ptr, tempbuf, ':');
			ptr++;	/* skip delimiter */
			if (cnt > 3)
				printf ("\t%s", tempbuf);
		}
		printf ("\n");
	}
	else
	{
		printf ("Could not open %s\n", general);
		retval = 1;
	}

	return retval;
}

