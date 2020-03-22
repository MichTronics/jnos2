
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
#include <sys/time.h>
#include <errno.h>

unsigned char *SHA512ByteHash (unsigned char *iBuf);

static unsigned char *random_salt (int len)
{
	unsigned char *retbuf, *ptr;

	struct timeval tv;

	int cnt;

	ptr = retbuf = malloc (len);

	/*
	 * 08Jan2010, Maiko (VE4KLM), Oops, you MUST set a seed value for
	 * the random function, because if you don't, you will get the same
	 * sequence of numbers each time this is called. It's very important
	 * for each user to have a salt value that differs from the others.
	 *
  	srand (time (NULL));
	 *
	 * 13Jan2020, Maiko, 1 second is simply not enough when looping the
	 * function over and over during an import of the ftpusers file :]
	 *
	 * Need microsecond precision, so using gettimeofday () function !
     */

	gettimeofday (&tv, NULL);

	srand (1000000 * tv.tv_sec + tv.tv_usec);

	for (cnt = 0; cnt < len; cnt++, ptr++)
		*ptr = random () % 255;

	return retbuf;
}

/* 15Jan2020, Maiko, MUST prototype this guys, ubuntu is unforgiving */
extern char *j2strlwr (char*);

/*
 * 05Jan2020, Maiko, Added 2 new args to j2adduser, no more ftpusers file !
 * 23Feb2020, Maiko, Added 'gecos' argument, requested by Fox (N6MEF)
 */
void j2adduser (int type, char *username, char *password, char *dirpath, char *privs, char *gecos)
{
	unsigned char *salt, *hash, final[64], *fptr = final;
	char userpath[100];
	int cnt, req;
	FILE *fp;

	/*
	 * 18Dec2019, Maiko (VE4KLM), Instead of adding another argument to
	 * this function, let's just OR a flag value to the type argument. It
	 * means I don't have to modify ANY of the calls to this function !
	 *
	 * I want the BBS user to request their own password, that way the
	 * sysop will never see it (or need too) in cleartext in order to
	 * enter it - let the BBS user do it, but flag it as a '.req' file,
	 * which gives the SYSOP the final word on whether to replace an
	 * existing password file or just rename it as the actual file.
	 *  (which relegates jnospwmgr to secondary use, perfectly fine)
	 *
	 * 05Jan2020, Maiko (VE4KLM), Scratch that idea, well leave it
	 * there, but jnospwmgr really is a primary use item, got some
	 * feedback from people saying so ! And now that I am getting
	 * rid of ftpusers, I need to add a couple more args anyway.
	 */
	if (type & 0x80)
		req = 1;
	else
		req = 0;

	type &= 0x01;	/* You HAVE TO mask out the request bit */

	/* 18Dec2019, end of OR a flag value */

	j2strlwr (username);	/* 30Oct2015, Maiko, force lower */

	/* 02Nov2015, Maiko, okay incorporate account type in filename */
	sprintf (userpath, "users/%s.%d.dat", username, type);

	/* 18Dec2019, Maiko, make it a REQUEST file */
	if (req) strcat (userpath, ".req");

	salt = random_salt (4);

	/* salt will take up the first 4 bytes */
	memcpy (fptr, salt, 4);
	fptr += 4;

	/* using strcpy which terminates what needs to be a string */
	strcpy (fptr, password);

	// printf ("password [%s]\n", password);

	/* now create a proper 64 byte SHA512 hash of the combo above */
	hash = SHA512ByteHash (final);

	if ((fp = fopen (userpath, "w+")))
	{
		fprintf (fp, "%d:%s:", type, username);

	/* let's stick with ascii representation for portability */

		for (cnt = 0; cnt < 64; cnt++, hash++)
			fprintf (fp, "%02x", *hash);

		fprintf (fp, ":");

		for (cnt = 0; cnt < 4; cnt++, salt++)
			fprintf (fp, "%02x", *salt);

		/*
		 * 05Jan2020, Maiko, Adding directory and privilege fields.
		 *
		 * You can specify NULL pointer values for these two fields when
		 * calling j2adduser, in that case, it will write in the legacy
		 * default values (been like that for years) as you can see.
		 */

		fprintf (fp, ":");

		if (dirpath)
			fprintf (fp, "%s", dirpath);
		else
			fprintf (fp, "/jnos/public");

		fprintf (fp, ":");

		if (privs)
			fprintf (fp, "%s", privs);
		else
			fprintf (fp, "0x0407f");

		/*
		 * 23Feb2020, Maiko, adding 'gecos' field - Fox (N6MEF) thought of that,
		 * and keep consistent number of delimiters (columns) in the file, even
		 * if the field is blank, which can be the case for the gecos field !
		 */

		fprintf (fp, ":");

		if (gecos)
			fprintf (fp, "%s", gecos);

		fprintf (fp, ":");

		fclose (fp);
	}
	else perror (NULL);
}

