
/*
 * 01Dec2019, Maiko Langelaar (VE4KLM), Copyright 2019
 *
 * Some test code I finally got working today, stuff that will replace
 * the existing j2pwmgr routines from JNOS 2.0m and earlier. Encrypting
 * passwords is no longer a desirable thing, time to move to HASH based
 * techniques (for now anyways), really liking how this is working.
 *
 * From the JNOS 2.0m release history (November 27, 2019), my reasoning :
 *
   Investigating the removal of passwords from ftpusers, incorporate them into
   the same JNOS 2.0 Password Management Database as currently used for saving
   the Winlink password. At the same time, I am removing the encryption of any
   passwords and replacing them with hash:salt information instead, as per the
   recommendations of several high profile security institutions, meeting the
   need that nobody, not even the administrator, will be able to determine a
   users password (because HASH values only go in one direction).

   One could even consider multiple iterations, one could include the CPU id
   of the physical or virtual computer or some other identifier unique to the
   JNOS host setup, locking the hashes to the specific server JNOS runs on.

   As much as I want to entertain the idea of using HMAC-SHA-256, PBKDF2, or
   whatever the flavour of the year, the code can get complex, so for a first
   time prototype, MD5 is fine - it's JNOS, not a financial institution :|
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include <openssl/md5.h>

static char *strlwr (char *s)
{
    register char *p = s;

    while (*p)
	*p = tolower(*p), p++;

    return s;
}

/* 01Dec2019, Maiko (VE4KLM), love writing this little minimal code but useful functions */

char *get_a_str_nxt_terminator (char *src, char *dst, char terminator)
{
	while (*src && *src != terminator)
		*dst++ = *src++;

	*dst = 0;	/* terminate destination string if passed */

	return src;
}

/* 08Jul2009, Maiko, New hextochar function for URI decoding */

char hextochar (char *ptr)
{
	char nib, val;
	int cnt = 2;

	while (cnt)
	{
		if (*ptr >= '0' && *ptr <= '9')
			nib = (*ptr - 0x30);
		else if (*ptr >= 'A' && *ptr <= 'F')
			nib = (*ptr - 0x41) + 10;
		else if (*ptr >= 'a' && *ptr <= 'f')
			nib = (*ptr - 0x61) + 10;
		else
		{
			printf ("invalid hex digit\n");
			nib = 0;
		}

		if (cnt == 2)
			val = nib * 16;
		else
			val += nib;
		cnt--;
		ptr++;
	}

	return val;
}

#ifdef	INTERNAL_DEBUGGING
static void dumpbinary (unsigned char *ptr, int len)
{
	int cnt;

	for (cnt = 0; cnt < len; cnt++, ptr++)
		printf (" %02x", *ptr);
}
#endif

static unsigned char *random_salt (int len)
{
	unsigned char *retbuf, *ptr;

	int cnt;

	ptr = retbuf = malloc (len);

	for (cnt = 0; cnt < len; cnt++, ptr++)
		*ptr = random () % 255;

	return retbuf;
}

static unsigned char *MD5ByteHash (unsigned char *iBuf)
{
	static unsigned char hash[MD5_DIGEST_LENGTH];

	MD5 (iBuf, strlen ((char*)iBuf), hash);

	return hash;
}

/*
 * MD5 et all will output 16 bytes (128 bits), good enough for JNOS 2.0
 *
 * question then is what is the max password length that I am willing to
 * allow for JNOS users ? This of course affects the length of the random
 * salt I want to tack onto the password before a final hash gets done.
 */

void j2adduser (int type, char *username, char *password)
{
	unsigned char *salt, *hash, final[16], *fptr = final;

	char userpath[100];

	int cnt;

	strlwr (username);	/* 30Oct2015, Maiko (VE4KLM), force lower */

	/* 02Nov2015, Maiko, okay incorporate account type in filename */
	sprintf (userpath, "users/%s.%d.dat", username, type);

	salt = random_salt (4);

	/* salt will take up the first 4 bytes */
	memcpy (fptr, salt, 4);
	fptr += 4;

	/* password will take up the final 12 bytes */
	memcpy (fptr, password, 12);

	/* now create a proper 16 byte MD5 hash of the combo above */
	hash = MD5ByteHash (final);

#ifdef	INTERNAL_DEBUGGING
	printf ("user %s : pass %s\n", username, password);
	printf ("hash : ");
	dumpbinary (hash, 16);
	printf (" salt : ");
	dumpbinary (salt, 4);
	printf ("\n");
#endif

	FILE *fp = fopen (userpath, "w+");

	if (fp)
	{
		fprintf (fp, "%d:%s:", type, username);

	/* let's stick with ascii representation for portability */

		for (cnt = 0; cnt < 16; cnt++, hash++)
			fprintf (fp, "%02x", *hash);

		fprintf (fp, ":");

		for (cnt = 0; cnt < 4; cnt++, salt++)
			fprintf (fp, "%02x", *salt);

		fclose (fp);
	}
	else perror (NULL);
}

int j2chkuser (int type, char *username, char *password)
{
	unsigned char *salt, *hash, final[16], *fptr = final;

	char general[100];

	int cnt;

	/* variables to hold stuff we read in from the file */
	char r_username[20], r_hash[16], *rp_hash, r_salt[4], *rp_salt, *ptr;
	int  r_type;

	strlwr (username);	/* 30Oct2015, Maiko (VE4KLM), force lower */

	/* 02Nov2015, Maiko, okay incorporate account type in filename */
	sprintf (general, "users/%s.%d.dat", username, type);

	FILE *fp = fopen (general, "r");

	if (fp)
	{
		/*
		 * let's stick with ascii representation for portability
		 *
		 * I originally started with fscanf, then decided to go the
		 * fgets route and use my own custom code to do the rest.
		 */

		fgets (general, sizeof(general)-3, fp);

		/* user TYPE */
		ptr = get_a_str_nxt_terminator (general, r_username, ':');

		ptr++;	/* skip delimiter */

		/* user NAME */
		ptr = get_a_str_nxt_terminator (ptr, r_username, ':');

		ptr++;	/* skip delimiter */

		for (cnt = 0, rp_hash = r_hash; cnt < 16; cnt++, rp_hash++, ptr++, ptr++)
			*rp_hash = hextochar (ptr);

		ptr++;	// skip ':' delimiter

		for (cnt = 0, rp_salt = r_salt; cnt < 4; cnt++, rp_salt++, ptr++, ptr++)
			*rp_salt = hextochar (ptr);

		fclose (fp);
	}
	else perror (NULL);

	/* salt will take up the first 4 bytes, use the one read from the file */
	memcpy (fptr, r_salt, 4);
	fptr += 4;

	/* password will take up the final 12 bytes */
	memcpy (fptr, password, 12);

	/* now create a proper 16 byte MD5 hash of the combo above */
	hash = MD5ByteHash (final);

#ifdef	INTERNAL_DEBUGGING
	printf ("user %s : pass %s\n", username, password);
	printf ("hash : ");
	dumpbinary (hash, 16);
	printf (" salt : ");
	dumpbinary (r_salt, 4);
	printf ("\n");
#endif

	/* does the hash generated match the one read in from the file ? */
	return (memcmp (hash, r_hash, 16) == 0);
}

main (int argc, char **argv)
{
	srandom (time(NULL));

	if (strcmp (argv[1], "add") == 0)
		j2adduser (0, argv[2], argv[3]);

	if (strcmp (argv[1], "check") == 0)
	{
		printf ("2 [%s] 3 [%s]\n", argv[2], argv[3]);

		if (j2chkuser (0, argv[2], argv[3]))
			printf ("password correct\n");
		else
			printf ("password failed\n");
	}
}

