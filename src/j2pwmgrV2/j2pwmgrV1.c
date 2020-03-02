
/*
 * I still need original j2pwmgr code to store the WL2K CMS password, but
 * since 'libcrypt' is deprecated, I have decided to remove the mangling
 * and just encrypt / decrypt using an EVP openssl example at this URL :

 https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption

 *
 * Here is the mandatory copyright notice for any borrowed openssl code :
 *

   Copyright OpenSSL [2019]
   Contents licensed under the terms of the OpenSSL license
   See https://www.openssl.org/source/license.html for details

 *
 * I have no choice but to use encryption / decryption because I need the
 * cleartext password for the challenge phrase processing. It's all about
 * logistics and overwhelming amounts of work in order to change things.
 *
 * 05Dec2019, Maiko Langelaar (VE4KLM), Copyright 2019
 *
 * 19Dec2019, Maiko, I am sure some will say this is major overkill :/
 *  (going to stick with it though, it has been quite educational)
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 02Nov2015, Maiko (VE4KLM), moved here, need it for lib purposes */

static char keyset = 0;

/*
 * 06Dec2019, Maiko (VE4KLM), I do NOT want to hardcode these, but
 * having trouble making this work by simply switching to arrays.
 * My intention is to have the SYSOP generate these keys, but just
 * not able to make that part work, call it a brain fart, so return
 * to this later I guess, the main thing is encryption works now.
 *
 * 14Dec2019, Maiko (VE4KLM), just out of whimsy perhaps, generated
 * random keys at first compile, each site will get a unique key. I
 * just didn't feel like storing a key in a file is the best way ?
 */

#ifdef	NOW_EXISTS_IN_RANDOM_GENERATED_SOURCE_FILE	/* 14Dec2019 */

   /* A 256 bit key */
//static unsigned char key[33];	/* 32 character text - do not hardcode */
//unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

unsigned char *key = (unsigned char*)0;	/* 10Dec2019 */

    /* A 128 bit IV */
//static unsigned char iv[17];	/* 16 character text - do not hardcode */
//unsigned char *iv = (unsigned char *)"0123456789012345";

unsigned char *iv = (unsigned char*)0;	/* 10Dec2019 */

void j2setkey ()
{
	/*
	 * 05Dec2019, Maiko (VE4KLM), Now using key and IV defs as shown at :
	 *
	 *  https://wiki.openssl.org/index.php/
	 *    EVP_Symmetric_Encryption_and_Decryption
	 *
	 * Should generate key and iv when first configuring the system.
	 *  (wiki says to not hardcode these values as in the example, agreed)
	 */

	if (!keyset)
	{
		/*
		 * 06Dec2019, Maiko (VE4KLM), I do NOT want to hardcode these, but
		 * having trouble making this work by simply switching to arrays.
		 */

		//memcpy (key, (unsigned char*)"01234567890123456789012345678901", 32);
		//key[32] = 0;

	 	//memcpy (iv, (unsigned char*)"0123456789012345", 16);
		//iv[16] = 0;

		/*
		 * 10Dec2019, Maiko (VE4KLM), stick with pointers, but use j2strdup
		 * to initialize them instead of hardcoding them at the top of this
		 * source file - hardcode this as a test, then read them from file.
		 *
		 * EXCELLENT - this is working nicely, my WL2K still decrypts properly !
		 */

		key = (unsigned char *)strdup ("01234567890123456789012345678901");

		iv = (unsigned char *)strdup ("0123456789012345");

		//nos_log (-1, "installed encryption keys");

		keyset = 1;
	}
}

#else

/*
 * 14Dec2019, Maiko, Technically this function not needed anymore, so remove it
 * in a later release, when I am 100 percent sure I like the way I did this :]
 */

extern unsigned char *key, *iv;

void j2setkey () { keyset = 1; }

#endif

/* 15Jan2020, Maiko, MUST prototype this guys, ubuntu is unforgiving */
extern char *j2strlwr (char*);
extern char j2hextochar (char*);

extern int encrypt (unsigned char *plaintext, int plaintext_len,
 unsigned char *key, unsigned char *iv, unsigned char *ciphertext);

extern int decrypt(unsigned char *ciphertext, int ciphertext_len,
 unsigned char *key, unsigned char *iv, unsigned char *plaintext);

/*
 * 24Oct2015, Maiko (VE4KLM), get type:password for specified user
 * 30Oct2015, was void, now returning string as a malloc() pointer
 *
void j2userpasswd (int type, char *username, char *password)
 *
 * 02Dec2019, Maiko (VE4KLM), renamed function with V1 to denote
 * the original version of the function required to retrieve the
 * user password needed to access any of the WL2K CMS servers.
 *
char *j2userpasswd (int type, char *username)
 *
 */

char *j2userpasswdV1 (int type, char *username)
{
	char filedpasswd[65], rusername[20];
	unsigned char passwdblock[65], *pbptr = passwdblock;
	int rtype, len;
	FILE *fp;
/*
	unsigned char *dtptr;
	int cnt;
*/

    /* Buffer for the decrypted text */
    unsigned char *decryptedtext = malloc (128);	/* Maiko, need to malloc since we return it */


    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */
    unsigned char ciphertext[128], *ctptr = ciphertext;

	j2strlwr (username);	/* 30Oct2015, Maiko (VE4KLM), force lower */

	/* 02Nov2015, Maiko, okay incorporate account type in filename */
	sprintf (filedpasswd, "users/%s.%d.dat", username, type);

	/*
	 * originally I was thinking having one password file per user, and
	 * having all the different account types in the one file, but not so
	 * sure now, so let's just use separate files - code much simpler. I
	 * can always merge them into one file down the road if desired ...
	 */

	if ((fp = fopen (filedpasswd, "r")))
	{
		fscanf (fp, "%d:%[^:]:%[^:]", &rtype, rusername, passwdblock);
		fclose (fp);
	}
	else
	{
/*
 * Would like to have these here, but then I have to include JNOS libs
 * so just return the NULL value, let JNOS itself print out the error.
 * 
		tprintf ("Unable to open [%s] for read\n", filedpasswd);
		if (type == 1)
			tprintf ("did you forget to configure a winlink CMS user ?\n");
 */

		return (char*)0;
	}

	/* 05Dec2019, Maiko (VE4KLM), need to convert from ascii to binary ! */

	// printf ("%s\n", passwdblock);

	for (len = 0; *pbptr; len++, ctptr++, pbptr += 2)
		*ctptr = (unsigned char)j2hextochar ((char*)pbptr);

	/*
	 * 05Dec2019, Maiko (VE4KLM), Now using encrypt example as show at
	 *
	 *  https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
	 *
	 */

	j2setkey ();

	// printf ("%d\n", len);

	len = decrypt (ciphertext, len, key, iv, decryptedtext);

	// printf ("%d\n", len);

	decryptedtext[len] = 0;

/*
	for (dtptr = decryptedtext, cnt = 0; cnt < len; cnt++)
		printf ("%02x", *dtptr++);

	printf ("\n");
*/

	return ((char*)decryptedtext);
}

#ifdef MD5AUTHENTICATE

/*
 * 21Feb2020, Maiko (VE4KLM), new j2chkmd5V1() function to get the
 * cleartext password from the recent JNOS password management libs,
 * no other choice if we are to continue supporting MD5AUTHENTICATE
 * feature, there are several organizations still using it.
 *
 * In the end, this is easy to add, just use the j2userpasswdV1()
 * function I wrote to get the cleartext password for Winlink CMS
 * stuff, so j2chkmd5V1() simply is a stub to that function, but
 * using a new type = 3, not type = 1 which we use for Winlink.
 */

char *j2chkmd5V1 (char *username)
{
	return j2userpasswdV1 (3, username);
}

#endif	/* end of MD5AUTHENTICATE */

/*
 * 24Oct2015, Maiko (VE4KLM), create user file to hold their type:password
 *
 * 02Dec2019, Maiko (VE4KLM), renamed function with V1 to denote
 * the original version of the function required to retrieve the
 * user password needed to access any of the WL2K CMS servers.
 *
void j2adduser (int type, char *username, char *passwdblock)
 *
 */

void j2adduserV1 (int type, char *username, char *password)
{
	char userpath[100];
	int cnt, len;
	FILE *fp;

    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */
    unsigned char ciphertext[128], *ctptr = ciphertext;

	j2strlwr (username);	/* 30Oct2015, Maiko (VE4KLM), force lower */

	/* 02Nov2015, Maiko, okay incorporate account type in filename */
	sprintf (userpath, "users/%s.%d.dat", username, type);

	len = encrypt ((unsigned char*)password, strlen (password), key, iv, ciphertext);

	/* printf ("len of ciphertext %d\n", len); */

	if ((fp = fopen (userpath, "w+")))
	{
		fprintf (fp, "%d:%s:", type, username);

		/* 05Dec2019, Maiko (VE4KLM), write it in ascii form ! */
		for (cnt = 0; cnt < len; cnt++, ctptr++)
			fprintf (fp, "%02x", *ctptr);

		fclose (fp);
	}
/*
 * Same reason as the other tprintf I commented out earlier
 *
	else tprintf ("Unable to open [%s] for write\n", userpath);
 */
}

#ifdef MD5AUTHENTICATE

/*
 * 21Feb2020, Maiko (VE4KLM), new j2addmd5V1() function to save the
 * cleartext password to the recent JNOS password management libs,
 * no other choice if we are to continue supporting MD5AUTHENTICATE
 * feature, there are several organizations still using it.
 *
 * In the end, this is easy to add, just use the j2adduserV1()
 * function I wrote to save the cleartext password for Winlink CMS
 * stuff, so j2addmd5V1() simply is a stub to that function, but
 * using a new type = 3, not type = 1 which we use for Winlink.
 */

void j2addmd5V1 (char *username, char *password)
{
	j2adduserV1 (3, username, password);
}

#endif	/* end of MD5AUTHENTICATE */

