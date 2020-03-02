
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
 */

#include <stdio.h>
#include <string.h>

static int usage ()
{
	printf ("\n JNOS 2.0 password manager V2 - Feb 2020, by Maiko Langelaar (VE4KLM)\n"); 

	printf ("\n  Usage: j2pwmgr { -a | -d | -l } <user> [-w] [-p <password>] [-r <rootdir>] [-# <permissons>] [-g <gecos>]\n\nArguments:\n  -a   create password entry for <user>\n  -d   delete password entry for <user>\n  -l   list password entry for <user>\n\nOptions:\n  -w   mark as a Winlink user; default is a JNOS user\n  -p   instead of prompting for password, set via the command line\n  -r   root directory; default is /jnos/public\n  -#   permissions; default is 0x0407f\n  -g   name, contact, notes, whatever; default is empty\n\n");

#ifdef MD5AUTHENTICATE
	printf ("  Warning: MD5AUTHENTICATE defined - JNOS user passwords can be decrypted\n\n");
#endif	/* end of MD5AUTHENTICATE */

	return 0;
}

/* 07Jan2020, Maiko (VE4KLM), New command and option definitions */

#define	J2PWMGR_ADD_USER	1
#define	J2PWMGR_DEL_USER	2
#define	J2PWMGR_LST_USER	3

#define	J2PWMGR_PW_CMD_LINE	0x01
#define	J2PWMGR_WINLINK_USER	0x02

#define stricmp strcasecmp

/* 23Feb2020, Maiko, Added gecos field */

int main (int argc, char **argv)
{
	char *usr, *passwd, *rootdir = NULL, *perms = NULL, *gecos = NULL;

	int cmd = 0, opt = 0, cnt = 0, retval = 0;	/* 24Feb2020, Maiko, return value for list command */

	if (argc < 3) return usage ();

	while (cnt < argc)
	{
		if (!stricmp (*argv, "-a"))
		{
			argv++; cnt++;

			if (cnt == argc) return usage ();

			usr = strdup (*argv);

			cmd = J2PWMGR_ADD_USER;
		}
		else if (!stricmp (*argv, "-d"))
		{
			argv++; cnt++;

			if (cnt == argc) return usage ();

			usr = strdup (*argv);

			cmd = J2PWMGR_DEL_USER;
		}
		/* 23Feb2020, Maiko, Added list user details command */
		else if (!stricmp (*argv, "-l"))
		{
			argv++; cnt++;

			if (cnt == argc) return usage ();

			usr = strdup (*argv);

			cmd = J2PWMGR_LST_USER;
		}
		else if (!stricmp (*argv, "-w"))
		{
			opt |= J2PWMGR_WINLINK_USER;
		}
		else if (!stricmp (*argv, "-p"))
		{
			argv++; cnt++;

			if (cnt == argc) return usage ();

			passwd = strdup (*argv);

			opt |= J2PWMGR_PW_CMD_LINE;
		}
		else if (!stricmp (*argv, "-r"))
		{
			argv++; cnt++;

			if (cnt == argc) return usage ();

			rootdir = strdup (*argv);
		}
		else if (!stricmp (*argv, "-#"))
		{
			argv++; cnt++;

			if (cnt == argc) return usage ();

			perms = strdup (*argv);
		}
		else if (!stricmp (*argv, "-g"))	/* 23Feb2020, Maiko, Added gecos field */
		{
			argv++; cnt++;

			if (cnt == argc) return usage ();

			gecos = strdup (*argv);
		}

		argv++; cnt++;
	}

	if (cmd == J2PWMGR_ADD_USER)
	{
		if (!(opt & J2PWMGR_PW_CMD_LINE))
		{
			printf ("enter your password\n");

			/*
			 * 24Jun2016, Maiko, deprecated, supposedly dangerous function,
			 * so yeah okay whatever, replace with something that requires
			 * more code, typical C scare mongers ...
			 *
				gets (cleartxtpasswd);
			 */
			passwd = malloc (20);

			fgets (passwd, 18, stdin);
		}

		j2rip (passwd);

		/*
		 * 03Dec2019, Maiko (VE4KLM), This is a bit of a let down, but that's
		 * life, use V2 for my type 0 JNOS users, and stick with the original
		 * version for the type 1 Winlink CMS user (for now) - the logistics
		 * involved in moving from passwords to hashes ? overwhelming, yup !
		 *
		j2adduser ((opt && (*opt == 'w')) ? 1 : 0, usr, passwd);
		 *
		 * 05Jan2020, Maiko, Added directory and privs to j2adduser function,
	 	 * setting to NULL for now, which will result in the default values
		 * being applied to the current user. Will add extra options later.
		 *
		 * 13Jan2020, Maiko, Can now specify rootdir and permission values.
		 */

		if (opt & J2PWMGR_WINLINK_USER)
			j2adduserV1 (1, usr, passwd);
		else
		{
			/* 23Feb2020, Maiko, Added 'gecos' argument, Fox (N6MEF) idea */
			j2adduser (0, usr, passwd, rootdir, perms, gecos);

#ifdef MD5AUTHENTICATE

			/*
			 * 21Feb2020, Add the encrypted password if MD5 is defined.
			 */
			j2addmd5V1 (usr, passwd);

#endif	/* end of MD5AUTHENTICATE */

		}
	}
	else if (cmd == J2PWMGR_DEL_USER)
	{
		j2deluser ((opt & J2PWMGR_WINLINK_USER) ? 1: 0, usr);
	}
	/* 23Feb2020, Maiko (VE4KLM), can now list specific user */
	else if (cmd == J2PWMGR_LST_USER)
	{
		if (!strcmp (usr, "ALL"))
			retval = j2lsteveryone ((opt & J2PWMGR_WINLINK_USER) ? 1: 0);
		else
			retval = j2lstuser ((opt & J2PWMGR_WINLINK_USER) ? 1: 0, usr);
	}
	else usage ();	/* 23Feb2020, Maiko, Oops this line is important */

	return retval;
}

