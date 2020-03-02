
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *jnosroot, *callsign;

static int tnc_is_present = 0, currgroupnum = 0;

static void prompt ()
{
	printf ("--> ");
}

/*
 * 01Oct2019, Maiko (VE4KLM), yeah yeah, this is a dangerous function, no longer
 * declared in stdio.h, but honestly don't care in the context of this particular
 * application, I mean really the linker is gonna complain to me too :) I'll get
 * it removed @ some point and have to add 5 lines of code to replace the one :|
 *
extern char *gets(char*);
 * 
 * 03Dec2019, Maiko (VE4KLM), replacing gets() calls with fgets () equivalent.
 *
 *  (just getting tired of compiler warnings, and yeah, it needs to be done)
 *
 */

/* New to version 2, allows user to choose to install option or not */

static int dothisone (char *str)
{
	char entry[5];

	printf ("%s (yes or no) ?\n", str);

	while (1)
	{
		// gets (entry);
		fgets (entry, sizeof(entry)-2, stdin);

		if (*entry == 'y' || *entry == 'n')
			break;

		printf ("you must answer yes or no.\n");
	}

	return (*entry == 'y');
}

static void write_group (FILE *fpo, char *ddptr)
{
	char entry[2];

	int thisgroupnum;

	/* get the group number */
	sprintf (entry, "%c", *ddptr++);

	thisgroupnum = atoi (entry);

	if (thisgroupnum == currgroupnum)
		fputs (ddptr, fpo);
}

/*
 * new for version 2, if this function returns 0, then don't write
 * a group, a return value of 1 means go ahead. In version 1, this
 * was just a void function.
 */

static int prompt_4_group (FILE *fpo, char *ddptr)
{
	static char entry[80];
	FILE *fpdns;

	/* get the group number */
	sprintf (entry, "%c", *ddptr++);
	currgroupnum = atoi (entry);

//	printf ("group # %d\n", currgroupnum);

	if (currgroupnum == 1)
	{
		printf ("Enter your callsign\n");

		while (1)
		{
			prompt ();

			// gets (entry);
			fgets (entry, sizeof(entry)-2, stdin);

			if (*entry)
				break;
			else
				printf ("you MUST enter a callsign, no exceptions !\n");
		}

	/* New to version 2.1, create 'domain.txt' file for local DNS */

		fpdns = fopen ("./domain.txt", "w");
		fprintf (fpdns, "%s.\t999999\tIN\tA\t192.168.2.2\n", entry);
		fclose (fpdns);

	/* end of new domain.txt addition */

		fprintf (fpo, "hostname %s\n", entry);
		fprintf (fpo, "ax25 mycall %s\n", entry);

		callsign = strdup (entry);
	}
#ifdef	DONT_COMPILE
	else if (currgroupnum == 2)
	{
		printf ("Enter the IP address of your DNS server (default - 192.168.1.1)\n> ");
		// gets (entry);
		fgets (entry, sizeof(entry)-2, stdin);

		if (*entry)
			fprintf (fpo, "domain addserver %s\n", entry);
		else
		{
			printf ("using default value\n");
			fprintf (fpo, "domain addserver 192.168.1.1\n");
		}
	}
#endif
	else if (currgroupnum == 3)
	{
		/* New to version 2, give a choice whether to install TNC or not */
		if (!dothisone ("do you want to add a TNC to this system"))
			return 0;

		fprintf (fpo, "#\n#%s#\n", ddptr);		/* Write group comment */

		printf ("Enter the serial port for the TNC (default - ttyS0)\n> ");
		// gets (entry);
		fgets (entry, sizeof(entry)-2, stdin);

		if (*entry)
			fprintf (fpo, "attach asy %s - ax25 vhf 4096 256 ", entry);
		else
		{
			printf ("using default value\n");
			fprintf (fpo, "attach asy ttyS0 - ax25 vhf 4096 256 ");
		}

		printf ("Enter the baud rate for the serial port (default - 9600 baud)\n> ");
		// gets (entry);
		fgets (entry, sizeof(entry)-2, stdin);

		if (*entry)
			fprintf (fpo, "%s\n", entry);
		else
		{
			printf ("using default value\n");
			fprintf (fpo, "9600\n");
		}

		tnc_is_present = 1;	/* let beacon part know that TNC is there */
	}
/*
 * New to version 2 - attach AXIP to a remote system 
 */
	else if (currgroupnum == 4)
	{
		/* New to version 2, give a choice whether to install AXIP or not */
		if (!dothisone ("do you want to add a (AXIP) wormhole"))
			return 0;

		fprintf (fpo, "#\n#%s#\n", ddptr);		/* Write group comment */

		printf ("Enter the IP address of the remote host\n> ");
		// gets (entry);
		fgets (entry, sizeof(entry)-2, stdin);

		if (*entry)
			fprintf (fpo, "attach axip axi0 256 %s\n", entry);
	}
/*
 * New to version 2 - attach AXUDP to a remote system 
 */
	else if (currgroupnum == 5)
	{
		/* New to version 2, give a choice whether to install AXUDP or not */
		if (!dothisone ("do you want to add a (AXUDP) wormhole"))
			return 0;

		fprintf (fpo, "#\n#%s#\n", ddptr);		/* Write group comment */

		printf ("Enter the IP address of the remote host\n> ");
		// gets (entry);
		fgets (entry, sizeof(entry)-2, stdin);

		if (*entry)
			fprintf (fpo, "attach axudp axu0 256 %s\n", entry);
	}
/*
 * New to version 2 - create a beacon out the TNC port
 */
	else if (currgroupnum == 6)
	{
		/* Don't bother with beacon, if user opted out of TNC install */
		if (!tnc_is_present)
			return 0;

		/* New to version 2, ask user if they want the ax25 beacon or not */
		if (!dothisone ("do you want the TNC to beacon every 20 minutes"))
			return 0;

		fprintf (fpo, "#\n#%s#\n", ddptr);		/* Write group comment */
	}

	return 1;
}

/*
 * JNOSINSTALLER - main entry point for program
 */

static int ji_system (char *buffer)
{
	printf ("%s", buffer);

	if (system (buffer))
	{
		printf ("failure!\n");
		return -1;
	}
	else printf ("success!\n");

	return 0;
}

static int ji_mkdir (char *buffer, char *rootdir, char *dpath)
{
	if (dpath == NULL)
		sprintf (buffer, "mkdir -p %s\n", rootdir);
	else
		sprintf (buffer, "mkdir -p %s/%s\n", rootdir, dpath);

	return (ji_system (buffer));
}


int main (int argc, char **argv)
{
	char buffer_ca[300];

	FILE *fpi, *fpo;

	printf ("\nWelcome to version 2.2 of the JNOS 2.0 installer program\n(C)opyright 2005-2015 by Maiko Langelaar / VE4KLM\n\n");
	printf ("Just answer the questions as they pop up. IF you do not know how to answer\n");
	printf ("a particular question, just hit the ENTER key to pick the default choice.\n\n");

	printf ("Enter the word 'install' to begin, or anything else to quit.\n");
	prompt ();
	// gets (buffer_ca);
	fgets (buffer_ca, sizeof(buffer_ca)-2, stdin);
	if (strcmp ("install", buffer_ca))
		exit (0);

	printf ("\nEnter the JNOS root directory (default is /jnos)\n");
	prompt ();
	// gets (buffer_ca);
	fgets (buffer_ca, sizeof(buffer_ca)-2, stdin);
	if (*buffer_ca)
		jnosroot = strdup (buffer_ca);
	else
	{
		printf ("using default value\n");
		jnosroot = "/jnos";
	}

	/*
	 * Try and create the root directory first
	 */
	printf ("creating root directory ...\n");

	if (ji_mkdir (buffer_ca, jnosroot, NULL) == -1)
		exit (0);
	/*
	 * In version 2 of the installer we simply extract a tar file
	 * of all the required directories (and files, like *.hlp). In
	 * the original version we had a 'directories.template' file,
	 * which simply gave us a list of directories to create, and
	 * there was no ability to put down files like *.hlp, etc.
	 */
	printf ("extracting required directories and files ...\n");

	sprintf (buffer_ca, "tar --directory=%s -xvf files.tar\n", jnosroot);

	if (ji_system (buffer_ca) == -1)
		exit (0);

	printf ("\nNow we are going to create the autoexec.nos (configuration) file.\n\n");

	if ((fpi = fopen ("./autoexec.template", "r")) == (FILE*)0)
	{
		printf ("could not open autoexec.nos template file\n");
		exit (0);
	}

	fpo = fopen ("./autoexec.nos", "w");

	while (fgets (buffer_ca, sizeof (buffer_ca) - 1, fpi))
	{
		switch (*buffer_ca)
		{
			case '-':
				if (!prompt_4_group (fpo, buffer_ca + 1))
					currgroupnum = -999;
				break;

		/*
		 * New in version 2, if we ask NOT to put in a specific PROMPT USER
		 * line from our autoexec.template, then make sure the *other* entries
		 * that are related are also NOT put into the new autoexec.nos as well.
		 */
			case '+':
				write_group (fpo, buffer_ca + 1);
				break;

			case '.':
				fputs (buffer_ca + 1, fpo);
				break;
		}
	}

	fclose (fpo);

	fclose (fpi);

	printf ("\ninstalling configuration file ...\n");

	sprintf (buffer_ca, "cp autoexec.nos %s\n", jnosroot);
	if (ji_system (buffer_ca) == -1)
		exit (0);

	printf ("\ninstalling local DNS file ...\n");

	sprintf (buffer_ca, "cp domain.txt %s\n", jnosroot);
	if (ji_system (buffer_ca) == -1)
		exit (0);

	printf ("\ninstalling jnos binary ...\n");

	sprintf (buffer_ca, "cp jnos %s\n", jnosroot);
	if (ji_system (buffer_ca) == -1)
		exit (0);

	printf ("\ncreating security file - give yourself a good password ...\n\n");

	while (1)
	{
		prompt ();

		// gets (buffer_ca);
		fgets (buffer_ca, sizeof(buffer_ca)-2, stdin);

		if (*buffer_ca)
			break;
		else
			printf ("you NEED to have a password, no exceptions !\n");
	}

	fpo = fopen ("./ftpusers", "w");

	fprintf (fpo, "%s %s %s/public 0x0405f\n",
		callsign, buffer_ca, jnosroot);

	fprintf (fpo, "univperm * %s/public 8\n", jnosroot);

	fclose (fpo);

	printf ("\ninstalling security file ...\n");

	sprintf (buffer_ca, "cp ftpusers %s\n", jnosroot);
	if (ji_system (buffer_ca) == -1)
		exit (0);

	printf ("\ncreating startnos script for inittab ...\n");

	fpo = fopen ("./startnos", "w");

	fprintf (fpo, "cd %s\n", jnosroot);

	fprintf (fpo, "rm -f %s/spool/mqueue/*.lck 2> /dev/null\n", jnosroot);
	fprintf (fpo, "rm -f %s/spool/mail/*.lck 2> /dev/null\n", jnosroot);

	fprintf (fpo, "sleep 1\n");

	fprintf (fpo, "export TZ=CST6CDT\n");
	fprintf (fpo, "export TERM=linux\n");

	fprintf (fpo, "exec ./jnos -d %s < $1 > $1 2>&1\n", jnosroot);

	fclose (fpo);

	printf ("\ninstalling startnos script ...\n");

	sprintf (buffer_ca, "cp startnos %s\n", jnosroot);
	if (ji_system (buffer_ca) == -1)
		exit (0);

	printf ("\nThe next section requires careful reading !\n\nHit the ENTER key to continue\n");
	prompt ();
	// gets (buffer_ca);
	fgets (buffer_ca, sizeof(buffer_ca)-2, stdin);

	printf ("\nFor System V style linux distros, if you want JNOS to automatically come up at\nboot time or any time it crashes, edit your '/etc/inittab' file and add a line\nsimilar to the following, after the section starting the console login getties\n\n");

	printf ("\tc5:1235:respawn:%s/startnos /dev/tty5\n\n", jnosroot);
	printf ("Make sure the console (in this case - c5 and /dev/tty5) is NOT configured\n");
	printf ("to run a getty process on it. Then run the command 'telinit q' to activate.\n");

	printf ("\nIF you are not comfortable with the above, or you are running a System D style\nlinux distro (I have no script), then you can run JNOS manually as follows :\n\n");

	printf ("\tcd %s\n\n", jnosroot);
	printf ("\t./jnos -d %s\n\n", jnosroot);

	printf ("You now have a basic JNOS system available to play with ...\n");
	printf ("\nOnce it's running, 'telnet 192.168.2.2' from the linux command prompt and\n");
	printf ("login to JNOS with your callsign and the password you entered earlier on.\n");

    printf ("\nWarning : This configuration uses the TUN kernel module, and is specifically\nsetup to use the 'tun0' interface. IF you are running OpenVPN or other software\ndependent on the TUN kernel module, running JNOS could mess things up for the\nother software, and/or vice versa. IF there is a possibility of this, then edit\nthe autoexec.nos file, and change 'tun0' to an unused interface.\n");

	exit (0); /* 27Jan2015, Maiko, The ntwk install 'fails' without this */
}

