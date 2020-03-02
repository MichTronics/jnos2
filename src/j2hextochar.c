
/*
 * 03Dec2019, Maiko, I need this all over the place, so just
 * one small nice little object file to include as I need :)
 */

/* 08Jul2009, Maiko, New hextochar function for URI decoding */

char j2hextochar (char *ptr)
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
			// printf ("invalid hex digit\n");
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

