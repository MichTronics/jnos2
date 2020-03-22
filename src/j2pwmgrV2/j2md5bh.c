
#include "string.h"

#include <openssl/sha.h>

unsigned char *SHA512ByteHash (unsigned char *iBuf)
{
	static unsigned char hash[SHA512_DIGEST_LENGTH];

	// printf ("iBuf [%s] [%d]\n", iBuf, strlen((char*)iBuf));

	SHA512 (iBuf, strlen ((char*)iBuf), hash);

	return hash;
}

