
#include "string.h"

#include <openssl/md5.h>

unsigned char *MD5ByteHash (unsigned char *iBuf)
{
	static unsigned char hash[MD5_DIGEST_LENGTH];

	MD5 (iBuf, strlen ((char*)iBuf), hash);

	return hash;
}

