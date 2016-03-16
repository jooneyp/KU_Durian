#include "EBDCrypto.h"
#include "EBDerror.h"

int main()
{
	AES_CBC_ValidTest_KUAPI();
	
	SHA224_ValidTest();
	SHA256_ValidTest();
	SHA384_ValidTest();
	SHA512_ValidTest();
	
	HASH_DRBG_ValidTest();
	HASH_DRBG_RandomGenTest();

	return 0;
}
