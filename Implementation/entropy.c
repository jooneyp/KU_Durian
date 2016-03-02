#include "EBDCrypto.h"
#include "EBDerror.h"


void K_DRBG_GetSysRandom(unsigned char* seed_entropy, unsigned int length)
{
	FILE *fp;
	fp = fopen("/dev/urandom", "r");
	if(fp == NULL)
		return;

	fread(seed_entropy, 1, length, fp);

	fclose(fp);
}
