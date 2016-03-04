#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "KUCrypto2.h"

void K_DRBG_GetSysRandom(UCHAR* seed_entropy, UINT length)
{
	FILE *fp;
	fp = fopen("/dev/urandom", "r");
	if(fp == NULL)
		return 0;

	fread(seed_entropy, 1, length, fp);

	fclose(fp);
}
