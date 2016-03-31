#include "EBDerror.h"
#include "EBDCrypto.h"

#define SIMPLE_WAY

#if defined(__LINUX__) || defined(__ANDROID__) || defined(__iOS__)
	#include <sys/resource.h>
	#include <sys/time.h>
	#include <time.h>
	#include <sys/types.h>
	#include <unistd.h>
#endif

#ifdef __WINDOWS__
	#include <windows.h>
	#include <Wincrypt.h>
	#include <tchar.h>
#endif

void Multiple(UCHAR *data1, UCHAR *data2, UCHAR *data3, SINT length)
{
	SINT i = 0;
	for (i=0; i<length; i++)
		data3[i] = data1[i] * data2[i];
}

void ADD(UCHAR *data1, UCHAR *data2, UCHAR *data3, SINT length)
{
	SINT i = 0;
	for (i=0; i<length; i++)
		data3[i] = data1[i] + data2[i];
}

// assumption : unsigned char* seed_entropy =(unsigned char *)malloc(length) 
SINT K_DRBG_GetEntropy(UCHAR* seed_entropy, SINT length)
{
/* for OS */
#if defined(__LINUX__) || defined(__ANDROID__) || defined(__iOS__)

#ifdef SIMPLE_WAY

	FILE *fp1;

	if ( (seed_entropy == NULL) || (length <= 0) )
		return ERR_INVALID_INPUT;

	if (!(fp1 = fopen("/dev/urandom", "r"))) 
	{
		return ERR_FILE_OPEN_FAIL;
	}
	fread(seed_entropy, 1, length, fp1);

	fclose(fp1);

#else

	UINT ranCase;
	struct timeval TV;
	SLONG USec;
	SINT ranCase;
	UCHAR * temp_seed_entropy;

	FILE *fp1;
	FILE *fp2;
	FILE *fp3;
	
	srand((UINT)time(NULL));
	ranCase = rand()%3;
	
	gettimeofday(&TV, NULL);
	USec = TV.tv_usec;

	if (!(fp1 = fopen("/dev/urandom", "r"))) 
	{
		//printf("fp1 open error\n");
		return ERR_FILE_OPEN_FAIL;
	}
	if (!(fp2 = popen("/bin/cat /proc/uptime 2> /dev/null", "r"))) 
	{
		//printf("fp2 open error\n");
		fclose(fp1);
		return ERR_FILE_OPEN_FAIL;
	}
	if (!(fp3 = popen("/bin/ps -elf 2> /dev/null", "r"))) 
	{
		//printf("fp3 open error\n");
		fclose(fp1);
		fclose(fp2);
		return ERR_FILE_OPEN_FAIL;
	}

	temp_seed_entropy = (UCHAR *)malloc(length);
	
	switch (ranCase) {
		case 0:
			fread(seed_entropy, length - 3, 1, fp1);
			ADD(seed_entropy, &USec, temp_seed_entropy, 3);
			memcpy(seed_entropy + length - 3, temp_seed_entropy, 3);
			break;
		case 1:
			fread(seed_entropy, length, 1, fp1);
			fread(temp_seed_entropy, length,  1, fp2);
			ADD(seed_entropy, temp_seed_entropy, seed_entropy, length);
			break;
		case 2:
			fread(seed_entropy, length, 1, fp1);
			fread(temp_seed_entropy, length, 1, fp3);
			ADD(seed_entropy, temp_seed_entropy, seed_entropy, length);
			break;
	}

	fclose(fp1);
	fclose(fp2);
	fclose(fp3);
	free(temp_seed_entropy);

#endif

#elif defined(__WINDOWS__)

#ifdef SIMPLE_WAY
	
	HCRYPTPROV hCryptProv;

	if( (seed_entropy == NULL) || (length <= 0) )
		return ERR_INVALID_INPUT;

	if(!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
	{
		return ERR_FUNCTION_CALL_FAILURE;
	}

	CryptGenRandom(hCryptProv, length, seed_entropy);

	if (!CryptReleaseContext(hCryptProv, 0))
	{
		return ERR_MEM_RELEASE;
	}

#else

	UINT ranCase;
	HCRYPTPROV hCryptProv;
	SYSTEMTIME st;
	MEMORYSTATUSEX statex;
	WORD MSec;
	DWORD BootingTime;

	UCHAR * temp_seed_entropy;

	if ( (seed_entropy == NULL) || (length <= 0) )
		return ERR_INVALID_INPUT;

	if(!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
	{
		free(temp_seed_entropy);
		return ERR_FUNCTION_CALL_FAILURE;
	}

	temp_seed_entropy = (UCHAR *)malloc(length);
	if(temp_seed_entropy == NULL)
		return ERR_MALLOC;

	srand((UINT)time(NULL));
	statex.dwLength = sizeof(statex);
	GlobalMemoryStatus((LPMEMORYSTATUS)&statex);
	ranCase = rand() % 3;				// case

	switch (ranCase)
	{
			case 0:
				GetSystemTime(&st);
				MSec = st.wMilliseconds * st.wMilliseconds;		// time value

				CryptGenRandom(hCryptProv, length - sizeof(MSec), seed_entropy);	// because of getting entropy of 'length' and later adding the value of USec, get entropy for length of 'length - sizeof(USec)'
				if (!CryptReleaseContext(hCryptProv, 0))
				{
					free(temp_seed_entropy);
					return ERR_MEM_RELEASE;
				}
				//memcpy(seed_entropy + length - sizeof(MSec), (SCHAR*)&MSec, sizeof(MSec));					
				break;
			case 1:
				BootingTime = GetTickCount() * GetTickCount();

				CryptGenRandom(hCryptProv, length, seed_entropy);
				if (!CryptReleaseContext(hCryptProv, 0))
				{
					free(temp_seed_entropy);
					return ERR_MEM_RELEASE;
				}
				//Multiple(seed_entropy, (UCHAR *)&BootingTime, seed_entropy, sizeof(BootingTime));
				break;
			case 2:
				CryptGenRandom(hCryptProv, length, seed_entropy);
				CryptGenRandom(hCryptProv, length, temp_seed_entropy);
				if (!CryptReleaseContext(hCryptProv, 0))
				{
					free(temp_seed_entropy);
					return ERR_MEM_RELEASE;
				}
				//ADD(seed_entropy, temp_seed_entropy, seed_entropy, length);
				break;
	}

	free(temp_seed_entropy);
#endif

#endif
	
	return EBD_CRYPTO_SUCCESS;
}


