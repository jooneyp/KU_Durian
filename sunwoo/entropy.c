#include <stdio.h>
#include "EBDCrypto.h"
#include "EBDerror.h"

//#define LINUX
#define WINDOWS
//#define ANDROID
//#define IOS


#ifdef LINUX
	#include <sys/resource.h>
	#include <sys/time.h>
	#include <time.h>
	#include <sys/types.h>
	#include <unistd.h>
#endif

#ifdef ANDROID
	#include <sys/resource.h>
	#include <sys/time.h>
	#include <time.h>
	#include <sys/types.h>
	#include <unistd.h>
#endif

#ifdef IOS
	#include <sys/resource.h>
	#include <sys/time.h>
	#include <time.h>
	#include <sys/types.h>
	#include <unistd.h>
#endif

#ifdef WINDOWS
	#include <windows.h>
	#include <Wincrypt.h>
	#include <tchar.h>
#endif

int K_DRBG_GetSysRandom(unsigned char* seed_entropy, unsigned int length);
void print_data(const void* data, long int len);
void Multiple(unsigned char *data1, unsigned char *data2, unsigned char *data3, int length);
void ADD(unsigned char *data1, unsigned char *data2, unsigned char *data3, int length);

// assumption : unsigned char* seed_entropy =(unsigned char *)malloc(length) 

int K_DRBG_GetSysRandom(unsigned char* seed_entropy, unsigned int length)
{
	/* To differ method of adding entropy, divide the case */
	unsigned int ranCase;		

/* for OS */
#ifdef LINUX
	struct timeval TV;
	long USec;
	int ranCase;
	unsigned char * temp_seed_entropy = (unsigned char *)malloc(length);
	
	ranCase = rand()%3;
	
	gettimeofday(&TV, NULL);
	USec = TV.tv_usec;

	FILE *fp1;
	FILE *fp2;
	FILE *fp3;

	if (!(fp1 = fopen("/dev/urandom", "r"))) 
	{
		printf("fp1 open error\n");
		return ERR_FAIL_FILE;
	}
	if (!(fp2 = popen("/bin/cat /proc/uptime 2> /dev/null", "r"))) 
	{
		printf("fp2 open error\n");
		return ERR_FAIL_FILE;
	}
	if (!(fp3 = popen("/bin/ps -elf 2> /dev/null", "r"))) 
	{
		printf("fp3 open error\n");
		return ERR_FAIL_FILE;
	}
	
	switch (ranCase) {
		case 0:
			fread(seed_entropy, length - 3, 1, fp1);
			//Multiple(seed_entropy, &USec, temp_seed_entropy, 3);
			ADD(seed_entropy, &USec, temp_seed_entropy, 3);
			memcpy(seed_entropy + length - 3, temp_seed_entropy, 3);
			break;
		case 1:
			fread(seed_entropy, length, 1, fp1);
			fread(temp_seed_entropy, length,  1, fp2);
			//Multiple(seed_entropy, temp_seed_entropy, seed_entropy, length);
			ADD(seed_entropy, temp_seed_entropy, seed_entropy, length);
			break;
		case 2:
			fread(seed_entropy, length, 1, fp1);
			fread(temp_seed_entropy, length, 1, fp3);
			//Multiple(seed_entropy, temp_seed_entropy, seed_entropy, length);
			ADD(seed_entropy, temp_seed_entropy, seed_entropy, length);
			break;
	}

	printf("case: %d\n", ranCase);

	fclose(fp1);
	fclose(fp2);
	fclose(fp3);
	free(temp_seed_entropy);
#endif


#ifdef ANDROID
	struct timeval TV;
	long USec;
	int ranCase;
	unsigned char * temp_seed_entropy = (unsigned char *)malloc(length);
	
	ranCase = rand()%3;
	
	gettimeofday(&TV, NULL);
	USec = TV.tv_usec;

	FILE *fp1;
	FILE *fp2;
	FILE *fp3;

	if (!(fp1 = fopen("/dev/urandom", "r"))) 
	{
		printf("fp1 open error\n");
		return ERR_FAIL_FILE;
	}
	if (!(fp2 = popen("/bin/cat /proc/uptime 2> /dev/null", "r"))) 
	{
		printf("fp2 open error\n");
		return ERR_FAIL_FILE;
	}
	if (!(fp3 = popen("/bin/ps -elf 2> /dev/null", "r"))) 
	{
		printf("fp3 open error\n");
		return ERR_FAIL_FILE;
	}
	
	switch (ranCase) {
		case 0:
			fread(seed_entropy, length - 3, 1, fp1);
			//Multiple(seed_entropy, &USec, temp_seed_entropy, 3);
			ADD(seed_entropy, &USec, temp_seed_entropy, 3);
			memcpy(seed_entropy + length - 3, temp_seed_entropy, 3);
			break;
		case 1:
			fread(seed_entropy, length, 1, fp1);
			fread(temp_seed_entropy, length,  1, fp2);
			//Multiple(seed_entropy, temp_seed_entropy, seed_entropy, length);
			ADD(seed_entropy, temp_seed_entropy, seed_entropy, length);
			break;
		case 2:
			fread(seed_entropy, length, 1, fp1);
			fread(temp_seed_entropy, length, 1, fp3);
			//Multiple(seed_entropy, temp_seed_entropy, seed_entropy, length);
			ADD(seed_entropy, temp_seed_entropy, seed_entropy, length);
			break;
	}

	printf("case: %d\n", ranCase);

	fclose(fp1);
	fclose(fp2);
	fclose(fp3);
	free(temp_seed_entropy);
#endif


#ifdef IOS
	struct timeval TV;
	long USec;
	int ranCase;
	unsigned char * temp_seed_entropy = (unsigned char *)malloc(length);
	
	ranCase = rand()%3;
	
	gettimeofday(&TV, NULL);
	USec = TV.tv_usec;

	FILE *fp1;
	FILE *fp2;
	FILE *fp3;

	if (!(fp1 = fopen("/dev/urandom", "r"))) 
	{
		printf("fp1 open error\n");
		return ERR_FAIL_FILE;
	}
	if (!(fp2 = popen("/bin/cat /proc/uptime 2> /dev/null", "r"))) 
	{
		printf("fp2 open error\n");
		return ERR_FAIL_FILE;
	}
	if (!(fp3 = popen("/bin/ps -elf 2> /dev/null", "r"))) 
	{
		printf("fp3 open error\n");
		return ERR_FAIL_FILE;
	}
	
	switch (ranCase) {
		case 0:
			fread(seed_entropy, length - 3, 1, fp1);
			//Multiple(seed_entropy, &USec, temp_seed_entropy, 3);
			ADD(seed_entropy, &USec, temp_seed_entropy, 3);
			memcpy(seed_entropy + length - 3, temp_seed_entropy, 3);
			break;
		case 1:
			fread(seed_entropy, length, 1, fp1);
			fread(temp_seed_entropy, length,  1, fp2);
			//Multiple(seed_entropy, temp_seed_entropy, seed_entropy, length);
			ADD(seed_entropy, temp_seed_entropy, seed_entropy, length);
			break;
		case 2:
			fread(seed_entropy, length, 1, fp1);
			fread(temp_seed_entropy, length, 1, fp3);
			//Multiple(seed_entropy, temp_seed_entropy, seed_entropy, length);
			ADD(seed_entropy, temp_seed_entropy, seed_entropy, length);
			break;
	}

	printf("case: %d\n", ranCase);

	fclose(fp1);
	fclose(fp2);
	fclose(fp3);
	free(temp_seed_entropy);
#endif


#ifdef WINDOWS
	HCRYPTPROV hCryptProv = NULL;
	SYSTEMTIME st;
	MEMORYSTATUSEX statex;
	WORD MSec;
	DWORD BootingTime;
	LARGE_INTEGER num;
	int randomvalue;
	unsigned char * temp_seed_entropy = (unsigned char *)malloc(length);

	statex.dwLength = sizeof(statex);
	GlobalMemoryStatus(&statex);
	
	if (seed_entropy == NULL || length <= 0)
		return ERR_INVALID_INPUT;
	
	ranCase = rand()%3;				// case
	//ranCase = 1;

	if(!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
		return ERR_INVALID_OUTPUT;


	GetSystemTime(&st);
	MSec = st.wMilliseconds * st.wMilliseconds;		// time value
	
	BootingTime = GetTickCount() * GetTickCount();

	/* adding entropy for cases */
	switch (ranCase)
	{
			case 0:
				CryptGenRandom(hCryptProv, length - sizeof(MSec), seed_entropy);	// because of getting entropy of 'length' and later adding the value of USec, get entropy for length of 'length - sizeof(USec)'
				if (!CryptReleaseContext(hCryptProv, 0))
					return ERR_INVALID_OUTPUT;
				memcpy(seed_entropy + length - sizeof(MSec), (char*)&MSec, sizeof(MSec));					
				break;
			case 1:
				CryptGenRandom(hCryptProv, length, seed_entropy);
				if (!CryptReleaseContext(hCryptProv, 0))
					return ERR_INVALID_OUTPUT;
				Multiple(seed_entropy, (unsigned char *)&BootingTime, seed_entropy, sizeof(BootingTime));
				break;
			case 2:
				CryptGenRandom(hCryptProv, length, seed_entropy);
				CryptGenRandom(hCryptProv, length, temp_seed_entropy);
				if (!CryptReleaseContext(hCryptProv, 0))
					return ERR_INVALID_OUTPUT;
				ADD(seed_entropy, seed_entropy, seed_entropy, length);
				//print_data(seed_entropy, length);
				//print_data(temp_seed_entropy, length);
				break;
	}

	printf("case: %d\n", ranCase);
	free(temp_seed_entropy);
#endif

}

void print_data(const void* data, long int len)
{
	const unsigned char * p = (const unsigned char*)data;

	int i =0;
	for (i = 0; i < len; i++)
	{
		printf("%02X ", *p++);
	}
	printf("\n");
}

void Multiple(unsigned char *data1, unsigned char *data2, unsigned char *data3, int length)
{
	int i = 0;
	for (i=0; i<length; i++)
		data3[i] = data1[i] * data2[i];
}

void ADD(unsigned char *data1, unsigned char *data2, unsigned char *data3, int length)
{
	int i = 0;
	for (i=0; i<length; i++)
		data3[i] = data1[i] + data2[i];
}

int main() 
{
  
	int length = 20;
	unsigned char seed_entropy[20];
	int i=0;

	srand(time(NULL));

	for (i=0; i<10; i++) 
	{
		int a = K_DRBG_GetSysRandom(seed_entropy, length);
		//Sleep(1000);
		print_data(seed_entropy, length);
	}
	return 0;

}


