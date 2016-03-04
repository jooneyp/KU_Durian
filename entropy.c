#include <stdio.h>
#include "EBDCrypto.h"
#include "EBDerror.h"

//#define LINUX
#define WINDOWS
//#define ANDROID
//#define IOS
#define DIV 1024


#ifdef LINUX || ANDROID || IOS
	#include <sys/resource.h>
	#include <sys/time.h>
	#include <sys/types.h>
	#include <sys/resource.h>
	#include <unistd.h>
#endif

#ifdef WINDOWS
	#include <windows.h>
	#include <Wincrypt.h>
	#include <tchar.h>
#endif

// assumption : unsigned char* seed_entropy =(unsigned char *)malloc(length) 

void K_DRBG_GetSysRandom(unsigned char* seed_entropy, unsigned int length)
{
	/* To differ method of adding entropy, divide the case */
	unsigned int ranCase;		

/* for OS */
#ifdef LINUX || ANDROID || IOS
	struct timeval TV;
	struct rusage usage;
	long USec;
	int PID;
	long SharedmemorySIze;

	srand(time(NULL));
	ranCase = rand()%3;		// case

	gettimeofday(&TV, NULL);
	USec = TV.tv_usec;		// time value

	PID = getpid();			// process ID

	getrusage(RUSAGE_SELF, &usage);
	SharedmemorySIze = usage.ru_ixrss;		// shared memory size


	FILE *fp;
	fp = fopen("/dev/urandom", "r");
	if(fp == NULL)
		return;


	/* adding entropy for cases */
	if (ranCase == 0)
	{
		fread(seed_entropy, length - sizeof(USec), 1, fp);		// because of getting entropy of 'length' and later adding the value of USec, get entropy for length of 'length - sizeof(USec)'
		memcpy(seed_entropy, (char *)USec, sizeof(USec));
	}
	else if (ranCase == 1)
	{
		fread(seed_entropy, length - sizeof(PID), 1, fp);
		memcpy(seed_entropy, (char *)PID, sizeof(PID));
	}
	else
	{
		fread(seed_entropy, length - sizeof(SharedmemorySIze), 1, fp);
		memcpy(seed_entropy, (char *)SharedmemorySIze, sizeof(SharedmemorySIze));
	}
	fclose(fp);
#endif


#ifdef WINDOWS
	HCRYPTPROV hCryptProv;
	SYSTEMTIME st;
	MEMORYSTATUSEX statex;
	
	unsigned long PhysicalMemory;
	unsigned short MSec;
	unsigned long CurrentThread;

	statex.dwLength = sizeof (statex);

	srand(time(NULL));
	ranCase = rand()%3;				// case

	GetSystemTime(&st);
	MSec = st.wMilliseconds;		// time value

	CurrentThread = GetCurrentThreadId();		// Thread value

	PhysicalMemory= statex.ullTotalPhys/DIV;	// Total used memory value


	/* adding entropy for cases */
	if (ranCase == 0)
	{
		CryptGenRandom(hCryptProv, length - sizeof(MSec), seed_entropy);	// because of getting entropy of 'length' and later adding the value of USec, get entropy for length of 'length - sizeof(USec)'
		memcpy(seed_entropy, (char*)&MSec, sizeof(MSec));					
	}
	else if (ranCase == 1)
	{
		CryptGenRandom(hCryptProv, length - sizeof(CurrentThread), seed_entropy);
		memcpy(seed_entropy, (char *)&CurrentThread, sizeof(CurrentThread));
	}
	else
	{
		CryptGenRandom(hCryptProv, length - sizeof(PhysicalMemory), seed_entropy);
		memcpy(seed_entropy, (char*)&PhysicalMemory, sizeof(PhysicalMemory));
	}
#endif

}


