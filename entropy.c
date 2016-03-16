#include <stdio.h>
#include "EBDCrypto.h"
#include "EBDerror.h"

//#define LINUX
#define WINDOWS
//#define ANDROID
//#define IOS
#define DIV 1024


#ifdef LINUX || ANDROID || IOS
<<<<<<< HEAD
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
=======
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

// seed_entropy는 이미 length바이트만큼 할당되어있다는 가정 하에

void K_DRBG_GetSysRandom(unsigned char* seed_entropy, unsigned int length)
{
	/* 경우마다 잡음원 추가하는 방법 다르게 하기 위해*/
	unsigned int ranCase;

	/* 운영체제 마다 */
>>>>>>> origin/master
#ifdef LINUX || ANDROID || IOS
	struct timeval TV;
	struct rusage usage;
	long USec;
	int PID;
	long SharedmemorySIze;

	srand(time(NULL));
<<<<<<< HEAD
	ranCase = rand()%3;		// case
=======
	ranCase = rand() % 3;      // 경우의 수 
>>>>>>> origin/master

	gettimeofday(&TV, NULL);
	USec = TV.tv_usec;		// time value

	PID = getpid();			// process ID

	getrusage(RUSAGE_SELF, &usage);
<<<<<<< HEAD
	SharedmemorySIze = usage.ru_ixrss;		// shared memory size
=======
	SharedmemorySIze = usage.ru_ixrss;      // 공유된 메모리 사이즈 
>>>>>>> origin/master


	FILE *fp;
	fp = fopen("/dev/urandom", "r");
<<<<<<< HEAD
	if(fp == NULL)
		return;


	/* adding entropy for cases */
	if (ranCase == 0)
	{
		fread(seed_entropy, length - sizeof(USec), 1, fp);		// because of getting entropy of 'length' and later adding the value of USec, get entropy for length of 'length - sizeof(USec)'
		memcpy(seed_entropy, (char *)USec, sizeof(USec));
=======
	if (fp == NULL)
		return;


	/* 케이스별로 잡음원 추가 */
	if (ranCase == 0)
	{
		fread(seed_entropy, length - sizeof(USec), 1, fp);
		memcpy(seed_entropy, (char *)USec, sizeof(USec));      // length만큼의 잡음원을 얻어야하기 때문에 처음에 시간값크기 빼고 잡음원 수집
>>>>>>> origin/master
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
<<<<<<< HEAD
	
=======

>>>>>>> origin/master
	unsigned long PhysicalMemory;
	unsigned short MSec;
	unsigned long CurrentThread;

	statex.dwLength = sizeof (statex);

	srand(time(NULL));
<<<<<<< HEAD
	ranCase = rand()%3;				// case
=======
	ranCase = rand() % 3;            // 경우의 수 
>>>>>>> origin/master

	GetSystemTime(&st);
	MSec = st.wMilliseconds;		// time value

	CurrentThread = GetCurrentThreadId();		// Thread value

	PhysicalMemory= statex.ullTotalPhys/DIV;	// Total used memory value


	/* adding entropy for cases */
	if (ranCase == 0)
	{
<<<<<<< HEAD
		CryptGenRandom(hCryptProv, length - sizeof(MSec), seed_entropy);	// because of getting entropy of 'length' and later adding the value of USec, get entropy for length of 'length - sizeof(USec)'
		memcpy(seed_entropy, (char*)&MSec, sizeof(MSec));					
=======
		CryptGenRandom(hCryptProv, length - sizeof(MSec), seed_entropy);
		memcpy(seed_entropy, (char*)&MSec, sizeof(MSec));               // length만큼의 잡음원을 얻어야하기 때문에 처음에 시간값크기 빼고 잡음원 수집
>>>>>>> origin/master
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
<<<<<<< HEAD

=======
>>>>>>> origin/master

