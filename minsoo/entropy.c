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

// seed_entropy는 이미 length바이트만큼 할당되어있다는 가정 하에

void K_DRBG_GetSysRandom(unsigned char* seed_entropy, unsigned int length)
{
	/* 경우마다 잡음원 추가하는 방법 다르게 하기 위해*/
	unsigned int ranCase;

	/* 운영체제 마다 */
#ifdef LINUX || ANDROID || IOS
	struct timeval TV;
	struct rusage usage;
	long USec;
	int PID;
	long SharedmemorySIze;

	srand(time(NULL));
	ranCase = rand() % 3;      // 경우의 수 

	gettimeofday(&TV, NULL);
	USec = TV.tv_usec;      // 시간 값

	PID = getpid();         // 프로세스 ID

	getrusage(RUSAGE_SELF, &usage);
	SharedmemorySIze = usage.ru_ixrss;      // 공유된 메모리 사이즈 


	FILE *fp;
	fp = fopen("/dev/urandom", "r");
	if (fp == NULL)
		return;


	/* 케이스별로 잡음원 추가 */
	if (ranCase == 0)
	{
		fread(seed_entropy, length - sizeof(USec), 1, fp);
		memcpy(seed_entropy, (char *)USec, sizeof(USec));      // length만큼의 잡음원을 얻어야하기 때문에 처음에 시간값크기 빼고 잡음원 수집
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

	statex.dwLength = sizeof(statex);

	srand(time(NULL));
	ranCase = rand() % 3;            // 경우의 수 

	GetSystemTime(&st);
	MSec = st.wMilliseconds;      // 시간 값

	CurrentThread = GetCurrentThreadId();      // 현재 스레드 값

	PhysicalMemory = statex.ullTotalPhys / DIV;   // 전체 사용 메모리


												  /* 케이스별로 잡음원 추가 */
	if (ranCase == 0)
	{
		CryptGenRandom(hCryptProv, length - sizeof(MSec), seed_entropy);
		memcpy(seed_entropy, (char*)&MSec, sizeof(MSec));               // length만큼의 잡음원을 얻어야하기 때문에 처음에 시간값크기 빼고 잡음원 수집
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