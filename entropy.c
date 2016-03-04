#include <stdio.h>
#include "EBDCrypto.h"
#include "EBDerror.h"

<<<<<<< HEAD

=======
>>>>>>> origin/master
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


void K_DRBG_GetSysRandom(unsigned char* seed_entropy, unsigned int length)
{
	FILE *fp;
	fp = fopen("/dev/urandom", "r");
	if(fp == NULL)
		return;

	fread(seed_entropy, 1, length, fp);

	fclose(fp);
}



// seed_entropyëŠ” ì´ë¯¸ lengthë°”ì´íŠ¸ë§Œí¼ í• ë‹¹ë˜ì–´ìˆë‹¤ëŠ” ê°€ì • í•˜ì—

void K_DRBG_GetSysRandom(unsigned char* seed_entropy, unsigned int length)
{
	/* ê²½ìš°ë§ˆë‹¤ ì¡ìŒì› ì¶”ê°€í•˜ëŠ” ë°©ë²• ë‹¤ë¥´ê²Œ í•˜ê¸° ìœ„í•´*/
	unsigned int ranCase;

	/* ìš´ì˜ì²´ì œ ë§ˆë‹¤ */
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

// seed_entropy´Â ÀÌ¹Ì length¹ÙÀÌÆ®¸¸Å­ ÇÒ´çµÇ¾îÀÖ´Ù´Â °¡Á¤ ÇÏ¿¡

void K_DRBG_GetSysRandom(unsigned char* seed_entropy, unsigned int length)
{
	/* °æ¿ì¸¶´Ù ÀâÀ½¿ø Ãß°¡ÇÏ´Â ¹æ¹ı ´Ù¸£°Ô ÇÏ±â À§ÇØ*/
	unsigned int ranCase;		

/* ¿î¿µÃ¼Á¦ ¸¶´Ù */
>>>>>>> origin/master
#ifdef LINUX || ANDROID || IOS
	struct timeval TV;
	struct rusage usage;
	long USec;
	int PID;
	long SharedmemorySIze;

	srand(time(NULL));
<<<<<<< HEAD
	ranCase = rand() % 3;      // ê²½ìš°ì˜ ìˆ˜ 

	gettimeofday(&TV, NULL);
	USec = TV.tv_usec;      // ì‹œê°„ ê°’

	PID = getpid();         // í”„ë¡œì„¸ìŠ¤ ID

	getrusage(RUSAGE_SELF, &usage);
	SharedmemorySIze = usage.ru_ixrss;      // ê³µìœ ëœ ë©”ëª¨ë¦¬ ì‚¬ì´ì¦ˆ 
=======
	ranCase = rand()%3;		// °æ¿ìÀÇ ¼ö 

	gettimeofday(&TV, NULL);
	USec = TV.tv_usec;		// ½Ã°£ °ª

	PID = getpid();			// ÇÁ·Î¼¼½º ID

	getrusage(RUSAGE_SELF, &usage);
	SharedmemorySIze = usage.ru_ixrss;		// °øÀ¯µÈ ¸Ş¸ğ¸® »çÀÌÁî 
>>>>>>> origin/master


	FILE *fp;
	fp = fopen("/dev/urandom", "r");
<<<<<<< HEAD
	if (fp == NULL)
		return;


	/* ì¼€ì´ìŠ¤ë³„ë¡œ ì¡ìŒì› ì¶”ê°€ */
	if (ranCase == 0)
	{
		fread(seed_entropy, length - sizeof(USec), 1, fp);
		memcpy(seed_entropy, (char *)USec, sizeof(USec));      // lengthë§Œí¼ì˜ ì¡ìŒì›ì„ ì–»ì–´ì•¼í•˜ê¸° ë•Œë¬¸ì— ì²˜ìŒì— ì‹œê°„ê°’í¬ê¸° ë¹¼ê³  ì¡ìŒì› ìˆ˜ì§‘
=======
	if(fp == NULL)
		return;


	/* ÄÉÀÌ½ºº°·Î ÀâÀ½¿ø Ãß°¡ */
	if (ranCase == 0)
	{
		fread(seed_entropy, length - sizeof(USec), 1, fp);
		memcpy(seed_entropy, (char *)USec, sizeof(USec));		// length¸¸Å­ÀÇ ÀâÀ½¿øÀ» ¾ò¾î¾ßÇÏ±â ¶§¹®¿¡ Ã³À½¿¡ ½Ã°£°ªÅ©±â »©°í ÀâÀ½¿ø ¼öÁı
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
	ranCase = rand() % 3;            // ê²½ìš°ì˜ ìˆ˜ 

	GetSystemTime(&st);
	MSec = st.wMilliseconds;      // ì‹œê°„ ê°’

	CurrentThread = GetCurrentThreadId();      // í˜„ì¬ ìŠ¤ë ˆë“œ ê°’

	PhysicalMemory = statex.ullTotalPhys / DIV;   // ì „ì²´ ì‚¬ìš© ë©”ëª¨ë¦¬


	/* ì¼€ì´ìŠ¤ë³„ë¡œ ì¡ìŒì› ì¶”ê°€ */
	if (ranCase == 0)
	{
		CryptGenRandom(hCryptProv, length - sizeof(MSec), seed_entropy);
		memcpy(seed_entropy, (char*)&MSec, sizeof(MSec));               // lengthë§Œí¼ì˜ ì¡ìŒì›ì„ ì–»ì–´ì•¼í•˜ê¸° ë•Œë¬¸ì— ì²˜ìŒì— ì‹œê°„ê°’í¬ê¸° ë¹¼ê³  ì¡ìŒì› ìˆ˜ì§‘
=======
	ranCase = rand()%3;				// °æ¿ìÀÇ ¼ö 

	GetSystemTime(&st);
	MSec = st.wMilliseconds;		// ½Ã°£ °ª

	CurrentThread = GetCurrentThreadId();		// ÇöÀç ½º·¹µå °ª

	PhysicalMemory= statex.ullTotalPhys/DIV;	// ÀüÃ¼ »ç¿ë ¸Ş¸ğ¸®


	/* ÄÉÀÌ½ºº°·Î ÀâÀ½¿ø Ãß°¡ */
	if (ranCase == 0)
	{
		CryptGenRandom(hCryptProv, length - sizeof(MSec), seed_entropy);
		memcpy(seed_entropy, (char*)&MSec, sizeof(MSec));					// length¸¸Å­ÀÇ ÀâÀ½¿øÀ» ¾ò¾î¾ßÇÏ±â ¶§¹®¿¡ Ã³À½¿¡ ½Ã°£°ªÅ©±â »©°í ÀâÀ½¿ø ¼öÁı
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

<<<<<<< HEAD
}
=======
}


>>>>>>> origin/master
