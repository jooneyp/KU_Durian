#include <time.h>
#include "BN.h"
#include "GFP.h"
/* macros for tests */
extern clock_t elapsed;
extern float sec;
#define START_WATCH \
{\
	elapsed = -clock(); \
}\
#define STOP_WATCH \
{\
	elapsed += clock();\
	sec = (float)elapsed/CLOCKS_PER_SEC;\
}\
#define PRINT_TIME(qstr) \
{\
	printf("\n[%s: %.5f s]\n",qstr,sec);\
}\
#define FPRNL fprintf(__fp,"\n");
#define FPREQ fprintf(__fp," = ");
#define FPRPL fprintf(__fp," + ");
#define FPRMN fprintf(__fp," - ");
#define FPRML fprintf(__fp," * ");
#define FPRDV fprintf(__fp," / ");
#define FPROPBR fprintf(__fp," [ ");
#define FPRCLBR fprintf(__fp," ] ");
#define PRNL fprintf(stdout,"\n");
#define PREQ fprintf(stdout," = ");
#define PRPL fprintf(stdout," + ");
#define PRMN fprintf(stdout," - ");
#define PRML fprintf(stdout," * ");
#define PRDV fprintf(stdout," / ");
#define PROPBR fprintf(stdout," [ ");
#define PRCLBR fprintf(stdout," ] ");
/* Debugging and test tools */
#define EXITPROG exit(0);
#define FP2FILE(qstr) { __fp=fopen(qstr,"wa+");}
#define FP2STDOUT { __fp=stdout;}
#define CLOSEFP close(__fp);
#define TRACE(fp,a) printf(__fp,a);
#define PRBN(x) BN_FPrintBN(stdout,(&x))