#include "EBDCrypto.h"
#include "EBDerror.h"

int AES_CBC_ValidTest_KUAPI()
{
	unsigned char TestKey128[16] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
	unsigned char TestIV128[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
	unsigned char TestPT128[160] = {0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A, 
									0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51, 
									0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF, 
									0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10};
	unsigned char TestCT128[176] = {0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19, 0x7D, 
									0x50, 0x86, 0xCB, 0x9B, 0x50, 0x72, 0x19, 0xEE, 0x95, 0xDB, 0x11, 0x3A, 0x91, 0x76, 0x78, 0xB2, 
									0x73, 0xBE, 0xD6, 0xB8, 0xE3, 0xC1, 0x74, 0x3B, 0x71, 0x16, 0xE6, 0x9E, 0x22, 0x22, 0x95, 0x16, 
									0x3F, 0xF1, 0xCA, 0xA1, 0x68, 0x1F, 0xAC, 0x09, 0x12, 0x0E, 0xCA, 0x30, 0x75, 0x86, 0xE1, 0xA7};
	unsigned char RCT1[180];
	unsigned char RPT1[180];
	int rctlen1_1, rctlen1_2, rctlen1_3, rptlen1_1, rptlen1_2, rptlen1_3, padlen1;

	unsigned char TestKey192[24] = {0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52, 0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
									0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B};
	unsigned char TestIV192[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
	unsigned char TestPT192[160] = {0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A, 
									0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51, 
									0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF, 
									0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10};
	unsigned char TestCT192[176] = {0x4F, 0x02, 0x1D, 0xB2, 0x43, 0xBC, 0x63, 0x3D, 0x71, 0x78, 0x18, 0x3A, 0x9F, 0xA0, 0x71, 0xE8,
									0xB4, 0xD9, 0xAD, 0xA9, 0xAD, 0x7D, 0xED, 0xF4, 0xE5, 0xE7, 0x38, 0x76, 0x3F, 0x69, 0x14, 0x5A,
									0x57, 0x1B, 0x24, 0x20, 0x12, 0xFB, 0x7A, 0xE0, 0x7F, 0xA9, 0xBA, 0xAC, 0x3D, 0xF1, 0x02, 0xE0,
									0x08, 0xB0, 0xE2, 0x79, 0x88, 0x59, 0x88, 0x81, 0xD9, 0x20, 0xA9, 0xE6, 0x4F, 0x56, 0x15, 0xCD};
	unsigned char RCT2[180];
	unsigned char RPT2[180];
	int rctlen2_1, rctlen2_2, rctlen2_3, rptlen2_1, rptlen2_2, rptlen2_3, padlen2;

	unsigned char TestKey256[32] = {0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
									0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4};
	unsigned char TestIV256[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
	unsigned char TestPT256[160] = {0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A, 
									0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51, 
									0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF, 
									0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10};
	unsigned char TestCT256[176] = {0xF5, 0x8C, 0x4C, 0x04, 0xD6, 0xE5, 0xF1, 0xBA, 0x77, 0x9E, 0xAB, 0xFB, 0x5F, 0x7B, 0xFB, 0xD6, 
									0x9C, 0xFC, 0x4E, 0x96, 0x7E, 0xDB, 0x80, 0x8D, 0x67, 0x9F, 0x77, 0x7B, 0xC6, 0x70, 0x2C, 0x7D, 
									0x39, 0xF2, 0x33, 0x69, 0xA9, 0xD9, 0xBA, 0xCF, 0xA5, 0x30, 0xE2, 0x63, 0x04, 0x23, 0x14, 0x61, 
									0xB2, 0xEB, 0x05, 0xE2, 0xC3, 0x9B, 0xE9, 0xFC, 0xDA, 0x6C, 0x19, 0x07, 0x8C, 0x6A, 0x9D, 0x1B};
	unsigned char RCT3[180];
	unsigned char RPT3[180];
	int rctlen3_1, rctlen3_2, rctlen3_3, rptlen3_1, rptlen3_2, rptlen3_3, padlen3;

	int check = 1;

	AES_CBC_INFO aes;
#ifdef DEBUG_MODE
	printf("\n==================================\n");
	printf(" AES_CBC(KU API) Validation TEST\n");
	printf("==================================\n");
#endif

	AES_CBC_init(&aes, 1, AES128, TestKey128, TestIV128);
	AES_CBC_process(&aes, TestPT128, 64, RCT1, &rctlen1_1);
	AES_CBC_close(&aes, RCT1+rctlen1_1, &padlen1);
	AES_CBC_clear(&aes);
	if(!memcmp(RCT1, TestCT128, 64))
	{
		//printf("AES Test 1 Enc Validation TEST(64 once) OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- AES Test 1 Enc Validation TEST(64 once) Fail\n");
#endif
		check = 0;
	}

	AES_CBC_init(&aes, 0, AES128, TestKey128, TestIV128);
	AES_CBC_process(&aes, RCT1, rctlen1_1+padlen1, RPT1, &rptlen1_1);
	AES_CBC_close(&aes, RPT1+rptlen1_1, &padlen1);
	AES_CBC_clear(&aes);
	if(!memcmp(RPT1, TestPT128, 64))
	{
		//printf("AES Test 1 Dec Validation TEST(64 once) OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- AES Test 1 Dec Validation TEST(64 once) Fail\n");
#endif
		check = 0;
	}
	memset(RCT1, 0x00, 180);
	memset(RPT1, 0x00, 180);


	AES_CBC_init(&aes, 1, AES128, TestKey128, TestIV128);
	AES_CBC_process(&aes, TestPT128, 59, RCT1, &rctlen1_1);
	AES_CBC_close(&aes, RCT1+rctlen1_1, &padlen1);
	AES_CBC_clear(&aes);

	AES_CBC_init(&aes, 0, AES128, TestKey128, TestIV128);
	AES_CBC_process(&aes, RCT1, rctlen1_1+padlen1, RPT1, &rptlen1_1);
	AES_CBC_close(&aes, RPT1+rptlen1_1, &padlen1);
	AES_CBC_clear(&aes);
	if(!memcmp(RPT1, TestPT128, 59))
	{
		//printf("AES Test 1 Enc/Dec Validation TEST(59 once) OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- AES Test 1 Enc/Dec Validation TEST(59 once) Fail\n");
#endif
		check = 0;
	}
	memset(RCT1, 0x00, 180);
	memset(RPT1, 0x00, 180);


	AES_CBC_init(&aes, 1, AES128, TestKey128, TestIV128);
	AES_CBC_process(&aes, TestPT128, 32, RCT1, &rctlen1_1);
	AES_CBC_process(&aes, TestPT128+32, 32, RCT1+rctlen1_1, &rctlen1_2);
	AES_CBC_close(&aes, RCT1+rctlen1_1+rctlen1_2, &padlen1);
	AES_CBC_clear(&aes);
	if(!memcmp(RCT1, TestCT128, 64))
	{
		//printf("AES Test 1 Enc Validation TEST(32+32) OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- AES Test 1 Enc Validation TEST(32+32) Fail\n");
#endif
		check = 0;
	}

	AES_CBC_init(&aes, 0, AES128, TestKey128, TestIV128);
	AES_CBC_process(&aes, RCT1, 32, RPT1, &rptlen1_1);
	AES_CBC_process(&aes, RCT1+32, 32, RPT1+rptlen1_1, &rptlen1_2);
	AES_CBC_process(&aes, RCT1+64, 16, RPT1+rptlen1_1+rptlen1_2, &rptlen1_3);
	AES_CBC_close(&aes, RPT1+rptlen1_1+rptlen1_2+rptlen1_3, &padlen1);
	AES_CBC_clear(&aes);
	if(!memcmp(RPT1, TestPT128, 64))
	{
		//printf("AES Test 1 Dec Validation TEST(32+32+16) OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- AES Test 1 Dec Validation TEST(32+32+16) Fail\n");
#endif
		check = 0;
	}
	memset(RCT1, 0x00, 160);
	memset(RPT1, 0x00, 160);


	AES_CBC_init(&aes, 1, AES128, TestKey128, TestIV128);
	AES_CBC_process(&aes, TestPT128, 13, RCT1, &rctlen1_1);
	AES_CBC_process(&aes, TestPT128+13, 15, RCT1+rctlen1_1, &rctlen1_2);
	AES_CBC_process(&aes, TestPT128+28, 36, RCT1+rctlen1_1+rctlen1_2, &rctlen1_3);
	AES_CBC_close(&aes, RCT1+rctlen1_1+rctlen1_2+rctlen1_3, &padlen1);
	AES_CBC_clear(&aes);
	if(!memcmp(RCT1, TestCT128, 64))
	{
		//printf("AES Test 1 Enc Validation TEST(13+15+36) OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- AES Test 1 Enc Validation TEST(13+15+36) Fail\n");
#endif
		check = 0;
	}

	AES_CBC_init(&aes, 0, AES128, TestKey128, TestIV128);
	AES_CBC_process(&aes, RCT1, 13, RPT1, &rptlen1_1);
	AES_CBC_process(&aes, RCT1+13, 27, RPT1+rptlen1_1, &rptlen1_2);
	AES_CBC_process(&aes, RCT1+40, 40, RPT1+rptlen1_1+rptlen1_2, &rptlen1_3);
	AES_CBC_close(&aes, RPT1+rptlen1_1+rptlen1_2+rptlen1_3, &padlen1);
	AES_CBC_clear(&aes);
	if(!memcmp(RPT1, TestPT128, 64))
	{
		//printf("AES Test 1 Dec Validation TEST(13+27+40) OK\n\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- AES Test 1 Dec Validation TEST(13+27+40) Fail\n\n");
#endif
		check = 0;
	}
	memset(RCT1, 0x00, 180);
	memset(RPT1, 0x00, 180);



	AES_CBC_init(&aes, 1, AES192, TestKey192, TestIV192);
	AES_CBC_process(&aes, TestPT192, 64, RCT2, &rctlen2_1);
	AES_CBC_close(&aes, RCT2+rctlen2_1, &padlen2);
	AES_CBC_clear(&aes);
	if(!memcmp(RCT2, TestCT192, 64))
	{
		//printf("AES Test 2 Enc Validation TEST(64 once) OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- AES Test 2 Enc Validation TEST(64 once) Fail\n");
#endif
		check = 0;
	}

	AES_CBC_init(&aes, 0, AES192, TestKey192, TestIV192);
	AES_CBC_process(&aes, RCT2, rctlen2_1+padlen2, RPT2, &rptlen2_1);
	AES_CBC_close(&aes, RPT2+rptlen2_1, &padlen2);
	AES_CBC_clear(&aes);
	if(!memcmp(RPT2, TestPT192, 64))
	{
		//printf("AES Test 2 Dec Validation TEST(64 once) OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- AES Test 2 Dec Validation TEST(64 once) Fail\n");
#endif
		check = 0;
	}
	memset(RCT2, 0x00, 180);
	memset(RPT2, 0x00, 180);


	AES_CBC_init(&aes, 1, AES192, TestKey192, TestIV192);
	AES_CBC_process(&aes, TestPT192, 45, RCT2, &rctlen2_1);
	AES_CBC_close(&aes, RCT2+rctlen2_1, &padlen2);
	AES_CBC_clear(&aes);

	AES_CBC_init(&aes, 0, AES192, TestKey192, TestIV192);
	AES_CBC_process(&aes, RCT2, rctlen2_1+padlen2, RPT2, &rptlen2_1);
	AES_CBC_close(&aes, RPT2+rptlen2_1, &padlen2);
	AES_CBC_clear(&aes);
	if(!memcmp(RPT2, TestPT192, 45))
	{
		//printf("AES Test 2 Enc/Dec Validation TEST(45 once) OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- AES Test 2 Enc/Dec Validation TEST(45 once) Fail\n");
#endif
		check = 0;
	}
	memset(RCT2, 0x00, 180);
	memset(RPT2, 0x00, 180);


	AES_CBC_init(&aes, 1, AES192, TestKey192, TestIV192);
	AES_CBC_process(&aes, TestPT192, 32, RCT2, &rctlen2_1);
	AES_CBC_process(&aes, TestPT192+32, 32, RCT2+rctlen2_1, &rctlen2_2);
	AES_CBC_close(&aes, RCT2+rctlen2_1+rctlen2_2, &padlen2);
	AES_CBC_clear(&aes);
	if(!memcmp(RCT2, TestCT192, 64))
	{
		//printf("AES Test 2 Enc Validation TEST(32+32) OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- AES Test 2 Enc Validation TEST(32+32) Fail\n");
#endif
		check = 0;
	}

	AES_CBC_init(&aes, 0, AES192, TestKey192, TestIV192);
	AES_CBC_process(&aes, RCT2, 32, RPT2, &rptlen2_1);
	AES_CBC_process(&aes, RCT2+32, 32, RPT2+rptlen2_1, &rptlen2_2);
	AES_CBC_process(&aes, RCT2+64, 16, RPT2+rptlen2_1+rptlen2_2, &rptlen2_3);
	AES_CBC_close(&aes, RPT2+rptlen2_1+rptlen2_2+rptlen2_3, &padlen2);
	AES_CBC_clear(&aes);
	if(!memcmp(RPT2, TestPT192, 64))
	{
		//printf("AES Test 2 Dec Validation TEST(32+32+16) OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- AES Test 2 Dec Validation TEST(32+32+16) Fail\n");
#endif
		check = 0;
	}
	memset(RCT2, 0x00, 180);
	memset(RPT2, 0x00, 180);


	AES_CBC_init(&aes, 1, AES192, TestKey192, TestIV192);
	AES_CBC_process(&aes, TestPT192, 13, RCT2, &rctlen2_1);
	AES_CBC_process(&aes, TestPT192+13, 15, RCT2+rctlen2_1, &rctlen2_2);
	AES_CBC_process(&aes, TestPT192+28, 36, RCT2+rctlen2_1+rctlen2_2, &rctlen2_3);
	AES_CBC_close(&aes, RCT2+rctlen2_1+rctlen2_2+rctlen2_3, &padlen2);
	AES_CBC_clear(&aes);
	if(!memcmp(RCT2, TestCT192, 64))
	{
		//printf("AES Test 2 Enc Validation TEST(13+15+36) OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- AES Test 2 Enc Validation TEST(13+15+36) Fail\n");
#endif
		check = 0;
	}

	AES_CBC_init(&aes, 0, AES192, TestKey192, TestIV192);
	AES_CBC_process(&aes, RCT2, 13, RPT2, &rptlen2_1);
	AES_CBC_process(&aes, RCT2+13, 27, RPT2+rptlen2_1, &rptlen2_2);
	AES_CBC_process(&aes, RCT2+40, 40, RPT2+rptlen2_1+rptlen2_2, &rptlen2_3);
	AES_CBC_close(&aes, RPT2+rptlen2_1+rptlen2_2+rptlen2_3, &padlen2);
	AES_CBC_clear(&aes);
	if(!memcmp(RPT2, TestPT192, 64))
	{
		//printf("AES Test 2 Dec Validation TEST(13+27+40) OK\n\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- AES Test 2 Dec Validation TEST(13+27+40) Fail\n\n");
#endif
		check = 0;
	}
	memset(RCT2, 0x00, 180);
	memset(RPT2, 0x00, 180);



	AES_CBC_init(&aes, 1, AES256, TestKey256, TestIV256);
	AES_CBC_process(&aes, TestPT256, 64, RCT3, &rctlen3_1);
	AES_CBC_close(&aes, RCT3+rctlen3_1, &padlen3);
	AES_CBC_clear(&aes);
	if(!memcmp(RCT3, TestCT256, 64))
	{
		//printf("AES Test 3 Enc Validation TEST(64 once) OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- AES Test 3 Enc Validation TEST(64 once) Fail\n");
#endif
		check = 0;
	}

	AES_CBC_init(&aes, 0, AES256, TestKey256, TestIV256);
	AES_CBC_process(&aes, RCT3, rctlen3_1+padlen3, RPT3, &rptlen3_1);
	AES_CBC_close(&aes, RPT3+rptlen3_1, &padlen3);
	AES_CBC_clear(&aes);
	if(!memcmp(RPT3, TestPT256, 64))
	{
		//printf("AES Test 3 Dec Validation TEST(64 once) OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- AES Test 3 Dec Validation TEST(64 once) Fail\n");
#endif
		check = 0;
	}
	memset(RCT3, 0x00, 180);
	memset(RPT3, 0x00, 180);


	AES_CBC_init(&aes, 1, AES256, TestKey256, TestIV256);
	AES_CBC_process(&aes, TestPT256, 58, RCT3, &rctlen3_1);
	AES_CBC_close(&aes, RCT3+rctlen3_1, &padlen3);
	AES_CBC_clear(&aes);

	AES_CBC_init(&aes, 0, AES256, TestKey256, TestIV256);
	AES_CBC_process(&aes, RCT3, rctlen3_1+padlen3, RPT3, &rptlen3_1);
	AES_CBC_close(&aes, RPT3+rptlen3_1, &padlen3);
	AES_CBC_clear(&aes);
	if(!memcmp(RPT3, TestPT256, 58))
	{
		//printf("AES Test 3 Enc/Dec Validation TEST(58 once) OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- AES Test 3 Enc/Dec Validation TEST(58 once) Fail\n");
#endif
		check = 0;
	}
	memset(RCT3, 0x00, 180);
	memset(RPT3, 0x00, 180);


	AES_CBC_init(&aes, 1, AES256, TestKey256, TestIV256);
	AES_CBC_process(&aes, TestPT256, 32, RCT3, &rctlen3_1);
	AES_CBC_process(&aes, TestPT256+32, 32, RCT3+rctlen3_1, &rctlen3_2);
	AES_CBC_close(&aes, RCT3+rctlen3_1+rctlen3_2, &padlen3);
	AES_CBC_clear(&aes);
	if(!memcmp(RCT3, TestCT256, 64))
	{
		//printf("AES Test 3 Enc Validation TEST(32+32) OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- AES Test 3 Enc Validation TEST(32+32) Fail\n");
#endif
		check = 0;
	}

	AES_CBC_init(&aes, 0, AES256, TestKey256, TestIV256);
	AES_CBC_process(&aes, RCT3, 32, RPT3, &rptlen3_1);
	AES_CBC_process(&aes, RCT3+32, 32, RPT3+rptlen3_1, &rptlen3_2);
	AES_CBC_process(&aes, RCT3+64, 16, RPT3+rptlen3_1+rptlen3_2, &rptlen3_3);
	AES_CBC_close(&aes, RPT3+rptlen3_1+rptlen3_2+rptlen3_3, &padlen3);
	AES_CBC_clear(&aes);
	if(!memcmp(RPT3, TestPT256, 64))
	{
		//printf("AES Test 3 Dec Validation TEST(32+32+16) OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- AES Test 3 Dec Validation TEST(32+32+16) Fail\n");
#endif
		check = 0;
	}
	memset(RCT3, 0x00, 180);
	memset(RPT3, 0x00, 180);


	AES_CBC_init(&aes, 1, AES256, TestKey256, TestIV256);
	AES_CBC_process(&aes, TestPT256, 13, RCT3, &rctlen3_1);
	AES_CBC_process(&aes, TestPT256+13, 15, RCT3+rctlen3_1, &rctlen3_2);
	AES_CBC_process(&aes, TestPT256+28, 36, RCT3+rctlen3_1+rctlen3_2, &rctlen3_3);
	AES_CBC_close(&aes, RCT3+rctlen3_1+rctlen3_2+rctlen3_3, &padlen3);
	AES_CBC_clear(&aes);
	if(!memcmp(RCT3, TestCT256, 64))
	{
		//printf("AES Test 3 Enc Validation TEST(13+15+36) OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- AES Test 3 Enc Validation TEST(13+15+36) Fail\n");
#endif
		check = 0;
	}

	AES_CBC_init(&aes, 0, AES256, TestKey256, TestIV256);
	AES_CBC_process(&aes, RCT3, 13, RPT3, &rptlen3_1);
	AES_CBC_process(&aes, RCT3+13, 27, RPT3+rptlen3_1, &rptlen3_2);
	AES_CBC_process(&aes, RCT3+40, 40, RPT3+rptlen3_1+rptlen3_2, &rptlen3_3);
	AES_CBC_close(&aes, RPT3+rptlen3_1+rptlen3_2+rptlen3_3, &padlen3);
	AES_CBC_clear(&aes);
	if(!memcmp(RPT3, TestPT256, 64))
	{
		//printf("AES Test 3 Dec Validation TEST(13+27+40) OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- AES Test 3 Dec Validation TEST(13+27+40) Fail\n");
#endif
		check = 0;
	}
	memset(RCT3, 0x00, 180);
	memset(RPT3, 0x00, 180);

	return check;
}
