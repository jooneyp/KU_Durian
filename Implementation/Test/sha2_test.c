#include "EBDCrypto.h"
#include "EBDerror.h"

int SHA224_ValidTest()
{
	unsigned char *message1 = "abc";
	unsigned char testVectorH1[28] = {0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2, 0x55, 0xb3, 0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7};
	unsigned char *message2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	unsigned char testVectorH2[28] = {0x75, 0x38, 0x8b, 0x16, 0x51, 0x27, 0x76, 0xcc, 0x5d, 0xba, 0x5d, 0xa1, 0xfd, 0x89, 0x01, 0x50, 0xb0, 0xc6, 0x45, 0x5c, 0xb4, 0xf5, 0x8b, 0x19, 0x52, 0x52, 0x25, 0x25};
	unsigned char *message3 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
	unsigned char testVectorH3[28] = {0xc9, 0x7c, 0xa9, 0xa5, 0x59, 0x85, 0x0c, 0xe9, 0x7a, 0x04, 0xa9, 0x6d, 0xef, 0x6d, 0x99, 0xa9, 0xe0, 0xe0, 0xe2, 0xab, 0x14, 0xe6, 0xb8, 0xdf, 0x26, 0x5f, 0xc0, 0xb3};
	unsigned char *message4 = "";
	unsigned char testVectorH4[28] = {0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b, 0xc9, 0x47, 0x61, 0x02, 0xbb, 0x28, 0x82, 0x34, 0xc4, 0x15, 0xa2, 0xb0, 0x1f, 0x82, 0x8e, 0xa6, 0x2a, 0xc5, 0xb3, 0xe4, 0x2f};

	unsigned char output[28];
	SHA224_INFO sha;

	int check = 1;

#ifdef DEBUG_MODE
	printf("\n=========================\n");
	printf(" SHA-224 Validation TEST\n");
	printf("=========================\n");
#endif

	SHA224_init(&sha);
	SHA224_update(&sha, message1, 3);
	SHA224_final(&sha, output);

	if(!memcmp(output, testVectorH1, 28))
	{
		//printf("SHA224 Test 1 Validation TEST OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- SHA224 Test 1 Validation TEST Fail\n");
#endif
		check = 0;
	}

	SHA224_init(&sha);
	SHA224_update(&sha, message2, 56);
	SHA224_final(&sha, output);

	if(!memcmp(output, testVectorH2, 28))
	{
		//printf("SHA224 Test 2 Validation TEST OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- SHA224 Test 2 Validation TEST Fail\n");
#endif
		check = 0;
	}

	SHA224_init(&sha);
	SHA224_update(&sha, message3, 112);
	SHA224_final(&sha, output);

	if(!memcmp(output, testVectorH3, 28))
	{
		//printf("SHA224 Test 3 Validation TEST OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- SHA224 Test 3 Validation TEST Fail\n");
#endif
		check = 0;
	}

	SHA224_init(&sha);
	SHA224_update(&sha, message4, 0);
	SHA224_final(&sha, output);

	if(!memcmp(output, testVectorH4, 28))
	{
		//printf("SHA224 Test 4 Validation TEST OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- SHA224 Test 4 Validation TEST Fail\n");
#endif
		check = 0;
	}

	return check;	
}

int SHA256_ValidTest()
{
	unsigned char *message1 = "abc";
	unsigned char testVectorH1[32] = {0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
		0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD};
	unsigned char *message2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	unsigned char testVectorH2[32] = {0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8, 0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E, 0x60, 0x39,
		0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67, 0xF6, 0xEC, 0xED, 0xD4, 0x19, 0xDB, 0x06, 0xC1};
	unsigned char *message3 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
	unsigned char testVectorH3[32] = {0xcf, 0x5b, 0x16, 0xa7, 0x78, 0xaf, 0x83, 0x80, 0x03, 0x6c, 0xe5, 0x9e, 0x7b, 0x04, 0x92, 0x37,
		0x0b, 0x24, 0x9b, 0x11, 0xe8, 0xf0, 0x7a, 0x51, 0xaf, 0xac, 0x45, 0x03, 0x7a, 0xfe, 0xe9, 0xd1};
	unsigned char *message4 = "";
	unsigned char testVectorH4[32] = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
		0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

	unsigned char output[32];
	SHA256_INFO sha;

	int check = 1;

#ifdef DEBUG_MODE
	printf("\n=========================\n");
	printf(" SHA-256 Validation TEST\n");
	printf("=========================\n");
#endif

	SHA256_init(&sha);
	SHA256_update(&sha, message1, 3);
	SHA256_final(&sha, output);

	if(!memcmp(output, testVectorH1, 32))
	{
		//printf("SHA256 Test 1 Validation TEST OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- SHA256 Test 1 Validation TEST Fail\n");
#endif
		check = 0;
	}

	SHA256_init(&sha);
	SHA256_update(&sha, message2, 56);
	SHA256_final(&sha, output);

	if(!memcmp(output, testVectorH2, 32))
	{
		//printf("SHA256 Test 2 Validation TEST OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- SHA256 Test 2 Validation TEST Fail\n");
#endif
		check = 0;
	}

	SHA256_init(&sha);
	SHA256_update(&sha, message3, 112);
	SHA256_final(&sha, output);

	if(!memcmp(output, testVectorH3, 32))
	{
		//printf("SHA256 Test 3 Validation TEST OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- SHA256 Test 3 Validation TEST Fail\n");
#endif
		check = 0;
	}

	SHA256_init(&sha);
	SHA256_update(&sha, message4, 0);
	SHA256_final(&sha, output);

	if(!memcmp(output, testVectorH4, 32))
	{
		//printf("SHA256 Test 4 Validation TEST OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- SHA256 Test 4 Validation TEST Fail\n");
#endif
		check = 0;
	}

	return check;
}

int SHA384_ValidTest()
{
	unsigned char *message1 = "abc";
	unsigned char testVectorH1[48] = {0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
		                              0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
									  0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7};
	unsigned char *message2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	unsigned char testVectorH2[48] = {0x33, 0x91, 0xfd, 0xdd, 0xfc, 0x8d, 0xc7, 0x39, 0x37, 0x07, 0xa6, 0x5b, 0x1b, 0x47, 0x09, 0x39,
		                              0x7c, 0xf8, 0xb1, 0xd1, 0x62, 0xaf, 0x05, 0xab, 0xfe, 0x8f, 0x45, 0x0d, 0xe5, 0xf3, 0x6b, 0xc6,
									  0xb0, 0x45, 0x5a, 0x85, 0x20, 0xbc, 0x4e, 0x6f, 0x5f, 0xe9, 0x5b, 0x1f, 0xe3, 0xc8, 0x45, 0x2b};
	unsigned char *message3 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
	unsigned char testVectorH3[48] = {0x09, 0x33, 0x0c, 0x33, 0xf7, 0x11, 0x47, 0xe8, 0x3d, 0x19, 0x2f, 0xc7, 0x82, 0xcd, 0x1b, 0x47,
		                              0x53, 0x11, 0x1b, 0x17, 0x3b, 0x3b, 0x05, 0xd2, 0x2f, 0xa0, 0x80, 0x86, 0xe3, 0xb0, 0xf7, 0x12,
									  0xfc, 0xc7, 0xc7, 0x1a, 0x55, 0x7e, 0x2d, 0xb9, 0x66, 0xc3, 0xe9, 0xfa, 0x91, 0x74, 0x60, 0x39};
	unsigned char *message4 = "";
	unsigned char testVectorH4[48] = {0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
		                              0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
									  0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b};

	unsigned char output[48];
	SHA384_INFO sha;

	int check = 1;

#ifdef DEBUG_MODE
	printf("\n=========================\n");
	printf(" SHA-384 Validation TEST\n");
	printf("=========================\n");
#endif

	SHA384_init(&sha);
	SHA384_update(&sha, message1, 3);
	SHA384_final(&sha, output);

	if(!memcmp(output, testVectorH1, 48))
	{
		//printf("SHA384 Test 1 Validation TEST OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- SHA384 Test 1 Validation TEST Fail\n");
#endif
		check = 0;
	}

	SHA384_init(&sha);
	SHA384_update(&sha, message2, 56);
	SHA384_final(&sha, output);

	if(!memcmp(output, testVectorH2, 48))
	{
		//printf("SHA384 Test 2 Validation TEST OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- SHA384 Test 2 Validation TEST Fail\n");
#endif
		check = 0;
	}

	SHA384_init(&sha);
	SHA384_update(&sha, message3, 112);
	SHA384_final(&sha, output);

	if(!memcmp(output, testVectorH3, 48))
	{
		//printf("SHA384 Test 3 Validation TEST OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- SHA384 Test 3 Validation TEST Fail\n");
#endif
		check = 0;
	}

	SHA384_init(&sha);
	SHA384_update(&sha, message4, 0);
	SHA384_final(&sha, output);

	if(!memcmp(output, testVectorH4, 48))
	{
		//printf("SHA384 Test 4 Validation TEST OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- SHA384 Test 4 Validation TEST Fail\n");
#endif
		check = 0;
	}

	return check;
}

int SHA512_ValidTest()
{
	unsigned char *message1 = "abc";
	unsigned char testVectorH1[64] = {0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
		0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
		0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
		0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f};
	unsigned char *message2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	unsigned char testVectorH2[64] = {0x20, 0x4a, 0x8f, 0xc6, 0xdd, 0xa8, 0x2f, 0x0a, 0x0c, 0xed, 0x7b, 0xeb, 0x8e, 0x08, 0xa4, 0x16,
		0x57, 0xc1, 0x6e, 0xf4, 0x68, 0xb2, 0x28, 0xa8, 0x27, 0x9b, 0xe3, 0x31, 0xa7, 0x03, 0xc3, 0x35,
		0x96, 0xfd, 0x15, 0xc1, 0x3b, 0x1b, 0x07, 0xf9, 0xaa, 0x1d, 0x3b, 0xea, 0x57, 0x78, 0x9c, 0xa0,
		0x31, 0xad, 0x85, 0xc7, 0xa7, 0x1d, 0xd7, 0x03, 0x54, 0xec, 0x63, 0x12, 0x38, 0xca, 0x34, 0x45};
	unsigned char *message3 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
	unsigned char testVectorH3[64] = {0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda, 0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc, 0x14, 0x3f,
		0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1, 0x72, 0x99, 0xae, 0xad, 0xb6, 0x88, 0x90, 0x18,
		0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4, 0x33, 0x1b, 0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a,
		0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54, 0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09};
	unsigned char *message4 = "";
	unsigned char testVectorH4[64] = {0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
		0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
		0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
		0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e};

	unsigned char output[64];
	SHA512_INFO sha;

	int check = 1;

#ifdef DEBUG_MODE
	printf("\n=========================\n");
	printf(" SHA-512 Validation TEST\n");
	printf("=========================\n");
#endif

	SHA512_init(&sha);
	SHA512_update(&sha, message1, 3);
	SHA512_final(&sha, output);

	if(!memcmp(output, testVectorH1, 64))
	{
		//printf("SHA512 Test 1 Validation TEST OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- SHA512 Test 1 Validation TEST Fail\n");
#endif
		check = 0;
	}

	SHA512_init(&sha);
	SHA512_update(&sha, message2, 56);
	SHA512_final(&sha, output);

	if(!memcmp(output, testVectorH2, 64))
	{
		//printf("SHA512 Test 2 Validation TEST OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- SHA512 Test 2 Validation TEST Fail\n");
#endif
		check = 0;
	}

	SHA512_init(&sha);
	SHA512_update(&sha, message3, 112);
	SHA512_final(&sha, output);

	if(!memcmp(output, testVectorH3, 64))
	{
		//printf("SHA512 Test 3 Validation TEST OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- SHA512 Test 3 Validation TEST Fail\n");
#endif
		check = 0;
	}

	SHA512_init(&sha);
	SHA512_update(&sha, message4, 0);
	SHA512_final(&sha, output);

	if(!memcmp(output, testVectorH4, 64))
	{
		//printf("SHA512 Test 4 Validation TEST OK\n");
	}
	else
	{
#ifdef DEBUG_MODE
		printf("-- SHA512 Test 4 Validation TEST Fail\n");
#endif
		check = 0;
	}

	return check;
}
