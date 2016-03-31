#ifndef EBD_HEADER_ERROR_H
#define EBD_HEADER_ERROR_H

#define EBD_CRYPTO_SUCCESS						1
#define EBD_CRYPTO_FAIL							0

#define ERR_MASK							0x10000000

#define ERR_INVALID_INPUT					0x10000001
#define ERR_INVALID_ALGORITHM_ID			0x10000002
#define ERR_INVALID_OPERATION_MASK			0x10000003
#define ERR_INVALID_PADDING					0x10000004
#define ERR_FINAL_FAILURE					0x10000005
#define ERR_INVALID_UNIT					0x10000006

#define ERR_MALLOC							0x20000000
#define ERR_MEM_RELEASE						0x20000001

#define ERR_FUNCTION_CALL_FAILURE			0x30000001
#define ERR_REQUESTED_NUM_OF_BITS_TOO_LONG  0x30000002
#define ERR_SUB_OPEATION_FAILURE			0x30000003
#define ERR_FILE_OPEN_FAIL					0x30000004
#define ERR_RESEED_REQUIRED					0x30000005


#define ERR_INVALID_PUBLIC_KEY				0x40000001
#define ERR_INVALID_PRIVATE_KEY				0x40000002
#define ERR_PUBLIC_KEY_VALID_TEST_FAIL		0x40000003
#define ERR_NEW_RANDOM_NEEDED				0x40000004
#define ERR_SIGN_FAILURE					0x40000005
#define ERR_VERIFY_FAILURE					0x40000006

#endif
