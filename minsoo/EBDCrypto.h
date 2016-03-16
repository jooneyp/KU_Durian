#ifndef EBD_CRYPTO_H
#define EBD_CRYPTO_H

#define DEBUG_MODE

#ifdef DEBUG_MODE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#endif

//#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

	typedef signed short	SSHORT;
	typedef unsigned short	USHORT;
	typedef signed short	SCHAR;
	typedef unsigned char	UCHAR;
	typedef signed int		SINT;
	typedef unsigned int	UINT;
	typedef signed long		SLONG;
	typedef unsigned long	ULONG;

	typedef int				BOOL;

#ifdef WIN32
	typedef unsigned __int64 ULLONG;
#else
	typedef unsigned long long ULLONG;
#endif




#define SHA1_BLOCK_BYTES 1












#define TRUE 1
#define FALSE 0

#define AES128 128
#define AES192 192
#define AES256 256

#define AES_BLOCK_SIZE 16

#define SHA256_BLOCK_SIZE		64
#define SHA512_BLOCK_SIZE		128

#define HD_MAX_V_LEN_IN_BYTES					111
#define HD_MAX_C_LEN_IN_BYTES					111

#define BITMASK_LONG 0xffffffff
#define BITMASK_HIGHER_LONG 0xffff0000
#define BITMASK_LOWER_LONG 0x0000ffff
#define HIGHER_MSB_ONE 0x80000000
#define LOWER_MSB_ONE 0x00008000
#define HIGHER_LSB_ONE 0x00010000
#define LOWER_LSB_ONE 0x00000001
#define LONG_BITS 32
#define HALF_LONG_BITS 16

#define HASH_SHA224 0x02000200
#define HASH_SHA256 0x02000300
#define HASH_SHA384 0x02000400
#define HASH_SHA512 0x02000500

#define MAX_BN_BUF_LEN (400 + 1)
#define MAX_GFP_BUF_LEN (400 + 1)
#define MAX_GF2N_BUF_LEN (50 + 1)

#define PRIME_TEST_NUM 50
#define KARA_2048_WORD_LEN 64
#define KARA_3072_WORD_LEN 96
#define KARA_SIZE_3072 3072
#define KARA_SIZE_2048 2048
#define KARA_SIZE_1024 1024
#define KARA_SIZE_512 512
#define WORD_SIZE 32

#define MPCONST_POS_SIG 1
#define MPCONST_NEG_SIG -1
#define MPCONST_ZERO_SIG 0

	/*!
	* \brief
	* AES 알고리즘을 위한 구조체
	*/
	typedef struct aes_key_st {
		unsigned int roundKey[60];
		int rounds;
	} AES_KEY;

	/*!
	* \brief
	* AES_KEY 구조체 초기화 함수 (암호화 키 셋팅)
	* \param userKey
	* 사용자 입력 비밀 키
	* \param bits
	* 사용자 입력 키의 길이 (bits 단위)
	* \param key
	* 초기화 할 AES_KEY 구조체
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	int AES_encrypt_init(const unsigned char *userKey, const int bits, AES_KEY *key);

	/*!
	* \brief
	* AES_KEY 구조체 초기화 함수 (복호화 키 셋팅)
	* \param userKey
	* 사용자 입력 비밀 키
	* \param bits
	* 사용자 입력 키의 길이 (bits 단위)
	* \param key
	* 초기화 할 AES_KEY 구조체
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	int AES_decrypt_init(const unsigned char *userKey, const int bits, AES_KEY *key);

	/*!
	* \brief
	* AES 1 Block 암호화 함수
	* \param in
	* 사용자 입력 평문 (16 bytes)
	* \param out
	* 암호화된 결과가 저장될 버퍼 (16 bytes)
	* \param key
	* 초기화 함수로 초기화된 AES_KEY 구조체
	*/
	void AES_encrypt_block(const unsigned char *in, unsigned char *out, const AES_KEY *key);

	/*!
	* \brief
	* AES 1 Block 복호화 함수
	* \param in
	* 사용자 입력 암호문 (16 bytes)
	* \param out
	* 복호화된 결과가 저장될 버퍼 (16 bytes)
	* \param key
	* 초기화 함수로 초기화된 AES_KEY 구조체
	*/
	void AES_decrypt_block(const unsigned char *in, unsigned char *out, const AES_KEY *key);

	/*!
	* \brief
	* AES CBC 운영모드 알고리즘을 위한 구조체
	*/
	typedef struct aes_cbc_info_st {
		int				encrypt;
		unsigned char	ivec[AES_BLOCK_SIZE];
		AES_KEY			aes_key;
		unsigned char	cbc_buffer[AES_BLOCK_SIZE];
		int				buffer_length;
		unsigned char	cbc_last_block[AES_BLOCK_SIZE];
		int				last_block_flag;
	} AES_CBC_INFO;

	/*!
	* \brief
	* AES_CBC_INFO 구조체 초기화 함수 (암/복호화 키 셋팅)
	* \param info
	* 초기화 할 AES_CBC_INFO 구조체
	* \param encrypt
	* 동작모드, 1:Encryption, 0:Decryption
	* \param bits
	* 사용자 입력 키의 길이 (bits 단위)
	* \param user_key
	* 사용자 입력 비밀 키
	* \param iv
	* 사용자 입력 IV
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	int AES_CBC_init(AES_CBC_INFO *info, int encrypt, int bits, unsigned char *user_key, unsigned char *iv);

	/*!
	* \brief
	* AES CBC 암/복호화 함수
	* \param info
	* 초기화된 AES_CBC_INFO 구조체
	* \param in
	* 사용자 입력 데이터
	* \param inLen
	* 사용자 입력 데이터의 길이 (bytes 단위)
	* \param out
	* 암/복호화된 결과가 저장될 출력 버퍼
	* \param outLen
	* 출력 버퍼의 길이를 저장할 포인터, 함수 종료 후 출력 버퍼에 저장된 길이가 입력됨
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	int AES_CBC_process(AES_CBC_INFO *info, unsigned char *in, int inLen, unsigned char *out, int *outLen);

	/*!
	* \brief
	* AES CBC 암/복호화 마무리 및 패딩처리 함수
	* \param info
	* 초기화된 AES_CBC_INFO 구조체
	* \param out
	* 암/복호화된 결과가 저장될 출력 버퍼
	* \param outLen
	* 출력 버퍼의 길이를 저장할 포인터, 함수 종료 후 출력 버퍼에 저장된 길이가 입력됨
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	int AES_CBC_close(AES_CBC_INFO *info, unsigned char *out, int *outLen);

	/*!
	* \brief
	* AES_CBC_INFO 구조체 메모리 삭제 함수
	* \param info
	* 삭제시킬 AES_CBC_INFO 구조체
	* \returns
	* -# 1 : Success
	*/
	int AES_CBC_clear(AES_CBC_INFO *info);

	/*!
	* \brief
	* AES CBC 통합 함수
	* \param enc
	* 동작모드, 1:Encryption, 0:Decryption
	* \param user_key
	* 사용자 입력 비밀 키
	* \param key_len
	* 사용자 입력 키의 길이 (bytes 단위)
	* \param iv
	* 사용자 입력 IV
	* \param in
	* 사용자 입력 데이터
	* \param len
	* 사용자 입력 데이터의 길이 (bytes 단위)
	* \param out
	* 암/복호화된 결과가 저장될 출력 버퍼
	* \returns
	* 출력 버퍼에 저장된 데이터의 길이가 입력됨(평문/암호문의 길이)
	*/
	int AES_CBC(int enc, unsigned char *user_key, unsigned int key_len, unsigned char *iv, unsigned char *in, unsigned int len, unsigned char *out);




	typedef struct sha256_structure {
		unsigned long long l1;
		unsigned int l2;
		unsigned long data[8];
		unsigned char buf[SHA256_BLOCK_SIZE];
	} SHA256_INFO;
	typedef SHA256_INFO SHA224_INFO;

	typedef struct sha512_structure {
		unsigned long long l1;
		unsigned int l2;
		unsigned long long data[8];
		unsigned char buf[SHA512_BLOCK_SIZE];
	} SHA512_INFO;
	typedef SHA512_INFO SHA384_INFO;

	/*!
	* \brief
	* SHA224_INFO 구조체 초기화 함수
	* \param sha224
	* 초기화 할 SHA224_INFO 구조체
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	int SHA224_init(SHA224_INFO *sha224);

	/*!
	* \brief
	* SHA224 Digest 중간 처리 함수
	* \param sha224
	* 초기화된 SHA224_INFO 구조체
	* \param in
	* 사용자 입력 데이터
	* \param inLen
	* 사용자 입력 데이터의 길이 (bytes 단위)
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	int SHA224_update(SHA224_INFO *sha224, const unsigned char *data, unsigned int length);

	/*!
	* \brief
	* SHA224 Digest 최종 해쉬값 출력 함수
	* \param sha224
	* 초기화된 SHA224_INFO 구조체
	* \param md
	* 해쉬값이 저장될 출력 버퍼 (28 bytes 이상 할당되어야 함)
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	int SHA224_final(SHA224_INFO *sha224, unsigned char *md);

	/*!
	* \brief
	* SHA256_INFO 구조체 초기화 함수
	* \param sha256
	* 초기화 할 SHA256_INFO 구조체
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	int SHA256_init(SHA256_INFO *sha256);

	/*!
	* \brief
	* SHA256 Digest 중간 처리 함수
	* \param sha256
	* 초기화된 SHA256_INFO 구조체
	* \param in
	* 사용자 입력 데이터
	* \param inLen
	* 사용자 입력 데이터의 길이 (bytes 단위)
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	int SHA256_update(SHA256_INFO *sha256, const unsigned char *data, unsigned int length);

	/*!
	* \brief
	* SHA256 Digest 최종 해쉬값 출력 함수
	* \param sha256
	* 초기화된 SHA256_INFO 구조체
	* \param md
	* 해쉬값이 저장될 출력 버퍼 (32 bytes 이상 할당되어야 함)
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	int SHA256_final(SHA256_INFO *sha256, unsigned char *md);

	/*!
	* \brief
	* SHA384_INFO 구조체 초기화 함수
	* \param sha384
	* 초기화 할 SHA384_INFO 구조체
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	int SHA384_init(SHA384_INFO *sha384);

	/*!
	* \brief
	* SHA384 Digest 중간 처리 함수
	* \param sha384
	* 초기화된 SHA384_INFO 구조체
	* \param in
	* 사용자 입력 데이터
	* \param inLen
	* 사용자 입력 데이터의 길이 (bytes 단위)
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	int SHA384_update(SHA384_INFO *sha384, const unsigned char *data, unsigned int length);

	/*!
	* \brief
	* SHA384 Digest 최종 해쉬값 출력 함수
	* \param sha384
	* 초기화된 SHA384_INFO 구조체
	* \param md
	* 해쉬값이 저장될 출력 버퍼 (48 bytes 이상 할당되어야 함)
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	int SHA384_final(SHA384_INFO *sha384, unsigned char *md);

	/*!
	* \brief
	* SHA512_INFO 구조체 초기화 함수
	* \param sha512
	* 초기화 할 SHA512_INFO 구조체
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	int SHA512_init(SHA512_INFO *sha512);

	/*!
	* \brief
	* SHA512 Digest 중간 처리 함수
	* \param sha512
	* 초기화된 SHA512_INFO 구조체
	* \param in
	* 사용자 입력 데이터
	* \param inLen
	* 사용자 입력 데이터의 길이 (bytes 단위)
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	int SHA512_update(SHA512_INFO *sha512, const unsigned char *data, unsigned int length);

	/*!
	* \brief
	* SHA512 Digest 최종 해쉬값 출력 함수
	* \param sha512
	* 초기화된 SHA512_INFO 구조체
	* \param md
	* 해쉬값이 저장될 출력 버퍼 (64 bytes 이상 할당되어야 함)
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	int SHA512_final(SHA512_INFO *sha512, unsigned char *md);

	/*!
	* \brief
	* HASH DRBG(난수생성기) 알고리즘을 위한 구조체
	*/
	typedef struct hash_drbg_state {
		unsigned char	algo;
		unsigned char	V[HD_MAX_V_LEN_IN_BYTES];
		int				Vlen;
		unsigned char	C[HD_MAX_C_LEN_IN_BYTES];
		int				Clen;
		int				seedlen;
		unsigned long long reseed_counter;
		int				security_strength;
		int				initialized_flag;
		unsigned char	prediction_flag;
		unsigned char	reseed_flag;
	} HASH_DRBG_STATE;

	/*!
	* \brief
	* HASH DRBG 난수 생성 함수
	* \param output
	* 생성된 난수가 저장될 버퍼
	* \param request_num_of_bits
	* 생성할 난수의 길이 (bits 단위)
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	int HASH_DRBG_Random_Gen(unsigned char *output, int request_num_of_bits);

	int HASH_DRBG_Generate(HASH_DRBG_STATE *state, unsigned char* output, int requested_num_of_bits, unsigned char* addtional_input, int addlen);









	typedef struct _MP_MONT_CTX {
		BN N;
		BN R;
		BN RR;
		ULONG m;
	} MP_MONT_CTX;
	typedef struct _MP_MONT_BUF {
		ULONG N_dat[MAX_BN_BUF_LEN];
		ULONG R_dat[MAX_BN_BUF_LEN];
		ULONG RR_dat[MAX_BN_BUF_LEN];
	}MP_MONT_BUF;






	typedef struct _BN {
		SINT sig;
		ULONG *dat;
		SINT len;
	}BN;
	typedef BN GFP;
	typedef struct _BN_X9_PRNG_CTX {
		BN xseed;
		BN xkey;
		BN sgord;
	}BN_X9_PRNG_CTX;
	typedef struct _BN_X9_PRNG_BUF {
		ULONG xseed_dat[MAX_BN_BUF_LEN];
		ULONG xkey_dat[MAX_BN_BUF_LEN];
		ULONG sgord_dat[MAX_BN_BUF_LEN];
	}BN_X9_PRNG_BUF;



	static const char bits_to_index_low[256] = {
		0,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
		5,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
		6,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
		5,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
		7,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
		5,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
		6,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
		5,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
	};
	static char bits_to_index[256] = {
		0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
		6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
		7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
		7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
	};





	typedef BN GFP_ECC_PRIVATE_KEY;
	typedef ULONG GFP_ECC_PRIVATE_KEY_BUF;
	typedef GFP_ECPT_AC GFP_ECC_PUBLIC_KEY;
	typedef GFP_ECPT_AC_BUF GFP_ECC_PUBLIC_KEY_BUF;



	typedef struct _GFP_ECPT_AC {
		BOOL is_O;
		GFP x;
		GFP y;
	}GFP_ECPT_AC;
	typedef struct _GFP_ECPT_AC_BUF {
		ULONG x_dat[MAX_GFP_BUF_LEN];
		ULONG y_dat[MAX_GFP_BUF_LEN];
	}GFP_ECPT_AC_BUF;
	typedef struct _GFP_EC_CTX {
		GFP prime;
		GFP a;
		GFP b;
		BN ord;
		BN cofactor;
		GFP_ECPT_AC base;
	}GFP_EC_CTX;
	typedef struct _GFP_EC_CTX_BUF {
		ULONG prime_buf[MAX_GFP_BUF_LEN];
		ULONG a_buf[MAX_GFP_BUF_LEN];
		ULONG b_buf[MAX_GFP_BUF_LEN];
		ULONG ord_buf[MAX_GF2N_BUF_LEN];
		ULONG cof_buf[MAX_GF2N_BUF_LEN];
		ULONG base_x_buf[MAX_GF2N_BUF_LEN];
		ULONG base_y_buf[MAX_GF2N_BUF_LEN];
	}GFP_EC_CTX_BUF;




	typedef struct ec_kcdsa_structure {
		GFP_EC_CTX ec_ctx;
		GFP_EC_CTX_BUF ec_ctx_buf;
		GFP_ECC_PUBLIC_KEY puk;
		GFP_ECPT_AC_BUF puk_buf;
		GFP_ECC_PRIVATE_KEY prk;
		GFP_ECC_PRIVATE_KEY_BUF prk_dat[MAX_GFP_BUF_LEN];
		UCHAR tmp_cdat[MAX_GFP_BUF_LEN << 2];
		BN_X9_PRNG_CTX randctx;
		BN_X9_PRNG_BUF randbuf;
		BN k;
		ULONG k_dat[MAX_GFP_BUF_LEN];
		int is_sign;
		int hash_alg;
	} EC_KCDSA_INFO;


	/**/
	int EC_KCDSA_init(EC_KCDSA_INFO *ec_kcdsa, int hash_alg);
	int EC_KCDSA_setkey(EC_KCDSA_INFO *ec_kcdsa, const UCHAR *qx, ULONG qx_len, const UCHAR *qy, ULONG qy_len, const UCHAR *d, ULONG d_len, SINT priv);
	int EC_KCDSA_gen_key_pair(EC_KCDSA_INFO *ec_kcdsa, UCHAR *qx, ULONG *qx_len, UCHAR *qy, ULONG *qy_len, UCHAR *d, ULONG *d_len);
	int EC_KCDSA_gen_random_k(EC_KCDSA_INFO *ec_kcdsa, SINT bits, UCHAR *k, ULONG *k_len);
	int EC_KCDSA_set_random_k(ECDSA_INFO *ecdsa, const UCHAR *k, ULONG k_len);
	int EC_KCDSA_sign(ECDSA_INFO *ecdsa, UCHAR *r, ULONG *rLen, UCHAR *s, ULONG *sLen, UCHAR *Msg, ULONG Msg_len);
	int EC_KCDSA_verify(ECDSA_INFO *ecdsa, UCHAR *r, ULONG rLen, UCHAR *s, ULONG sLen, UCHAR *Msg, ULONG Msg_len);
	int EC_KCDSA_clear(ECDSA_INFO *ecdsa);

	*/




#ifdef __cplusplus
}
#endif

#endif