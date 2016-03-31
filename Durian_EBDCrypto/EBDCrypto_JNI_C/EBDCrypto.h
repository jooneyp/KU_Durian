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

#define __LINUX__
//#define __WINDOWS__
//#define __ANDROID__
//#define __iOS__


#ifdef __cplusplus
extern "C" {
#endif	

#ifdef WIN32
	typedef long			SLONG;
	typedef unsigned long	ULONG;
#else
	typedef int				SLONG;
	typedef unsigned int	ULONG;
#endif

	typedef int				SINT;
	typedef unsigned int	UINT;

	typedef short			SSHORT;
	typedef unsigned short	USHORT;

	typedef char			SCHAR;
	typedef unsigned char	UCHAR;

	typedef int				BOOL;	

#ifdef WIN32
	typedef __int64 LLONG;
	typedef unsigned __int64 ULLONG;
#else
	typedef long long LLONG;
	typedef unsigned long long ULLONG;
#endif


#define AES128					128
#define AES192					192
#define AES256					256

#define AES_BLOCK_SIZE			16


#define SHA224					0x21
#define SHA256					0x22
#define SHA384					0x23
#define SHA512					0x24

#define SHA256_BLOCK_SIZE		64
#define SHA512_BLOCK_SIZE		128

#define ECDSA_SIGN			1
#define ECDSA_VERIFY			0

    
	/*!
	* \brief
	* AES 알고리즘을 위한 구조체
	*/
	typedef struct aes_key_st {
		UINT roundKey[60];
		SINT rounds;
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
	SINT AES_encrypt_init(const UCHAR *userKey, const SINT bits, AES_KEY *key);

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
	SINT AES_decrypt_init(const UCHAR *userKey, const SINT bits, AES_KEY *key);

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
	void AES_encrypt_block(const UCHAR *in, UCHAR *out, const AES_KEY *key);

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
	void AES_decrypt_block(const UCHAR *in, UCHAR *out, const AES_KEY *key);

	/*!
	* \brief
	* AES CBC 운영모드 알고리즘을 위한 구조체
	*/
	typedef struct aes_cbc_info_st {
		SINT				encrypt;
		UCHAR	ivec[AES_BLOCK_SIZE];
		AES_KEY			aes_key;
		UCHAR	cbc_buffer[AES_BLOCK_SIZE];
		SINT				buffer_length;
		UCHAR	cbc_last_block[AES_BLOCK_SIZE];
		SINT				last_block_flag;
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
	SINT AES_CBC_init(AES_CBC_INFO *info, SINT encrypt, SINT bits, UCHAR *user_key, UCHAR *iv);

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
	SINT AES_CBC_process(AES_CBC_INFO *info, UCHAR *in, SINT inLen, UCHAR *out, SINT *outLen);

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
	SINT AES_CBC_close(AES_CBC_INFO *info, UCHAR *out, SINT *outLen);

	/*!
	* \brief
	* AES_CBC_INFO 구조체 메모리 삭제 함수
	* \param info
	* 삭제시킬 AES_CBC_INFO 구조체
	* \returns
	* -# 1 : Success
	*/
	SINT AES_CBC_clear(AES_CBC_INFO *info);

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
	SINT AES_CBC(SINT enc, UCHAR *user_key, UINT key_len, UCHAR *iv, UCHAR *in, UINT len, UCHAR *out);




	typedef struct sha256_structure {
		ULLONG l1;
		UINT l2;
		ULONG data[8];
		UCHAR buf[SHA256_BLOCK_SIZE];
	} SHA256_INFO;
	typedef SHA256_INFO SHA224_INFO;

	typedef struct sha512_structure {
		ULLONG l1;
		UINT l2;
		ULLONG data[8];
		UCHAR buf[SHA512_BLOCK_SIZE];
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
	SINT SHA224_init(SHA224_INFO *sha224);

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
	SINT SHA224_update(SHA224_INFO *sha224, const UCHAR *data, SINT length);

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
	SINT SHA224_final(SHA224_INFO *sha224, UCHAR *md);

	/*!
	* \brief
	* SHA256_INFO 구조체 초기화 함수
	* \param sha256
	* 초기화 할 SHA256_INFO 구조체
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	SINT SHA256_init(SHA256_INFO *sha256);

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
	SINT SHA256_update(SHA256_INFO *sha256, const UCHAR *data, SINT length);

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
	SINT SHA256_final(SHA256_INFO *sha256, UCHAR *md);

	/*!
	* \brief
	* SHA384_INFO 구조체 초기화 함수
	* \param sha384
	* 초기화 할 SHA384_INFO 구조체
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	SINT SHA384_init(SHA384_INFO *sha384);

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
	SINT SHA384_update(SHA384_INFO *sha384, const UCHAR *data, SINT length);

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
	SINT SHA384_final(SHA384_INFO *sha384, UCHAR *md);

	/*!
	* \brief
	* SHA512_INFO 구조체 초기화 함수
	* \param sha512
	* 초기화 할 SHA512_INFO 구조체
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	SINT SHA512_init(SHA512_INFO *sha512);

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
	SINT SHA512_update(SHA512_INFO *sha512, const UCHAR *data, SINT length);

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
	SINT SHA512_final(SHA512_INFO *sha512, UCHAR *md);

	SINT sha224(UCHAR *input, SINT input_length, UCHAR *Digest);
	SINT sha256(UCHAR *input, SINT input_length, UCHAR *Digest);
	SINT sha384(UCHAR *input, SINT input_length, UCHAR *Digest);
	SINT sha512(UCHAR *input, SINT input_length, UCHAR *Digest);


#define HD_MAX_V_LEN_IN_BYTES					111
#define HD_MAX_C_LEN_IN_BYTES					111
	/*!
	* \brief
	* HASH DRBG(난수생성기) 알고리즘을 위한 구조체
	*/
	typedef struct hash_drbg_state{
		UCHAR	algo;
		UCHAR	V[HD_MAX_V_LEN_IN_BYTES];
		SINT				Vlen;
		UCHAR	C[HD_MAX_C_LEN_IN_BYTES];
		SINT				Clen;
		SINT				seedlen;
		ULLONG reseed_counter;
		SINT				security_strength;
		SINT				initialized_flag;
		UCHAR	prediction_flag;
		UCHAR	reseed_flag;
	} HASH_DRBG_STATE;

	SINT K_DRBG_GetEntropy(UCHAR* seed_entropy, SINT length);

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
	SINT HASH_DRBG_Random_Gen(UCHAR *output, SINT request_num_of_bits);


#define MAX_BN_BUF_LEN (400 + 1)
#define MAX_GFP_BUF_LEN (400 + 1)
#define MAX_GF2N_BUF_LEN (50 + 1)

	typedef struct _BN {
		SINT sig;
		ULONG *dat;
		SINT len;
	}BN;
	typedef BN GFP;
	
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

	typedef BN GFP_ECC_PRIVATE_KEY;
	typedef ULONG GFP_ECC_PRIVATE_KEY_BUF;
	typedef GFP_ECPT_AC GFP_ECC_PUBLIC_KEY;
	typedef GFP_ECPT_AC_BUF GFP_ECC_PUBLIC_KEY_BUF;

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
		SINT is_sign;
		SINT hash_alg;
	} ECDSA_INFO;

	SINT ECDSA_init(ECDSA_INFO *ec_kcdsa, SINT hash_alg);
	SINT ECDSA_setkey(ECDSA_INFO *ec_kcdsa, const UCHAR *qx, ULONG qx_len, const UCHAR *qy, ULONG qy_len, const UCHAR *d, ULONG d_len, SINT priv);
	SINT ECDSA_gen_key_pair(ECDSA_INFO *ec_kcdsa, UCHAR *qx, ULONG *qx_len, UCHAR *qy, ULONG *qy_len, UCHAR *d, ULONG *d_len);
	SINT ECDSA_gen_random_k(ECDSA_INFO *ec_kcdsa, SINT bits, UCHAR *k, ULONG *k_len);
	SINT ECDSA_set_random_k(ECDSA_INFO *ecdsa, const UCHAR *k, ULONG k_len);
	SINT ECDSA_sign(ECDSA_INFO *ecdsa, UCHAR *r, ULONG *rLen, UCHAR *s, ULONG *sLen, UCHAR *Msg, ULONG Msg_len);
	SINT ECDSA_verify(ECDSA_INFO *ecdsa, UCHAR *r, ULONG rLen, UCHAR *s, ULONG sLen, UCHAR *Msg, ULONG Msg_len);
	SINT ECDSA_clear(ECDSA_INFO *ecdsa);

	SINT ECDSA_generate_signature(SINT hash_alg, const UCHAR *d, ULONG d_len, UCHAR *msg, ULONG msg_len, UCHAR *r, ULONG *r_len, UCHAR *s, ULONG *s_len);
	SINT ECDSA_verify_signature(SINT hash_alg, const UCHAR *qx, ULONG qx_len, const UCHAR *qy, ULONG qy_len, UCHAR *msg, ULONG msg_len, UCHAR *r, ULONG r_len, UCHAR *s, ULONG s_len);

#ifdef __cplusplus
}
#endif

#endif
