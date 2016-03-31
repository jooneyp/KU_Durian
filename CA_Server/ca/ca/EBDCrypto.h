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
	* AES �˰����� ���� ����ü
	*/
	typedef struct aes_key_st {
		UINT roundKey[60];
		SINT rounds;
	} AES_KEY;

	/*!
	* \brief
	* AES_KEY ����ü �ʱ�ȭ �Լ� (��ȣȭ Ű ����)
	* \param userKey
	* ����� �Է� ��� Ű
	* \param bits
	* ����� �Է� Ű�� ���� (bits ����)
	* \param key
	* �ʱ�ȭ �� AES_KEY ����ü
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	SINT AES_encrypt_init(const UCHAR *userKey, const SINT bits, AES_KEY *key);

	/*!
	* \brief
	* AES_KEY ����ü �ʱ�ȭ �Լ� (��ȣȭ Ű ����)
	* \param userKey
	* ����� �Է� ��� Ű
	* \param bits
	* ����� �Է� Ű�� ���� (bits ����)
	* \param key
	* �ʱ�ȭ �� AES_KEY ����ü
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	SINT AES_decrypt_init(const UCHAR *userKey, const SINT bits, AES_KEY *key);

	/*!
	* \brief
	* AES 1 Block ��ȣȭ �Լ�
	* \param in
	* ����� �Է� �� (16 bytes)
	* \param out
	* ��ȣȭ�� ����� ����� ���� (16 bytes)
	* \param key
	* �ʱ�ȭ �Լ��� �ʱ�ȭ�� AES_KEY ����ü
	*/
	void AES_encrypt_block(const UCHAR *in, UCHAR *out, const AES_KEY *key);

	/*!
	* \brief
	* AES 1 Block ��ȣȭ �Լ�
	* \param in
	* ����� �Է� ��ȣ�� (16 bytes)
	* \param out
	* ��ȣȭ�� ����� ����� ���� (16 bytes)
	* \param key
	* �ʱ�ȭ �Լ��� �ʱ�ȭ�� AES_KEY ����ü
	*/
	void AES_decrypt_block(const UCHAR *in, UCHAR *out, const AES_KEY *key);

	/*!
	* \brief
	* AES CBC ���� �˰����� ���� ����ü
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
	* AES_CBC_INFO ����ü �ʱ�ȭ �Լ� (��/��ȣȭ Ű ����)
	* \param info
	* �ʱ�ȭ �� AES_CBC_INFO ����ü
	* \param encrypt
	* ���۸��, 1:Encryption, 0:Decryption
	* \param bits
	* ����� �Է� Ű�� ���� (bits ����)
	* \param user_key
	* ����� �Է� ��� Ű
	* \param iv
	* ����� �Է� IV
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	SINT AES_CBC_init(AES_CBC_INFO *info, SINT encrypt, SINT bits, UCHAR *user_key, UCHAR *iv);

	/*!
	* \brief
	* AES CBC ��/��ȣȭ �Լ�
	* \param info
	* �ʱ�ȭ�� AES_CBC_INFO ����ü
	* \param in
	* ����� �Է� ������
	* \param inLen
	* ����� �Է� �������� ���� (bytes ����)
	* \param out
	* ��/��ȣȭ�� ����� ����� ��� ����
	* \param outLen
	* ��� ������ ���̸� ������ ������, �Լ� ���� �� ��� ���ۿ� ����� ���̰� �Էµ�
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	SINT AES_CBC_process(AES_CBC_INFO *info, UCHAR *in, SINT inLen, UCHAR *out, SINT *outLen);

	/*!
	* \brief
	* AES CBC ��/��ȣȭ ������ �� �е�ó�� �Լ�
	* \param info
	* �ʱ�ȭ�� AES_CBC_INFO ����ü
	* \param out
	* ��/��ȣȭ�� ����� ����� ��� ����
	* \param outLen
	* ��� ������ ���̸� ������ ������, �Լ� ���� �� ��� ���ۿ� ����� ���̰� �Էµ�
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	SINT AES_CBC_close(AES_CBC_INFO *info, UCHAR *out, SINT *outLen);

	/*!
	* \brief
	* AES_CBC_INFO ����ü �޸� ���� �Լ�
	* \param info
	* ������ų AES_CBC_INFO ����ü
	* \returns
	* -# 1 : Success
	*/
	SINT AES_CBC_clear(AES_CBC_INFO *info);

	/*!
	* \brief
	* AES CBC ���� �Լ�
	* \param enc
	* ���۸��, 1:Encryption, 0:Decryption
	* \param user_key
	* ����� �Է� ��� Ű
	* \param key_len
	* ����� �Է� Ű�� ���� (bytes ����)
	* \param iv
	* ����� �Է� IV
	* \param in
	* ����� �Է� ������
	* \param len
	* ����� �Է� �������� ���� (bytes ����)
	* \param out
	* ��/��ȣȭ�� ����� ����� ��� ����
	* \returns
	* ��� ���ۿ� ����� �������� ���̰� �Էµ�(��/��ȣ���� ����)
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
	* SHA224_INFO ����ü �ʱ�ȭ �Լ�
	* \param sha224
	* �ʱ�ȭ �� SHA224_INFO ����ü
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	SINT SHA224_init(SHA224_INFO *sha224);

	/*!
	* \brief
	* SHA224 Digest �߰� ó�� �Լ�
	* \param sha224
	* �ʱ�ȭ�� SHA224_INFO ����ü
	* \param in
	* ����� �Է� ������
	* \param inLen
	* ����� �Է� �������� ���� (bytes ����)
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	SINT SHA224_update(SHA224_INFO *sha224, const UCHAR *data, SINT length);

	/*!
	* \brief
	* SHA224 Digest ���� �ؽ��� ��� �Լ�
	* \param sha224
	* �ʱ�ȭ�� SHA224_INFO ����ü
	* \param md
	* �ؽ����� ����� ��� ���� (28 bytes �̻� �Ҵ�Ǿ�� ��)
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	SINT SHA224_final(SHA224_INFO *sha224, UCHAR *md);

	/*!
	* \brief
	* SHA256_INFO ����ü �ʱ�ȭ �Լ�
	* \param sha256
	* �ʱ�ȭ �� SHA256_INFO ����ü
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	SINT SHA256_init(SHA256_INFO *sha256);

	/*!
	* \brief
	* SHA256 Digest �߰� ó�� �Լ�
	* \param sha256
	* �ʱ�ȭ�� SHA256_INFO ����ü
	* \param in
	* ����� �Է� ������
	* \param inLen
	* ����� �Է� �������� ���� (bytes ����)
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	SINT SHA256_update(SHA256_INFO *sha256, const UCHAR *data, SINT length);

	/*!
	* \brief
	* SHA256 Digest ���� �ؽ��� ��� �Լ�
	* \param sha256
	* �ʱ�ȭ�� SHA256_INFO ����ü
	* \param md
	* �ؽ����� ����� ��� ���� (32 bytes �̻� �Ҵ�Ǿ�� ��)
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	SINT SHA256_final(SHA256_INFO *sha256, UCHAR *md);

	/*!
	* \brief
	* SHA384_INFO ����ü �ʱ�ȭ �Լ�
	* \param sha384
	* �ʱ�ȭ �� SHA384_INFO ����ü
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	SINT SHA384_init(SHA384_INFO *sha384);

	/*!
	* \brief
	* SHA384 Digest �߰� ó�� �Լ�
	* \param sha384
	* �ʱ�ȭ�� SHA384_INFO ����ü
	* \param in
	* ����� �Է� ������
	* \param inLen
	* ����� �Է� �������� ���� (bytes ����)
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	SINT SHA384_update(SHA384_INFO *sha384, const UCHAR *data, SINT length);

	/*!
	* \brief
	* SHA384 Digest ���� �ؽ��� ��� �Լ�
	* \param sha384
	* �ʱ�ȭ�� SHA384_INFO ����ü
	* \param md
	* �ؽ����� ����� ��� ���� (48 bytes �̻� �Ҵ�Ǿ�� ��)
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	SINT SHA384_final(SHA384_INFO *sha384, UCHAR *md);

	/*!
	* \brief
	* SHA512_INFO ����ü �ʱ�ȭ �Լ�
	* \param sha512
	* �ʱ�ȭ �� SHA512_INFO ����ü
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	SINT SHA512_init(SHA512_INFO *sha512);

	/*!
	* \brief
	* SHA512 Digest �߰� ó�� �Լ�
	* \param sha512
	* �ʱ�ȭ�� SHA512_INFO ����ü
	* \param in
	* ����� �Է� ������
	* \param inLen
	* ����� �Է� �������� ���� (bytes ����)
	* \returns
	* -# 1 : Success
	* -# 0 : Fail
	*/
	SINT SHA512_update(SHA512_INFO *sha512, const UCHAR *data, SINT length);

	/*!
	* \brief
	* SHA512 Digest ���� �ؽ��� ��� �Լ�
	* \param sha512
	* �ʱ�ȭ�� SHA512_INFO ����ü
	* \param md
	* �ؽ����� ����� ��� ���� (64 bytes �̻� �Ҵ�Ǿ�� ��)
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
	* HASH DRBG(����������) �˰����� ���� ����ü
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
	* HASH DRBG ���� ���� �Լ�
	* \param output
	* ������ ������ ����� ����
	* \param request_num_of_bits
	* ������ ������ ���� (bits ����)
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
