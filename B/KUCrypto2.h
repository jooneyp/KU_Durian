#ifndef KU_CRYPTO2_H
#define KU_CRYPTO2_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define _MATHEMATICA_EXPRESS_

typedef unsigned long ULONG;
typedef ULONG* P_ULONG;
typedef signed long SLONG;
typedef SLONG* SLONG_PTR;
typedef unsigned short USHORT;
typedef USHORT* USHORT_PTR;
typedef signed short SSHORT;
typedef SSHORT* SSHORT_PTR;
typedef unsigned int UINT;
typedef UINT* P_UINT;
typedef signed int SINT;
typedef SINT* SINT_PTR;
typedef unsigned char UCHAR;
typedef UCHAR* UCHAR_PTR;
typedef char SCHAR;
typedef SCHAR* SCHAR_PTR;
typedef int BOOL;
typedef SINT HASH_INFO;

#define TRUE 1
#define FALSE 0

typedef unsigned char UINT8;
typedef unsigned short UINT16;
typedef unsigned int UINT32;
typedef unsigned long long UINT64;
typedef struct _OSTR{
	UCHAR *val;
	UINT len;
}OSTR;

#define BITMASK_LONG 0xffffffff
#define BITMASK_HIGHER_LONG 0xffff0000
#define BITMASK_LOWER_LONG 0x0000ffff
#define HIGHER_MSB_ONE 0x80000000
#define LOWER_MSB_ONE 0x00008000
#define HIGHER_LSB_ONE 0x00010000
#define LOWER_LSB_ONE 0x00000001
#define LOW_DEG_FIND 0x0000001f
#define LONG_BITS 32
#define HALF_LONG_BITS 16
#define MEM_MARGIN_8 8
#define MEM_MARGIN_1 1

#define HASH_SHA1	0x02000100
#define HASH_SHA224 0x02000200
#define HASH_SHA256 0x02000300
#define HASH_SHA384 0x02000400
#define HASH_SHA512 0x02000500
#define MAX_BN_BUF_LEN (400 + 1)
#define MAX_GFP_BUF_LEN (400 + 1)
#define MAX_GF2N_BUF_LEN (50 + 1)
#define MAX_HASH_BUF_BYTES (64 + 1)

void K_DRBG_GetSysRandom(UCHAR* seed_entropy, UINT length);

#define SHA1_HASH_BYTES 20
#define SHA1_BLOCK_BYTES 64
	typedef struct _SHA1_CTX {
		UINT32 state[5];
		UINT32 bits[2];
		UINT8 input[64];
	} SHA1_CTX;

	void SHA11_init(SHA1_CTX *C);
	void SHA11_update(SHA1_CTX *C, UINT8 *dat, UINT len);
	void SHA11_final(SHA1_CTX *C, UINT8 Hash[SHA1_HASH_BYTES]);
	void SHA1_at_once(UINT8 *M, UINT len, UINT8 Hash[SHA1_HASH_BYTES]);
	void SHA1_dgst_unit(UINT32 h[5], UINT8 b[SHA1_BLOCK_BYTES]);


#define SHA224_BLK_BYTE_LEN 64
#define SHA224_HASH_BYTE_LEN 28
#define SHA256_BLK_BYTE_LEN 64
#define SHA256_HASH_BYTE_LEN 32
#define SHA384_BLK_BYTE_LEN 128
#define SHA384_HASH_BYTE_LEN 48
#define SHA512_BLK_BYTE_LEN 128
#define SHA512_HASH_BYTE_LEN 64

	typedef struct {
		UINT32 state[8];
		UINT32 count[2];
		UINT8 buffer[64];
	} SHA256_CTX;
	typedef struct {
		UINT64 state[8];
		UINT64 count[2];
		UINT8 buffer[128];
	} SHA512_CTX;
	typedef SHA512_CTX SHA384_CTX;
	typedef SHA256_CTX SHA224_CTX;

	void SHA2241_init (SHA224_CTX *ctx);
	void SHA2241_update (SHA224_CTX *ctx, UINT8 *input, UINT32 inputLength);
	void SHA2241_final (SHA224_CTX *ctx, UINT8 *hash);
	void SHA224_hash (UINT8 *input, UINT32 inputLength, UINT8 *hash);
	void SHA224_hmac (UINT8 *M, UINT Mlen, UINT8 *key, UINT keylen, UINT8 MAC[SHA224_HASH_BYTE_LEN]);

	void SHA2561_init (SHA256_CTX *ctx);
	void SHA2561_update (SHA256_CTX *ctx, UINT8 *input, UINT32 inputLength);
	void SHA2561_final (SHA256_CTX *ctx, UINT8 *hash);
	void SHA256_hash (UINT8 *input, UINT32 inputLength, UINT8 *hash);
	void SHA256_hmac (UINT8 *M, UINT Mlen, UINT8 *key, UINT keylen, UINT8 MAC[SHA256_HASH_BYTE_LEN]);

	void SHA3841_init (SHA384_CTX *ctx);
	void SHA3841_update (SHA384_CTX *ctx, UINT8 *input, UINT32 inputLength);
	void SHA3841_final (SHA384_CTX *ctx, UINT8 *hash);
	void SHA384_hash (UINT8 *input, UINT32 inputLength, UINT8 *hash);
	void SHA384_hmac (UINT8 *M, UINT Mlen, UINT8 *key, UINT keylen, UINT8 MAC[SHA384_HASH_BYTE_LEN]);

	void SHA5121_init (SHA512_CTX *ctx);
	void SHA5121_update (SHA512_CTX *ctx, UINT8 *input, UINT32 inputLength);
	void SHA5121_final (SHA512_CTX *ctx, UINT8 *hash);
	void SHA5121_hash (UINT8 *input, UINT32 inputLength, UINT8 *hash);
	void SHA512_hmac (UINT8 *M, UINT Mlen, UINT8 *key, UINT keylen, UINT8 MAC[SHA512_HASH_BYTE_LEN]);


typedef struct _BN {
	SINT sig;
	ULONG *dat;
	SINT len;
}BN;
typedef BN GFP;
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
#define MPCONST_POS_SIG 1
#define MPCONST_NEG_SIG -1
#define MPCONST_ZERO_SIG 0
#define PRIME_TEST_NUM 50
#define KARA_2048_WORD_LEN 64
#define KARA_3072_WORD_LEN 96
#define KARA_SIZE_3072 3072
#define KARA_SIZE_2048 2048
#define KARA_SIZE_1024 1024
#define KARA_SIZE_512 512
#define WORD_SIZE 32

static const char bits_to_index_low[256]={
	0,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
	5,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
	6,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
	5,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
	7,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
	5,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
	6,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
	5,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
};
static char bits_to_index[256]={
	0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
	6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
	7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
	7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
	8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
	8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
	8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
	8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
};
#define MAC_NONZERO_BITS_NUM_ULONG(a, i) \
{ \
	if((a) & 0xffff0000L){ \
	if((a) & 0xff000000L) \
	(i) = bits_to_index[(a)>>24L]+24; \
else \
	(i) = bits_to_index[(a)>>16L]+16; \
	}else{ \
	if((a) & 0xff00L) \
	(i) = bits_to_index[(a)>>8]+8; \
else \
	(i) = bits_to_index[(a) ]; \
	} \
	}
#define MAC_NONZERO_BYTES_NUM(a) ((BN_nonzero_bits_num((a))+7)>>3)
#define MAC_BN_INIT(x,y,s)\
{\
	(x).dat = (y); \
	(x).len = 0; \
	(x).sig = (s); \
	}
#define MAC_BN_INIT_MEM_CLR(x,y,s)\
{\
	(x).dat = (y); \
	(x).len = 0; \
	(x).sig = (s); \
	memset(y,0,sizeof(y));\
	}
#define MAC_CLR_UPPER_ZEROBYTES(x) \
{ \
	ULONG *__pl; \
	for(__pl= &((x).dat[(x).len-1]); (x).len > 0; (x).len--) \
	if(*(__pl--)) break; \
	}
#define MAC_DIV2EXP(a,e) ((a)>>(e))
#define MAC_MULT2EXP(a,e) ((a)<<(e))
#define MAC_SWAP(a,b,t) { (t) = (a);(a) = (b);(b) = (t); }
#define MAC_MAX(x,y) (((x)>=(y))? (x):(y))
#define MAC_IS_BN_ZERO(x) ((x).len == 0 || (((x).len <= 1) && ((x).dat[0] == 0)))
#define MAC_IS_BN_ONE(x) ((x).len == 1 && (x).dat[0] == 1)
#define MAC_IS_POSITIVE_INTEGER(x) ((x).sig == MPCONST_POS_SIG)
#define MAC_IS_ODD_INTEGER(x) (((x).dat[0]&0x1) == 1)
#define MAC_BIT_IS_SET(x,i) (( ((x).dat[(i)/LONG_BITS] & ((ULONG)1<<((i)%LONG_BITS))) > 0 ) ? 1 : 0)
#define MAC_MAKE_ZERO(x) { (x).sig = MPCONST_ZERO_SIG;(x).len = 0;(x).dat[0]= 0; }
#define MAC_MAKE_ONE(x) { (x).sig = MPCONST_POS_SIG;(x).len = 1;(x).dat[0]= 1; }
#define MAC_MAKE_ULONG2BN(u,s,x) { (x).sig = (s);(x).len = 1;(x).dat[0]= u; }
#define MAC_LW(x) ((x) & BITMASK_LOWER_LONG)
#define MAC_HW(x) (((x) & BITMASK_HIGHER_LONG)>>HALF_LONG_BITS)
#define BN_ULONG_ABS(x) (x>=0?(x):(-(x)))

	SINT BN_copy(BN *dest, BN *src);
	SINT BN_bit_is_set(BN *a, ULONG nth);
	SINT BN_shl_1bit(BN *b, BN *a);
	SINT BN_shr_1bit(BN *b, BN *a);
	SINT BN_shl(BN *r, BN *a, SINT n);
	SINT BN_shr(BN *r, BN *a, SINT n);
	SINT BN_nonzero_bits_num(BN *a);
	SINT BN_LOW_zero_bits_num(BN *a);
	SINT BN_abs_comp(BN *a, BN *b);
	SINT BN_comp(BN *a, BN *b);
	SINT BN_add_ULONG(BN *c, BN *a,	ULONG b);
	SINT BN_asym_add(BN *c, BN *a, BN *b);
	SINT BN_sub_ULONG(BN *r, BN *a, ULONG b);
	SINT BN_asym_sub(BN *a, BN *b, BN *c);
	SINT BN_add(BN *c, BN *a, BN *b);
	SINT BN_sub(BN *c, BN *a, BN *b);
	SINT BN_mult_ULONG(BN *c, BN *a, ULONG b);
	SINT BN_mult_ULONG_add(BN *c, BN *a, ULONG b);
	SINT BN_plain_mul(BN *c, BN *a, BN *b);
	SINT BN_kar_mul(BN *c, BN *a, BN *b);
	SINT BN_plain_sqr(BN *b, BN *a);
	SINT BN_kar_sqr(BN *c, BN *a);
	ULONG BN_ULONG_div(ULONG h, ULONG l, ULONG d);
	SINT BN_div(BN *c, BN *d, BN *a, BN *b);
	SINT BN_kar_mul_2048(BN *c, BN *a, BN *b);
	SINT BN_kar_mul_3072(BN *c, BN *a, BN *b);

#define BN_mul(c,a,b) BN_plain_mul(c,a,b)
#define BN_sqr(c,a) BN_plain_sqr(c,a)

	SINT BN_mod(BN *r, BN *a, BN *m);
	ULON GBN_mod_half_ULONG(BN *a, ULONG l);
	SINT BN_add_mod(BN *r, BN *a, BN *b, BN *m);
	SINT BN_sub_mod(BN *r, BN *a, BN *b, BN *m);
	SINT BN_mul_mod(BN *r, BN *a, BN *b, BN *m);
	SINT BN_sqr_mod(BN *r, BN *a, BN *m);
	SINT BN_mul_inv_mod(BN *b, BN *a, BN *m);
	SINT BN_l2r_pow_mod(BN *r, BN *x ,BN *e, BN *m);
	ULONG BN_ULONG_mul_inv_mod_2e(ULONG x);
	SINT BN_assign_MONT_BUF(MP_MONT_CTX *mont_ctx, MP_MONT_BUF *mont_buf);
	SINT BN_mont_init_mod(MP_MONT_CTX *mont_ctx, BN *mod);
	SINT BN_mont_red_mod(BN *a, MP_MONT_CTX *mont_ctx);
	SINT BN_mont_mul_mod(BN *a, BN *x, BN *y, MP_MONT_CTX *mont_ctx);
	SINT BN_mont_pow_mod(BN *r, BN *x, BN *e, MP_MONT_CTX *mont_ctx);
	SINT BN_mont_sw_pow_mod(BN *r,BN *x, BN *e, MP_MONT_CTX *ms);
	SINT BN_pow_mod(BN *r, BN *x, BN *e, BN *m);
	SINT BN_euclid_gcd(BN *c, BN *a, BN *b);
	SINT BN_gcd(BN *c, BN *a, BN *b);
	SINT BN_MR_prime_test(BN *n, SINT icnt);
	SINT BN_gen_prime(BN *a, BN_X9_PRNG_CTX *prng_ctx, BN *b, BN *c, BN *d);
	SINT BN_X9_31_PRNG_CTX_init(BN_X9_PRNG_CTX *prng_ctx, BN_X9_PRNG_BUF *prng_buf);
	SINT BN_X9_31_PRNG(BN *p, BN_X9_PRNG_CTX *prng_ctx, SINT l);
	SINT BN2OSTR(UCHAR *hstr, ULONG *hstrlen, BN *a);
	SINT OSTR2BN(BN *a, UCHAR *hstr, ULONG hstrlen);
	SINT BN_ASCII2OSTR(UCHAR *bstr, ULONG *bstrlen, SCHAR *ascii);
	SINT STR2ULONG(UCHAR *str, ULONG* data);

#define InbySTR(qstr,buf,a)\
	{\
	ULONG __alen;\
	memset(buf,0,strlen(qstr));\
	BN_ASCII2OSTR((buf),&__alen,qstr);\
	OSTR2BN(&(a),(buf),__alen);\
	}\
	
	
	SINT GFP_add(GFP *r, GFP *a, GFP *b, GFP *p);
	SINT GFP_sub(GFP *r, GFP *a, GFP *b, GFP *p);
	SINT GFP_mul(GFP *r, GFP *a, GFP *b, GFP *p);
	SINT GFP_mul_inv(GFP *r, GFP *a,GFP *p);
	SINT GFP_sqr(GFP *r, GFP *a, GFP *p);

#define GFP_bit_is_set BN_bit_is_set
#define GFP_shl_1bit BN_shl_1bit
#define GFP_shr_1bit BN_shr_1bit
#define GFP_shl BN_shl
#define GFP_shr BN_shr
#define GFP_copy BN_copy
#define GFP_comp BN_comp
#define MAC_GFP_INIT MAC_BN_INIT
#define MAC_GFP_INIT_MEM_CLR MAC_GFP_INIT_MEM_CLR
#define MAC_MAKE_ULONG2GFP MAC_MAKE_ULONG2BN	
	

	typedef struct _GFP_ECPT_AC {
		BOOL is_O;
		GFP x;
		GFP y;
	}GFP_ECPT_AC;
	typedef struct _GFP_ECPT_AC_BUF {
		ULONG x_dat[MAX_GFP_BUF_LEN];
		ULONG y_dat[MAX_GFP_BUF_LEN];
	}GFP_ECPT_AC_BUF;
	typedef struct _GFP_EC_CTX{
		GFP prime;
		GFP a;
		GFP b;
		BN ord;
		BN cofactor;
		GFP_ECPT_AC base;
	}GFP_EC_CTX;
	typedef struct _GFP_EC_CTX_BUF{
		ULONG prime_buf[MAX_GFP_BUF_LEN];
		ULONG a_buf[MAX_GFP_BUF_LEN];
		ULONG b_buf[MAX_GFP_BUF_LEN];
		ULONG ord_buf[MAX_GF2N_BUF_LEN];
		ULONG cof_buf[MAX_GF2N_BUF_LEN];
		ULONG base_x_buf[MAX_GF2N_BUF_LEN];
		ULONG base_y_buf[MAX_GF2N_BUF_LEN];
	}GFP_EC_CTX_BUF;
	void GFP_EC_CTX_init(GFP_EC_CTX *ec_ctx, GFP_EC_CTX_BUF *ec_ctx_buf);
	void GFP_ECPT_AC_init(GFP_ECPT_AC *ecpt, GFP_ECPT_AC_BUF *ecptbuf);
	SINT GFP_EC_IsPT_on(GFP_EC_CTX *ec_ctx, GFP_ECPT_AC *ecpt);
	SINT GFP_ECPT_AC_add(GFP_ECPT_AC *R, GFP_EC_CTX *ec_ctx,GFP_ECPT_AC *P, GFP_ECPT_AC *Q);
	SINT GFP_ECPT_AC_dbl(GFP_ECPT_AC *R, GFP_EC_CTX *ec_ctx, GFP_ECPT_AC *P);
	SINT GFP_ECPT_AC_smul(GFP_ECPT_AC *R, GFP_EC_CTX *ec_ctx, BN *n, GFP_ECPT_AC *P);
	
	
#define ECDSA_SIGN			1
#define ECDSA_VERIFY		0

#define ECP224			0x01000001
#define ECP256			0x01000002

#define SHA1			0x02000100
#define SHA224			0x02000200
#define SHA256			0x02000300
#define SHA384			0x02000400
#define SHA512			0x02000500

	typedef BN GFP_ECC_PRIVATE_KEY;
	typedef ULONG GFP_ECC_PRIVATE_KEY_BUF;
	typedef GFP_ECPT_AC GFP_ECC_PUBLIC_KEY;
	typedef GFP_ECPT_AC_BUF GFP_ECC_PUBLIC_KEY_BUF;

	typedef struct ecdsa_structure	{
		GFP_EC_CTX ec_ctx;
		GFP_EC_CTX_BUF ec_ctx_buf;
		GFP_ECC_PUBLIC_KEY puk;
		GFP_ECPT_AC_BUF puk_buf;
		GFP_ECC_PRIVATE_KEY prk;
		GFP_ECC_PRIVATE_KEY_BUF prk_dat[MAX_GFP_BUF_LEN];
		UCHAR tmp_cdat[MAX_GFP_BUF_LEN<<2];
		BN_X9_PRNG_CTX randctx;
		BN_X9_PRNG_BUF randbuf;
		BN k;
		ULONG k_dat[MAX_GFP_BUF_LEN];
		int is_sign;
		int hash_alg;
	} ECDSA_INFO;

	int ECDSA_init(ECDSA_INFO *ecdsa, int hash_alg);
	int ECDSA_gen_key_pair(ECDSA_INFO *ecdsa, UCHAR *qx, ULONG *qx_len, UCHAR *qy, ULONG *qy_len, UCHAR *d, ULONG *d_len);
	int ECDSA_setkey(ECDSA_INFO *ecdsa, const UCHAR *qx, ULONG qx_len, const UCHAR *qy, ULONG qy_len, const UCHAR *d, ULONG d_len, int priv);
	int ECDSA_gen_random_k(ECDSA_INFO *ecdsa, int bits, UCHAR *k, ULONG *k_len);
	int ECDSA_set_random_k(ECDSA_INFO *ecdsa, const UCHAR *k, ULONG k_len);
	int EC_KCDSA_sign(ECDSA_INFO *ecdsa, UCHAR *msg, ULONG msg_len, UCHAR *r, ULONG *rLen, UCHAR *s, ULONG *sLen);
	int EC_KCDSA_verify(ECDSA_INFO *ecdsa, UCHAR *msg, ULONG msg_len, UCHAR *r, ULONG rLen, UCHAR *s, ULONG sLen);
	int ECDSA_clear(ECDSA_INFO *ecdsa);

#ifdef __cplusplus
}
#endif

#endif
