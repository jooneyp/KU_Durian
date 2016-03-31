#include "EBDerror.h"
#include "EBDCrypto.h"

#define MPCONST_POS_SIG 1
#define MPCONST_NEG_SIG -1
#define MPCONST_ZERO_SIG 0

#define TRUE 1
#define FALSE 0

void GFP_ECPT_AC_init(GFP_ECPT_AC *ecpt, GFP_ECPT_AC_BUF *ecptbuf);
void GFP_EC_CTX_init(GFP_EC_CTX *ec_ctx, GFP_EC_CTX_BUF *ec_ctx_buf);
SINT BN_ASCII2OSTR(UCHAR *bstr, ULONG *bstrlen, SCHAR *ascii);
SINT OSTR2BN(BN *a, UCHAR *hstr, ULONG hstrlen);
SINT BN_comp(BN *a, BN *b);
SINT GFP_ECPT_AC_smul(GFP_ECPT_AC *R, GFP_EC_CTX *ec_ctx, BN *n, GFP_ECPT_AC *P);
SINT BN_sqr_mod(BN *r, BN *a, BN *m);
SINT BN_mul_mod(BN *r, BN *a, BN *b, BN *m);
SINT BN_add_mod(BN *r, BN *a, BN *b, BN *m);
SINT BN_gen_rand(BN *p, SINT bits_length);
SINT BN_copy(BN *dest, BN *src);
SINT BN2OSTR(UCHAR *hstr, ULONG *hstrlen, BN *a);
SINT BN_mod(BN *r, BN *a, BN *m);
SINT BN_mul_inv_mod(BN *b, BN *a, BN *m);
SINT GFP_EC_IsPT_on(GFP_EC_CTX *ec_ctx, GFP_ECPT_AC *ecpt);
SINT GFP_ECPT_AC_add(GFP_ECPT_AC *R, GFP_EC_CTX *ec_ctx, GFP_ECPT_AC *P, GFP_ECPT_AC *Q);
SINT PRNG_CTX_init(BN_X9_PRNG_CTX *prng_ctx, BN_X9_PRNG_BUF *prng_buf);
SINT PRNG_generate(BN *p, BN_X9_PRNG_CTX *prng_ctx, SINT l);


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

#define MAC_IS_BN_ZERO(x) ((x).len == 0 || (((x).len <= 1) && ((x).dat[0] == 0)))

#define InbySTR(qstr,buf,a)\
	{\
	ULONG __alen;\
	memset(buf,0,strlen(qstr));\
	BN_ASCII2OSTR((buf),&__alen,qstr);\
	OSTR2BN(&(a),(buf),__alen);\
	}\



void GFP_ECC_PUBLIC_KEY_init(GFP_ECC_PUBLIC_KEY *puk, GFP_ECC_PUBLIC_KEY_BUF *puk_buf)
{
	GFP_ECPT_AC_init(puk, puk_buf);
}

void GFP_ECC_PRIVATE_KEY_init(GFP_ECC_PRIVATE_KEY *prk, GFP_ECC_PRIVATE_KEY_BUF *prk_buf)
{
	prk->dat = prk_buf;
	prk->sig = MPCONST_POS_SIG;
	prk->len = 0;
}

SINT ECDSA_init(ECDSA_INFO *ecdsa, SINT hash_alg)
{
	if( !ecdsa || ((hash_alg != SHA224) && (hash_alg != SHA256) && (hash_alg != SHA384) && (hash_alg != SHA512)) )
		return ERR_INVALID_INPUT;

	GFP_EC_CTX_init(&(ecdsa->ec_ctx), &(ecdsa->ec_ctx_buf));
	GFP_ECC_PRIVATE_KEY_init(&(ecdsa->prk), ecdsa->prk_dat);
	GFP_ECC_PUBLIC_KEY_init(&(ecdsa->puk), &(ecdsa->puk_buf));

	PRNG_CTX_init(&(ecdsa->randctx), &(ecdsa->randbuf));
	MAC_BN_INIT(ecdsa->k, ecdsa->k_dat, MPCONST_POS_SIG);

	InbySTR("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", ecdsa->tmp_cdat, ecdsa->ec_ctx.prime);
	InbySTR("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", ecdsa->tmp_cdat, ecdsa->ec_ctx.ord);
	InbySTR("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", ecdsa->tmp_cdat, ecdsa->ec_ctx.a);
	InbySTR("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", ecdsa->tmp_cdat, ecdsa->ec_ctx.b);
	InbySTR("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", ecdsa->tmp_cdat, ecdsa->ec_ctx.base.x);
	InbySTR("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", ecdsa->tmp_cdat, ecdsa->ec_ctx.base.y);
	InbySTR("01", ecdsa->tmp_cdat, ecdsa->ec_ctx.cofactor);

	ecdsa->hash_alg = hash_alg;

	return EBD_CRYPTO_SUCCESS;
}

SINT ECDSA_setkey(ECDSA_INFO *ecdsa, const UCHAR *qx, ULONG qx_len, const UCHAR *qy, ULONG qy_len, const UCHAR *d, ULONG d_len, SINT priv)
{
	GFP_ECPT_AC temp;
	GFP_ECPT_AC_BUF temp_buf;
	GFP_ECC_PUBLIC_KEY puk;
	GFP_ECPT_AC_BUF puk_buf;
	BN tmp1, tmp2;
	ULONG tmp1_dat[MAX_GFP_BUF_LEN];
	ULONG tmp2_dat[MAX_GFP_BUF_LEN];

	GFP_ECPT_AC_init(&temp, &temp_buf);
	GFP_ECC_PUBLIC_KEY_init(&puk, &puk_buf);

	if ((d != NULL) && (d_len == 32) && priv)
	{
		{
			BN temprand;
			ULONG temprand_dat[MAX_GFP_BUF_LEN];
			MAC_BN_INIT(temprand, temprand_dat, MPCONST_POS_SIG);

			OSTR2BN(&temprand, (UCHAR *)d, d_len);

			if (BN_comp(&temprand, &(ecdsa->ec_ctx.ord)) >= 0)
				return ERR_INVALID_PRIVATE_KEY;

			GFP_ECPT_AC_smul(&puk, &(ecdsa->ec_ctx), &temprand, &(ecdsa->ec_ctx.base)); //public key generation
		}
		//pubkey test
		if ((BN_comp(&(puk.x), &(ecdsa->ec_ctx.prime)) >= 0) || (BN_comp(&(puk.y), &(ecdsa->ec_ctx.prime)) >= 0))
			return ERR_PUBLIC_KEY_VALID_TEST_FAIL;

		MAC_BN_INIT(tmp1, tmp1_dat, MPCONST_POS_SIG);
		MAC_BN_INIT(tmp2, tmp2_dat, MPCONST_POS_SIG);

		BN_sqr_mod(&tmp2, &(puk.x), &(ecdsa->ec_ctx.prime)); //tmp2 = x^2
		BN_mul_mod(&tmp1, &tmp2, &(puk.x), &(ecdsa->ec_ctx.prime)); //tmp1 = x^3
		BN_mul_mod(&tmp2, &(ecdsa->ec_ctx.a), &(puk.x), &(ecdsa->ec_ctx.prime)); //tmp2 = a*x
		BN_add_mod(&tmp1, &tmp1, &tmp2, &(ecdsa->ec_ctx.prime)); // tmp1 = x^3 + a*x
		BN_add_mod(&tmp1, &tmp1, &(ecdsa->ec_ctx.b), &(ecdsa->ec_ctx.prime)); //tmp1 = x^3 + a*x + b
		BN_sqr_mod(&tmp2, &(puk.y), &(ecdsa->ec_ctx.prime)); //tmp2 = y^2

		if (BN_comp(&tmp1, &tmp2) != 0)
			return ERR_PUBLIC_KEY_VALID_TEST_FAIL;

		GFP_ECPT_AC_smul(&temp, &(ecdsa->ec_ctx), &(ecdsa->ec_ctx.ord), &puk);

		if (temp.is_O == TRUE)
		{
			OSTR2BN(&(ecdsa->prk), (UCHAR *)d, d_len);
			GFP_ECPT_AC_smul(&(ecdsa->puk), &(ecdsa->ec_ctx), &(ecdsa->prk), &(ecdsa->ec_ctx.base));
			ecdsa->is_sign = priv;

			return EBD_CRYPTO_SUCCESS;
		}
		else
			return EBD_CRYPTO_FAIL;
	}
	else
	{
		if ((qx == NULL) || (qy == NULL) || priv)
			return ERR_INVALID_INPUT;

		//public key valid test
		OSTR2BN(&(puk.x), (UCHAR *)qx, qx_len);
		OSTR2BN(&(puk.y), (UCHAR *)qy, qy_len);

		if ((BN_comp(&(puk.x), &(ecdsa->ec_ctx.prime)) >= 0) || (BN_comp(&(puk.y), &(ecdsa->ec_ctx.prime)) >= 0))
			return ERR_INVALID_PUBLIC_KEY;

		MAC_BN_INIT(tmp1, tmp1_dat, MPCONST_POS_SIG);
		MAC_BN_INIT(tmp2, tmp2_dat, MPCONST_POS_SIG);

		BN_sqr_mod(&tmp2, &(puk.x), &(ecdsa->ec_ctx.prime)); //tmp2 = x^2
		BN_mul_mod(&tmp1, &tmp2, &(puk.x), &(ecdsa->ec_ctx.prime)); //tmp1 = x^3
		BN_mul_mod(&tmp2, &(ecdsa->ec_ctx.a), &(puk.x), &(ecdsa->ec_ctx.prime)); //tmp2 = a*x
		BN_add_mod(&tmp1, &tmp1, &tmp2, &(ecdsa->ec_ctx.prime)); // tmp1 = x^3 + a*x
		BN_add_mod(&tmp1, &tmp1, &(ecdsa->ec_ctx.b), &(ecdsa->ec_ctx.prime)); //tmp1 = x^3 + a*x + b
		BN_sqr_mod(&tmp2, &(puk.y), &(ecdsa->ec_ctx.prime)); //tmp2 = y^2

		if (BN_comp(&tmp1, &tmp2) != 0)
			return ERR_PUBLIC_KEY_VALID_TEST_FAIL;

		GFP_ECPT_AC_smul(&temp, &(ecdsa->ec_ctx), &(ecdsa->ec_ctx.ord), &puk);

		if (temp.is_O == TRUE)
		{
			OSTR2BN(&(ecdsa->puk.x), (UCHAR *)qx, qx_len);
			OSTR2BN(&(ecdsa->puk.y), (UCHAR *)qy, qy_len);
			ecdsa->is_sign = priv;

			return EBD_CRYPTO_SUCCESS;
		}
		else
			return EBD_CRYPTO_FAIL;
	}
}

SINT ECDSA_gen_key_pair(ECDSA_INFO *ecdsa, UCHAR *qx, ULONG *qx_len, UCHAR *qy, ULONG *qy_len, UCHAR *d, ULONG *d_len)
{
	GFP_ECC_PUBLIC_KEY puk;
	GFP_ECPT_AC_BUF puk_buf;

	BN temprand;
	ULONG temprand_dat[MAX_GFP_BUF_LEN];
	SINT bits;

	BN tmp1, tmp2;
	ULONG tmp1_dat[MAX_GFP_BUF_LEN];
	ULONG tmp2_dat[MAX_GFP_BUF_LEN];

	GFP_ECPT_AC temp;
	GFP_ECPT_AC_BUF temp_buf;

	if(!ecdsa || !qx || !qx_len || !qy || !qy_len || !d || !d_len)
		return ERR_INVALID_INPUT;

	GFP_ECPT_AC_init(&temp, &temp_buf);
	GFP_ECC_PUBLIC_KEY_init(&puk, &puk_buf);
	MAC_BN_INIT(temprand, temprand_dat, MPCONST_POS_SIG);
	MAC_BN_INIT(tmp1, tmp1_dat, MPCONST_POS_SIG);
	MAC_BN_INIT(tmp2, tmp2_dat, MPCONST_POS_SIG);

	bits = 256;

	while (1)
	{
		//if (!BN_gen_rand(&temprand, bits))
		if(!PRNG_generate(&temprand, &(ecdsa->randctx), bits))
		{
			if (BN_comp(&temprand, &(ecdsa->ec_ctx.ord)) >= 0)
				continue;

			GFP_ECPT_AC_smul(&puk, &(ecdsa->ec_ctx), &temprand, &(ecdsa->ec_ctx.base)); //public key generation

			//pubkey test
			if ((BN_comp(&(puk.x), &(ecdsa->ec_ctx.prime)) >= 0) || (BN_comp(&(puk.y), &(ecdsa->ec_ctx.prime)) >= 0))
				continue;

			BN_sqr_mod(&tmp2, &(puk.x), &(ecdsa->ec_ctx.prime)); //tmp2 = x^2
			BN_mul_mod(&tmp1, &tmp2, &(puk.x), &(ecdsa->ec_ctx.prime)); //tmp1 = x^3
			BN_mul_mod(&tmp2, &(ecdsa->ec_ctx.a), &(puk.x), &(ecdsa->ec_ctx.prime)); //tmp2 = a*x
			BN_add_mod(&tmp1, &tmp1, &tmp2, &(ecdsa->ec_ctx.prime)); // tmp1 = x^3 + a*x
			BN_add_mod(&tmp1, &tmp1, &(ecdsa->ec_ctx.b), &(ecdsa->ec_ctx.prime)); //tmp1 = x^3 + a*x + b
			BN_sqr_mod(&tmp2, &(puk.y), &(ecdsa->ec_ctx.prime)); //tmp2 = y^2

			if (BN_comp(&tmp1, &tmp2) != 0)
				continue;

			GFP_ECPT_AC_smul(&temp, &(ecdsa->ec_ctx), &(ecdsa->ec_ctx.ord), &puk);

			if (temp.is_O == TRUE)
			{
				break;
			}
			else
				continue;
		}

	}

	BN_copy(&ecdsa->prk, &temprand);
	GFP_ECPT_AC_smul(&(ecdsa->puk), &(ecdsa->ec_ctx), &temprand, &(ecdsa->ec_ctx.base));

	BN2OSTR(d, d_len, &temprand);
	BN2OSTR(qx, qx_len, &(puk.x));
	BN2OSTR(qy, qy_len, &(puk.y));

	return EBD_CRYPTO_SUCCESS;
}

SINT ECDSA_gen_random_k(ECDSA_INFO *ecdsa, SINT bits, UCHAR *k, ULONG *k_len)
{
	BN temprand;
	ULONG temprand_dat[MAX_GFP_BUF_LEN];
	MAC_BN_INIT(temprand, temprand_dat, MPCONST_POS_SIG);

	if(!ecdsa || !k || !k_len || (bits <= 0))
		return ERR_INVALID_INPUT;

	while (1)
	{
		//if (!BN_gen_rand(&temprand, bits))
		if(!PRNG_generate(&temprand, &(ecdsa->randctx), bits))
		{
			if (BN_comp(&temprand, &(ecdsa->ec_ctx.ord)) >= 0)
				continue;
			else
				break;
		}
	}

	BN_copy(&(ecdsa->k), &temprand);
	*k_len = bits / 8;

	return EBD_CRYPTO_SUCCESS;
}

SINT ECDSA_set_random_k(ECDSA_INFO *ecdsa, const UCHAR *k, ULONG k_len)
{
	if(!ecdsa || !k || (k_len <= 0))
		return ERR_INVALID_INPUT;

	OSTR2BN(&(ecdsa->k), (UCHAR *)k, k_len);

	return EBD_CRYPTO_SUCCESS;
}

SINT ECDSA_sign(ECDSA_INFO *ecdsa, UCHAR *r, ULONG *rLen, UCHAR *s, ULONG *sLen, UCHAR *Msg, ULONG Msg_len)
{
	BN t1, t2, t3, t4, r_temp;
	SINT HASH_OUTPUT_BYTE_LEN;
	ULONG t1_dat[MAX_GFP_BUF_LEN], t2_dat[MAX_GFP_BUF_LEN], t3_dat[MAX_GFP_BUF_LEN], t4_dat[MAX_GFP_BUF_LEN], r_temp_dat[MAX_GFP_BUF_LEN];
	GFP_ECPT_AC Q;
	GFP_ECPT_AC_BUF Q_buf;
	UCHAR md_HASH[64] = { 0, };

	if(!ecdsa || !r || !rLen || !s || !sLen || !Msg)
		return ERR_INVALID_INPUT;

	MAC_BN_INIT_MEM_CLR(t1, t1_dat, MPCONST_POS_SIG);
	MAC_BN_INIT_MEM_CLR(t2, t2_dat, MPCONST_POS_SIG);
	MAC_BN_INIT_MEM_CLR(t3, t3_dat, MPCONST_POS_SIG);
	MAC_BN_INIT_MEM_CLR(t4, t4_dat, MPCONST_POS_SIG);
	MAC_BN_INIT_MEM_CLR(r_temp, r_temp_dat, MPCONST_POS_SIG);
	GFP_ECPT_AC_init(&Q, &Q_buf);
	switch (ecdsa->hash_alg) {
		case SHA224: /* SHA224 */
			sha224(Msg, Msg_len, md_HASH);
			HASH_OUTPUT_BYTE_LEN = 28;
			break;
		case SHA256: /* SHA256 */
			sha256(Msg, Msg_len, md_HASH);
			HASH_OUTPUT_BYTE_LEN = 32;
			break;
		case SHA384:/* SHA384 */
			sha384(Msg, Msg_len, md_HASH);
			HASH_OUTPUT_BYTE_LEN = 32;
			break;
		case SHA512:/* SHA512 */
			sha512(Msg, Msg_len, md_HASH);
			HASH_OUTPUT_BYTE_LEN = 32;
			break;
		default:
			return ERR_INVALID_ALGORITHM_ID;
	}

	GFP_ECPT_AC_smul(&Q, &(ecdsa->ec_ctx), &(ecdsa->k), &(ecdsa->ec_ctx.base)); //Q = kG
	BN_mod(&r_temp, &Q.x, &(ecdsa->ec_ctx.ord)); // r_temp = Q_x (mod ord)
	MAC_CLR_UPPER_ZEROBYTES(r_temp); // r_temp ���� ����

	if (MAC_IS_BN_ZERO(r_temp) == TRUE) {
		//printf("EC_KCDSA_SIGN FAILED(���ο� ���� �ʿ�)");
		return ERR_NEW_RANDOM_NEEDED; // r�� ���� 0 �� ��� ���� ���ο� ���� k �ʿ�
	}

	if (r_temp.len < ecdsa->ec_ctx.ord.len)
		r_temp.dat[r_temp.len] = 0x0;

	BN2OSTR(r, rLen, &r_temp); // ���� r ����
	BN_mul_mod(&t3, &(ecdsa->prk), &r_temp, &(ecdsa->ec_ctx.ord)); // t3 = prk * r_temp (mod ord)

	OSTR2BN(&t2, md_HASH, HASH_OUTPUT_BYTE_LEN);
	BN_mod(&t2, &t2, &(ecdsa->ec_ctx.ord)); // t2 = HASH(md) �޽��� �ؽ� ��
	BN_add_mod(&t4, &t3, &t2, &(ecdsa->ec_ctx.ord)); // t4 = t3 + t2 (mod ord)

	BN_mul_inv_mod(&t1, &(ecdsa->k), &(ecdsa->ec_ctx.ord)); //���� �� k �� ����

	BN_mul_mod(&t2, &t1, &t4, &(ecdsa->ec_ctx.ord)); // t2 = t1 * t4 (mod ord) = k^-1(e+dr) (mod ord)

	if (MAC_IS_BN_ZERO(t2) == TRUE) {
		//printf("EC_KCDSA_SIGN FAILED(���ο� ���� �ʿ�)");
		return ERR_NEW_RANDOM_NEEDED; // s�� ���� 0 �� ��� ���� ���ο� ���� k �ʿ�
	}
	BN2OSTR(s, sLen, &t2); // ���� s ����
	
	return EBD_CRYPTO_SUCCESS;
}

SINT ECDSA_verify(ECDSA_INFO *ecdsa, UCHAR *r, ULONG rLen, UCHAR *s, ULONG sLen, UCHAR *Msg, ULONG Msg_len)
{
	BN t1, t2, t3, t4, t5, r_temp, s_temp;
	SINT HASH_OUTPUT_BYTE_LEN;
	ULONG t1_dat[MAX_GFP_BUF_LEN], t2_dat[MAX_GFP_BUF_LEN], t3_dat[MAX_GFP_BUF_LEN], t4_dat[MAX_GFP_BUF_LEN], t5_dat[MAX_GFP_BUF_LEN], r_temp_dat[MAX_GFP_BUF_LEN], s_temp_dat[MAX_GFP_BUF_LEN];
	GFP_ECPT_AC P, Q, R;
	GFP_ECPT_AC_BUF P_buf, Q_buf, R_buf;
	UCHAR md_HASH[64] = { 0, };

	if(!ecdsa || !r || !s || !Msg || (rLen != 32) || (sLen != 32))
		return ERR_INVALID_INPUT;

	MAC_BN_INIT_MEM_CLR(t1, t1_dat, MPCONST_POS_SIG);
	MAC_BN_INIT_MEM_CLR(t2, t2_dat, MPCONST_POS_SIG);
	MAC_BN_INIT_MEM_CLR(t3, t3_dat, MPCONST_POS_SIG);
	MAC_BN_INIT_MEM_CLR(t4, t4_dat, MPCONST_POS_SIG);
	MAC_BN_INIT_MEM_CLR(t5, t5_dat, MPCONST_POS_SIG);
	MAC_BN_INIT_MEM_CLR(r_temp, r_temp_dat, MPCONST_POS_SIG);
	MAC_BN_INIT_MEM_CLR(s_temp, s_temp_dat, MPCONST_POS_SIG);
	GFP_ECPT_AC_init(&P, &P_buf);
	GFP_ECPT_AC_init(&Q, &Q_buf);
	GFP_ECPT_AC_init(&R, &R_buf);

	switch (ecdsa->hash_alg) {
		case SHA224: /* SHA224 */
			sha224(Msg, Msg_len, md_HASH);
			HASH_OUTPUT_BYTE_LEN = 28;
			break;
		case SHA256: /* SHA256 */
			sha256(Msg, Msg_len, md_HASH);
			HASH_OUTPUT_BYTE_LEN = 32;
			break;
		case SHA384:/* SHA384 */
			sha384(Msg, Msg_len, md_HASH);
			HASH_OUTPUT_BYTE_LEN = 32;
			break;
		case SHA512:/* SHA512 */
			sha512(Msg, Msg_len, md_HASH);
			HASH_OUTPUT_BYTE_LEN = 32;
			break;
		default:
			return ERR_INVALID_ALGORITHM_ID;
	}

	if (GFP_EC_IsPT_on(&(ecdsa->ec_ctx), &(ecdsa->puk)) != TRUE)
		return ERR_INVALID_PUBLIC_KEY; //puk not on ec

	OSTR2BN(&r_temp, r, rLen); // r_temp = r
	MAC_CLR_UPPER_ZEROBYTES(r_temp); // r_temp ���� ����
	OSTR2BN(&s_temp, s, sLen); // s_temp = s
	OSTR2BN(&t3, md_HASH, HASH_OUTPUT_BYTE_LEN); // t3
	BN_mul_inv_mod(&t4, &s_temp, &(ecdsa->ec_ctx.ord)); // t4 = s^-1 (mod ord)
	BN_mul_mod(&t5, &t3, &t4, &(ecdsa->ec_ctx.ord)); // t5 = t3 * t4 (mod ord) = s^(-1) * md (mod ord)
	BN_mul_mod(&t3, &r_temp, &t4, &(ecdsa->ec_ctx.ord)); // t3 = r * t4 (mod ord) = s^(-1) * r (mod ord)
	GFP_ECPT_AC_smul(&P, &(ecdsa->ec_ctx), &t5, &(ecdsa->ec_ctx.base)); //P = t5*G
	GFP_ECPT_AC_smul(&R, &(ecdsa->ec_ctx), &t3, &(ecdsa->puk)); //P = t5*G
	GFP_ECPT_AC_add(&Q, &(ecdsa->ec_ctx), &P, &R);
	BN_mod(&t3, &Q.x, &(ecdsa->ec_ctx.ord));

	MAC_CLR_UPPER_ZEROBYTES(t3); // t3 ���� ����
	if (BN_comp(&r_temp, &t3) == 0) {
		return EBD_CRYPTO_SUCCESS;
	}
	else {
		return ERR_VERIFY_FAILURE;
	}
}

SINT ECDSA_clear(ECDSA_INFO *ecdsa)
{
	if(!ecdsa)
		return ERR_INVALID_INPUT;

	memset(ecdsa, 0x00, sizeof(ECDSA_INFO));

	return EBD_CRYPTO_SUCCESS;
}

SINT ECDSA_generate_signature(SINT hash_alg, const UCHAR *d, ULONG d_len, UCHAR *msg, ULONG msg_len, UCHAR *r, ULONG *r_len, UCHAR *s, ULONG *s_len)
{
	ECDSA_INFO ecdsa;

	UCHAR rtemp[33]={0, };
	ULONG rtempLen=0;

	UCHAR stemp[33]={0, };
	ULONG stempLen=0;

	UCHAR ktemp[33]={0, };
	ULONG ktempLen=0;

	ECDSA_init(&ecdsa, hash_alg);
	if(!ECDSA_setkey(&ecdsa, NULL, 0, NULL, 0, d, d_len, ECDSA_SIGN))
		return ERR_INVALID_PRIVATE_KEY;

	ECDSA_gen_random_k(&ecdsa, 256, ktemp, &ktempLen);
	
	if(ECDSA_sign(&ecdsa, rtemp, &rtempLen, stemp, &stempLen, msg, msg_len) != EBD_CRYPTO_SUCCESS)
		return ERR_SIGN_FAILURE;

	ECDSA_clear(&ecdsa);

	memcpy(r, rtemp, rtempLen);
	memcpy(s, stemp, stempLen);
	*r_len = rtempLen;
	*s_len = stempLen;

	memset(rtemp, 0x00, 33);
	memset(stemp, 0x00, 33);
	memset(ktemp, 0x00, 33);

	return EBD_CRYPTO_SUCCESS;
}

SINT ECDSA_verify_signature(SINT hash_alg, const UCHAR *qx, ULONG qx_len, const UCHAR *qy, ULONG qy_len, UCHAR *msg, ULONG msg_len, UCHAR *r, ULONG r_len, UCHAR *s, ULONG s_len)
{
	ECDSA_INFO ecdsa;

	ECDSA_init(&ecdsa, hash_alg);
	if(!ECDSA_setkey(&ecdsa, qx, qx_len, qy, qy_len, NULL, 0, ECDSA_VERIFY))
		return ERR_INVALID_PUBLIC_KEY;

	if(ECDSA_verify(&ecdsa, r, r_len, s, s_len, msg, msg_len) != EBD_CRYPTO_SUCCESS)
		return ERR_VERIFY_FAILURE;

	ECDSA_clear(&ecdsa);

	return EBD_CRYPTO_SUCCESS;
}