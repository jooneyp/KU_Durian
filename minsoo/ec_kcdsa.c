#include "EBDCrypto.h"

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

int EC_KCDSA_init(EC_KCDSA_INFO *ec_kcdsa, int hash_alg)
{
	GFP_EC_CTX_init(&(ec_kcdsa->ec_ctx), &(ec_kcdsa->ec_ctx_buf));
	GFP_ECC_PRIVATE_KEY_init(&(ec_kcdsa->prk), ec_kcdsa->prk_dat);
	GFP_ECC_PUBLIC_KEY_init(&(ec_kcdsa->puk), &(ec_kcdsa->puk_buf));

	BN_X9_31_PRNG_CTX_init(&(ec_kcdsa->randctx), &(ec_kcdsa->randbuf));
	MAC_BN_INIT(ec_kcdsa->k, ec_kcdsa->k_dat, MPCONST_POS_SIG);

	InbySTR("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", ec_kcdsa->tmp_cdat, ec_kcdsa->ec_ctx.prime);
	InbySTR("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", ec_kcdsa->tmp_cdat, ec_kcdsa->ec_ctx.ord);
	InbySTR("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", ec_kcdsa->tmp_cdat, ec_kcdsa->ec_ctx.a);
	InbySTR("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", ec_kcdsa->tmp_cdat, ec_kcdsa->ec_ctx.b);
	InbySTR("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", ec_kcdsa->tmp_cdat, ec_kcdsa->ec_ctx.base.x);
	InbySTR("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", ec_kcdsa->tmp_cdat, ec_kcdsa->ec_ctx.base.y);
	InbySTR("01", ec_kcdsa->tmp_cdat, ec_kcdsa->ec_ctx.cofactor);

	ec_kcdsa->hash_alg = hash_alg;

	return 1;
}

int EC_KCDSA_setkey(EC_KCDSA_INFO *ec_kcdsa, const UCHAR *qx, ULONG qx_len, const UCHAR *qy, ULONG qy_len, const UCHAR *d, ULONG d_len, SINT priv)
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

	if ((d != NULL) && (d_len > 0) && priv)
	{
		{
			BN temprand;
			ULONG temprand_dat[MAX_GFP_BUF_LEN];
			MAC_BN_INIT(temprand, temprand_dat, MPCONST_POS_SIG);

			OSTR2BN(&temprand, (unsigned char *)d, d_len);

			if (BN_comp(&temprand, &(ec_kcdsa->ec_ctx.ord)) >= 0)
				return FALSE;

			GFP_ECPT_AC_smul(&puk, &(ec_kcdsa->ec_ctx), &temprand, &(ec_kcdsa->ec_ctx.base)); //public key generation
		}
		//pubkey test
		if ((BN_comp(&(puk.x), &(ec_kcdsa->ec_ctx.prime)) >= 0) || (BN_comp(&(puk.y), &(ec_kcdsa->ec_ctx.prime)) >= 0))
			return FALSE;

		MAC_BN_INIT(tmp1, tmp1_dat, MPCONST_POS_SIG);
		MAC_BN_INIT(tmp2, tmp2_dat, MPCONST_POS_SIG);

		BN_sqr_mod(&tmp2, &(puk.x), &(ec_kcdsa->ec_ctx.prime)); //tmp2 = x^2
		BN_mul_mod(&tmp1, &tmp2, &(puk.x), &(ec_kcdsa->ec_ctx.prime)); //tmp1 = x^3
		BN_mul_mod(&tmp2, &(ec_kcdsa->ec_ctx.a), &(puk.x), &(ec_kcdsa->ec_ctx.prime)); //tmp2 = a*x
		BN_add_mod(&tmp1, &tmp1, &tmp2, &(ec_kcdsa->ec_ctx.prime)); // tmp1 = x^3 + a*x
		BN_add_mod(&tmp1, &tmp1, &(ec_kcdsa->ec_ctx.b), &(ec_kcdsa->ec_ctx.prime)); //tmp1 = x^3 + a*x + b
		BN_sqr_mod(&tmp2, &(puk.y), &(ec_kcdsa->ec_ctx.prime)); //tmp2 = y^2

		if (BN_comp(&tmp1, &tmp2) != 0)
			return FALSE;

		GFP_ECPT_AC_smul(&temp, &(ec_kcdsa->ec_ctx), &(ec_kcdsa->ec_ctx.ord), &puk);

		if (temp.is_O == TRUE)
		{
			OSTR2BN(&(ec_kcdsa->prk), (unsigned char *)d, d_len);
			GFP_ECPT_AC_smul(&(ec_kcdsa->puk), &(ec_kcdsa->ec_ctx), &(ec_kcdsa->prk), &(ec_kcdsa->ec_ctx.base));
			ec_kcdsa->is_sign = priv;

			return TRUE;
		}
		else
			return FALSE;
	}
	else
	{
		if ((qx == NULL) || (qy == NULL) || priv)
			return FALSE;

		//public key valid test
		OSTR2BN(&(puk.x), (unsigned char *)qx, qx_len);
		OSTR2BN(&(puk.y), (unsigned char *)qy, qy_len);

		if ((BN_comp(&(puk.x), &(ec_kcdsa->ec_ctx.prime)) >= 0) || (BN_comp(&(puk.y), &(ec_kcdsa->ec_ctx.prime)) >= 0))
			return FALSE;

		MAC_BN_INIT(tmp1, tmp1_dat, MPCONST_POS_SIG);
		MAC_BN_INIT(tmp2, tmp2_dat, MPCONST_POS_SIG);

		BN_sqr_mod(&tmp2, &(puk.x), &(ec_kcdsa->ec_ctx.prime)); //tmp2 = x^2
		BN_mul_mod(&tmp1, &tmp2, &(puk.x), &(ec_kcdsa->ec_ctx.prime)); //tmp1 = x^3
		BN_mul_mod(&tmp2, &(ec_kcdsa->ec_ctx.a), &(puk.x), &(ec_kcdsa->ec_ctx.prime)); //tmp2 = a*x
		BN_add_mod(&tmp1, &tmp1, &tmp2, &(ec_kcdsa->ec_ctx.prime)); // tmp1 = x^3 + a*x
		BN_add_mod(&tmp1, &tmp1, &(ec_kcdsa->ec_ctx.b), &(ec_kcdsa->ec_ctx.prime)); //tmp1 = x^3 + a*x + b
		BN_sqr_mod(&tmp2, &(puk.y), &(ec_kcdsa->ec_ctx.prime)); //tmp2 = y^2

		if (BN_comp(&tmp1, &tmp2) != 0)
			return FALSE;

		GFP_ECPT_AC_smul(&temp, &(ec_kcdsa->ec_ctx), &(ec_kcdsa->ec_ctx.ord), &puk);

		if (temp.is_O == TRUE)
		{
			OSTR2BN(&(ec_kcdsa->puk.x), (unsigned char *)qx, qx_len);
			OSTR2BN(&(ec_kcdsa->puk.y), (unsigned char *)qy, qy_len);
			ec_kcdsa->is_sign = priv;

			return TRUE;
		}
		else
			return FALSE;
	}
}

int EC_KCDSA_gen_key_pair(EC_KCDSA_INFO *ec_kcdsa, UCHAR *qx, ULONG *qx_len, UCHAR *qy, ULONG *qy_len, UCHAR *d, ULONG *d_len)
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

	GFP_ECPT_AC_init(&temp, &temp_buf);
	GFP_ECC_PUBLIC_KEY_init(&puk, &puk_buf);
	MAC_BN_INIT(temprand, temprand_dat, MPCONST_POS_SIG);
	MAC_BN_INIT(tmp1, tmp1_dat, MPCONST_POS_SIG);
	MAC_BN_INIT(tmp2, tmp2_dat, MPCONST_POS_SIG);

	bits = 256;

	while (1)
	{
		if (!BN_X9_31_PRNG(&temprand, &(ec_kcdsa->randctx), bits))
		{
			if (BN_comp(&temprand, &(ec_kcdsa->ec_ctx.ord)) >= 0)
				continue;

			GFP_ECPT_AC_smul(&puk, &(ec_kcdsa->ec_ctx), &temprand, &(ec_kcdsa->ec_ctx.base)); //public key generation

																						//pubkey test
			if ((BN_comp(&(puk.x), &(ec_kcdsa->ec_ctx.prime)) >= 0) || (BN_comp(&(puk.y), &(ec_kcdsa->ec_ctx.prime)) >= 0))
				continue;

			BN_sqr_mod(&tmp2, &(puk.x), &(ec_kcdsa->ec_ctx.prime)); //tmp2 = x^2
			BN_mul_mod(&tmp1, &tmp2, &(puk.x), &(ec_kcdsa->ec_ctx.prime)); //tmp1 = x^3
			BN_mul_mod(&tmp2, &(ec_kcdsa->ec_ctx.a), &(puk.x), &(ec_kcdsa->ec_ctx.prime)); //tmp2 = a*x
			BN_add_mod(&tmp1, &tmp1, &tmp2, &(ec_kcdsa->ec_ctx.prime)); // tmp1 = x^3 + a*x
			BN_add_mod(&tmp1, &tmp1, &(ec_kcdsa->ec_ctx.b), &(ec_kcdsa->ec_ctx.prime)); //tmp1 = x^3 + a*x + b
			BN_sqr_mod(&tmp2, &(puk.y), &(ec_kcdsa->ec_ctx.prime)); //tmp2 = y^2

			if (BN_comp(&tmp1, &tmp2) != 0)
				continue;

			GFP_ECPT_AC_smul(&temp, &(ec_kcdsa->ec_ctx), &(ec_kcdsa->ec_ctx.ord), &puk);

			if (temp.is_O == TRUE)
			{
				break;
			}
			else
				continue;
		}

	}

	BN_copy(&ec_kcdsa->prk, &temprand);
	GFP_ECPT_AC_smul(&(ec_kcdsa->puk), &(ec_kcdsa->ec_ctx), &temprand, &(ec_kcdsa->ec_ctx.base));

	BN2OSTR(d, d_len, &temprand);
	BN2OSTR(qx, qx_len, &(puk.x));
	BN2OSTR(qy, qy_len, &(puk.y));

	return 1;
}

int EC_KCDSA_gen_random_k(EC_KCDSA_INFO *ec_kcdsa, SINT bits, UCHAR *k, ULONG *k_len)
{
	BN temprand;
	ULONG temprand_dat[MAX_GFP_BUF_LEN];
	MAC_BN_INIT(temprand, temprand_dat, MPCONST_POS_SIG);

	while (1)
	{
		if (!BN_X9_31_PRNG(&temprand, &(ec_kcdsa->randctx), bits))
		{
			if (BN_comp(&temprand, &(ec_kcdsa->ec_ctx.ord)) >= 0)
				continue;
			else
				break;
		}
	}

	BN_copy(&(ec_kcdsa->k), &temprand);
	*k_len = bits / 8;

	return 1;
}

int EC_KCDSA_set_random_k(EC_KCDSA_INFO *ec_kcdsa, const UCHAR *k, ULONG k_len)
{
	OSTR2BN(&(ec_kcdsa->k), (unsigned char *)k, k_len);

	return 1;
}

int EC_KCDSA_sign(EC_KCDSA_INFO *ec_kcdsa, UCHAR *r, ULONG *rLen, UCHAR *s, ULONG *sLen, UCHAR *Msg, ULONG Msg_len)
{
	BN t1, t2, t3, t4, r_temp;
	SINT HASH_OUTPUT_BYTE_LEN;
	ULONG t1_dat[MAX_GFP_BUF_LEN], t2_dat[MAX_GFP_BUF_LEN],
		t3_dat[MAX_GFP_BUF_LEN], t4_dat[MAX_GFP_BUF_LEN],
		r_temp_dat[MAX_GFP_BUF_LEN];
	GFP_ECPT_AC Q;
	GFP_ECPT_AC_BUF Q_buf;
	UCHAR md_HASH[64] = { 0, };

	// 	if(!ec_kcdsa->is_sign)
	// 		return 0;

	MAC_BN_INIT_MEM_CLR(t1, t1_dat, MPCONST_POS_SIG);
	MAC_BN_INIT_MEM_CLR(t2, t2_dat, MPCONST_POS_SIG);
	MAC_BN_INIT_MEM_CLR(t3, t3_dat, MPCONST_POS_SIG);
	MAC_BN_INIT_MEM_CLR(t4, t4_dat, MPCONST_POS_SIG);
	MAC_BN_INIT_MEM_CLR(r_temp, r_temp_dat, MPCONST_POS_SIG);
	GFP_ECPT_AC_init(&Q, &Q_buf);
	switch (ec_kcdsa->hash_alg) {
	case HASH_SHA224: /* SHA224 */
		SHA224_hash(Msg, Msg_len, md_HASH);
		HASH_OUTPUT_BYTE_LEN = 28;
		break;
	case HASH_SHA256: /* SHA256 */
		SHA256_hash(Msg, Msg_len, md_HASH);
		HASH_OUTPUT_BYTE_LEN = 32;
		break;
	case HASH_SHA384:/* SHA384 */
		SHA384_hash(Msg, Msg_len, md_HASH);
		HASH_OUTPUT_BYTE_LEN = 32;
		break;
	case HASH_SHA512:/* SHA512 */
		SHA512_hash(Msg, Msg_len, md_HASH);
		HASH_OUTPUT_BYTE_LEN = 32;
		break;
	}

	GFP_ECPT_AC_smul(&Q, &(ec_kcdsa->ec_ctx), &(ec_kcdsa->k), &(ec_kcdsa->ec_ctx.base)); //Q = kG
	BN_mod(&r_temp, &Q.x, &(ec_kcdsa->ec_ctx.ord)); // r_temp = Q_x (mod ord)
	MAC_CLR_UPPER_ZEROBYTES(r_temp); // r_temp 길이 보정
	if (MAC_IS_BN_ZERO(r_temp) == TRUE) {
		printf("EC_KCDSA_SIGN FAILED(새로운 난수 필요)");
		return 0; // r의 값이 0 인 경우 실패 새로운 난수 k 필요
	}
	if (r_temp.len < ec_kcdsa->ec_ctx.ord.len)
		r_temp.dat[r_temp.len] = 0x0;
	BN2OSTR(r, rLen, &r_temp); // 사인 r 생성
	BN_mul_mod(&t3, &(ec_kcdsa->prk), &r_temp, &(ec_kcdsa->ec_ctx.ord)); // t3 = prk * r_temp (mod ord)

	OSTR2BN(&t2, md_HASH, HASH_OUTPUT_BYTE_LEN);
	BN_mod(&t2, &t2, &(ec_kcdsa->ec_ctx.ord)); // t2 = HASH(md) 메시지 해쉬 값
	BN_add_mod(&t4, &t3, &t2, &(ec_kcdsa->ec_ctx.ord)); // t4 = t3 + t2 (mod ord)

	BN_mul_inv_mod(&t1, &(ec_kcdsa->k), &(ec_kcdsa->ec_ctx.ord)); //랜덤 수 k 의 역원

	BN_mul_mod(&t2, &t1, &t4, &(ec_kcdsa->ec_ctx.ord)); // t2 = t1 * t4 (mod ord) = k^-1(e+dr) (mod ord)

	if (MAC_IS_BN_ZERO(t2) == TRUE) {
		printf("EC_KCDSA_SIGN FAILED(새로운 난수 필요)");
		return 0; // s의 값이 0 인 경우 실패 새로운 난수 k 필요
	}
	BN2OSTR(s, sLen, &t2); // 사인 s 생성
	return 1;
}

int EC_KCDSA_verify(EC_KCDSA_INFO *ec_kcdsa, UCHAR *r, ULONG rLen, UCHAR *s, ULONG sLen, UCHAR *Msg, ULONG Msg_len)
{
	BN t1, t2, t3, t4, t5, r_temp, s_temp;
	SINT HASH_OUTPUT_BYTE_LEN;
	ULONG t1_dat[MAX_GFP_BUF_LEN], t2_dat[MAX_GFP_BUF_LEN],
		t3_dat[MAX_GFP_BUF_LEN], t4_dat[MAX_GFP_BUF_LEN],
		t5_dat[MAX_GFP_BUF_LEN], r_temp_dat[MAX_GFP_BUF_LEN],
		s_temp_dat[MAX_GFP_BUF_LEN];
	GFP_ECPT_AC P, Q, R;
	GFP_ECPT_AC_BUF P_buf, Q_buf, R_buf;
	UCHAR md_HASH[64] = { 0, };

	// 	if(ec_kcdsa->is_sign)
	// 		return 0;

	//printf("In verify\n");

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

	//printf("after init\n");

	switch (ec_kcdsa->hash_alg) {
	case HASH_SHA224: /* SHA224 */
		SHA224_hash(Msg, Msg_len, md_HASH);
		HASH_OUTPUT_BYTE_LEN = 28;
		break;
	case HASH_SHA256: /* SHA256 */
		SHA256_hash(Msg, Msg_len, md_HASH);
		HASH_OUTPUT_BYTE_LEN = 32;
		break;
	case HASH_SHA384:/* SHA384 */
		SHA384_hash(Msg, Msg_len, md_HASH);
		HASH_OUTPUT_BYTE_LEN = 32;
		break;
	case HASH_SHA512:/* SHA512 */
		SHA512_hash(Msg, Msg_len, md_HASH);
		HASH_OUTPUT_BYTE_LEN = 32;
		break;
	}

	//printf("after hash\n");

	if (GFP_EC_IsPT_on(&(ec_kcdsa->ec_ctx), &(ec_kcdsa->puk)) != TRUE)
		return -1; //puk not on ec
	OSTR2BN(&r_temp, r, rLen); // r_temp = r
	MAC_CLR_UPPER_ZEROBYTES(r_temp); // r_temp 길이 보정
	OSTR2BN(&s_temp, s, sLen); // s_temp = s
	OSTR2BN(&t3, md_HASH, HASH_OUTPUT_BYTE_LEN); // t3
	BN_mul_inv_mod(&t4, &s_temp, &(ec_kcdsa->ec_ctx.ord)); // t4 = s^-1 (mod ord)
	BN_mul_mod(&t5, &t3, &t4, &(ec_kcdsa->ec_ctx.ord)); // t5 = t3 * t4 (mod ord) = s^(-1) * md (mod ord)
	BN_mul_mod(&t3, &r_temp, &t4, &(ec_kcdsa->ec_ctx.ord)); // t3 = r * t4 (mod ord) = s^(-1) * r (mod ord)
	GFP_ECPT_AC_smul(&P, &(ec_kcdsa->ec_ctx), &t5, &(ec_kcdsa->ec_ctx.base)); //P = t5*G
	GFP_ECPT_AC_smul(&R, &(ec_kcdsa->ec_ctx), &t3, &(ec_kcdsa->puk)); //P = t5*G
	GFP_ECPT_AC_add(&Q, &(ec_kcdsa->ec_ctx), &P, &R);
	BN_mod(&t3, &Q.x, &(ec_kcdsa->ec_ctx.ord));

	//printf("after mod\n");

	MAC_CLR_UPPER_ZEROBYTES(t3); // t3 길이 보정
	if (BN_comp(&r_temp, &t3) == 0) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}

int EC_KCDSA_clear(EC_KCDSA_INFO *ec_kcdsa)
{
	memset(ec_kcdsa, 0x00, sizeof(EC_KCDSA_INFO));

	return 1;
}
