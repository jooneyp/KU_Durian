// #include "KUCrypto2.h"
#include "EBDCrypto.h"

void GFP_ECC_PUBLIC_KEY_init(GFP_ECC_PUBLIC_KEY *puk, GFP_ECC_PUBLIC_KEY_BUF *puk_buf)
{
	GFP_ECPT_AC_init(puk,puk_buf);
}

void GFP_ECC_PRIVATE_KEY_init(GFP_ECC_PRIVATE_KEY *prk, GFP_ECC_PRIVATE_KEY_BUF *prk_buf)
{
	prk->dat = prk_buf;
	prk->sig = MPCONST_POS_SIG;
	prk->len = 0;
}

int ECDSA_init(ECDSA_INFO *ecdsa, int hash_alg)
{
	GFP_EC_CTX_init(&(ecdsa->ec_ctx),&(ecdsa->ec_ctx_buf));
	GFP_ECC_PRIVATE_KEY_init(&(ecdsa->prk), ecdsa->prk_dat);
	GFP_ECC_PUBLIC_KEY_init(&(ecdsa->puk), &(ecdsa->puk_buf));

	BN_X9_31_PRNG_CTX_init(&(ecdsa->randctx), &(ecdsa->randbuf));
	MAC_BN_INIT(ecdsa->k,ecdsa->k_dat,MPCONST_POS_SIG);

	InbySTR("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", ecdsa->tmp_cdat, ecdsa->ec_ctx.prime);
	InbySTR("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", ecdsa->tmp_cdat, ecdsa->ec_ctx.ord);
	InbySTR("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", ecdsa->tmp_cdat, ecdsa->ec_ctx.a);
	InbySTR("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", ecdsa->tmp_cdat, ecdsa->ec_ctx.b);
	InbySTR("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", ecdsa->tmp_cdat, ecdsa->ec_ctx.base.x);
	InbySTR("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", ecdsa->tmp_cdat, ecdsa->ec_ctx.base.y);
	InbySTR("01", ecdsa->tmp_cdat, ecdsa->ec_ctx.cofactor);

	ecdsa->hash_alg = hash_alg;

	return 1;
}

int ECDSA_gen_key_pair(ECDSA_INFO *ecdsa, UCHAR *qx, ULONG *qx_len, UCHAR *qy, ULONG *qy_len, UCHAR *d, ULONG *d_len)
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
	MAC_BN_INIT(temprand,temprand_dat,MPCONST_POS_SIG);
	MAC_BN_INIT(tmp1,tmp1_dat,MPCONST_POS_SIG);
	MAC_BN_INIT(tmp2,tmp2_dat,MPCONST_POS_SIG);
	
	bits = 256;

	while(1)
	{
		if(!BN_X9_31_PRNG(&temprand, &(ecdsa->randctx), bits))
		{
			if( BN_comp(&temprand, &(ecdsa->ec_ctx.ord)) >= 0)
				continue;

			GFP_ECPT_AC_smul(&puk, &(ecdsa->ec_ctx), &temprand, &(ecdsa->ec_ctx.base)); //public key generation
		
			//pubkey test
			if( (BN_comp(&(puk.x), &(ecdsa->ec_ctx.prime)) >= 0) || (BN_comp(&(puk.y), &(ecdsa->ec_ctx.prime)) >= 0) )
				continue;
			
			BN_sqr_mod(&tmp2, &(puk.x), &(ecdsa->ec_ctx.prime)); //tmp2 = x^2
			BN_mul_mod(&tmp1, &tmp2, &(puk.x), &(ecdsa->ec_ctx.prime)); //tmp1 = x^3
			BN_mul_mod(&tmp2, &(ecdsa->ec_ctx.a), &(puk.x), &(ecdsa->ec_ctx.prime)); //tmp2 = a*x
			BN_add_mod(&tmp1, &tmp1, &tmp2, &(ecdsa->ec_ctx.prime)); // tmp1 = x^3 + a*x
			BN_add_mod(&tmp1, &tmp1, &(ecdsa->ec_ctx.b), &(ecdsa->ec_ctx.prime)); //tmp1 = x^3 + a*x + b
			BN_sqr_mod(&tmp2, &(puk.y), &(ecdsa->ec_ctx.prime)); //tmp2 = y^2

			if( BN_comp(&tmp1, &tmp2) != 0 )
				continue;

			GFP_ECPT_AC_smul(&temp, &(ecdsa->ec_ctx), &(ecdsa->ec_ctx.ord), &puk);

			if(temp.is_O == TRUE)
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

	return 1;
}

int ECDSA_setkey(ECDSA_INFO *ecdsa, const UCHAR *qx, ULONG qx_len, const UCHAR *qy, ULONG qy_len, const UCHAR *d, ULONG d_len, int priv)
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
				
	if( (d != NULL) && (d_len > 0) && priv )
	{
		{
			BN temprand;
			ULONG temprand_dat[MAX_GFP_BUF_LEN];
			MAC_BN_INIT(temprand,temprand_dat,MPCONST_POS_SIG);

			OSTR2BN(&temprand, (unsigned char *)d, d_len);

			if( BN_comp(&temprand, &(ecdsa->ec_ctx.ord)) >= 0)
				return FALSE;

			GFP_ECPT_AC_smul(&puk, &(ecdsa->ec_ctx), &temprand, &(ecdsa->ec_ctx.base)); //public key generation
		}
		//pubkey test
		if( (BN_comp(&(puk.x), &(ecdsa->ec_ctx.prime)) >= 0) || (BN_comp(&(puk.y), &(ecdsa->ec_ctx.prime)) >= 0) )
			return FALSE;

		MAC_BN_INIT(tmp1,tmp1_dat,MPCONST_POS_SIG);
		MAC_BN_INIT(tmp2,tmp2_dat,MPCONST_POS_SIG);

		BN_sqr_mod(&tmp2, &(puk.x), &(ecdsa->ec_ctx.prime)); //tmp2 = x^2
		BN_mul_mod(&tmp1, &tmp2, &(puk.x), &(ecdsa->ec_ctx.prime)); //tmp1 = x^3
		BN_mul_mod(&tmp2, &(ecdsa->ec_ctx.a), &(puk.x), &(ecdsa->ec_ctx.prime)); //tmp2 = a*x
		BN_add_mod(&tmp1, &tmp1, &tmp2, &(ecdsa->ec_ctx.prime)); // tmp1 = x^3 + a*x
		BN_add_mod(&tmp1, &tmp1, &(ecdsa->ec_ctx.b), &(ecdsa->ec_ctx.prime)); //tmp1 = x^3 + a*x + b
		BN_sqr_mod(&tmp2, &(puk.y), &(ecdsa->ec_ctx.prime)); //tmp2 = y^2

		if( BN_comp(&tmp1, &tmp2) != 0 )
			return FALSE;

		GFP_ECPT_AC_smul(&temp, &(ecdsa->ec_ctx), &(ecdsa->ec_ctx.ord), &puk);

		if(temp.is_O == TRUE)
		{
			OSTR2BN(&(ecdsa->prk), (unsigned char *)d, d_len);
			GFP_ECPT_AC_smul(&(ecdsa->puk), &(ecdsa->ec_ctx), &(ecdsa->prk), &(ecdsa->ec_ctx.base));
			ecdsa->is_sign = priv;

			return TRUE;
		}
		else
			return FALSE;
	}
	else
	{
		if( (qx == NULL) || (qy == NULL) || priv )
			return FALSE;

		//public key valid test
		OSTR2BN(&(puk.x), (unsigned char *)qx, qx_len);
		OSTR2BN(&(puk.y), (unsigned char *)qy, qy_len);

		if( (BN_comp(&(puk.x), &(ecdsa->ec_ctx.prime)) >= 0) || (BN_comp(&(puk.y), &(ecdsa->ec_ctx.prime)) >= 0) )
			return FALSE;

		MAC_BN_INIT(tmp1,tmp1_dat,MPCONST_POS_SIG);
		MAC_BN_INIT(tmp2,tmp2_dat,MPCONST_POS_SIG);

		BN_sqr_mod(&tmp2, &(puk.x), &(ecdsa->ec_ctx.prime)); //tmp2 = x^2
		BN_mul_mod(&tmp1, &tmp2, &(puk.x), &(ecdsa->ec_ctx.prime)); //tmp1 = x^3
		BN_mul_mod(&tmp2, &(ecdsa->ec_ctx.a), &(puk.x), &(ecdsa->ec_ctx.prime)); //tmp2 = a*x
		BN_add_mod(&tmp1, &tmp1, &tmp2, &(ecdsa->ec_ctx.prime)); // tmp1 = x^3 + a*x
		BN_add_mod(&tmp1, &tmp1, &(ecdsa->ec_ctx.b), &(ecdsa->ec_ctx.prime)); //tmp1 = x^3 + a*x + b
		BN_sqr_mod(&tmp2, &(puk.y), &(ecdsa->ec_ctx.prime)); //tmp2 = y^2

		if( BN_comp(&tmp1, &tmp2) != 0 )
			return FALSE;

		GFP_ECPT_AC_smul(&temp, &(ecdsa->ec_ctx), &(ecdsa->ec_ctx.ord), &puk);
			
		if(temp.is_O == TRUE)
		{
			OSTR2BN(&(ecdsa->puk.x), (unsigned char *)qx, qx_len);
			OSTR2BN(&(ecdsa->puk.y), (unsigned char *)qy, qy_len);
			ecdsa->is_sign = priv;

			return TRUE;
		}
		else
			return FALSE;
	}
}


int ECDSA_gen_random_k(ECDSA_INFO *ecdsa, int bits, UCHAR *k, ULONG *k_len)
{
	BN temprand;
	ULONG temprand_dat[MAX_GFP_BUF_LEN];
	MAC_BN_INIT(temprand,temprand_dat,MPCONST_POS_SIG);

	while(1)
	{
		if(!BN_X9_31_PRNG(&temprand, &(ecdsa->randctx), bits))
		{
			if( BN_comp(&temprand, &(ecdsa->ec_ctx.ord)) >= 0)
				continue;
			else
				break;
		}
	}

	BN_copy(&(ecdsa->k), &temprand);
	*k_len = bits/8;

	return 1;
}

int ECDSA_set_random_k(ECDSA_INFO *ecdsa, const UCHAR *k, ULONG k_len)
{
	OSTR2BN(&(ecdsa->k), (unsigned char *)k, k_len);

	return 1;
}

int EC_KCDSA_sign(ECDSA_INFO *ecdsa, UCHAR *msg, ULONG msg_len, UCHAR *r, ULONG *rLen, UCHAR *s, ULONG *sLen)
{
	BN t1,t2,t3,t4, r_temp;
	SINT HASH_OUTPUT_BYTE_LEN;
	ULONG t1_dat[MAX_GFP_BUF_LEN], t2_dat[MAX_GFP_BUF_LEN],
		t3_dat[MAX_GFP_BUF_LEN], t4_dat[MAX_GFP_BUF_LEN],
		r_temp_dat[MAX_GFP_BUF_LEN];
	GFP_ECPT_AC Q;
	GFP_ECPT_AC_BUF Q_buf;
	UINT8 md_HASH[64] ={0, };

// 	if(!ecdsa->is_sign)
// 		return 0;

	msg

	MAC_BN_INIT_MEM_CLR(t1,t1_dat,MPCONST_POS_SIG);
	MAC_BN_INIT_MEM_CLR(t2,t2_dat,MPCONST_POS_SIG);
	MAC_BN_INIT_MEM_CLR(t3,t3_dat,MPCONST_POS_SIG);
	MAC_BN_INIT_MEM_CLR(t4,t4_dat,MPCONST_POS_SIG);
	MAC_BN_INIT_MEM_CLR(r_temp,r_temp_dat,MPCONST_POS_SIG);
	GFP_ECPT_AC_init(&Q,&Q_buf);
	switch(ecdsa->hash_alg){
	case HASH_SHA1: /* SHA1 */
		SHA1_at_once(msg, msg_len, md_HASH);
		HASH_OUTPUT_BYTE_LEN = 20;
		break;
	case HASH_SHA224: /* SHA224 */
		SHA224_hash(msg, msg_len, md_HASH);
		HASH_OUTPUT_BYTE_LEN = 28;
		break;
	case HASH_SHA256: /* SHA256 */
		SHA256_hash(msg, msg_len, md_HASH);
		HASH_OUTPUT_BYTE_LEN = 32;
	case HASH_SHA384:/* SHA384 */
		SHA384_hash(msg, msg_len, md_HASH);
		HASH_OUTPUT_BYTE_LEN = 32;
	case HASH_SHA512:/* SHA512 */
		SHA512_hash(msg, msg_len, md_HASH);
		HASH_OUTPUT_BYTE_LEN = 32;
	}

	GFP_ECPT_AC_smul(&Q, &(ecdsa->ec_ctx), &(ecdsa->k), &(ecdsa->ec_ctx.base)); //Q = kG
	BN_mod(&r_temp,&Q.x,&(ecdsa->ec_ctx.ord)); // r_temp = Q_x (mod ord)
	MAC_CLR_UPPER_ZEROBYTES(r_temp); // r_temp 길이 보정
	if(MAC_IS_BN_ZERO(r_temp)==TRUE){
		printf("ECDSA_SIGN FAILED(새로운 난수 필요)");
		return 0; // r의 값이 0 인 경우 실패 새로운 난수 k 필요
	}
	if(r_temp.len < ecdsa->ec_ctx.ord.len)
		r_temp.dat[r_temp.len]=0x0;
	BN2OSTR(r,rLen,&r_temp); // 사인 r 생성
	BN_mul_mod(&t3, &(ecdsa->prk), &r_temp, &(ecdsa->ec_ctx.ord)); // t3 = prk * r_temp (mod ord)

	OSTR2BN(&t2, md_HASH, HASH_OUTPUT_BYTE_LEN);
	BN_mod(&t2, &t2, &(ecdsa->ec_ctx.ord)); // t2 = HASH(md) 메시지 해쉬 값
	BN_add_mod(&t4, &t3, &t2, &(ecdsa->ec_ctx.ord)); // t4 = t3 + t2 (mod ord)

	BN_mul_inv_mod(&t1,&(ecdsa->k),&(ecdsa->ec_ctx.ord)); //랜덤 수 k 의 역원

	BN_mul_mod(&t2,&t1,&t4, &(ecdsa->ec_ctx.ord)); // t2 = t1 * t4 (mod ord) = k^-1(e+dr) (mod ord)

	if(MAC_IS_BN_ZERO(t2)==TRUE){
		printf("ECDSA_SIGN FAILED(새로운 난수 필요)");
		return 0; // s의 값이 0 인 경우 실패 새로운 난수 k 필요
	}
	BN2OSTR(s, sLen, &t2); // 사인 s 생성
	return 1;
}

int EC_KCDSA_verify(ECDSA_INFO *ecdsa, UCHAR *r, ULONG rLen, UCHAR *s, ULONG sLen, UCHAR *msg, ULONG msg_len)
{
	BN t1,t2,t3,t4,t5,r_temp, s_temp;
	SINT HASH_OUTPUT_BYTE_LEN;
	ULONG t1_dat[MAX_GFP_BUF_LEN],t2_dat[MAX_GFP_BUF_LEN],
		t3_dat[MAX_GFP_BUF_LEN],t4_dat[MAX_GFP_BUF_LEN],
		t5_dat[MAX_GFP_BUF_LEN],r_temp_dat[MAX_GFP_BUF_LEN],
		s_temp_dat[MAX_GFP_BUF_LEN];
	GFP_ECPT_AC P,Q,R;
	GFP_ECPT_AC_BUF P_buf, Q_buf, R_buf;
	UINT8 md_HASH[64] ={0, };

// 	if(ecdsa->is_sign)
// 		return 0;

	//printf("In verify\n");

	MAC_BN_INIT_MEM_CLR(t1,t1_dat,MPCONST_POS_SIG);
	MAC_BN_INIT_MEM_CLR(t2,t2_dat,MPCONST_POS_SIG);
	MAC_BN_INIT_MEM_CLR(t3,t3_dat,MPCONST_POS_SIG);
	MAC_BN_INIT_MEM_CLR(t4,t4_dat,MPCONST_POS_SIG);
	MAC_BN_INIT_MEM_CLR(t5,t5_dat,MPCONST_POS_SIG);
	MAC_BN_INIT_MEM_CLR(r_temp,r_temp_dat,MPCONST_POS_SIG);
	MAC_BN_INIT_MEM_CLR(s_temp,s_temp_dat,MPCONST_POS_SIG);
	GFP_ECPT_AC_init(&P,&P_buf);
	GFP_ECPT_AC_init(&Q,&Q_buf);
	GFP_ECPT_AC_init(&R,&R_buf);

	//printf("after init\n");

	switch(ecdsa->hash_alg){
	case HASH_SHA1: /* SHA1 */
		SHA1_at_once(msg, msg_len, md_HASH);
		HASH_OUTPUT_BYTE_LEN = 20;
		break;
	case HASH_SHA224: /* SHA224 */
		SHA224_hash(msg, msg_len, md_HASH);
		HASH_OUTPUT_BYTE_LEN = 28;
		break;
	case HASH_SHA256: /* SHA256 */
		SHA256_hash(msg, msg_len, md_HASH);
		if(ecdsa->curve == ECP224)
			HASH_OUTPUT_BYTE_LEN = 28;
		else if(ecdsa->curve == ECP256)
			HASH_OUTPUT_BYTE_LEN = 32;
		else
			HASH_OUTPUT_BYTE_LEN = 32;
		break;
	case HASH_SHA384:/* SHA384 */
		SHA384_hash(msg, msg_len, md_HASH);
		if(ecdsa->curve == ECP224)
			HASH_OUTPUT_BYTE_LEN = 28;
		else if(ecdsa->curve == ECP256)
			HASH_OUTPUT_BYTE_LEN = 32;
		else
			HASH_OUTPUT_BYTE_LEN = 48;
		break;
	case HASH_SHA512:/* SHA512 */
		SHA512_hash(msg, msg_len, md_HASH);
		if(ecdsa->curve == ECP224)
			HASH_OUTPUT_BYTE_LEN = 28;
		else if(ecdsa->curve == ECP256)
			HASH_OUTPUT_BYTE_LEN = 32;
		else
			HASH_OUTPUT_BYTE_LEN = 64;
		break;
	}

	//printf("after hash\n");

	if(GFP_EC_IsPT_on(&(ecdsa->ec_ctx), &(ecdsa->puk)) != TRUE)
		return -1; //puk not on ec
	OSTR2BN(&r_temp, r, rLen); // r_temp = r
	MAC_CLR_UPPER_ZEROBYTES(r_temp); // r_temp 길이 보정
	OSTR2BN(&s_temp, s, sLen); // s_temp = s
	OSTR2BN(&t3, md_HASH, HASH_OUTPUT_BYTE_LEN); // t3
	BN_mul_inv_mod(&t4,&s_temp,&(ecdsa->ec_ctx.ord)); // t4 = s^-1 (mod ord)
	BN_mul_mod(&t5, &t3, &t4, &(ecdsa->ec_ctx.ord)); // t5 = t3 * t4 (mod ord) = s^(-1) * md (mod ord)
	BN_mul_mod(&t3, &r_temp, &t4, &(ecdsa->ec_ctx.ord)); // t3 = r * t4 (mod ord) = s^(-1) * r (mod ord)
	GFP_ECPT_AC_smul(&P, &(ecdsa->ec_ctx), &t5, &(ecdsa->ec_ctx.base)); //P = t5*G
	GFP_ECPT_AC_smul(&R, &(ecdsa->ec_ctx), &t3, &(ecdsa->puk)); //P = t5*G
	GFP_ECPT_AC_add(&Q, &(ecdsa->ec_ctx), &P, &R);
	BN_mod(&t3,&Q.x,&(ecdsa->ec_ctx.ord));
	
	//printf("after mod\n");

	MAC_CLR_UPPER_ZEROBYTES(t3); // t3 길이 보정
	if(BN_comp(&r_temp,&t3)==0){
		return TRUE;
	}else{
		return FALSE;
	}
}

int ECDSA_clear(ECDSA_INFO *ecdsa)
{
	memset(ecdsa, 0x00, sizeof(ECDSA_INFO));

	return 1;
}
