#include "EBDCrypto.h"

#define HIGHER_MSB_ONE 0x80000000
#define LONG_BITS 32

#define MPCONST_POS_SIG 1
#define MPCONST_NEG_SIG -1
#define MPCONST_ZERO_SIG 0

#define TRUE 1
#define FALSE 0

SINT BN_copy(BN *dest, BN *src);
SINT BN_comp(BN *a, BN *b);
SINT GFP_sub(GFP *r, GFP *a, GFP *b, GFP *p);
SINT GFP_mul_inv(GFP *r, GFP *a, GFP *p);
SINT GFP_mul(GFP *r, GFP *a, GFP *b, GFP *p);
SINT GFP_sqr(GFP *r, GFP *a, GFP *p);
SINT BN_shl_1bit(BN *b, BN *a);
SINT BN_sub(BN *c, BN *a, BN *b);
SINT GFP_add(GFP *r, GFP *a, GFP *b, GFP *p);
SINT BN_nonzero_bits_num(BN *a);

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

#define MAC_GFP_INIT MAC_BN_INIT
#define GFP_copy BN_copy
#define GFP_comp BN_comp


void GFP_EC_CTX_init(GFP_EC_CTX *ec_ctx, GFP_EC_CTX_BUF *ec_ctx_buf)
{
	MAC_GFP_INIT(ec_ctx->prime, ec_ctx_buf->prime_buf, MPCONST_POS_SIG);
	MAC_GFP_INIT(ec_ctx->a, ec_ctx_buf->a_buf, MPCONST_POS_SIG);
	MAC_GFP_INIT(ec_ctx->b, ec_ctx_buf->b_buf, MPCONST_POS_SIG);
	MAC_GFP_INIT(ec_ctx->ord, ec_ctx_buf->ord_buf, MPCONST_POS_SIG);
	MAC_GFP_INIT(ec_ctx->cofactor, ec_ctx_buf->cof_buf, MPCONST_POS_SIG);
	MAC_GFP_INIT(ec_ctx->base.x, ec_ctx_buf->base_x_buf, MPCONST_POS_SIG);
	MAC_GFP_INIT(ec_ctx->base.y, ec_ctx_buf->base_y_buf, MPCONST_POS_SIG);
	ec_ctx->base.is_O = FALSE;
}

void GFP_ECPT_AC_init(GFP_ECPT_AC *ecpt, GFP_ECPT_AC_BUF *ecptbuf)
{
	MAC_GFP_INIT(ecpt->x, ecptbuf->x_dat, MPCONST_POS_SIG);
	MAC_GFP_INIT(ecpt->y, ecptbuf->y_dat, MPCONST_POS_SIG);
	ecpt->is_O = FALSE;
}

SINT GFP_ECPT_AC_dbl(GFP_ECPT_AC *R, GFP_EC_CTX *ec_ctx, GFP_ECPT_AC *P)
{
	GFP *x1, *y1, *x3, *y3, *p, *a;
	GFP lambda, tmp1, tmp2, tmp3;
	ULONG lambda_dat[MAX_GFP_BUF_LEN] = { 0, }, tmp1_dat[MAX_GFP_BUF_LEN] = { 0, },
		tmp2_dat[MAX_GFP_BUF_LEN] = { 0, }, tmp3_dat[MAX_GFP_BUF_LEN] = { 0, };
	MAC_GFP_INIT(lambda, lambda_dat, MPCONST_POS_SIG);
	MAC_GFP_INIT(tmp1, tmp1_dat, MPCONST_POS_SIG);
	MAC_GFP_INIT(tmp2, tmp2_dat, MPCONST_POS_SIG);
	MAC_GFP_INIT(tmp3, tmp3_dat, MPCONST_POS_SIG);
	x1 = &P->x;
	y1 = &P->y;
	x3 = &R->x;
	y3 = &R->y;
	p = &ec_ctx->prime;
	a = &ec_ctx->a;
	if ((P->is_O == TRUE) || (MAC_IS_BN_ZERO(*y1))) {
		R->is_O = TRUE;
		return 0;
	}
	/* Use 3x = (a<<1) + a */
	GFP_sqr(&tmp1, x1, p);
	/*-> tmp1 = x1**2 */
	BN_shl_1bit(&tmp2, &tmp1);
	if (BN_comp(&tmp2, p)>0) {
		BN_sub(&tmp2, &tmp2, p);
	}
	GFP_add(&tmp2, &tmp2, &tmp1, p);
	/*-> tmp2 = 3*x1**2 */
	GFP_add(&tmp2, &tmp2, a, p);
	/*-> tmp2 = 3*x1**2 + a */
	BN_shl_1bit(&tmp1, y1);
	if (BN_comp(&tmp1, p)>0) {
		BN_sub(&tmp1, &tmp1, p);
	}
	/*-> tmp1 = 2*y1 */
	GFP_mul_inv(&tmp3, &tmp1, p);
	//GFP_mul_inv(&tmp1,&tmp1,p);
	/*-> tmp1 = (2*y1)**(-1) */
	GFP_mul(&lambda, &tmp3, &tmp2, p);
	/*-> lambda =(3*x1**2 + a )/( 2*y1 ) */
	GFP_sqr(&tmp1, &lambda, p);
	/*-> tmp1 = lambda**2 */
	BN_shl_1bit(&tmp2, x1);
	if (BN_comp(&tmp2, p)>0) {
		BN_sub(&tmp2, &tmp2, p);
	}
	/*-> tmp2 = 2*x1 */
	GFP_sub(&tmp2, &tmp1, &tmp2, p);
	/*-> tmp2 = lambda**2 - 2*x1 */
	GFP_sub(&tmp1, x1, &tmp2, p);
	/*-> tmp1 = x1 - (lambda**2 - 2*x1) */
	GFP_copy(x3, &tmp2);
	/*-> x3 = lambda**2 - 2*x1 */
	GFP_mul(&tmp2, &tmp1, &lambda, p);
	/*-> tmp2 = (x1 - (lambda**2 - 2*x1))*lambda */
	GFP_sub(y3, &tmp2, y1, p);
	/*-> y3 = (x1 - (lambda**2 - 2*x1))*lambda -y1 */
	R->is_O = FALSE;
	return 0;
}

SINT GFP_ECPT_AC_add(GFP_ECPT_AC *R, GFP_EC_CTX *ec_ctx, GFP_ECPT_AC *P, GFP_ECPT_AC *Q)
{
	GFP *x1, *y1, *x2, *y2, *x3, *y3, *p;
	GFP lambda, tmp1, tmp2, tmp3;
	ULONG lambda_dat[MAX_GFP_BUF_LEN], tmp1_dat[MAX_GFP_BUF_LEN],
		tmp2_dat[MAX_GFP_BUF_LEN], tmp3_dat[MAX_GFP_BUF_LEN];
	MAC_GFP_INIT(lambda, lambda_dat, MPCONST_POS_SIG);
	MAC_GFP_INIT(tmp1, tmp1_dat, MPCONST_POS_SIG);
	MAC_GFP_INIT(tmp2, tmp2_dat, MPCONST_POS_SIG);
	MAC_GFP_INIT(tmp3, tmp3_dat, MPCONST_POS_SIG);
	x1 = &P->x;
	y1 = &P->y;
	x2 = &Q->x;
	y2 = &Q->y;
	x3 = &R->x;
	y3 = &R->y;
	p = &ec_ctx->prime;
	/* Check if a is O. */
	if (P->is_O == TRUE) {
		GFP_copy(x3, x2);
		GFP_copy(y3, y2);
		R->is_O = Q->is_O;
		return 0;
	}
	/* Check if b is O. */
	if (Q->is_O == TRUE) {
		GFP_copy(x3, x1);
		GFP_copy(y3, y1);
		R->is_O = P->is_O;
		return 0;
	}
	/* Check if two points are additive invers to each other. */
	if (GFP_comp(x1, x2) != 0) {
		GFP_sub(&tmp1, x2, x1, p);
		GFP_sub(&tmp2, y2, y1, p);
		GFP_mul_inv(&tmp3, &tmp1, p);
		GFP_mul(&lambda, &tmp2, &tmp3, p);
		GFP_sqr(&tmp1, &lambda, p); /* tmp1 = lambda*lambda */
		GFP_sub(&tmp2, &tmp1, x1, p);
		GFP_sub(&tmp1, &tmp2, x2, p);
		GFP_sub(&tmp2, x1, &tmp1, p);
		GFP_copy(x3, &tmp1);
		GFP_mul(&tmp1, &tmp2, &lambda, p);
		GFP_sub(y3, &tmp1, y1, p);
	}
	else {
		if (GFP_comp(y1, y2) == 0) {
			GFP_ECPT_AC_dbl(R, ec_ctx, P);
		}
		else {
			R->is_O = TRUE;
			return 0;
		}
	}
	R->is_O = FALSE;
	return 0;
}

SINT GFP_ECPT_AC_smul(GFP_ECPT_AC *R, GFP_EC_CTX *ec_ctx, BN *n, GFP_ECPT_AC *P)
{
	/*
	Modular exponentiation using Left to right binary exponentiation.
	r = x^e (mod m)
	*/
	SINT n_len, n_bit;
	GFP_ECPT_AC tmp;
	GFP_ECPT_AC_BUF tmp_buf;
	ULONG *n_dat, mask;
	GFP_ECPT_AC_init(&tmp, &tmp_buf);
	n_bit = (BN_nonzero_bits_num(n) - 1) % LONG_BITS;
	mask = 1 << n_bit;
	n_len = n->len;
	n_dat = &((n->dat)[n_len - 1]);
	R->is_O = TRUE;
	while (n_len--) {
		while (mask) {
			GFP_ECPT_AC_dbl(&tmp, ec_ctx, R);
			if ((*n_dat) & mask) {
				GFP_ECPT_AC_add(R, ec_ctx, &tmp, P);
			}
			else {
				GFP_copy(&R->x, &tmp.x);
				GFP_copy(&R->y, &tmp.y);
				R->is_O = tmp.is_O;
			}
			mask >>= 1;
		}
		mask = HIGHER_MSB_ONE;
		n_dat--;
	}
	MAC_CLR_UPPER_ZEROBYTES(R->x);
	MAC_CLR_UPPER_ZEROBYTES(R->y);
	if (MAC_IS_BN_ZERO(R->x))
		R->is_O = TRUE;
	return 0;
}

SINT GFP_EC_IsPT_on(GFP_EC_CTX *ec_ctx, GFP_ECPT_AC *ecpt)
{
	/* Check if given point satisfies the ec. eq. */
	/* Y^2 = X^3 + a*X + b */
	/* OR Y^2 = X*(X^2 + a) + b */
	GFP S, T;
	GFP *x, *y, *a, *b, *p;
	ULONG S_dat[MAX_GFP_BUF_LEN], T_dat[MAX_GFP_BUF_LEN];
	MAC_BN_INIT_MEM_CLR(S, S_dat, MPCONST_POS_SIG);
	MAC_BN_INIT_MEM_CLR(T, T_dat, MPCONST_POS_SIG);
	a = &ec_ctx->a; b = &ec_ctx->b; p = &ec_ctx->prime;
	x = &ecpt->x; y = &ecpt->y;
	/* right side of the eq. */
	GFP_sqr(&S, x, p);
	GFP_add(&T, &S, a, p);
	GFP_mul(&S, &T, x, p);
	GFP_add(&T, &S, b, p);
	/* left side of the eq. */
	GFP_sqr(&S, y, p);
	/* Compare two sides */
	if (GFP_comp(&S, &T) == 0)
		return TRUE;
	else
		return FALSE;
}
