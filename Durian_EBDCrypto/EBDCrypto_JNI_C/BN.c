#include "EBDerror.h"
#include "EBDCrypto.h"

#define TRUE 1
#define FALSE 0

#define MPCONST_POS_SIG 1
#define MPCONST_NEG_SIG -1
#define MPCONST_ZERO_SIG 0

#define BITMASK_HIGHER_LONG 0xffff0000
#define BITMASK_LOWER_LONG 0x0000ffff
#define BITMASK_LONG 0xffffffff

#define HIGHER_MSB_ONE 0x80000000
#define HIGHER_LSB_ONE 0x00010000
#define LOWER_MSB_ONE 0x00008000
#define LOWER_LSB_ONE 0x00000001

#define HALF_LONG_BITS 16
#define LONG_BITS 32

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

#define MAC_CLR_UPPER_ZEROBYTES(x) \
{ \
	ULONG *__pl; \
	for(__pl= &((x).dat[(x).len-1]); (x).len > 0; (x).len--) \
	if(*(__pl--)) break; \
	}

#define MAC_MAX(x,y) (((x)>=(y))? (x):(y))
#define MAC_MULT2EXP(a,e) ((a)<<(e))

#define MAC_IS_BN_ZERO(x) ((x).len == 0 || (((x).len <= 1) && ((x).dat[0] == 0)))
#define MAC_IS_BN_ONE(x) ((x).len == 1 && (x).dat[0] == 1)
#define MAC_IS_POSITIVE_INTEGER(x) ((x).sig == MPCONST_POS_SIG)

#define MAC_MAKE_ONE(x) { (x).sig = MPCONST_POS_SIG;(x).len = 1;(x).dat[0]= 1; }
#define MAC_MAKE_ZERO(x) { (x).sig = MPCONST_ZERO_SIG;(x).len = 0;(x).dat[0]= 0; }

#define MAC_LW(x) ((x) & BITMASK_LOWER_LONG)
#define MAC_HW(x) (((x) & BITMASK_HIGHER_LONG)>>HALF_LONG_BITS)

#define BN_mul(c,a,b) BN_plain_mul(c,a,b)
#define BN_sqr(c,a) BN_plain_sqr(c,a)

static SCHAR bits_to_index[256] = {
	0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
	6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
	7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
	7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
	8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
	8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
	8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
	8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
};

//#define _MAC_64BIT_
#if defined(_MAC_64BIT_)
/**********************************/
/* ū �� ������ ���� Macro �Լ� */
/**********************************/
/* (d,c) = (a*b)+d */
#define MAC_ULONG_MULT(/* ULONG */a,/* ULONG */b,/* ULONG */c,/* ULONG */d) \
{\
	UINT64 __x1;\
	__x1 = (UINT64)(a)*(UINT64)(b);\
	__x1 = __x1+(UINT64)(d);\
	(d) = __x1>>LONG_BITS;\
	(c) = __x1&BITMASK_LONG;\
}
/* (d,c) = (a*b)+c+d */
#define MAC_ULONG_MULT_ADD(/* ULONG */a,/* ULONG */b,/* ULONG */c,/* ULONG */d) \
{\
	UINT64 __x1;\
	__x1 = (UINT64)(a)*(UINT64)(b);\
	__x1 = __x1+(UINT64)(d);\
	__x1 = __x1+(UINT64)(c);\
	(d) = __x1>>LONG_BITS;\
	(c) = __x1&BITMASK_LONG;\
}
/* (c,b) = a*a */
#define MAC_ULONG_SQUARE(/*(ULONG)*/ a,/*(ULONG)*/ b,/*(ULONG)*/ c) \
{\
	UINT64 __x1;\
	__x1 = (UINT64)(a)*(UINT64)(a);\
	(c) = __x1>>LONG_BITS;\
	(b) = __x1&BITMASK_LONG;\
}
#else
#define MAC_ULONG_MULT(/* ULONG */a,/* ULONG */b,/* ULONG */c,/* ULONG */d) \
{\
	ULONG __x1,__x2,__x3,__x4;\
	__x1 = MAC_LW(a)*MAC_LW(b);\
	__x2 = MAC_LW(a)*MAC_HW(b);\
	__x3 = MAC_HW(a)*MAC_LW(b);\
	__x4 = MAC_HW(a)*MAC_HW(b);\
	__x2 += __x3;\
	if(__x2 < __x3) __x4 += HIGHER_LSB_ONE;\
	__x4 += MAC_HW(__x2);\
	__x3 = MAC_LW(__x2)<<HALF_LONG_BITS;\
	__x1 += __x3;\
	if(__x1 < __x3) __x4++;\
	__x1 += (d);\
	if( __x1 < (d)) __x4++;\
	(d) = __x4;\
	(c) = __x1;\
}
#define MAC_ULONG_MULT_ADD(/* ULONG */a,/* ULONG */b,/* ULONG */c,/* ULONG */d) \
{\
	ULONG __x1,__x2,__x3,__x4;\
	__x1 = MAC_LW(a)*MAC_LW(b);\
	__x2 = MAC_LW(a)*MAC_HW(b);\
	__x3 = MAC_HW(a)*MAC_LW(b);\
	__x4 = MAC_HW(a)*MAC_HW(b);\
	__x2 += __x3;\
	if(__x2 < __x3) __x4 += HIGHER_LSB_ONE; \
	__x4 += MAC_HW(__x2);\
	__x3 = MAC_LW(__x2)<<HALF_LONG_BITS;\
	__x1 += __x3;\
	if(__x1 < __x3) __x4++;\
	__x1 += (d);\
	if( __x1 < (d)) __x4++;\
	__x1 += (c);\
	if( __x1 < (c)) __x4++;\
	(d) = __x4;\
	(c) = __x1;\
}
#define MAC_ULONG_SQUARE(/*(ULONG)*/ a,/*(ULONG)*/ b,/*(ULONG)*/ c) \
{\
	ULONG __h,__m,__l;\
	__l = MAC_LW(a);\
	__h = MAC_HW(a);\
	__m = __l*__h;\
	__h *= __h;\
	__l *= __l;\
	__h += __m >> (HALF_LONG_BITS - 1);\
	__m = __m << (HALF_LONG_BITS + 1);\
	__l += __m;\
	if( __l < __m ) __h++;\
	b = __l;\
	c = __h;\
}
#endif/*}_MAC_64BIT_*/

/**************************************/
/* ū �� ������ ���� �⺻ ���� �Լ� */
/**************************************/
/**********************************************************************
* �� �� �� : BN_copy
*
* �Լ����� :
* *dest - ��¹��� ū �� dest�� ������
* *src - �Է¹��� ū �� src�� ������
* Return :
* 0 - src�� 0�� 0 ��ȯ
* i - src�� ���� ��ȯ
*
*---------------------------------------------------------------------
* �Լ����� : ū �� src�� dest�� �����ϴ� �Լ�
***********************************************************************/
SINT BN_copy(BN *dest, BN *src)
{
	SINT i, src_len;
	ULONG *dest_datp, *src_datp;
	if (MAC_IS_BN_ZERO(*src)) {
		MAC_MAKE_ZERO(*dest);
		return 0;
	}
	src_len = src->len;
	dest_datp = dest->dat;
	src_datp = src->dat;
	for (i = 0; i < src_len; i++) {
		(dest->dat)[i] = (src->dat)[i];
	}
	dest->sig = src->sig;
	dest->len = src->len;
	return i;
}

/***********************************************************************
* �� �� �� : BN_shl_1bit
*
* �Լ����� :
* *b - ��¹��� ū �� b�� ������
* *a - �Է¹��� ū �� a�� ������
* Return :
* 0 - ����
*
*----------------------------------------------------------------------
* �Լ����� : ū �� a�� 1��Ʈ left shift�Ͽ� b�� �����ϴ� �Լ�
************************************************************************/
SINT BN_shl_1bit(BN *b, BN *a)
{
	ULONG c, *a_datp, *b_datp, tmp;
	SINT i;
	c = 0;
	a_datp = a->dat;
	b_datp = b->dat;
	b->sig = a->sig;
	b->len = a->len;
	for (i = 0; i < a->len; i++)
	{
		tmp = *(a_datp++);
		*(b_datp++) = (tmp << 1) | c;
		c = (tmp & HIGHER_MSB_ONE) ? 1 : 0;
	}
	if (c)
	{
		*b_datp = 1;
		b->len++;
	}
	return 0;
}

/***********************************************************************
* �� �� �� : BN_shl
*
* �Լ����� :
* *r - ��¹��� ū �� r�� ������
* *a - �Է¹��� ū �� a�� ������
* n - �̵��� ��Ʈ�� ����
* Return :
* 0 - ����
*
*----------------------------------------------------------------------
* �Լ����� : ū �� a�� n��Ʈ left shift�Ͽ� r�� �����ϴ� �Լ�
************************************************************************/
SINT BN_shl(BN *r, BN *a, SINT n)
{
	SINT i, nw, lb, rb;
	ULONG *t, *f;
	ULONG l;
	r->sig = a->sig;
#if 0
	nw = n / LONG_BITS;
	lb = n % LONG_BITS;
#else
	nw = n / LONG_BITS;
	lb = n - nw*LONG_BITS;
#endif
	rb = LONG_BITS - lb;
	f = a->dat;
	t = r->dat;
	t[a->len + nw] = 0;
	if (lb == 0) {
		for (i = a->len - 1; i >= 0; i--)
			t[nw + i] = f[i];
	}
	else {
		for (i = a->len - 1; i >= 0; i--)
		{
			l = f[i];
			t[nw + i + 1] |= (l >> rb) & BITMASK_LONG;
			t[nw + i] = (l << lb) & BITMASK_LONG;
		}
	}
	memset(t, 0, nw * sizeof(t[0]));
	r->len = a->len + nw + 1;
	MAC_CLR_UPPER_ZEROBYTES(*r);
	return 0;
}

/***********************************************************************
* �� �� �� : BN_shr
*
* �Լ����� :
* *r - ��¹��� ū �� r�� ������
* *a - �Է¹��� ū �� a�� ������
* n - �̵��� ��Ʈ�� ����
* Return :
* 0 - ����
*
*----------------------------------------------------------------------
* �Լ����� : ū �� a�� n��Ʈ right shift�Ͽ� r�� �����ϴ� �Լ�
************************************************************************/
SINT BN_shr(BN *r, BN *a, SINT n)
{
	SINT i;
	SINT nw, nb;
	ULONG *rd, *ad;
	ULONG l, t;
#if 0
	nw = n / LONG_BITS;
	nb = n % LONG_BITS;
#else
	nw = n / LONG_BITS;
	nb = n - nw*LONG_BITS;
#endif
	if (nw > a->len) {
		MAC_CLR_UPPER_ZEROBYTES(*r);
		return 0;
	}
	if (r != a)
		r->sig = a->sig;
	ad = &(a->dat[nw]);
	rd = r->dat;
	r->len = a->len - nw;
	if (nb == 0) {
		for (i = a->len - nw; (SINT)i > 0; i--)
			*(rd++) = *(ad++);
	}
	else {
		l = *(ad++);
		for (i = 1; i < a->len - nw; i++) {
			t = (l >> nb) & BITMASK_LONG;
			l = *(ad++);
			*(rd++) = t | ((l << (LONG_BITS - nb)) & BITMASK_LONG);
		}
		*(rd++) = (l >> nb) & BITMASK_LONG;
	}
	*rd = 0;
	MAC_CLR_UPPER_ZEROBYTES(*r);
	return 0;
}

/***********************************************************************
* �� �� �� : BN_nonzero_bits_num
*
* �Լ����� :
* *a - �Է¹��� ū �� a�� ������
* Return :
* ��� - a�� ��Ʈ ���� ��ȯ
*
*----------------------------------------------------------------------
* �Լ����� : ū �� a�� ��Ʈ ���̸� ��ȯ�ϴ� �Լ�
************************************************************************/
SINT BN_nonzero_bits_num(BN *a)
{
	/*
	This function is fixed to 32-bit processor.
	If you work with another-bits processor, customize the codes.
	*/
	ULONG l;
	SINT i;
	if (a->len == 0)
		return(0);
	l = a->dat[a->len - 1];
	i = (a->len - 1) * 32;
	if ((l == 0) && (a->len - 1 == 0)) {
		MAC_CLR_UPPER_ZEROBYTES(*a);
		l = a->dat[a->len - 1];
		i = (a->len - 1) * 32;
	}
	if (l & 0xffff0000L)
	{
		if (l & 0xff000000L)
			return(i + bits_to_index[l >> 24L] + 24);
		else
			return(i + bits_to_index[l >> 16L] + 16);
	}
	else {
		if (l & 0xff00L)
			return(i + bits_to_index[l >> 8] + 8);
		else
			return(i + bits_to_index[l]);
	}
}

/*********************/
/* ū �� ���� �Լ� */
/*********************/
/***********************************************************************
* �� �� �� : BN_abs_comp
*
* �Լ����� :
* *a - �Է¹��� ū �� a�� ������
* *b - �Է¹��� ū �� b�� ������
* Return :
* 1 - |a| > |b|�� ���
* 0 - |a| = |b|�� ���
* -1 - |a| < |b|�� ���
*
*----------------------------------------------------------------------
* �Լ����� : �� ū �� a�� b�� ���밪�� ũ�⸦ ���ϴ� �Լ�
************************************************************************/
SINT BN_abs_comp(BN *a, BN *b)
{
	SINT i, cmplen;
	ULONG *a_datp, *b_datp;
	if (cmplen = a->len - b->len)
		return ((cmplen > 0) ? 1 : -1);
	a_datp = a->dat;
	b_datp = b->dat;
	for (i = a->len - 1; i >= 0; i--) {
		if (a_datp[i] != b_datp[i]) {
			return ((a_datp[i] > b_datp[i]) ? 1 : -1);
		}
	}
	return 0;
}
/***********************************************************************
* �� �� �� : BN_comp
*
* �Լ����� :
* *a - �Է¹��� ū �� a�� ������
* *b - �Է¹��� ū �� b�� ������
* Return :
* 1 or 2 - a > b�� ���
* 0 - a = b�� ���
* -1 or -2 - a < b�� ���
*
*----------------------------------------------------------------------
* �Լ����� : �� ū �� a�� b�� ũ�⸦ ���ϴ� �Լ�
************************************************************************/
SINT BN_comp(BN *a, BN *b)
{
	if (a->sig == b->sig) {
		if (a->sig == 0)
			return 0; /* the case a=b=0 */
		else
			return (a->sig) * BN_abs_comp(a, b);
	}
	else {
		return a->sig - b->sig;
	}
}

/***********************************************************************
* �� �� �� : BN_add_ULONG
*
* �Լ����� :
* *c - ��¹��� ū �� c�� ������
* *a - �Է¹��� ū �� a�� ������
* b - �Է¹��� ��� b�� ������ ����
* Return :
* 0 - ����
*
*----------------------------------------------------------------------
* �Լ����� : ū �� a�� ��� b�� ���� ���� �Լ� (c = a+b),
a�� c�� ���� �ٸ� �����͸� ������ ��
************************************************************************/
SINT BN_add_ULONG(BN *c, BN *a, ULONG b)
{
	SINT i;
	ULONG *a_datp,*c_datp;
	i = 0;
	a_datp = a->dat;
	c_datp = c->dat;
	c_datp[i] = a_datp[i] + b;
	while(i < a->len)
		if(c_datp[i] < a_datp[i++])
			c_datp[i] = a_datp[i] + 1;
		else
			c_datp[i] = a_datp[i];
	c->len = i;
	return 0;
}

/***********************************************************************
* �� �� �� : BN_asym_add
*
* �Լ����� :
* *c - ��¹��� ū �� c�� ������
* *a - �Է¹��� ū �� a�� ������
* *b - �Է¹��� ū �� b�� ������
* Return :
* 0 - ����
*
*----------------------------------------------------------------------
* �Լ����� : ū �� a�� b�� ���밪�� ���� ���� �Լ� (c = a+b),
a>=b ������ �����Ͽ��� ��
************************************************************************/
SINT BN_asym_add(BN *c, BN *a, BN *b)
{
	/*
	asymmetric unsigned addition:c = a+b, a >=b and input can be output
	*/
	ULONG carry, tmp;
	SINT i, a_len, b_len;
	ULONG *a_datp, *b_datp, *c_datp;
	a_len = a->len;
	b_len = b->len;
	a_datp = a->dat;
	b_datp = b->dat;
	c_datp = c->dat;
	carry = 0;
	for (i = 0; i < b_len; i++) {
		tmp = a_datp[i];
		c_datp[i] = tmp + b_datp[i] + carry;
		carry = tmp > c_datp[i] - carry;
	}
	if (carry) {
		for (; i< a_len; i++) {
			tmp = a_datp[i];
			c_datp[i] = tmp + carry;
			//carry = (tmp > c_datp[i]);
			if (tmp > c_datp[i]) carry = 1;
			else carry = 0;
		}
		if (carry) {
			c_datp[i] = 1;
			i++;
		}
	}
	else {
		for (; i< a_len; i++)
			c_datp[i] = a_datp[i];
	}
	c->len = i;
	return 0;
}

/***********************************************************************
* �� �� �� : BN_asym_sub
*
* �Լ����� :
* *c - ��¹��� ū �� c�� ������
* *a - �Է¹��� ū �� a�� ������
* *b - �Է¹��� ū �� b�� ������
* Return :
* 0 - ����
*
*----------------------------------------------------------------------
* �Լ����� : ū �� a�� b�� ���밪�� ���� ���� �Լ� (c = a-b),
a>=b ������ �����Ͽ��� ��
************************************************************************/
SINT BN_asym_sub(BN *c, BN *a, BN *b)
{
	/*
	asymmetric unsigned subtraction :c = a-b, a >=b and input can be output.
	*/
	ULONG borrow;
	SINT i, a_len, b_len;
	ULONG *a_datp, *b_datp, *c_datp;
	borrow = 0;
	a_len = a->len;
	b_len = b->len;
	a_datp = a->dat;
	b_datp = b->dat;
	c_datp = c->dat;
	for (i = 0; i < b->len; i++) {
		if (borrow) {
			borrow = a_datp[i] <= b_datp[i];
			c_datp[i] = a_datp[i] - b_datp[i] - 1;
		}
		else {
			borrow = a_datp[i] < b_datp[i];
			c_datp[i] = a_datp[i] - b_datp[i];
		}
	}
	if (borrow)
	{
		for (; a_datp[i] == 0; i++) {
			c_datp[i] = a_datp[i] - 1;
			if (i >= a_len - 1) break;
		}
		c_datp[i] = a_datp[i] - 1;
		i++;
	}
	if (a->len > i)
		memcpy((SCHAR*)&(c_datp[i]), (SCHAR*)&(a_datp[i]), sizeof(ULONG)*(a_len - i));
	c->len = a->len;
	return 0;
}

/***********************************************************************
* �� �� �� : BN_add
*
* �Լ����� :
* *c - ��¹��� ū �� c�� ������
* *a - �Է¹��� ū �� a�� ������
* *b - �Է¹��� ū �� b�� ������
* Return :
* 0 - ����
*
*----------------------------------------------------------------------
* �Լ����� : ū �� a�� b�� ���� ���� �Լ� (c = a+b),
************************************************************************/
SINT BN_add(BN *c, BN *a, BN *b)
{
	/*
	addition:c = a+b, input can be output
	*/
	SINT sigx;
	sigx = a->sig * b->sig;
	if (sigx >= 0) {
		if (a->len >= b->len) {
			BN_asym_add(c, a, b);
			c->sig = a->sig;
		}
		else {
			BN_asym_add(c, b, a);
			c->sig = b->sig;
		}
	}
	else {
		if ((sigx = BN_abs_comp(a, b)) >= 0) {
			BN_asym_sub(c, a, b);
			c->sig = a->sig;
		}
		else if (sigx < 0) {
			BN_asym_sub(c, b, a);
			c->sig = b->sig;
		}
	}
	return 0;
}
/***********************************************************************
* �� �� �� : BN_sub
*
* �Լ����� :
* *c - ��¹��� ū �� c�� ������
* *a - �Է¹��� ū �� a�� ������
* *b - �Է¹��� ū �� b�� ������
* Return :
* 0 - ����
*
*----------------------------------------------------------------------
* �Լ����� : ū �� a�� b�� ���� ���� �Լ� (c = a-b),
************************************************************************/
SINT BN_sub(BN *c, BN *a, BN *b)
{
	/*
	subtraction:c = a-b, input can be output
	*/
	SINT sigx;
	sigx = a->sig*b->sig;
	if (sigx <= 0) {
		if (a->len >= b->len) {
			BN_asym_add(c, a, b);
		}
		else {
			BN_asym_add(c, b, a);
		}
		c->sig = (a->sig != 0) ? a->sig : -b->sig;
	}
	else {
		if (BN_abs_comp(a, b) >= 0) {
			BN_asym_sub(c, a, b);
			c->sig = a->sig;
		}
		else {
			BN_asym_sub(c, b, a);
			c->sig = -b->sig;
		}
	}
	MAC_CLR_UPPER_ZEROBYTES(*c);
	return 0;
}

/***********************************************************************
* �� �� �� : BN_mult_ULONG
*
* �Լ����� :
* *c - ��¹��� ū �� c�� ������
* *a - �Է¹��� ū �� a�� ������
* b - �Է¹��� ��� b�� ������ ����
* Return :
* 0 - ����
*
*----------------------------------------------------------------------
* �Լ����� : ū �� a�� ��� b�� ���� ���� �Լ� (c = a*b),
* �� ū �� a�� c�� ���� �ٸ� �����͸� ������ ��
************************************************************************/
SINT BN_mult_ULONG(BN *c, BN *a, ULONG b)
{
	/*
	a and c MUST be different BNs
	*/
	ULONG higher;
	SINT i, a_len;
	ULONG *a_datp, *c_datp;
	higher = 0;
	a_len = a->len;
	a_datp = a->dat;
	c_datp = c->dat;
	for (i = 0; i<a_len; i++) {
		MAC_ULONG_MULT(a_datp[i], b, c_datp[i], higher);
	}
	if (higher) {
		c_datp[i] = higher;
		c->len = i + 1;
	}
	else {
		c->len = i;
	}
	return 0;
}

/*************************************************************************
* �� �� �� : BN_mult_ULONG_add
*
* �Լ����� :
* *c - ��¹��� ū �� c�� ������
* *a - �Է¹��� ū �� a�� ������
* b - �Է¹��� ��� b�� ������ ����
* Return :
* 0 - ����
*
*-------------------------------------------------------------------------
* �Լ����� : ū �� a�� ��� b�� ������ c�� �����ϴ� �Լ� (c = (a*b) + c),
* �� ū �� a�� c�� ���� �ٸ� �����͸� ������ ��
**************************************************************************/
SINT BN_mult_ULONG_add(BN *c, BN *a, ULONG b)
{
	/*
	a and c MUST be different BNs
	And c is assumed to be evaluated outside aleady!
	*/
	ULONG higher, tmp;
	SINT i, a_len, c_len;
	ULONG *a_datp, *c_datp;
	higher = 0;
	a_len = a->len;
	c_len = c->len;
	a_datp = a->dat;
	c_datp = c->dat;
	if (c_len <= a_len) {
		for (i = a_len; i >= c_len; i--) {
			c_datp[i] = 0;
		}
	}/*Bug fixed: Check out of range of 'c'. */
	for (i = 0; i<a_len; i++) {
		MAC_ULONG_MULT_ADD(a_datp[i], b, c_datp[i], higher);
	}
	tmp = c_datp[i] + higher;
	higher = (tmp < c_datp[i]);
	if (higher) {
		c_datp[i] = tmp;
		i++;
		while (1) {
			tmp = c_datp[i] + 1;
			if (tmp > c_datp[i]) {
				c_datp[i] = tmp;
				break;
			}
			c_datp[i] = tmp;
			i++;
		}
	}
	else {
		c_datp[i] = tmp;
	}
	c->len = MAC_MAX(i + 1/* when c->len <= a->len */, c->len);
	return 0;
}

/*************************************************************************
* �� �� �� : BN_plain_mul
*
* �Լ����� :
* *c - ��¹��� ū �� c�� ������
* *a - �Է¹��� ū �� a�� ������
* *b - �Է¹��� ū �� b�� ������
* Return :
* 0 - ����
*
*-------------------------------------------------------------------------
* �Լ����� : �� ū �� a�� b�� ���� ���� �Լ� (c = a*b),
* �� ū �� a, b�� c�� ���� �ٸ� �����͸� ������ ��
**************************************************************************/
SINT BN_plain_mul(BN *c, BN *a, BN *b)
{
	/*
	a and c MUST be different BNs
	*/
	SINT i, b_len;
	BN tc;
	ULONG *b_datp;
	b_len = b->len;
	b_datp = b->dat;
	memset(c->dat, 0, ((a->len + b->len) << 2) + 4);
	c->sig = a->sig * b->sig;
	c->len = a->len + b->len;
	tc.dat = c->dat;
	BN_mult_ULONG(&tc, a, b_datp[0]);
	tc.dat++;
	tc.len--;
	for (i = 1; i < b_len; i++) {
		BN_mult_ULONG_add(&tc, a, b_datp[i]);
		tc.dat++;
	}
	MAC_CLR_UPPER_ZEROBYTES(*c);
	return 0;
}

/*************************************************************************
* �� �� �� : BN_plain_sqr
*
* �Լ����� :
* *b - ��¹��� ū �� b�� ������
* *a - �Է¹��� ū �� a�� ������
* Return :
* 0 - ����
*
*-------------------------------------------------------------------------
* �Լ����� : ū �� a�� ���� ���� �Լ� (b = a^2),
* ū �� a�� c�� ���� �ٸ� �����͸� ������ ��
**************************************************************************/
SINT BN_plain_sqr(BN *b, BN *a)
{
	/*
	a and b MUST be different BNs
	*/
	SINT i, j, k;
	SINT m, n;
	ULONG higher;
	ULONG carry, tmp, *a_datp, *b_datp;
	ULONG tmp_dat[MAX_BN_BUF_LEN];
	m = a->len;
	n = (m << 1) - 1;
	carry = 0;
	a_datp = a->dat;
	b_datp = b->dat;
	memset((SCHAR*)tmp_dat, 0, (a->len << 3) + 4);
	for (i = 0; i < m; i++) {
		MAC_ULONG_SQUARE(a_datp[i], b_datp[i << 1], b_datp[(i << 1) + 1]);
	}
	/* k MUST be initialized as ZERO since k may not be evaluated in the loop when m = 1 */
	k = 0;
	for (i = 0; i < m; i++) {
		higher = 0;
		for (j = i + 1; j < m; j++) {
			k = i + j;
			MAC_ULONG_MULT_ADD(a_datp[i], a_datp[j], tmp_dat[k], higher);
		}
		tmp_dat[k + 1] += higher;
	}
	/* ' * 2 ' can be replaced by shift-left one bit */
	n++;
	for (i = n; i > 0; i--) {
		tmp_dat[i] = tmp_dat[i] << 1;
		if (tmp_dat[i - 1] & HIGHER_MSB_ONE) {
			tmp_dat[i] |= LOWER_LSB_ONE;
		}
	}
	tmp_dat[0] = tmp_dat[0] << 1;
	for (i = 0; i <= n; i++) {
		tmp = tmp_dat[i];
		b_datp[i] += tmp + carry;
		carry = tmp > b_datp[i];
	}
	b->sig = MPCONST_POS_SIG;
	b->len = n;
	MAC_CLR_UPPER_ZEROBYTES(*b);
	return 0;
}

/*************************************************************************
* �� �� �� : BN_ULONG_div
*
* �Լ����� :
* h - ���� ���尪 h�� ������ ����
* l - ���� ���尪 l�� ������ ����
* d - devider d�� ������ ����
* Return :
* ��� - �������� �� �� ��ȯ
*
*-------------------------------------------------------------------------
* �Լ����� : �� ������ �� hl�� d�� ���� ���� ���ϴ� �Լ� (q = hl/d)
**************************************************************************/
ULONG BN_ULONG_div(ULONG h, ULONG l, ULONG d)
{
	ULONG dh, dl, q, ret = 0, th, tl, t;
	SINT i, count = 2;
	if (d == 0)
		return(BITMASK_LONG);
	MAC_NONZERO_BITS_NUM_ULONG(d, i);
	i = LONG_BITS - i;
	if (h >= d)
		h -= d;
	if (i)
	{
		d <<= i;
		h = (h << i) | (l >> (LONG_BITS - i));
		l <<= i;
	}
	dh = (d & BITMASK_HIGHER_LONG) >> HALF_LONG_BITS;
	dl = (d & BITMASK_LOWER_LONG);
	for (;;)
	{
		if ((h >> HALF_LONG_BITS) == dh)
			q = BITMASK_LOWER_LONG;
		else
			q = h / dh;
		for (;;)
		{
			t = (h - q * dh);
			if ((t & BITMASK_HIGHER_LONG) ||
				((dl * q) <= (
					(t << HALF_LONG_BITS) +
					((l & BITMASK_HIGHER_LONG) >> HALF_LONG_BITS))))
				break;
			q--;
		}
		th = q * dh;
		tl = q * dl;
		t = (tl >> HALF_LONG_BITS);
		tl = (tl << HALF_LONG_BITS) & BITMASK_HIGHER_LONG;
		th += t;
		if (l < tl)
			th++;
		l -= tl;
		if (h < th)
		{
			h += d;
			q--;
		}
		h -= th;
		if (--count == 0)
			break;
		ret = q << HALF_LONG_BITS;
		h = ((h << HALF_LONG_BITS) | (l >> HALF_LONG_BITS)) & BITMASK_LONG;
		l = (l & BITMASK_LOWER_LONG) << HALF_LONG_BITS;
	}
	ret |= q;
	return(ret);
}
/*************************************************************************
* �� �� �� : BN_div
*
* �Լ����� :
* *c - ��¹��� ū �� c�� ������
* *d - ��¹��� ū �� d�� ������
* *a - �Է¹��� ū �� a�� ������
* *b - �Է¹��� ū �� b�� ������
* Return :
* 0 - ����
*
*-------------------------------------------------------------------------
* �Լ����� : ū �� a�� b�� ������ ���� �Լ� (a = (b*c) +d)
* a:dividend
* b:devider
* c:quotient --> ���� ��ȣ�� a*b�� ��������.
* d:residue --> �������� ��ȣ�� a�� ��������.
* ��) a = 10, b = 7 --> 10 = 1*7 -3
* a = -10, b = 7 --> -10 = (-1)*7 -3
* a = 10, b = -7 --> 10 = (-1)*(-7) +3
* a = -10, b = -7 --> -10 = 1*(-7) -3
* ū �� a, b, c�� d�� ���� �ٸ� �����͸� ������ ��
**************************************************************************/
SINT BN_div(BN *c, BN *d, BN *a, BN *b)
{
	SINT normbits;
	BN dvder, dvdnd, window, tmp_dvdnd;
	ULONG dvder_dat[MAX_BN_BUF_LEN], dvdnd_dat[MAX_BN_BUF_LEN],
		tmp_dvdnd_dat[MAX_BN_BUF_LEN], *c_datp, *window_datp;
	UINT dvder1st, dvder2nd, tmp_quota, x3, x2, x1;
	SINT i;
	SINT cmp_result;
	SINT loop;
	dvder.dat = dvder_dat;
	dvdnd.dat = dvdnd_dat;
	tmp_dvdnd.dat = tmp_dvdnd_dat;
	/* For trivial cases */
	cmp_result = BN_abs_comp(b, a);
	if (cmp_result > 0) {
		//BN_copy(a,d);
		BN_copy(d, a);
		//_BN_make_0(*c);
		MAC_MAKE_ZERO(*c);
		return 0;
	}
	else if (cmp_result == 0) {
		//_BN_make_0(*d);
		MAC_MAKE_ZERO(*d);
		//_BN_make_1(*c);
		MAC_MAKE_ONE(*c);
		return 0;
	}
	/* normalization of the dividend and the dvider */
	normbits = LONG_BITS - (BN_nonzero_bits_num(b) % LONG_BITS);

	BN_shl(&dvder, b, normbits);
	normbits += LONG_BITS;

	BN_shl(&dvdnd, a, normbits);
	loop = dvdnd.len - dvder.len;
	window.dat = &(dvdnd.dat[loop]);
	window.len = dvder.len;
	window_datp = &(dvdnd.dat[dvdnd.len - 1]);
	dvder1st = dvder.dat[dvder.len - 1];
	dvder2nd = (dvder.len == 1) ? 0 : dvder.dat[dvder.len - 2];
	c->len = loop;
	c_datp = &(c->dat[loop - 1]);

	cmp_result = BN_abs_comp(&window, &dvder);
	if (cmp_result >= 0) {
		BN_asym_sub(&window, &window, &dvder);
		*c_datp = 1;
	}
	else
		c->len--;
	c_datp--;
	for (i = 0; i < loop - 1; i++) {
		UINT window1st, window2nd;
		window.dat--;
		window.len++;
		window1st = window_datp[0];
		window2nd = window_datp[-1];
		if (window1st == dvder1st)
			tmp_quota = BITMASK_LONG;
		else
			tmp_quota = BN_ULONG_div(window1st, window2nd, dvder1st);
		for (;;) {
			x3 = 0; x2 = 0; /* must be initialized every time */
			MAC_ULONG_MULT(dvder2nd, tmp_quota, x1, x2);
			MAC_ULONG_MULT_ADD(dvder1st, tmp_quota, x2, x3);
			if (window_datp[0] > x3) break;
			if (window_datp[0] == x3) {
				if (window_datp[-1] > x2) break;
				if (window_datp[-1] == x2) {
					if (window_datp[-2] >= x1) break;
				}
			}
			tmp_quota--;
		}
		//BN_UWORD_mul(&dvder,tmp_quota,&tmp_dvdnd);
		BN_mult_ULONG(&tmp_dvdnd, &dvder, tmp_quota);
		MAC_CLR_UPPER_ZEROBYTES(tmp_dvdnd);
		if (/*BN_ucomp(&window,&tmp_dvdnd)*/BN_abs_comp(&window, &tmp_dvdnd) >= 0) {
			BN_asym_sub(&window, &window, &tmp_dvdnd);
			if (window_datp[0]) {
				BN_asym_sub(&window, &window, &dvder);
				tmp_quota++;
			}
		}
		else {
			/* DO NOT change the order of operations */
			if (window.len >= dvder.len)
				BN_asym_add(&window, &window, &dvder);
			else
				BN_asym_add(&window, &dvder, &window);
			BN_asym_sub(&window, &window, &tmp_dvdnd);
			tmp_quota--;
		}
		*(c_datp--) = tmp_quota;
		window_datp--;
	}
	BN_shr(d, &dvdnd, normbits);
	if (MAC_IS_BN_ZERO(*d)) {
		d->sig = MPCONST_ZERO_SIG;
	}
	else {
		d->sig = a->sig;
	}
	c->sig = a->sig*b->sig;
	return 0;
}

/*****************************/
/* ū �� modular ���� �Լ� */
/*****************************/
/*************************************************************************
* �� �� �� : BN_mod
*
* �Լ����� :
* *r - ��¹��� ū �� r�� ������
* *a - �Է¹��� ū �� a�� ������
* *m - �Է¹��� ū �� m�� ������
* Return :
* 0 - ����
*
*-------------------------------------------------------------------------
* �Լ����� : ū �� a�� m ���� modular ���� �Լ� (r = a mod m),
* Modulus m�� �׻� ����� ���� (m�� ������ m = |m|)
**************************************************************************/
SINT BN_mod(BN *r, BN *a, BN *m)
{
	BN tmp;
	ULONG tmp_dat[MAX_BN_BUF_LEN];
	MAC_BN_INIT_MEM_CLR(tmp, tmp_dat, 1);
	BN_div(&tmp, r, a, m);
	if (r->sig == MPCONST_NEG_SIG) BN_add(r, r, m);
	return 0;
}

/*******************************************************************************
* �� �� �� : BN_add_mod
*
* �Լ����� :
* *r - ��¹��� ū �� r�� ������
* *a - �Է¹��� ū �� a�� ������
* *b - �Է¹��� ū �� b�� ������
* *m - �Է¹��� ū �� m�� ������
* Return :
* 0 - ����
*
*-------------------------------------------------------------------------------
* �Լ����� : ū �� a�� b�� ���� ����� m���� modular �ϴ� �Լ� (r = a+b mod m),
* Modulus m�� �׻� ����� ���� (m�� ������ m = |m|)
********************************************************************************/
SINT BN_add_mod(BN *r, BN *a, BN *b, BN *m)
{
	BN_add(r, a, b);
	BN_mod(r, r, m);
	return 0;
}

/*******************************************************************************
* �� �� �� : BN_mul_mod
*
* �Լ����� :
* *r - ��¹��� ū �� r�� ������
* *a - �Է¹��� ū �� a�� ������
* *b - �Է¹��� ū �� b�� ������
* *m - �Է¹��� ū �� m�� ������
* Return :
* 0 - ����
*
*-------------------------------------------------------------------------------
* �Լ����� : ū �� a�� b�� ���� ����� m���� modular �ϴ� �Լ� (r = a*b mod m),
* Modulus m�� �׻� ����� ���� (m�� ������ m = |m|),
* ū �� a, b�� r�� ���� �ٸ� �����͸� ������ ��
********************************************************************************/
SINT BN_mul_mod(BN *r, BN *a, BN *b, BN *m)
{
	BN_mul(r, a, b);
	BN_mod(r, r, m);
	return 0;
}
/*******************************************************************************
* �� �� �� : BN_sqr_mod
*
* �Լ����� :
* *r - ��¹��� ū �� r�� ������
* *a - �Է¹��� ū �� a�� ������
* *m - �Է¹��� ū �� m�� ������
* Return :
* 0 - ����
*
*-------------------------------------------------------------------------------
* �Լ����� : ū �� a�� ���� ����� m���� modular �ϴ� �Լ� (r = a^2 mod m),
* Modulus m�� �׻� ����� ���� (m�� ������ m = |m|),
* ū �� a�� r�� ���� �ٸ� �����͸� ������ ��
********************************************************************************/
SINT BN_sqr_mod(BN *r, BN *a, BN *m)
{
	BN_sqr(r, a);
	BN_mod(r, r, m);
	return 0;
}
/*******************************************************************************
* �� �� �� : BN_mul_inv_mod
*
* �Լ����� :
* *b - ��¹��� ū �� b�� ������
* *a - �Է¹��� ū �� a�� ������
* *m - �Է¹��� ū �� m�� ������
* Return :
* 0 - ����
*
*-------------------------------------------------------------------------------
* �Լ����� : ū �� a�� modular m�� ���� ������ ���� ���� �Լ� (b = a^(-1) mod m),
* Modulus m�� �׻� ����� ���� (m�� ������ m = |m|),
* ū �� a�� b�� ���� �ٸ� �����͸� ������ ��
********************************************************************************/
SINT BN_mul_inv_mod(BN *b, BN *a, BN *m)
{
	BN ta, tb, x, y, q, r;
	BN *pta, *ptb, *px, *py, *pq, *pr, *pt;
	SINT sig;
	ULONG ta_dat[MAX_BN_BUF_LEN], tb_dat[MAX_BN_BUF_LEN], x_dat[MAX_BN_BUF_LEN],
		y_dat[MAX_BN_BUF_LEN], q_dat[MAX_BN_BUF_LEN], r_dat[MAX_BN_BUF_LEN];
	MAC_BN_INIT(ta, ta_dat, MPCONST_POS_SIG);
	MAC_BN_INIT(tb, tb_dat, MPCONST_POS_SIG);
	MAC_BN_INIT(x, x_dat, MPCONST_POS_SIG);
	MAC_BN_INIT(y, y_dat, MPCONST_POS_SIG);
	MAC_BN_INIT(q, q_dat, MPCONST_POS_SIG);
	MAC_BN_INIT(r, r_dat, MPCONST_POS_SIG);
	pta = &ta; ptb = &tb;
	px = &x; py = &y;
	pq = &q; pr = &r;
	/* step 1 */
	MAC_MAKE_ZERO(x); /* x = 0 */
	MAC_MAKE_ONE(y); /* y = 1 */
	BN_copy(&ta, a);
	BN_copy(&tb, m);
	sig = 1;
	while (MAC_IS_POSITIVE_INTEGER(*ptb)) {
		/*step 2.1: pta = pq*ptb + pr */
		BN_div(pq, pr, pta, ptb);
		pt = pta; /* This is mere a memory allocation to use pt temporarily for step 2.2*/
		pta = ptb;
		ptb = pr;
		/*step 2.2: px = py - pq*px , py = px
		since py and -px have same sign always BN_Add() used
		inspite of BN_sub().
		*/
		BN_mul(pt, pq, px);
		BN_add(pt, py, pt);
		pr = py; /* This is mere a memory allocation to use pr temporarily for step 2.1*/
		py = px;
		px = pt;
		sig = -sig;
	}
	/* step 3 */
	// if(sig < 0)
	// BN_sub(py,py,m);
	py->sig = sig;
	if (MAC_IS_BN_ONE(*pta))
		BN_mod(b, py, m);
	else
		MAC_MAKE_ZERO(*b);
	/* result is alway positive! */
	b->sig = MPCONST_POS_SIG;
	return 0;
}

/*******************************************************************************
* �� �� �� : BN2OSTR
*
* �Լ����� :
* *hstr - ��¹��� octet string�� ������
* *hstrlen - ��¹��� octet string�� ���� ������ ������
* *a - �Է¹��� ū �� a�� ������
* Return :
* 0 - ����
* -1 - ���� (�Էµ����� ����)
*
*-------------------------------------------------------------------------------
* �Լ����� : ū �� a�� octet ��Ʈ�� ������ �����ͷ� ����ϴ� ����
********************************************************************************/
SINT BN2OSTR(UCHAR *hstr, ULONG *hstrlen, BN *a)
{
	ULONG hstrind;
	ULONG hstrbnd;
	if ((a == NULL) || (hstr == NULL))
		return -1;
	if (a->len == 0) {
		*hstrlen = 0;
		return 0;
	}
	*hstrlen = ((BN_nonzero_bits_num((a)) + 7) >> 3);
	hstrbnd = *hstrlen - 1;
	for (hstrind = 0; hstrind < *hstrlen; hstrind++) {
		hstr[hstrind] = (SCHAR)(((a->dat[(hstrbnd - hstrind) >> 2] >> ((hstrbnd - hstrind) % 4) * 8)) & 0xff);
	}
	return 0;
}

/*******************************************************************************
* �� �� �� : BN2OSTR
*
* �Լ����� :
* *a - ��¹��� ū �� a�� ������
* *hstr - �Է¹��� octet string�� ������
* *hstrlen - �Է¹��� octet string�� ���� ����
* Return :
* 0 - ����
*
*-------------------------------------------------------------------------------
* �Լ����� : octet ��Ʈ�� ������ �����͸� ū �� a�� ���·� ��ȯ�ϴ� ����
********************************************************************************/
SINT OSTR2BN(BN *a, UCHAR *hstr, ULONG hstrlen)
{
	SINT i;
	ULONG bnd;
	bnd = hstrlen - 1;
	a->len = (hstrlen + 3) >> 2;
	memset((ULONG*)a->dat, 0, MAC_MULT2EXP(a->len, 2));
	for (i = bnd; i >= 0; i--) {
		a->dat[(bnd - i) >> 2] |= hstr[i] << (((bnd - i) % 4) * 8);
	}
	return 0;
}

/*********************************************************************************
* �� �� �� : BN_ASCII2OSTR
*
* �Լ����� :
* *hstr - ��¹��� octet string�� ������
* *hstrlen - ��¹��� octet string�� ���� ����
* *ascii - �Է¹��� �ƽ�Ű �ڵ� string�� ������
* Return :
* 0 - ����
*
*---------------------------------------------------------------------------------
* �Լ����� : �ƽ�Ű�ڵ� ��Ʈ�� ������ �����͸� octet ��Ʈ�� ���·� ��ȯ�ϴ� ����
**********************************************************************************/
SINT BN_ASCII2OSTR(UCHAR *bstr, ULONG *bstrlen, SCHAR *ascii)
{
	SINT i = 0;
	SINT j = 0;
	SINT l;
	UINT tmp;
	l = ((SINT)strlen(ascii) + 1) / 2;
	*bstrlen = l;
	if ((SINT)strlen(ascii) % 2)
	{
		if ((ascii[0] >= 'a') && (ascii[0] <= 'f'))
			bstr[i++] = ascii[0] - 'a' + 0xa;
		else
			bstr[i++] = ascii[0] - '0';
		j++;
	}
	for (; i < l; i++, j += 2) {
#if defined(__LINUX__) || defined(__ANDROID__) || defined(__iOS__)
		sscanf(ascii + j, "%02X", &tmp);
#elif defined(__WINDOWS__)
		sscanf_s(ascii + j, "%02X", &tmp);
#endif
		bstr[i] = tmp & 255;
	}
	return 0;
}

SINT BN_gen_rand(BN *p, SINT bits_length)
{
	UCHAR *temp;

	temp = (UCHAR *)malloc( (bits_length / 8) + 1);
	if(temp == NULL)
		return ERR_MALLOC;

	HASH_DRBG_Random_Gen(temp, bits_length);

	OSTR2BN(p,temp,(bits_length>>3));

	free(temp);

	return EBD_CRYPTO_SUCCESS;
}

#define K1 0x5A827999
#define K2 0x6ED9EBA1
#define K3 0x8F1BBCDC
#define K4 0xCA62C1D6
#define F1(B,C,D) (((B) & (C)) | ((~(B)) & (D)))
#define F2(B,C,D) ((B) ^ (C) ^ (D))
#define F3(B,C,D) (((B) & (C)) | ((B) & (D)) | ((C) & (D)))
#define F4(B,C,D) ((B) ^ (C) ^ (D))
#define ROTL(x,n) (((x)<<(n))|((x)>>(32-(n))))
#define SHA1_RND1(a,b,c,d,e,t) \
{ \
	e += ROTL(a,5) + F1(b,c,d) + W[t] + K1; \
	b = ROTL(b,30); \
}
#define SHA1_RND2(a,b,c,d,e,t) \
{ \
	e += ROTL(a,5) + F2(b,c,d) + W[t] + K2; \
	b = ROTL(b,30); \
}
#define SHA1_RND3(a,b,c,d,e,t) \
{ \
	e += ROTL(a,5) + F3(b,c,d) + W[t] + K3; \
	b = ROTL(b,30); \
}
#define SHA1_RND4(a,b,c,d,e,t) \
{ \
	e += ROTL(a,5) + F4(b,c,d) + W[t] + K4; \
	b = ROTL(b,30); \
}
void SHA1_dgst_unit(UINT h[5], UCHAR blk[64])
{
	UINT A,B,C,D,E,W[80],t, tmp;
	UCHAR *pb;
	pb = blk;
	A = h[0];
	B = h[1];
	C = h[2];
	D = h[3];
	E = h[4];
	for (t=0; t<16; t++){
		W[t] = (UINT)(*pb); pb++; W[t] <<= 8;
		W[t] |= (UINT)(*pb); pb++; W[t] <<= 8;
		W[t] |= (UINT)(*pb); pb++; W[t] <<= 8;
		W[t] |= (UINT)(*pb); pb++;
	}
	for (; t<80; t++){
		tmp = W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16];
		W[t] = ROTL(tmp,1);
	}
	SHA1_RND1(A,B,C,D,E,0); SHA1_RND1(E,A,B,C,D,1); SHA1_RND1(D,E,A,B,C,2);
	SHA1_RND1(C,D,E,A,B,3); SHA1_RND1(B,C,D,E,A,4);
	SHA1_RND1(A,B,C,D,E,5); SHA1_RND1(E,A,B,C,D,6); SHA1_RND1(D,E,A,B,C,7);
	SHA1_RND1(C,D,E,A,B,8); SHA1_RND1(B,C,D,E,A,9);
	SHA1_RND1(A,B,C,D,E,10);SHA1_RND1(E,A,B,C,D,11);SHA1_RND1(D,E,A,B,C,12);SHA1_RND1(
		C,D,E,A,B,13);SHA1_RND1(B,C,D,E,A,14);
	SHA1_RND1(A,B,C,D,E,15);SHA1_RND1(E,A,B,C,D,16);SHA1_RND1(D,E,A,B,C,17);SHA1_RND1(
		C,D,E,A,B,18);SHA1_RND1(B,C,D,E,A,19);
	SHA1_RND2(A,B,C,D,E,20);SHA1_RND2(E,A,B,C,D,21);SHA1_RND2(D,E,A,B,C,22);SHA1_RND2(
		C,D,E,A,B,23);SHA1_RND2(B,C,D,E,A,24);
	SHA1_RND2(A,B,C,D,E,25);SHA1_RND2(E,A,B,C,D,26);SHA1_RND2(D,E,A,B,C,27);SHA1_RND2(
		C,D,E,A,B,28);SHA1_RND2(B,C,D,E,A,29);
	SHA1_RND2(A,B,C,D,E,30);SHA1_RND2(E,A,B,C,D,31);SHA1_RND2(D,E,A,B,C,32);SHA1_RND2(
		C,D,E,A,B,33);SHA1_RND2(B,C,D,E,A,34);
	SHA1_RND2(A,B,C,D,E,35);SHA1_RND2(E,A,B,C,D,36);SHA1_RND2(D,E,A,B,C,37);SHA1_RND2(
		C,D,E,A,B,38);SHA1_RND2(B,C,D,E,A,39);
	SHA1_RND3(A,B,C,D,E,40);SHA1_RND3(E,A,B,C,D,41);SHA1_RND3(D,E,A,B,C,42);SHA1_RND3(
		C,D,E,A,B,43);SHA1_RND3(B,C,D,E,A,44);
	SHA1_RND3(A,B,C,D,E,45);SHA1_RND3(E,A,B,C,D,46);SHA1_RND3(D,E,A,B,C,47);SHA1_RND3(
		C,D,E,A,B,48);SHA1_RND3(B,C,D,E,A,49);
	SHA1_RND3(A,B,C,D,E,50);SHA1_RND3(E,A,B,C,D,51);SHA1_RND3(D,E,A,B,C,52);SHA1_RND3(
		C,D,E,A,B,53);SHA1_RND3(B,C,D,E,A,54);
	SHA1_RND3(A,B,C,D,E,55);SHA1_RND3(E,A,B,C,D,56);SHA1_RND3(D,E,A,B,C,57);SHA1_RND3(
		C,D,E,A,B,58);SHA1_RND3(B,C,D,E,A,59);
	SHA1_RND4(A,B,C,D,E,60);SHA1_RND4(E,A,B,C,D,61);SHA1_RND4(D,E,A,B,C,62);SHA1_RND4(
		C,D,E,A,B,63);SHA1_RND4(B,C,D,E,A,64);
	SHA1_RND4(A,B,C,D,E,65);SHA1_RND4(E,A,B,C,D,66);SHA1_RND4(D,E,A,B,C,67);SHA1_RND4(
		C,D,E,A,B,68);SHA1_RND4(B,C,D,E,A,69);
	SHA1_RND4(A,B,C,D,E,70);SHA1_RND4(E,A,B,C,D,71);SHA1_RND4(D,E,A,B,C,72);SHA1_RND4(
		C,D,E,A,B,73);SHA1_RND4(B,C,D,E,A,74);
	SHA1_RND4(A,B,C,D,E,75);SHA1_RND4(E,A,B,C,D,76);SHA1_RND4(D,E,A,B,C,77);SHA1_RND4(
		C,D,E,A,B,78);SHA1_RND4(B,C,D,E,A,79);
	h[0] += A;
	h[1] += B;
	h[2] += C;
	h[3] += D;
	h[4] += E;
}

/*******************************************************************************
* �� �� �� : BN_X9_31_PRNG_CTX_init
*
* �Լ����� :
* *prng_ctx - BN_X9_PRNG_CTX�� ������
* *prng_buf - BN_X9_PRNG_BUF�� ������
* Return :
* 0 - �Ҽ� ���� ����
* -1 - �Ҽ� ���� ����
*
*-------------------------------------------------------------------------------
* �Լ����� : �������� �Լ��� ���� BN_X9_PRNG_CTX ����ü�� �޷θ� �Ҵ� �Լ�
********************************************************************************/

SINT PRNG_CTX_init(BN_X9_PRNG_CTX *prng_ctx, BN_X9_PRNG_BUF *prng_buf)
{
	UCHAR sha1_in[64];
	// ULONG cur_time;
	UINT t[20+1];
	// SINT i;
	/* Allocate memories to input context. */
	MAC_BN_INIT_MEM_CLR(prng_ctx->sgord,prng_buf->sgord_dat,1);
	MAC_BN_INIT_MEM_CLR(prng_ctx->xseed,prng_buf->xseed_dat,1);
	MAC_BN_INIT_MEM_CLR(prng_ctx->xkey,prng_buf->xkey_dat,1);
	/* xkey value will not be evaluated here. It changes everytime when PRNG used by user. */
	/* Initialize xseed with the SHA1_DgstUnit */
	t[0] = 0x67452301;
	t[1] = 0xefcdab89;
	t[2] = 0x98badcfe;
	t[3] = 0x10325476;
	t[4] = 0xc3d2e1f0;
	K_DRBG_GetEntropy(sha1_in, 64);
	SHA1_dgst_unit(t,sha1_in);
	prng_ctx->xseed.dat[0] = t[0];
	prng_ctx->xseed.dat[1] = t[1];
	prng_ctx->xseed.dat[2] = t[2];
	prng_ctx->xseed.dat[3] = t[3];
	prng_ctx->xseed.dat[4] = t[4];
	prng_ctx->xseed.len = 5;
	/* Initialize a default xkey with the SHA1_DgstUnit */
	SHA1_dgst_unit(t,sha1_in);
	prng_ctx->xkey.dat[0] = t[0];
	prng_ctx->xkey.dat[1] = t[1];
	prng_ctx->xkey.dat[2] = t[2];
	prng_ctx->xkey.dat[3] = t[3];
	prng_ctx->xkey.dat[4] = t[4];
	prng_ctx->xkey.len = 5;
	/* Set up the prime q used in X9.31 PRNG with a fixed value. */
	prng_ctx->sgord.dat[0] = 0x5F51A6F9;
	prng_ctx->sgord.dat[1] = 0xC642E516;
	prng_ctx->sgord.dat[2] = 0xFFF96962;
	prng_ctx->sgord.dat[3] = 0xB6795C7F;
	prng_ctx->sgord.dat[4] = 0xC468245B;
	prng_ctx->sgord.len = 5;
	return 0;
}

/*******************************************************************************
* �� �� �� : BN_X9_31_PRNG
*
* �Լ����� :
* *a - ��¹��� ū �� a�� ������
* *prng_ctx - BN_X9_PRNG_CTX�� ������
* l - ������ ������ ���� ����
* Return :
* 0 - ���� ���� ����
* -1 - ���� (�Է� ���� ���̰� 0���� ���� ���)
*
*-------------------------------------------------------------------------------
* �Լ����� : X9.31 ���������⸦ �̿��Ͽ� l ��Ʈ ���� p�� �����ϴ� �Լ�
********************************************************************************/
SINT PRNG_generate(BN *p, BN_X9_PRNG_CTX *prng_ctx, SINT l)
{
	/*
	PRNG follows ANSI x9.31 standard.
	input 'xkey' will be updated for next call of this procedure
	*/
	BN *xseed,*xkey,*sgord;
	BN xval,x;
	ULONG x_dat[5+1],xval_dat[5+1],c_len,x_len,m,i;
	UINT t[20+1];
	UCHAR c[64],x_cdat[20+1];
	UCHAR r[MAX_BN_BUF_LEN<<2], *pr;
	if(l <= 0){
		return -1;
	}
	// �ּ� copy
	xseed=&prng_ctx->xseed;
	xkey=&prng_ctx->xkey;
	sgord=&prng_ctx->sgord;
	pr = r;
	MAC_BN_INIT(x,x_dat,MPCONST_POS_SIG);
	MAC_BN_INIT(xval,xval_dat,MPCONST_POS_SIG);
	t[0] = 0x67452301;
	t[1] = 0xefcdab89;
	t[2] = 0x98badcfe;
	t[3] = 0x10325476;
	t[4] = 0xc3d2e1f0;
	m = (l+159)/160;
	for(i = 0 ; i < m ; i++){
		x.len = 5;
		xseed->len = 5;
		/* Step 4-b: xval = (xkey + xseed) mod 2^160 */
		BN_add(&xval,xkey,xseed);
		xval.len = 5;
		xval.dat[5]=0;
		/* Step 4-c: x = G(t,xval) mod q */
		/* G-function from this point */
		BN2OSTR(c,&c_len,&xval);
		memset(c+c_len,0,64-c_len);
		SHA1_dgst_unit(t,c);
		/* G-function to this point */
		x.dat[0] = t[4];
		x.dat[1] = t[3];
		x.dat[2] = t[2];
		x.dat[3] = t[1];
		x.dat[4] = t[0];
		x.len = 5;
		BN_mod(&x,&x,sgord);
		/* Step 4-d: xkey = (1 + xkey + x) mod 2^160 */
		BN_add_ULONG(xkey,xkey,1);
		BN_add(xkey,xkey,&x);
		xkey->len = 5;
		BN2OSTR(x_cdat,&x_len,xkey);
		memcpy(pr,x_cdat,20);
		pr += 20;
	}
	memset(r+(l>>3),0,sizeof(ULONG));
	OSTR2BN(p,r,(l>>3));
	return 0;
}
