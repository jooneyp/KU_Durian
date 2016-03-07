/********************************************************************************
* 파일설명 : 큰 수 연산 함수
********************************************************************************/
#include <stdlib.h>
#include <time.h>
#include "EBDCrypto.h"

//#define _MAC_64BIT_
#if defined(_MAC_64BIT_)
/**********************************/
/* 큰 수 연산을 위한 Macro 함수 */
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
/*
Specialized sigle precision division preparing for multiple precision division
*/
#define MAC_ULONG_DIVIDE(/*(ULONG)*/ a,/*(ULONG)*/ b,/*ULONG*/ c,/*(ULONG)*/ d) \
{\
	ULONG __x3x2,__x1x0,__y1,__y0,__q,__z2z1,__z1z0,__tmp;\
	SINT __cnt=2;\
	__x3x2 = (b) ;__x1x0 = (a);\
	__y1=MAC_HW(c);__y0=MAC_LW(c);\
	if( __x3x2 > (c) ){ __x3x2 -=__y1; }\
	while(1){\
	__q = ((__x3x2 == __y1) ? BITMASK_LOWER_LONG : __x3x2/__y1);\
	while(1){\
	__tmp = __x3x2 - __q*__y1;\
	if( (__tmp & BITMASK_HIGHER_LONG) || ( (__q*__y0) <= ((__tmp<<HALF_LONG_BITS)+ MAC_HW(__x1x0))))\
	break;\
	__q--;\
	}\
	__z2z1 = __q*__y1; __z1z0 = __q*__y0;\
	__tmp= (__z1z0>>HALF_LONG_BITS);\
	__z1z0 = (__z1z0<<HALF_LONG_BITS)&BITMASK_HIGHER_LONG;\
	__z2z1 +=__tmp;\
	if( __x1x0 < __z1z0) __z2z1++; /* or hi-- */\
	__x1x0 -= __z1z0;\
	if(__x3x2 < __z2z1){ __z2z1 += c; __q --;}\
	__x3x2 -= __z2z1;\
	if(--__cnt == 0) break;\
	(d) = __q << HALF_LONG_BITS;\
	__x3x2 = ((__x3x2 << HALF_LONG_BITS) | (__x1x0 >> HALF_LONG_BITS)) & BITMASK_LONG;\
	__x1x0 = (__x1x0 & BITMASK_LOWER_LONG) << HALF_LONG_BITS;\
	}\
	(d) |= __q;\
}
/**************************************/
/* 큰 수 연산을 위한 기본 연산 함수 */
/**************************************/
/**********************************************************************
* 함 수 명 : BN_copy
*
* 함수인자 :
* *dest - 출력받을 큰 수 dest의 포인터
* *src - 입력받은 큰 수 src의 포인터
* Return :
* 0 - src가 0인 0 반환
* i - src의 길이 반환
*
*---------------------------------------------------------------------
* 함수설명 : 큰 수 src를 dest에 복사하는 함수
***********************************************************************/
SINT
BN_copy(
	BN *dest,
	BN *src
	)
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
* 함 수 명 : BN_bit_is_set
*
* 함수인자 :
* *a - 입력받은 큰 수 a의 포인터
* nth - 확인할 비트 위치
* Return :
* 0 - 비트가 0인 경우 0 반환
* 1 - 비트가 1인 경우 1 반환
*
*----------------------------------------------------------------------
* 함수설명 : 큰 수 a의 nth 번째 비트가 0인지 1인지를 판단하는 함수
************************************************************************/
SINT
BN_bit_is_set(
	BN *a,
	ULONG nth
	)
{
	/*
	similar to the macro MAC_BIT_IS_SET
	but the latter is faster than the former.
	*/
	SINT i, j;
	if (nth < 0) return 0;
	i = nth / LONG_BITS;
	if (a->len <= i) return 0;
	j = nth % LONG_BITS;
	return((a->dat[i] & (1 << j)) ? 1 : 0);
}
/***********************************************************************
* 함 수 명 : BN_shl_1bit
*
* 함수인자 :
* *b - 출력받을 큰 수 b의 포인터
* *a - 입력받은 큰 수 a의 포인터
* Return :
* 0 - 성공
*
*----------------------------------------------------------------------
* 함수설명 : 큰 수 a를 1비트 left shift하여 b에 저장하는 함수
************************************************************************/
SINT
BN_shl_1bit(
	BN *b,
	BN *a
	)
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
* 함 수 명 : BN_shr_1bit
*
* 함수인자 :
* *b - 출력받을 큰 수 b의 포인터
* *a - 입력받은 큰 수 a의 포인터
* Return :
* 0 - 성공
*
*----------------------------------------------------------------------
* 함수설명 : 큰 수 a를 1비트 right shift하여 b에 저장하는 함수
***********************************************************************/
SINT
BN_shr_1bit(BN *b, BN *a)
{
	ULONG c, *a_datp, *b_datp, tmp;
	SINT i;
	c = 0;
	a_datp = a->dat;
	b_datp = b->dat;
	b->sig = a->sig;
	b->len = a->len;
	for (i = a->len - 1; i >= 0; i--) {
		tmp = a_datp[i];
		b_datp[i] = (tmp >> 1) | c;
		c = (tmp & 1) ? HIGHER_MSB_ONE : 0;
	}
	MAC_CLR_UPPER_ZEROBYTES(*b);
	return 0;
}
/***********************************************************************
* 함 수 명 : BN_shl
*
* 함수인자 :
* *r - 출력받을 큰 수 r의 포인터
* *a - 입력받은 큰 수 a의 포인터
* n - 이동할 비트의 정보
* Return :
* 0 - 성공
*
*----------------------------------------------------------------------
* 함수설명 : 큰 수 a를 n비트 left shift하여 r에 저장하는 함수
************************************************************************/
SINT
BN_shl(
	BN *r,
	BN *a,
	SINT n
	)
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
* 함 수 명 : BN_shr
*
* 함수인자 :
* *r - 출력받을 큰 수 r의 포인터
* *a - 입력받은 큰 수 a의 포인터
* n - 이동할 비트의 정보
* Return :
* 0 - 성공
*
*----------------------------------------------------------------------
* 함수설명 : 큰 수 a를 n비트 right shift하여 r에 저장하는 함수
************************************************************************/
SINT
BN_shr(
	BN *r,
	BN *a,
	SINT n
	)
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
* 함 수 명 : BN_nonzero_bits_num
*
* 함수인자 :
* *a - 입력받은 큰 수 a의 포인터
* Return :
* 상수 - a의 비트 길이 반환
*
*----------------------------------------------------------------------
* 함수설명 : 큰 수 a의 비트 길이를 반환하는 함수
************************************************************************/
SINT
BN_nonzero_bits_num(
	BN *a
	)
{
	/*
	This function is fixed to 32-bit processor.
	If you work with another-bits processor, customize the codes.
	*/
	ULONG l;
	int i;
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
/***********************************************************************
* 함 수 명 : BN_LOW_zero_bits_num
*
* 함수인자 :
* *a - 입력받은 큰 수 a의 포인터
* Return :
* 상수 - a의 하위 비트가 0의 갯수 반환
*
*----------------------------------------------------------------------
* 함수설명 : 큰 수 a의 최하위에 연속된 0 비트의 갯수 반환 함수
************************************************************************/
SINT
BN_LOW_zero_bits_num(
	BN *a
	)
{
	/*
	This function is fixed to 32-bit processor.
	If you work with another-bits processor, customize the codes.
	*/
	int num, i = 0;
	ULONG data;
	if (a->len == 0) return 0;
	//i = (a->len-1) * 32;
	while (i < a->len && a->dat[i] == 0) i++;
	num = i * 32;
	data = a->dat[i];
	if (!(data & 0x0000ffffL))
	{
		if (!(data & 0x00ff0000L)) return(num + bits_to_index_low[data >> 24] + 24);
		else return(num + bits_to_index_low[data >> 16] + 16);
	}
	else {
		if (!(data & 0x000000ffL)) return(num + bits_to_index_low[data >> 8] + 8);
		else return(num + bits_to_index_low[data & 0xff]);
	}
}
/*********************/
/* 큰 수 연산 함수 */
/*********************/
/***********************************************************************
* 함 수 명 : BN_abs_comp
*
* 함수인자 :
* *a - 입력받은 큰 수 a의 포인터
* *b - 입력받은 큰 수 b의 포인터
* Return :
* 1 - |a| > |b|인 경우
* 0 - |a| = |b|인 경우
* -1 - |a| < |b|인 경우
*
*----------------------------------------------------------------------
* 함수설명 : 두 큰 수 a와 b의 절대값의 크기를 비교하는 함수
************************************************************************/
SINT
BN_abs_comp(
	BN *a,
	BN *b
	)
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
* 함 수 명 : BN_comp
*
* 함수인자 :
* *a - 입력받은 큰 수 a의 포인터
* *b - 입력받은 큰 수 b의 포인터
* Return :
* 1 or 2 - a > b인 경우
* 0 - a = b인 경우
* -1 or -2 - a < b인 경우
*
*----------------------------------------------------------------------
* 함수설명 : 두 큰 수 a와 b의 크기를 비교하는 함수
************************************************************************/
SINT
BN_comp(
	BN *a,
	BN *b
	)
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
* 함 수 명 : BN_add_ULONG
*
* 함수인자 :
* *c - 출력받을 큰 수 c의 포인터
* *a - 입력받은 큰 수 a의 포인터
* b - 입력받은 상수 b의 데이터 정보
* Return :
* 0 - 성공
*
*----------------------------------------------------------------------
* 함수설명 : 큰 수 a와 상수 b의 덧셈 연산 함수 (c = a+b),
a와 c는 서로 다른 포인터를 가져야 함
************************************************************************/
SINT
BN_add_ULONG(
	BN *c,
	BN *a,
	ULONG b
	)
{
	/*
	a and c MUST be different BNs
	*/
	SINT i;
	ULONG *a_datp, *c_datp;
	i = 0;
	a_datp = a->dat;
	c_datp = c->dat;
	c_datp[i] = a_datp[i] + b;
	while (i < a->len)
		if (c_datp[i] < a_datp[i++])
			c_datp[i] = a_datp[i] + 1;
		else
			c_datp[i] = a_datp[i];
	c->len = i;
	return 0;
}
/***********************************************************************
* 함 수 명 : BN_asym_add
*
* 함수인자 :
* *c - 출력받을 큰 수 c의 포인터
* *a - 입력받은 큰 수 a의 포인터
* *b - 입력받은 큰 수 b의 포인터
* Return :
* 0 - 성공
*
*----------------------------------------------------------------------
* 함수설명 : 큰 수 a와 b의 절대값의 덧셈 연산 함수 (c = a+b),
a>=b 조건을 만족하여야 함
************************************************************************/
SINT
BN_asym_add(
	BN *c,
	BN *a,
	BN *b
	)
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
* 함 수 명 : BN_sub_ULONG
*
* 함수인자 :
* *r - 출력받을 큰 수 r의 포인터
* *a - 입력받은 큰 수 a의 포인터
* b - 입력받은 상수 b의 데이터 정보
* Return :
* 0 - 성공
*
*----------------------------------------------------------------------
* 함수설명 : 큰 수 a와 상수 b의 뺄셈 연산 함수 (r = a-b),
a와 r는 서로 다른 포인터를 가져야 함
************************************************************************/
SINT
BN_sub_ULONG(
	BN *r,
	BN *a,
	ULONG b
	)
{
	ULONG tmp1, tmp2, *a_datp, *r_datp;
	SINT i = 0, c, la;
	a_datp = a->dat;
	r_datp = r->dat;
	la = a->len;
	tmp1 = *(a_datp++);
	c = (tmp1 < b);
	*(r_datp++) = (tmp1 - b) & BITMASK_LONG;
	if (c) {
		for (; i < la; i++) {
			tmp1 = *(a_datp++);
			tmp2 = (tmp1 - b) & BITMASK_LONG;
			*(r_datp++) = tmp2;
			if (tmp1 > tmp2)
				break;
		}
	}
	memcpy(r_datp, a_datp, sizeof(*r_datp) * (la - i));
	r->sig = a->sig;
	r->len = la;
	MAC_CLR_UPPER_ZEROBYTES(*r);
	return 0;
}
/***********************************************************************
* 함 수 명 : BN_asym_sub
*
* 함수인자 :
* *c - 출력받을 큰 수 c의 포인터
* *a - 입력받은 큰 수 a의 포인터
* *b - 입력받은 큰 수 b의 포인터
* Return :
* 0 - 성공
*
*----------------------------------------------------------------------
* 함수설명 : 큰 수 a와 b의 절대값의 뺄셈 연산 함수 (c = a-b),
a>=b 조건을 만족하여야 함
************************************************************************/
SINT
BN_asym_sub(
	BN *c,
	BN *a,
	BN *b
	)
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
		memcpy((char*)&(c_datp[i]), (char*)&(a_datp[i]), sizeof(ULONG)*(a_len - i));
	c->len = a->len;
	return 0;
}
/***********************************************************************
* 함 수 명 : BN_add
*
* 함수인자 :
* *c - 출력받을 큰 수 c의 포인터
* *a - 입력받은 큰 수 a의 포인터
* *b - 입력받은 큰 수 b의 포인터
* Return :
* 0 - 성공
*
*----------------------------------------------------------------------
* 함수설명 : 큰 수 a와 b의 덧셈 연산 함수 (c = a+b),
************************************************************************/
SINT
BN_add(
	BN *c,
	BN *a,
	BN *b
	)
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
* 함 수 명 : BN_sub
*
* 함수인자 :
* *c - 출력받을 큰 수 c의 포인터
* *a - 입력받은 큰 수 a의 포인터
* *b - 입력받은 큰 수 b의 포인터
* Return :
* 0 - 성공
*
*----------------------------------------------------------------------
* 함수설명 : 큰 수 a와 b의 뺄셈 연산 함수 (c = a-b),
************************************************************************/
SINT
BN_sub(
	BN *c,
	BN *a,
	BN *b
	)
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
* 함 수 명 : BN_mult_ULONG
*
* 함수인자 :
* *c - 출력받을 큰 수 c의 포인터
* *a - 입력받은 큰 수 a의 포인터
* b - 입력받은 상수 b의 데이터 정보
* Return :
* 0 - 성공
*
*----------------------------------------------------------------------
* 함수설명 : 큰 수 a와 상수 b의 곱셈 연산 함수 (c = a*b),
* 두 큰 수 a와 c는 서로 다른 포인터를 가져야 함
************************************************************************/
SINT
BN_mult_ULONG(
	BN *c,
	BN *a,
	ULONG b
	)
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
* 함 수 명 : BN_mult_ULONG_add
*
* 함수인자 :
* *c - 출력받을 큰 수 c의 포인터
* *a - 입력받은 큰 수 a의 포인터
* b - 입력받은 상수 b의 데이터 정보
* Return :
* 0 - 성공
*
*-------------------------------------------------------------------------
* 함수설명 : 큰 수 a와 상수 b의 곱셈에 c를 덧셈하는 함수 (c = (a*b) + c),
* 두 큰 수 a와 c는 서로 다른 포인터를 가져야 함
**************************************************************************/
SINT
BN_mult_ULONG_add(
	BN *c,
	BN *a,
	ULONG b
	)
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
* 함 수 명 : BN_plain_mul
*
* 함수인자 :
* *c - 출력받을 큰 수 c의 포인터
* *a - 입력받은 큰 수 a의 포인터
* *b - 입력받은 큰 수 b의 포인터
* Return :
* 0 - 성공
*
*-------------------------------------------------------------------------
* 함수설명 : 두 큰 수 a와 b의 곱셈 연산 함수 (c = a*b),
* 두 큰 수 a, b와 c는 서로 다른 포인터를 가져야 함
**************************************************************************/
SINT
BN_plain_mul(
	BN *c,
	BN *a,
	BN *b
	)
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
* 함 수 명 : BN_kar_mul
*
* 함수인자 :
* *c - 출력받을 큰 수 c의 포인터
* *a - 입력받은 큰 수 a의 포인터
* *b - 입력받은 큰 수 b의 포인터
* Return :
* 0 - 성공
*
*-------------------------------------------------------------------------
* 함수설명 : 두 큰 수 a와 b의 카라슈바 곱셈 연산 함수 (c = a*b),
* 두 큰 수 a, b와 c는 서로 다른 포인터를 가져야 함
**************************************************************************/
SINT
BN_kar_mul(
	BN *c,
	BN *a,
	BN *b
	)
{
#define KAR_MIN_LEN 16
	SINT i;
	SINT curlen, sublen;
	BN c0, c1, c2;
	BN ah, al, bh, bl;
	ULONG c0_dat[MAX_BN_BUF_LEN], c1_dat[MAX_BN_BUF_LEN], c2_dat[MAX_BN_BUF_LEN];
	c0.dat = c0_dat;
	c1.dat = c1_dat;
	c2.dat = c2_dat;
	curlen = a->len;
	sublen = MAC_DIV2EXP(curlen, 1);
	if ((curlen == b->len) && (curlen > KAR_MIN_LEN) && ((curlen & 1) == 0)) {
		/* split a into ah and al */
		al.dat = a->dat;
		al.len = sublen;
		ah.dat = a->dat + sublen;
		ah.len = sublen;
		/* split b into bh and bl */
		bl.dat = b->dat;
		bl.len = sublen;
		bh.dat = b->dat + sublen;
		bh.len = sublen;
		/* c2 = (al + ah)*(bl + bh) */
		BN_asym_add(&c0, &al, &ah);
		BN_asym_add(&c1, &bl, &bh);
		BN_kar_mul(&c2, &c0, &c1);
		/* c0 = al*bl, c1=ah*bh */
		BN_kar_mul(&c0, &al, &bl);
		BN_kar_mul(&c1, &ah, &bh);
		/* c2 = (al + ah)*(bl + bh) - c0 - c1*/
		BN_asym_sub(&c2, &c0, &c2);
		BN_asym_sub(&c2, &c1, &c2);
		/* c = (B^k)*( (B^k)*c1 + c2 ) + c0 */
		/*Following is equivalent to : BN_shl(&c1,MAC_MULT2EXP(sublen,5),c);*/
		for (i = c1.len - 1; i >= 0; i--) {
			c->dat[i + sublen] = c1.dat[i];
		}
		for (i = sublen - 1; i >= 0; i--) {
			c->dat[i] = 0;
		}
		c->len = c1.len + sublen;
		BN_asym_add(c, c, &c2);
		/*Following is equivalent to : BN_shl(c,MAC_MULT2EXP(sublen,5),&c2);*/
		for (i = c->len - 1; i >= 0; i--) {
			c2.dat[i + sublen] = c->dat[i];
		}
		for (i = sublen - 1; i >= 0; i--) {
			c2.dat[i] = 0;
		}
		c2.len = c->len + sublen;
		BN_asym_add(c, &c2, &c0);
		c->sig = a->sig*b->sig;
	}
	else {
		BN_plain_mul(c, a, b);
	}
	return 0;
}
/*************************************************************************
* 함 수 명 : BN_plain_sqr
*
* 함수인자 :
* *b - 출력받을 큰 수 b의 포인터
* *a - 입력받은 큰 수 a의 포인터
* Return :
* 0 - 성공
*
*-------------------------------------------------------------------------
* 함수설명 : 큰 수 a의 제곱 연산 함수 (b = a^2),
* 큰 수 a와 c는 서로 다른 포인터를 가져야 함
**************************************************************************/
SINT
BN_plain_sqr(
	BN *b,
	BN *a
	)
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
	memset((char*)tmp_dat, 0, (a->len << 3) + 4);
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
* 함 수 명 : BN_kar_sqr
*
* 함수인자 :
* *c - 출력받을 큰 수 c의 포인터
* *a - 입력받은 큰 수 a의 포인터
* Return :
* 0 - 성공
*
*-------------------------------------------------------------------------
* 함수설명 : 큰 수 a의 카라슈바 제곱 연산 함수 (c = a^2),
* 큰 수 a와 c는 서로 다른 포인터를 가져야 함
**************************************************************************/
SINT
BN_kar_sqr(
	BN *c,
	BN *a
	)
{
#define KAR_MIN_LEN 16
	SINT i;
	SINT curlen, sublen;
	BN c0, c1, c2;
	BN ah, al;
	ULONG c0_dat[MAX_BN_BUF_LEN], c1_dat[MAX_BN_BUF_LEN],
		c2_dat[MAX_BN_BUF_LEN];
	c0.dat = c0_dat;
	c1.dat = c1_dat;
	c2.dat = c2_dat;
	curlen = a->len;
	sublen = MAC_DIV2EXP(curlen, 1);
	if ((curlen > KAR_MIN_LEN) && ((curlen & 1) == 0)) {
		/* split a into ah and al */
		al.dat = a->dat;
		al.len = sublen;
		ah.dat = a->dat + sublen;
		ah.len = sublen;
		/* c2 = (al + ah)^2 */
		BN_asym_add(&c0, &al, &ah);
		BN_kar_sqr(&c2, &c0);
		/* c0 = al^2, c1=ah^2 */
		BN_kar_sqr(&c0, &al);
		BN_kar_sqr(&c1, &ah);
		/* c2 = (al + ah)^2 - c0 - c1*/
		BN_asym_sub(&c2, &c0, &c2);
		BN_asym_sub(&c2, &c1, &c2);
		/* c = (B^k)*( (B^k)*c1 + c2 ) + c0 */
		/*Following is equivalent to : PZ_ShL(&c1,MAC_MULT2EXP(sublen,5),c);*/
		for (i = c1.len - 1; i >= 0; i--) {
			c->dat[i + sublen] = c1.dat[i];
		}
		for (i = sublen - 1; i >= 0; i--) {
			c->dat[i] = 0;
		}
		c->len = c1.len + sublen;
		BN_asym_add(c, c, &c2);
		/*Following is equivalent to : BN_shl(c,MAC_MULT2EXP(sublen,5),&c2);*/
		for (i = c->len - 1; i >= 0; i--) {
			c2.dat[i + sublen] = c->dat[i];
		}
		for (i = sublen - 1; i >= 0; i--) {
			c2.dat[i] = 0;
		}
		c2.len = c->len + sublen;
		BN_asym_add(c, &c2, &c0);
		c->sig = a->sig;
	}
	else {
		BN_plain_sqr(c, a);
	}
	return 0;
}
/*************************************************************************
* 함 수 명 : BN_ULONG_div
*
* 함수인자 :
* h - 상위 워드값 h의 데이터 정보
* l - 하위 워드값 l의 데이터 정보
* d - devider d의 데이터 정보
* Return :
* 상수 - 나누어진 몫 값 반환
*
*-------------------------------------------------------------------------
* 함수설명 : 두 워드의 수 hl을 d로 나눈 몫을 구하는 함수 (q = hl/d)
**************************************************************************/
ULONG
BN_ULONG_div(
	ULONG h,
	ULONG l,
	ULONG d
	)
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
* 함 수 명 : BN_div
*
* 함수인자 :
* *c - 출력받을 큰 수 c의 포인터
* *d - 출력받을 큰 수 d의 포인터
* *a - 입력받은 큰 수 a의 포인터
* *b - 입력받은 큰 수 b의 포인터
* Return :
* 0 - 성공
*
*-------------------------------------------------------------------------
* 함수설명 : 큰 수 a와 b의 나눗셈 연산 함수 (a = (b*c) +d)
* a:dividend
* b:devider
* c:quotient --> 몫의 부호는 a*b와 같아진다.
* d:residue --> 나머지의 부호는 a와 같아진다.
* 예) a = 10, b = 7 --> 10 = 1*7 -3
* a = -10, b = 7 --> -10 = (-1)*7 -3
* a = 10, b = -7 --> 10 = (-1)*(-7) +3
* a = -10, b = -7 --> -10 = 1*(-7) -3
* 큰 수 a, b, c와 d는 서로 다른 포인터를 가져야 함
**************************************************************************/
SINT
BN_div(
	BN *c,
	BN *d,
	BN *a,
	BN *b
	)
{
	SINT normbits;
	BN dvder, dvdnd, window, tmp_dvdnd;
	UINT dvder_dat[MAX_BN_BUF_LEN], dvdnd_dat[MAX_BN_BUF_LEN],
		tmp_dvdnd_dat[MAX_BN_BUF_LEN];
	UINT dvder1st, dvder2nd, tmp_quota, x3, x2, x1,
		*c_datp, *window_datp;
	SINT i;
	SINT cmp_result;
	SINT loop;
	dvder.dat = dvder_dat;
	dvdnd.dat = dvdnd_dat;
	tmp_dvdnd.dat = tmp_dvdnd_dat;
	/* For trivial cases */
	/*
	_BN_rm_upper_zeros(*a);
	_BN_rm_upper_zeros(*b);
	*/
	//cmp_result=BN_ucomp(b,a);
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
	//BN_shl(b,normbits,&dvder);
	BN_shl(&dvder, b, normbits);
	normbits += LONG_BITS;
	//BN_shl(a,normbits,&dvdnd);
	BN_shl(&dvdnd, a, normbits);
	loop = dvdnd.len - dvder.len;
	window.dat = &(dvdnd.dat[loop]);
	window.len = dvder.len;
	window_datp = &(dvdnd.dat[dvdnd.len - 1]);
	dvder1st = dvder.dat[dvder.len - 1];
	dvder2nd = (dvder.len == 1) ? 0 : dvder.dat[dvder.len - 2];
	c->len = loop;
	c_datp = &(c->dat[loop - 1]);
	//cmp_result=BN_ucomp(&window,&dvder);
	cmp_result = BN_abs_comp(&window, &dvder);
	if (cmp_result >= 0) {
		//BN_usub(&window,&dvder,&window);
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
			//BN_usub(&window,&tmp_dvdnd,&window);
			BN_asym_sub(&window, &window, &tmp_dvdnd);
			if (window_datp[0]) {
				//BN_usub(&window,&dvder,&window);
				BN_asym_sub(&window, &window, &dvder);
				tmp_quota++;
			}
		}
		else {
			/* DO NOT change the order of operations */
			if (window.len >= dvder.len)
				//BN_uadd(&window,&dvder,&window);
				BN_asym_add(&window, &window, &dvder);
			else
				//BN_uadd(&dvder,&window,&window);
				BN_asym_add(&window, &dvder, &window);
			//BN_usub(&window,&tmp_dvdnd,&window);
			BN_asym_sub(&window, &window, &tmp_dvdnd);
			tmp_quota--;
		}
		*(c_datp--) = tmp_quota;
		window_datp--;
	}
	// BN_shr(&dvdnd,normbits,d);
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
#define _KARATSUBA_1024(/*(BN)*/_ret, /*(BN)*/_opA, /*(BN)*/_opB) \
{ \
	BN _higherA_1024, _lowerA_1024, _subA_1024, \
	_higherB_1024, _lowerB_1024, _subB_1024, \
	_higherRet_1024, _lowerRet_1024, _midRet_1024; \
	UINT _suA_data_1024[KARA_SIZE_512/WORD_SIZE],\
	_suB_data_1024[KARA_SIZE_512/WORD_SIZE],\
	_midRet_data_1024[KARA_SIZE_1024/WORD_SIZE/2*3];\
	UINT *pTemp_1024;\
	_subA_1024.dat = _suA_data_1024;\
	_subB_1024.dat = _suB_data_1024;\
	_midRet_1024.dat = _midRet_data_1024;\
	MAC_BN_INIT(_lowerA_1024, (_opA).dat, (_opA).sig); \
	_lowerA_1024.len = KARA_SIZE_1024/WORD_SIZE/2; \
	MAC_BN_INIT(_higherA_1024, (_opA).dat + KARA_SIZE_1024/WORD_SIZE/2, (_opA).sig); \
	_higherA_1024.len = KARA_SIZE_1024/WORD_SIZE/2; \
	MAC_BN_INIT(_lowerB_1024, (_opB).dat, (_opB).sig); \
	_lowerB_1024.len = KARA_SIZE_1024/WORD_SIZE/2; \
	MAC_BN_INIT(_higherB_1024, (_opB).dat + KARA_SIZE_1024/WORD_SIZE/2, (_opB).sig); \
	_higherB_1024.len = KARA_SIZE_1024/WORD_SIZE/2; \
	MAC_BN_INIT(_lowerRet_1024, (_ret).dat, MPCONST_ZERO_SIG); \
	MAC_BN_INIT(_higherRet_1024, (_ret).dat+(KARA_SIZE_1024/WORD_SIZE),MPCONST_ZERO_SIG); \
	/* (a-b)와(c-d) 각각 저장 */ \
	BN_sub(&_subA_1024, &_higherA_1024, &_lowerA_1024); \
	BN_sub(&_subB_1024, &_higherB_1024, &_lowerB_1024); \
	/* 다음 레벨 카라슈바 */ \
	BN_mul(&_lowerRet_1024, &_lowerA_1024, &_lowerB_1024); \
	BN_mul(&_higherRet_1024, &_higherA_1024, &_higherB_1024);\
	BN_mul(&_midRet_1024, &_subA_1024, &_subB_1024); \
	/* (a-b)(c-d)-ac-bd */ \
	BN_sub(&_midRet_1024, &_midRet_1024, &_higherRet_1024); \
	BN_sub(&_midRet_1024, &_midRet_1024, &_lowerRet_1024); \
	_midRet_1024.sig = _midRet_1024.sig * MPCONST_NEG_SIG;\
	/* ab+cd+ac+bd */ \
	(_ret).len = KARA_SIZE_1024/WORD_SIZE/2*3; \
	(_ret).sig = (_opA).sig * (_opB).sig; \
	pTemp_1024 = (_ret).dat;\
	(_ret).dat = (_ret).dat+KARA_SIZE_1024/WORD_SIZE/2;\
	BN_add(&_ret, &_ret, &_midRet_1024); \
	(_ret).len = KARA_SIZE_1024/WORD_SIZE*2; \
	(_ret).dat = pTemp_1024; \
}
#define _KARATSUBA_2048( /*(BN)*/_ret, /*(BN)*/_opA, /*(BN)*/_opB) \
{ \
	BN _higherA_2048, _lowerA_2048, _subA_2048, \
	_higherB_2048, _lowerB_2048, _subB_2048, \
	_higherRet_2048, _lowerRet_2048, _midRet_2048; \
	UINT _suA_data_2048[KARA_SIZE_1024/WORD_SIZE]={0},\
	_suB_data_2048[KARA_SIZE_1024/WORD_SIZE]={0},\
	_midRet_data_2048[KARA_SIZE_2048/WORD_SIZE/2*3]={0};\
	UINT *pTemp_2048;\
	_subA_2048.dat = _suA_data_2048;\
	_subB_2048.dat = _suB_data_2048;\
	_midRet_2048.dat = _midRet_data_2048;\
	/*MPZ 초기화*/\
	MAC_BN_INIT(_lowerA_2048, _opA->dat, _opA->sig); \
	_lowerA_2048.len = KARA_SIZE_2048/WORD_SIZE/2; \
	MAC_BN_INIT(_higherA_2048, _opA->dat + KARA_SIZE_2048/WORD_SIZE/2, _opA->sig); \
	_higherA_2048.len = KARA_SIZE_2048/WORD_SIZE/2; \
	MAC_BN_INIT(_lowerB_2048, _opB->dat, _opB->sig); \
	_lowerB_2048.len = KARA_SIZE_2048/WORD_SIZE/2; \
	MAC_BN_INIT(_higherB_2048, _opB->dat + KARA_SIZE_2048/WORD_SIZE/2, _opB->sig); \
	_higherB_2048.len = KARA_SIZE_2048/WORD_SIZE/2; \
	MAC_BN_INIT(_lowerRet_2048, (_ret)->dat, MPCONST_ZERO_SIG); \
	MAC_BN_INIT(_higherRet_2048, (_ret)->dat+(KARA_SIZE_2048/WORD_SIZE), MPCONST_ZERO_SIG); \
	/* (a-b)와(c-d) 각각 저장 */ \
	BN_sub(&_subA_2048, &_higherA_2048, &_lowerA_2048); \
	BN_sub(&_subB_2048, &_higherB_2048, &_lowerB_2048); \
	/* 다음 레벨 카라슈바 */ \
	_KARATSUBA_1024(_lowerRet_2048, _lowerA_2048, _lowerB_2048); \
	_KARATSUBA_1024(_higherRet_2048, _higherA_2048, _higherB_2048);\
	_KARATSUBA_1024(_midRet_2048, _subA_2048, _subB_2048); \
	/* (a-b)(c-d)-ac-bd */ \
	BN_sub(&_midRet_2048, &_midRet_2048, &_higherRet_2048); \
	BN_sub(&_midRet_2048, &_midRet_2048, &_lowerRet_2048);\
	_midRet_2048.sig = _midRet_2048.sig * MPCONST_NEG_SIG;\
	/* ab+cd+ac+bd */ \
	(_ret)->len = KARA_SIZE_2048/WORD_SIZE/2*3; \
	(_ret)->sig = (_opA)->sig * (_opB)->sig; \
	pTemp_2048 = (_ret)->dat;\
	(_ret)->dat = (_ret)->dat+KARA_SIZE_2048/WORD_SIZE/2;\
	BN_add(_ret, _ret, &_midRet_2048); \
	(_ret)->len = KARA_SIZE_2048/WORD_SIZE*2; \
	(_ret)->dat = pTemp_2048;\
}
#define _KARATSUBA_2048_3072(/*(BN)*/_ret, /*(BN)*/_opA, /*(BN)*/_opB) \
{ \
	BN _higherA_2048, _lowerA_2048, _subA_2048, \
	_higherB_2048, _lowerB_2048, _subB_2048, \
	_higherRet_2048, _lowerRet_2048, _midRet_2048; \
	UINT _suA_data_2048[KARA_SIZE_1024/WORD_SIZE],\
	_suB_data_2048[KARA_SIZE_1024/WORD_SIZE],\
	_midRet_data_2048[KARA_SIZE_2048/WORD_SIZE/2*3];\
	UINT *pTemp_2048;\
	_subA_2048.dat = _suA_data_2048;\
	_subB_2048.dat = _suB_data_2048;\
	_midRet_2048.dat = _midRet_data_2048;\
	MAC_BN_INIT(_lowerA_2048, (_opA).dat, (_opA).sig); \
	_lowerA_2048.len = KARA_SIZE_2048/WORD_SIZE/2; \
	MAC_BN_INIT(_higherA_2048, (_opA).dat + KARA_SIZE_2048/WORD_SIZE/2, (_opA).sig); \
	_higherA_2048.len = KARA_SIZE_2048/WORD_SIZE/2; \
	MAC_BN_INIT(_lowerB_2048, (_opB).dat, (_opB).sig); \
	_lowerB_2048.len = KARA_SIZE_2048/WORD_SIZE/2; \
	MAC_BN_INIT(_higherB_2048, (_opB).dat + KARA_SIZE_2048/WORD_SIZE/2, (_opB).sig); \
	_higherB_2048.len = KARA_SIZE_2048/WORD_SIZE/2; \
	MAC_BN_INIT(_lowerRet_2048, (_ret).dat, MPCONST_ZERO_SIG); \
	MAC_BN_INIT(_higherRet_2048, (_ret).dat+(KARA_SIZE_2048/WORD_SIZE), MPCONST_ZERO_SIG); \
	/* (a-b)와(c-d) 각각 저장 */ \
	BN_sub(&_subA_2048, &_higherA_2048, &_lowerA_2048); \
	BN_sub(&_subB_2048, &_higherB_2048, &_lowerB_2048); \
	/* 다음 레벨 카라슈바 */ \
	_KARATSUBA_1024(_lowerRet_2048, _lowerA_2048, _lowerB_2048); \
	_KARATSUBA_1024(_higherRet_2048, _higherA_2048, _higherB_2048); \
	_KARATSUBA_1024(_midRet_2048, _subA_2048, _subB_2048); \
	/* (a-b)(c-d)-ac-bd */ \
	BN_sub(&_midRet_2048, &_midRet_2048, &_higherRet_2048); \
	BN_sub(&_midRet_2048, &_midRet_2048, &_lowerRet_2048); \
	_midRet_2048.sig = _midRet_2048.sig * MPCONST_NEG_SIG;\
	/* ab+cd+ac+bd */ \
	(_ret).len = KARA_SIZE_2048/WORD_SIZE/2*3; \
	(_ret).sig = (_opA).sig * (_opB).sig; \
	pTemp_2048 = (_ret).dat;\
	(_ret).dat = (_ret).dat+KARA_SIZE_2048/WORD_SIZE/2;\
	BN_add(&_ret, &_ret, &_midRet_2048); \
	(_ret).len = KARA_SIZE_2048/WORD_SIZE*2; \
	(_ret).dat = pTemp_2048; \
}
#define _KARATSUBA_3072(/*(BN)*/_ret, /*(BN)*/_opA, /*(BN)*/_opB)\
{\
	BN _higherA_3072, _lowerA_3072, _subA_3072,\
	_higherB_3072, _lowerB_3072, _subB_3072,\
	_higherRet_3072, _lowerRet_3072, _midRet_3072; \
	UINT _suA_data_3072[65]={0}, \
	_suB_data_3072[65]={0}, \
	_midRet_data_3072[129]={0}; \
	UINT *pTemp_3072;\
	_subA_3072.dat = _suA_data_3072; \
	_subB_3072.dat = _suB_data_3072; \
	_midRet_3072.dat = _midRet_data_3072; \
	/* MPZ 초기화*/ \
	MAC_BN_INIT(_lowerA_3072, _opA->dat, _opA->sig); \
	_lowerA_3072.len = KARA_SIZE_1024/WORD_SIZE; \
	MAC_BN_INIT(_higherA_3072, _opA->dat + KARA_SIZE_1024/WORD_SIZE, _opA->sig); \
	_higherA_3072.len = KARA_SIZE_2048/WORD_SIZE; \
	MAC_BN_INIT(_lowerB_3072, _opB->dat, _opB->sig); \
	_lowerB_3072.len = KARA_SIZE_1024/WORD_SIZE; \
	MAC_BN_INIT(_higherB_3072, _opB->dat + KARA_SIZE_1024/WORD_SIZE, _opB->sig); \
	_higherB_3072.len = KARA_SIZE_2048/WORD_SIZE; \
	MAC_BN_INIT(_lowerRet_3072, (_ret)->dat, MPCONST_ZERO_SIG); \
	MAC_BN_INIT(_higherRet_3072, (_ret)->dat+KARA_SIZE_2048/WORD_SIZE, MPCONST_ZERO_SIG); \
	/* (a-b)와(c-d) 각각 저장 */ \
	BN_sub(&_subA_3072, &_higherA_3072, &_lowerA_3072); \
	BN_sub(&_subB_3072, &_higherB_3072, &_lowerB_3072); \
	/* 다음 레벨 카라슈바 */ \
	_KARATSUBA_1024(_lowerRet_3072, _lowerA_3072, _lowerB_3072);\
	_KARATSUBA_2048_3072(_higherRet_3072, _higherA_3072, _higherB_3072);\
	_KARATSUBA_2048_3072(_midRet_3072, _subA_3072, _subB_3072);\
	/* (a-b)(c-d)-ac-bd */ \
	BN_sub(&_midRet_3072, &_midRet_3072, &_higherRet_3072); \
	BN_sub(&_midRet_3072, &_midRet_3072, &_lowerRet_3072); \
	_midRet_3072.sig = _midRet_3072.sig * MPCONST_NEG_SIG; \
	/* ab+cd+ac+bd */ \
	(_ret)->len = 160; \
	(_ret)->sig = (_opA)->sig * (_opB)->sig; \
	pTemp_3072 = (_ret)->dat; \
	(_ret)->dat = (_ret)->dat+32; \
	BN_add(_ret, _ret, &_midRet_3072); \
	(_ret)->len = KARA_SIZE_3072/WORD_SIZE*2; \
	(_ret)->dat = pTemp_3072;\
}
/*************************************************************************
* 함 수 명 : BN_kar_mul_2048
*
* 함수인자 :
* *c - 출력받을 큰 수 c의 포인터
* *a - 입력받은 큰 수 a의 포인터
* *b - 입력받은 큰 수 b의 포인터
* Return :
* 0 - 성공
*
*-------------------------------------------------------------------------
* 함수설명 : 2048비트 크기의 두 큰 수 a와 b의 카라슈바 곱셈 연산 함수 (c = a*b),
* 두 큰 수 a, b와 c는 서로 다른 포인터를 가져야 함
**************************************************************************/
SINT
BN_kar_mul_2048(
	BN *c,
	BN *a,
	BN *b
	)
{
	_KARATSUBA_2048(c, a, b);
	return 0;
}
/*************************************************************************
* 함 수 명 : BN_kar_mul_3072
*
* 함수인자 :
* *c - 출력받을 큰 수 c의 포인터
* *a - 입력받은 큰 수 a의 포인터
* *b - 입력받은 큰 수 b의 포인터
* Return :
* 0 - 성공
*
*-------------------------------------------------------------------------
* 함수설명 : 3072비트 크기의 두 큰 수 a와 b의 카라슈바 곱셈 연산 함수 (c = a*b),
* 두 큰 수 a, b와 c는 서로 다른 포인터를 가져야 함
**************************************************************************/
SINT
BN_kar_mul_3072(
	BN *c,
	BN *a,
	BN *b
	)
{
	_KARATSUBA_3072(c, a, b);
	return 0;
}
/*****************************/
/* 큰 수 modular 연산 함수 */
/*****************************/
/*************************************************************************
* 함 수 명 : BN_mod
*
* 함수인자 :
* *r - 출력받을 큰 수 r의 포인터
* *a - 입력받은 큰 수 a의 포인터
* *m - 입력받은 큰 수 m의 포인터
* Return :
* 0 - 성공
*
*-------------------------------------------------------------------------
* 함수설명 : 큰 수 a와 m 대한 modular 연산 함수 (r = a mod m),
* Modulus m은 항상 양수로 간주 (m이 음수면 m = |m|)
**************************************************************************/
SINT
BN_mod(
	BN *r,
	BN *a,
	BN *m
	)
{
	BN tmp;
	ULONG tmp_dat[MAX_BN_BUF_LEN];
	MAC_BN_INIT_MEM_CLR(tmp, tmp_dat, 1);
	BN_div(&tmp, r, a, m);
	if (r->sig == MPCONST_NEG_SIG) BN_add(r, r, m);
	return 0;
}
/*************************************************************************
* 함 수 명 : BN_mod_half_ULONG
*
* 함수인자 :
* *a - 입력받은 큰 수 a의 포인터
* l - modular 변수 ㅣ의 데이터 정보
* Return :
* r - modular 결과 값 반환
*
*-------------------------------------------------------------------------
* 함수설명 : 큰 수 a와 변수 l에 대한 modular 연산 함수 (r = a mod l),
* Modulus l은 ULONG 변수
**************************************************************************/
ULONG
BN_mod_half_ULONG(
	BN *a,
	ULONG l
	)
{
	int i;
	ULONG r = 0;
	ULONG *d;
	d = a->dat;
	for (i = a->len - 1; i >= 0; i--) {
		r = ((r << 16) | ((d[i] >> 16) & BITMASK_LOWER_LONG)) % (int)l;
		r = ((r << 16) | (d[i] & BITMASK_LOWER_LONG)) % (int)l;
	}
	return r;
}
/*******************************************************************************
* 함 수 명 : BN_add_mod
*
* 함수인자 :
* *r - 출력받을 큰 수 r의 포인터
* *a - 입력받은 큰 수 a의 포인터
* *b - 입력받은 큰 수 b의 포인터
* *m - 입력받은 큰 수 m의 포인터
* Return :
* 0 - 성공
*
*-------------------------------------------------------------------------------
* 함수설명 : 큰 수 a와 b의 덧셈 결과를 m으로 modular 하는 함수 (r = a+b mod m),
* Modulus m은 항상 양수로 간주 (m이 음수면 m = |m|)
********************************************************************************/
SINT
BN_add_mod(
	BN *r,
	BN *a,
	BN *b,
	BN *m
	)
{
	BN_add(r, a, b);
	BN_mod(r, r, m);
	return 0;
}
/*******************************************************************************
* 함 수 명 : BN_sub_mod
*
* 함수인자 :
* *r - 출력받을 큰 수 r의 포인터
* *a - 입력받은 큰 수 a의 포인터
* *b - 입력받은 큰 수 b의 포인터
* *m - 입력받은 큰 수 m의 포인터
* Return :
* 0 - 성공
*
*-------------------------------------------------------------------------------
* 함수설명 : 큰 수 a와 b의 뺄셈 결과를 m으로 modular 하는 함수 (r = a-b mod m),
* Modulus m은 항상 양수로 간주 (m이 음수면 m = |m|),
* 큰 수 a, b와 r는 서로 다른 포인터를 가져야 함
********************************************************************************/
SINT
BN_sub_mod(
	BN *r,
	BN *a,
	BN *b,
	BN *m
	)
{
	BN_sub(r, a, b);
	BN_mod(r, r, m);
	return 0;
}
/*******************************************************************************
* 함 수 명 : BN_mul_mod
*
* 함수인자 :
* *r - 출력받을 큰 수 r의 포인터
* *a - 입력받은 큰 수 a의 포인터
* *b - 입력받은 큰 수 b의 포인터
* *m - 입력받은 큰 수 m의 포인터
* Return :
* 0 - 성공
*
*-------------------------------------------------------------------------------
* 함수설명 : 큰 수 a와 b의 곱셈 결과를 m으로 modular 하는 함수 (r = a*b mod m),
* Modulus m은 항상 양수로 간주 (m이 음수면 m = |m|),
* 큰 수 a, b와 r는 서로 다른 포인터를 가져야 함
********************************************************************************/
SINT
BN_mul_mod(
	BN *r,
	BN *a,
	BN *b,
	BN *m
	)
{
	BN_mul(r, a, b);
	BN_mod(r, r, m);
	return 0;
}
/*******************************************************************************
* 함 수 명 : BN_sqr_mod
*
* 함수인자 :
* *r - 출력받을 큰 수 r의 포인터
* *a - 입력받은 큰 수 a의 포인터
* *m - 입력받은 큰 수 m의 포인터
* Return :
* 0 - 성공
*
*-------------------------------------------------------------------------------
* 함수설명 : 큰 수 a의 제곱 결과를 m으로 modular 하는 함수 (r = a^2 mod m),
* Modulus m은 항상 양수로 간주 (m이 음수면 m = |m|),
* 큰 수 a와 r는 서로 다른 포인터를 가져야 함
********************************************************************************/
SINT
BN_sqr_mod(
	BN *r,
	BN *a,
	BN *m
	)
{
	BN_sqr(r, a);
	BN_mod(r, r, m);
	return 0;
}
/*******************************************************************************
* 함 수 명 : BN_mul_inv_mod
*
* 함수인자 :
* *b - 출력받을 큰 수 b의 포인터
* *a - 입력받은 큰 수 a의 포인터
* *m - 입력받은 큰 수 m의 포인터
* Return :
* 0 - 성공
*
*-------------------------------------------------------------------------------
* 함수설명 : 큰 수 a의 modular m에 대한 곱셈의 역원 연산 함수 (b = a^(-1) mod m),
* Modulus m은 항상 양수로 간주 (m이 음수면 m = |m|),
* 큰 수 a와 b는 서로 다른 포인터를 가져야 함
********************************************************************************/
SINT
BN_mul_inv_mod(
	BN *b,
	BN *a,
	BN *m
	)
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
* 함 수 명 : BN_l2r_pow_mod
*
* 함수인자 :
* *r - 출력받을 큰 수 r의 포인터
* *x - 입력받은 큰 수 x의 포인터
* *e - 입력받은 큰 수 e의 포인터
* *m - 입력받은 큰 수 m의 포인터
* Return :
* 0 - 성공
*
*-------------------------------------------------------------------------------
* 함수설명 : 큰 수 x와 e의 modular m에 대한 지수승 연산 함수 (r = x^(e) mod m),
* Modulus m은 항상 양수로 간주 (m이 음수면 m = |m|),
* 큰 수 x, e와 r는 서로 다른 포인터를 가져야 함
********************************************************************************/
SINT
BN_l2r_pow_mod(
	BN *r,
	BN *x,
	BN *e,
	BN *m
	)
{
	/*
	Modular exponentiation using Left to right binary exponentiation.
	r = x^e (mod m)
	*/
	SINT e_len, e_bit;
	BN tmp;
	ULONG tmp_dat[MAX_BN_BUF_LEN];
	ULONG *e_dat, mask;
	/* Check trivial cases */
	if (MAC_IS_BN_ZERO(*e)) {
		MAC_MAKE_ONE(*r);
		return 0;
	}
	if (MAC_IS_BN_ZERO(*x)) {
		MAC_MAKE_ZERO(*r);
		return 0;
	}
	MAC_BN_INIT(tmp, tmp_dat, MPCONST_POS_SIG);
	e_bit = (BN_nonzero_bits_num(e) - 1) % LONG_BITS;
	mask = 1 << e_bit;
	e_len = e->len;
	e_dat = &((e->dat)[e_len - 1]);
	MAC_MAKE_ONE(*r);
	while (e_len--) {
		while (mask) {
			BN_sqr_mod(&tmp, r, m);
			if ((*e_dat) & mask) {
				BN_mul_mod(r, &tmp, x, m);
			}
			else {
				BN_copy(r, &tmp);
			}
			mask >>= 1;
		}
		mask = HIGHER_MSB_ONE;
		e_dat--;
	}
	MAC_CLR_UPPER_ZEROBYTES(*r);
	return 0;
}
/*
Followings are for Montgomery exponentiation, originally.
*/
ULONG
BN_ULONG_mul_inv_mod_2e(ULONG x)
{
	/*
	Must check if a is odd and modulo is a power of 2.
	*/
	ULONG y, pow2, tmp, mask;
	SINT i;
	y = 1;
	mask = 1;
	pow2 = 1;
	for (i = 2; i <= LONG_BITS; i++) {
		/* pow2=2^(i-1) */
		pow2 <<= 1;
		mask = (mask << 1) + 1;
		/* t = xy (mod 2^i) */
		tmp = (x * y) & mask;
		if (pow2 < tmp) y |= pow2;
	}
	return y;
}
/*******************************************************************************
* 함 수 명 : BN_assign_MONT_BUF
*
* 함수인자 :
* *mont_ctx - MP_MONT_CTX의 포인터
* *mont_buf - MP_MONT_BUF의 포인터
* Return :
* 0 - 성공
*
*-------------------------------------------------------------------------------
* 함수설명 : Montgomery 연산을 위한 MP_MONT_CTX 구조체에 메모리 할당 함수
********************************************************************************/
SINT
BN_assign_MONT_BUF(
	MP_MONT_CTX *mont_ctx,
	MP_MONT_BUF *mont_buf
	)
{
	MAC_BN_INIT((mont_ctx->N), mont_buf->N_dat, MPCONST_POS_SIG);
	MAC_BN_INIT((mont_ctx->R), mont_buf->R_dat, MPCONST_POS_SIG);
	MAC_BN_INIT((mont_ctx->RR), mont_buf->RR_dat, MPCONST_POS_SIG);
	return 0;
}
/*******************************************************************************
* 함 수 명 : BN_assign_MONT_BUF
*
* 함수인자 :
* *mont_ctx - MP_MONT_CTX의 포인터
* *mod - 입력받은 큰 수 mod의 포인터
* Return :
* 0 - 성공
*
*-------------------------------------------------------------------------------
* 함수설명 : modular mod를 이용하여 Montgomery 연산을 위한 MP_MONT_CTX 구조체의
* 파라미터를 연산하는 함수
********************************************************************************/
SINT
BN_mont_init_mod(
	MP_MONT_CTX *mont_ctx,
	BN *mod
	)
{
	/*
	Given the modulus "mod", create a Montgomery context.
	R = b^n mod N,
	RR = R^2 mod N,
	m = -N^(-1) mod b.
	where b = 2^(LONG_BITS).
	*/
	BN tmp;
	ULONG tmp_dat[MAX_BN_BUF_LEN << 2];
	SINT n;
	n = mod->len;
	MAC_BN_INIT(tmp, tmp_dat, MPCONST_POS_SIG);
	/* R = b^n (mod N) */
	MAC_MAKE_ONE(tmp);
	BN_shl(&tmp, &tmp, n * LONG_BITS);
	BN_mod(&(mont_ctx->R), &tmp, mod);
	/* m = -N^(-1) (mod b = 2^LONG_BITS) */
	mont_ctx->m = BN_ULONG_mul_inv_mod_2e(mod->dat[0]);
	mont_ctx->m *= -1;
	/* RR = R^2 = b^(2*n) (mod N) */
	MAC_MAKE_ONE(tmp);
	BN_shl(&tmp, &tmp, (n << 1)*LONG_BITS);
	BN_mod(&(mont_ctx->RR), &tmp, mod);
	MAC_CLR_UPPER_ZEROBYTES(mont_ctx->RR);
	/* Setting the modulus. */
	BN_copy(&(mont_ctx->N), mod);
	return 0;
}
/*******************************************************************************
* 함 수 명 : BN_mont_mul_mod
*
* 함수인자 :
* *a - 큰 수 a의 포인터
* *mont_ctx - MP_MONT_CTX의 포인터
* Return :
* 0 - 성공
*
*-------------------------------------------------------------------------------
* 함수설명 : 큰 수 a에 대한 Montgomery 감산 연산 함수 (a = a mod m)
********************************************************************************/
SINT
BN_mont_red_mod(BN *a, MP_MONT_CTX *mont_ctx)
{
	/*
	Montgomery Reduction
	Make a = aR^(-1) (mod m).
	Refer to algorithm 14.32 (p601) of Handbook of Applied Cryptography.
	*/
	SINT i, n;
	BN *m, ta;
	ULONG mprime, u;
	/* Check trivial case */
	if (MAC_IS_BN_ZERO(*a))
		return 0;
	m = &(mont_ctx->N);
	n = m->len;
	mprime = mont_ctx->m;
	ta.dat = a->dat;
	ta.len = a->len;
	ta.sig = a->sig;
	/* MUST Check first unused word upper dat of BN before using BN_mult_ULONG_add() */
	ta.dat[ta.len] = 0;
	for (i = 0; i<n; i++) {
		u = ((ta.dat[0])*mprime) & BITMASK_LONG;
		BN_mult_ULONG_add(&ta, m, u);
		ta.dat++;
		ta.len--;
	}
	BN_copy(a, &ta);
	/* After Copying data from it to itself, we must clear upper words */
	memset(&a->dat[a->len], 0, a->len*sizeof(ULONG));
	if (BN_abs_comp(a, m) >= 0)
		BN_asym_sub(a, a, m);
	return 0;
}
/*******************************************************************************
* 함 수 명 : BN_mont_mul_mod
*
* 함수인자 :
* *a - 출력받을 큰 수 a의 포인터
* *x - 입력받은 큰 수 x의 포인터
* *y - 입력받은 큰 수 y의 포인터
* *mont_ctx - MP_MONT_CTX의 포인터
* Return :
* 0 - 성공
*
*-------------------------------------------------------------------------------
* 함수설명 : 큰 수 x와 y의 Montgomery 곱셈 연산 함수 (a = x*y mod m),
* 큰 수 x, y와 a는 서로 다른 포인터를 가져야 함
********************************************************************************/
SINT
BN_mont_mul_mod(
	BN *a,
	BN *x,
	BN *y,
	MP_MONT_CTX *mont_ctx
	)
{
	/*
	Montgomery multiplication.
	*/
	BN t;
	ULONG tmp[MAX_BN_BUF_LEN];
	memset(tmp, 0, (MAC_MAX(x->len, y->len) << 3) + 4);
	t.dat = tmp;
	/* 카라슈바 곱셈 사용*/
	if ((x->len == KARA_2048_WORD_LEN) && (y->len == KARA_2048_WORD_LEN)) {
		if (x == y)
			BN_sqr(&t, x);
		else
			BN_kar_mul_2048(&t, x, y);
	}
	else if ((x->len == KARA_3072_WORD_LEN) && (y->len == KARA_3072_WORD_LEN)) {
		if (x == y)
			BN_sqr(&t, x);
		else
			BN_kar_mul_3072(&t, x, y);
	}
	else {
		if (x == y)
			BN_sqr(&t, x);
		else
			BN_mul(&t, x, y);
	}
	BN_mont_red_mod(&t, mont_ctx);
	BN_copy(a, &t);
	return 0;
}
/*******************************************************************************
* 함 수 명 : BN_mont_pow_mod
*
* 함수인자 :
* *r - 출력받을 큰 수 r의 포인터
* *x - 입력받은 큰 수 x의 포인터
* *e - 입력받은 큰 수 e의 포인터
* *mont_ctx - MP_MONT_CTX의 포인터
* Return :
* 0 - 성공
*
*-------------------------------------------------------------------------------
* 함수설명 : 큰 수 x와 e의 Montgomery 지수승 연산 함수 (r = x^(e) mod m),
* 큰 수 x, e와 r는 서로 다른 포인터를 가져야 함
********************************************************************************/
SINT
BN_mont_pow_mod(
	BN *r,
	BN *x,
	BN *e,
	MP_MONT_CTX *mont_ctx
	)
{
	/*
	Montgomery exponentiation. x^e(mod N)
	*/
	SINT e_len, e_bit;
	BN tmp1, tmp2;
	ULONG tmp1_dat[MAX_BN_BUF_LEN], tmp2_dat[MAX_BN_BUF_LEN];
	ULONG *e_dat, mask;
	if (MAC_IS_BN_ZERO(*e)) {
		MAC_MAKE_ONE(*r);
		return 0;
	}
	if (MAC_IS_BN_ZERO(*x)) {
		MAC_MAKE_ZERO(*r);
		return 0;
	}
	MAC_BN_INIT(tmp1, tmp1_dat, MPCONST_POS_SIG);
	MAC_BN_INIT(tmp2, tmp2_dat, MPCONST_POS_SIG);
	BN_mont_mul_mod(&tmp2, x, &(mont_ctx->RR), mont_ctx);
	BN_copy(r, &(mont_ctx->R));
	/* Set up a mask. */
	e_bit = (BN_nonzero_bits_num(e) - 1) % LONG_BITS;
	mask = 1 << e_bit;
	e_len = e->len;
	e_dat = &((e->dat)[e_len - 1]);
	while (e_len--) {
		while (mask) {
			//BN_sqr(r,&tmp1);
			//BN_mont_red_mod(&tmp1,mont_ctx);
			BN_mont_mul_mod(r, &tmp1, &tmp1, mont_ctx);
			if ((*e_dat) & mask) {
				if (tmp2.len < mont_ctx->N.len) {
					BN_asym_add(&tmp2, &mont_ctx->N, &tmp2);
				}
				BN_mont_mul_mod(r, &tmp1, &tmp2, mont_ctx);
			}
			else {
				BN_copy(r, &tmp1);
			}
			mask >>= 1;
		}
		mask = HIGHER_MSB_ONE;
		e_dat--;
	}
	BN_mont_red_mod(r, mont_ctx);
	MAC_CLR_UPPER_ZEROBYTES(*r);
	return 0;
}
/*******************************************************************************
* 함 수 명 : BN_mont_sw_pow_mod
*
* 함수인자 :
* *r - 출력받을 큰 수 r의 포인터
* *x - 입력받은 큰 수 x의 포인터
* *e - 입력받은 큰 수 e의 포인터
* *mont_ctx - MP_MONT_CTX의 포인터
* Return :
* 0 - 성공
*
*-------------------------------------------------------------------------------
* 함수설명 : 큰 수 x와 e의 슬라이딩 윈도우 Montgomery 지수승 연산 함수
* (r = x^(e) mod m), 큰 수 x, e와 r는 서로 다른 포인터를 가져야 함
********************************************************************************/
SINT
BN_mont_sw_pow_mod(BN *r, BN *x, BN *e, MP_MONT_CTX *mont_ctx)
{
#define PRECOMP_NUM 16 /* Number of items in the precomputation = 2^(WINBITS-1) (only store odd multiples) */
#define WIN_BITS 5 /* Maximum number of bits in a sliding window */
#define WIN_BITS_1 4 /* = WIN_BITS - 1 */
	/*
	Montgomery exponentiation. x^e(mod N) using a sliding window method.
	*/
	BN tmp;
	ULONG tmp_dat[MAX_BN_BUF_LEN];
	BN precomp_tab[PRECOMP_NUM];
	ULONG precomp_tab_dat[PRECOMP_NUM][MAX_BN_BUF_LEN << 2];
	BN *cur, *not_cur, *tmp_cur;
	SINT ind, this_win_size, end_win_ind, i, precomp_ind;
	/*
	Check trivial cases.
	*/
	if (MAC_IS_BN_ZERO(*e)) {
		MAC_MAKE_ONE(*r);
	}
	if (MAC_IS_BN_ZERO(*x)) {
		MAC_MAKE_ZERO(*r);
	}
	MAC_BN_INIT(tmp, tmp_dat, MPCONST_POS_SIG);
	/* Precomputation */
	for (i = 0; i<PRECOMP_NUM; i++) {
		precomp_tab[i].dat = precomp_tab_dat[i];
		precomp_tab[i].len = 0;
		precomp_tab[i].sig = MPCONST_ZERO_SIG;
	}
	BN_mont_mul_mod(&precomp_tab[0], x, &(mont_ctx->RR), mont_ctx); /* precomp_tab[0] = x */
	BN_sqr(&tmp, &precomp_tab[0]);
	BN_mont_red_mod(&tmp, mont_ctx); /* tmp = x^2 */
	for (i = 1; i<PRECOMP_NUM; i++) {
		/* precomp_tab[i] = x^(2*i + 1) */
		BN_mont_mul_mod(&precomp_tab[i], &precomp_tab[i - 1], &tmp, mont_ctx);
	}
	/* End precomputation */
	BN_copy(r, &(mont_ctx->R)); /* r = 1 */
	cur = r;
	not_cur = &tmp;
	ind = (BN_nonzero_bits_num(e) - 1);
	while (ind >= 0) {
		if (!MAC_BIT_IS_SET(*e, ind)) {
			BN_sqr(not_cur, cur);
			BN_mont_red_mod(not_cur, mont_ctx);
			tmp_cur = cur;
			cur = not_cur;
			not_cur = tmp_cur;
			ind--;
		}
		else {
			end_win_ind = ((ind > WIN_BITS_1) ? (ind - WIN_BITS_1) : 0);
			while (!MAC_BIT_IS_SET(*e, end_win_ind)) {
				end_win_ind++;
			}
			this_win_size = ind - end_win_ind + 1;
			if (this_win_size & 1) {
				BN_sqr(not_cur, cur);
				BN_mont_red_mod(not_cur, mont_ctx);
			}
			else {
				tmp_cur = cur;
				cur = not_cur;
				not_cur = tmp_cur;
			}
			for (i = 0; i<this_win_size >> 1; i++) {
				BN_sqr(cur, not_cur);
				BN_mont_red_mod(cur, mont_ctx);
				BN_sqr(not_cur, cur);
				BN_mont_red_mod(not_cur, mont_ctx);
			}
			precomp_ind = 1;
			for (i = ind - 1; i >= end_win_ind; i--) {
				precomp_ind = precomp_ind << 1;
				precomp_ind |= MAC_BIT_IS_SET(*e, i);
			}
			precomp_ind = precomp_ind >> 1;
			BN_mont_mul_mod(cur, &precomp_tab[precomp_ind], not_cur, mont_ctx);
			ind = end_win_ind - 1;
		}
	}
	if (r != cur) {
		BN_copy(r, cur);
	}
	BN_mont_red_mod(r, mont_ctx);
	MAC_CLR_UPPER_ZEROBYTES(*r);
	return 0;
}
/*******************************************************************************
* 함 수 명 : BN_pow_mod
*
* 함수인자 :
* *r - 출력받을 큰 수 r의 포인터
* *x - 입력받은 큰 수 x의 포인터
* *e - 입력받은 큰 수 e의 포인터
* *m - 입력받은 큰 수 m의 포인터
* Return :
* 0 - 성공
*
*-------------------------------------------------------------------------------
* 함수설명 : 큰 수 x와 e의 modular m에 대한 지수승 연산 함수
* (r = x^(e) mod m), 큰 수 x, e와 r는 서로 다른 포인터를 가져야 함
********************************************************************************/
SINT
BN_pow_mod(
	BN *r,
	BN *x,
	BN *e,
	BN *m
	)
{
	/*
	An Interface for BN modular exponentiations.
	Define one macro constant to use one algorithm.
	*/
#define _USE_MONT_WIN_POW_MOD_
	/*
	#define _USE_MONT_POW_MOD_
	#define _USE_MONT_WIN_POW_MOD_
	*/
#if defined (_USE_L2R_POW_MOD_)
	BN_l2r_pow_mod(r, x, e, m);
#else
	MP_MONT_CTX mont_ctx;
	ULONG N_dat[MAX_BN_BUF_LEN], R_dat[MAX_BN_BUF_LEN], RR_dat[MAX_BN_BUF_LEN];
	mont_ctx.N.dat = N_dat;
	mont_ctx.R.dat = R_dat;
	mont_ctx.RR.dat = RR_dat;
	if (x->len >= m->len) {
		BN_mod(x, x, m);
	}
	BN_mont_init_mod(&mont_ctx, m);
#if defined (_USE_MONT_POW_MOD_)
	BN_mont_pow_mod(r, x, e, &mont_ctx);
#elif defined (_USE_MONT_WIN_POW_MOD_)
	BN_mont_sw_pow_mod(r, x, e, &mont_ctx);
#endif
#endif /* _USE_L2R_POW_MOD_ */
	if (e->dat[0] & LOWER_LSB_ONE /*case that e is odd */) {
		r->sig = x->sig;
	}
	else {
		r->sig = MPCONST_POS_SIG;
	}
	return 0;
}
/*****************************************/
/* BN Gcd algorithms */
/* Warning : not optimized sufficiently */
/*****************************************/
/*******************************************************************************
* 함 수 명 : BN_euclid_gcd
*
* 함수인자 :
* *c - 출력받을 큰 수 r의 포인터
* *a - 입력받은 큰 수 x의 포인터
* *b - 입력받은 큰 수 e의 포인터
* Return :
* 0 - 성공
*
*-------------------------------------------------------------------------------
* 함수설명 : 큰 수 a와 b의 Euclid GCD 연산 함수 (c = GCD(a,b)),
* 큰 수 a, b와 r는 서로 다른 포인터를 가져야 함
********************************************************************************/
SINT
BN_euclid_gcd(
	BN *c,
	BN *a,
	BN *b
	)
{
	/*
	Euclidean G.C.D algorithm
	Algorithm Spec : Refer to chapter 14 of 'Handbook of Applied Cryptography' (Menezes)
	*/
	BN *pta, *ptb, *swp_t;
	if (BN_abs_comp(a, b)>0) {
		pta = a;
		ptb = b;
	}
	else {
		pta = b;
		ptb = a;
	}
	while (1) {
		if (MAC_IS_BN_ZERO(*ptb))
			break;
		BN_mod(pta, pta, ptb);
		MAC_SWAP(pta, ptb, swp_t);
	}
	BN_copy(c, pta);
	return 0;
}
/*******************************************************************************
* 함 수 명 : BN_gcd
*
* 함수인자 :
* *c - 출력받을 큰 수 r의 포인터
* *a - 입력받은 큰 수 x의 포인터
* *b - 입력받은 큰 수 e의 포인터
* Return :
* 0 - 성공
*
*-------------------------------------------------------------------------------
* 함수설명 : 큰 수 a와 b의 GCD 연산 함수 (c = GCD(a,b)),
* 큰 수 a, b와 r는 서로 다른 포인터를 가져야 함
********************************************************************************/
SINT
BN_gcd(
	BN *c,
	BN *a,
	BN *b
	)
{
	/*
	WARNING!
	Binary , Euclidean cases need tmporary buffers since they are
	implemented to change input values in the procedures.
	But lehmer has its own buffers in it.
	*/
	BN ta, tb;
	ULONG ta_dat[MAX_BN_BUF_LEN], tb_dat[MAX_BN_BUF_LEN];
	ta.dat = ta_dat;
	tb.dat = tb_dat;
	BN_copy(&ta, a);
	BN_copy(&tb, b);
	BN_euclid_gcd(c, &ta, &tb);
	return 0;
}
/****************************************/
/* 큰 수 prime test 및 소수 생성 함수 */
/****************************************/
static ULONG small_prime[] = {
	2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
	59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131,
	137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223,
	227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311,
	313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
	419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
	509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613,
	617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719,
	727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827,
	829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
	947, 953, 967, 971, 977, 983, 991, 997,1009,1013,1019,1021,1031,1033,1039,1049,
	1051,1061,1063,1069,1087,1091,1093,1097,1103,1109,1117,1123,1129,1151,1153,1163,
	1171,1181,1187,1193,1201,1213,1217,1223,1229,1231,1237,1249,1259,1277,1279,1283,
	1289,1291,1297,1301,1303,1307,1319,1321,1327,1361,1367,1373,1381,1399,1409,1423,
	1427,1429,1433,1439,1447,1451,1453,1459,1471,1481,1483,1487,1489,1493,1499,1511,
	1523,1531,1543,1549,1553,1559,1567,1571,1579,1583,1597,1601,1607,1609,1613,1619,
	1621,1627,1637,1657,1663,1667,1669,1693,1697,1699,1709,1721,1723,1733,1741,1747,
	1753,1759,1777,1783,1787,1789,1801,1811,1823,1831,1847,1861,1867,1871,1873,1877,
	1879,1889,1901,1907,1913,1931,1933,1949,1951,1973,1979,1987,1993,1997,1999,2003,
	2011,2017,2027,2029,2039,2053,2063,2069,2081,2083,2087,2089,2099,2111,2113,2129,
	2131,2137,2141,2143,2153,2161,2179,2203,2207,2213,2221,2237,2239,2243,2251,2267,
	2269,2273,2281,2287,2293,2297,2309,2311,2333,2339,2341,2347,2351,2357,2371,2377,
	2381,2383,2389,2393,2399,2411,2417,2423,2437,2441,2447,2459,2467,2473,2477,2503,
	2521,2531,2539,2543,2549,2551,2557,2579,2591,2593,2609,2617,2621,2633,2647,2657,
	2659,2663,2671,2677,2683,2687,2689,2693,2699,2707,2711,2713,2719,2729,2731,2741,
	2749,2753,2767,2777,2789,2791,2797,2801,2803,2819,2833,2837,2843,2851,2857,2861,
	2879,2887,2897,2903,2909,2917,2927,2939,2953,2957,2963,2969,2971,2999,3001,3011,
	3019,3023,3037,3041,3049,3061,3067,3079,3083,3089,3109,3119,3121,3137,3163,3167,
	3169,3181,3187,3191,3203,3209,3217,3221,3229,3251,3253,3257,3259,3271,3299,3301,
	3307,3313,3319,3323,3329,3331,3343,3347,3359,3361,3371,3373,3389,3391,3407,3413,
	3433,3449,3457,3461,3463,3467,3469,3491,3499,3511,3517,3527,3529,3533,3539,3541,
	3547,3557,3559,3571,3581,3583,3593,3607,3613,3617,3623,3631,3637,3643,3659,3671,
	3673,3677,3691,3697,3701,3709,3719,3727,3733,3739,3761,3767,3769,3779,3793,3797,
	3803,3821,3823,3833,3847,3851,3853,3863,3877,3881,3889,3907,3911,3917,3919,3923,
	3929,3931,3943,3947,3967,3989,4001,4003,4007,4013,4019,4021,4027,4049,4051,4057,
	4073,4079,4091,4093,4099,4111,4127,4129,4133,4139,4153,4157,4159,4177,4201,4211,
	4217,4219,4229,4231,4241,4243,4253,4259,4261,4271,4273,4283,4289,4297,4327,4337,
	4339,4349,4357,4363,4373,4391,4397,4409,4421,4423,4441,4447,4451,4457,4463,4481,
	4483,4493,4507,4513,4517,4519,4523,4547,4549,4561,4567,4583,4591,4597,4603,4621,
	4637,4639,4643,4649,4651,4657,4663,4673,4679,4691,4703,4721,4723,4729,4733,4751,
	4759,4783,4787,4789,4793,4799,4801,4813,4817,4831,4861,4871,4877,4889,4903,4909,
	4919,4931,4933,4937,4943,4951,4957,4967,4969,4973,4987,4993,4999,5003,5009,5011,
	5021,5023,5039,5051,5059,5077,5081,5087,5099,5101,5107,5113,5119,5147,5153,5167,
	5171,5179,5189,5197,5209,5227,5231,5233,5237,5261,5273,5279,5281,5297,5303,5309,
	5323,5333,5347,5351,5381,5387,5393,5399,5407,5413,5417,5419,5431,5437,5441,5443,
	5449,5471,5477,5479,5483,5501,5503,5507,5519,5521,5527,5531,5557,5563,5569,5573,
	5581,5591,5623,5639,5641,5647,5651,5653,5657,5659,5669,5683,5689,5693,5701,5711,
	5717,5737,5741,5743,5749,5779,5783,5791,5801,5807,5813,5821,5827,5839,5843,5849,
	5851,5857,5861,5867,5869,5879,5881,5897,5903,5923,5927,5939,5953,5981,5987,6007,
	6011,6029,6037,6043,6047,6053,6067,6073,6079,6089,6091,6101,6113,6121,6131,6133,
	6143,6151,6163,6173,6197,6199,6203,6211,6217,6221,6229,6247,6257,6263,6269,6271,
	6277,6287,6299,6301,6311,6317,6323,6329,6337,6343,6353,6359,6361,6367,6373,6379,
	6389,6397,6421,6427,6449,6451,6469,6473,6481,6491,6521,6529,6547,6551,6553,6563,
	6569,6571,6577,6581,6599,6607,6619,6637,6653,6659,6661,6673,6679,6689,6691,6701,
	6703,6709,6719,6733,6737,6761,6763,6779,6781,6791,6793,6803,6823,6827,6829,6833,
	6841,6857,6863,6869,6871,6883,6899,6907,6911,6917,6947,6949,6959,6961,6967,6971,
	6977,6983,6991,6997,7001,7013,7019,7027,7039,7043,7057,7069,7079,7103,7109,7121,
	7127,7129,7151,7159,7177,7187,7193,7207,7211,7213,7219,7229,7237,7243,7247,7253,
	7283,7297,7307,7309,7321,7331,7333,7349,7351,7369,7393,7411,7417,7433,7451,7457,
	7459,7477,7481,7487,7489,7499,7507,7517,7523,7529,7537,7541,7547,7549,7559,7561,
	7573,7577,7583,7589,7591,7603,7607,7621,7639,7643,7649,7669,7673,7681,7687,7691,
	7699,7703,7717,7723,7727,7741,7753,7757,7759,7789,7793,7817,7823,7829,7841,7853,
	7867,7873,7877,7879,7883,7901,7907,7919,7927,7933,7937,7949,7951,7963,7993,8009,
	8011,8017,8039,8053,8059,8069,8081,8087,8089,8093,8101,8111,8117,8123,8147,8161,
	8167,8171,8179,8191,8209,8219,8221,8231,8233,8237,8243,8263,8269,8273,8287,8291,
	8293,8297,8311,8317,8329,8353,8363,8369,8377,8387,8389,8419,8423,8429,8431,8443,
	8447,8461,8467,8501,8513,8521,8527,8537,8539,8543,8563,8573,8581,8597,8599,8609,
	8623,8627,8629,8641,8647,8663,8669,8677,8681,8689,8693,8699,8707,8713,8719,8731,
	8737,8741,8747,8753,8761,8779,8783,8803,8807,8819,8821,8831,8837,8839,8849,8861,
	8863,8867,8887,8893,8923,8929,8933,8941,8951,8963,8969,8971,8999,9001,9007,9011,
	9013,9029,9041,9043,9049,9059,9067,9091,9103,9109,9127,9133,9137,9151,9157,9161,
	9173,9181,9187,9199,9203,9209,9221,9227,9239,9241,9257,9277,9281,9283,9293,9311,
	9319,9323,9337,9341,9343,9349,9371,9377,9391,9397,9403,9413,9419,9421,9431,9433,
	9437,9439,9461,9463,9467,9473,9479,9491,9497,9511,9521,9533,9539,9547,9551,9587,
	9601,9613,9619,9623,9629,9631,9643,9649,9661,9677,9679,9689,9697,9719,9721,9733,
	9739,9743,9749,9767,9769,9781,9787,9791,9803,9811,9817,9829,9833,9839,9851,9857,
	9859,9871,9883,9887,9901,9907,9923,9929,9931,9941,9949,9967,9973,10007,10009,10037,
	10039,10061,10067,10069,10079,10091,10093,10099,10103,10111,10133,10139,10141,10151,10159,10163,
	10169,10177,10181,10193,10211,10223,10243,10247,10253,10259,10267,10271,10273,10289,10301,10303,
	10313,10321,10331,10333,10337,10343,10357,10369,10391,10399,10427,10429,10433,10453,10457,10459,
	10463,10477,10487,10499,10501,10513,10529,10531,10559,10567,10589,10597,10601,10607,10613,10627,
	10631,10639,10651,10657,10663,10667,10687,10691,10709,10711,10723,10729,10733,10739,10753,10771,
	10781,10789,10799,10831,10837,10847,10853,10859,10861,10867,10883,10889,10891,10903,10909,10937,
	10939,10949,10957,10973,10979,10987,10993,11003,11027,11047,11057,11059,11069,11071,11083,11087,
	11093,11113,11117,11119,11131,11149,11159,11161,11171,11173,11177,11197,11213,11239,11243,11251,
	11257,11261,11273,11279,11287,11299,11311,11317,11321,11329,11351,11353,11369,11383,11393,11399,
	11411,11423,11437,11443,11447,11467,11471,11483,11489,11491,11497,11503,11519,11527,11549,11551,
	11579,11587,11593,11597,11617,11621,11633,11657,11677,11681,11689,11699,11701,11717,11719,11731,
	11743,11777,11779,11783,11789,11801,11807,11813,11821,11827,11831,11833,11839,11863,11867,11887,
	11897,11903,11909,11923,11927,11933,11939,11941,11953,11959,11969,11971,11981,11987,12007,12011,
	12037,12041,12043,12049,12071,12073,12097,12101,12107,12109,12113,12119,12143,12149,12157,12161,
	12163,12197,12203,12211,12227,12239,12241,12251,12253,12263,12269,12277,12281,12289,12301,12323,
	12329,12343,12347,12373,12377,12379,12391,12401,12409,12413,12421,12433,12437,12451,12457,12473,
	12479,12487,12491,12497,12503,12511,12517,12527,12539,12541,12547,12553,12569,12577,12583,12589,
	12601,12611,12613,12619,12637,12641,12647,12653,12659,12671,12689,12697,12703,12713,12721,12739,
	12743,12757,12763,12781,12791,12799,12809,12821,12823,12829,12841,12853,12889,12893,12899,12907,
	12911,12917,12919,12923,12941,12953,12959,12967,12973,12979,12983,13001,13003,13007,13009,13033,
	13037,13043,13049,13063,13093,13099,13103,13109,13121,13127,13147,13151,13159,13163,13171,13177,
	13183,13187,13217,13219,13229,13241,13249,13259,13267,13291,13297,13309,13313,13327,13331,13337,
	13339,13367,13381,13397,13399,13411,13417,13421,13441,13451,13457,13463,13469,13477,13487,13499,
	13513,13523,13537,13553,13567,13577,13591,13597,13613,13619,13627,13633,13649,13669,13679,13681,
	13687,13691,13693,13697,13709,13711,13721,13723,13729,13751,13757,13759,13763,13781,13789,13799,
	13807,13829,13831,13841,13859,13873,13877,13879,13883,13901,13903,13907,13913,13921,13931,13933,
	13963,13967,13997,13999,14009,14011,14029,14033,14051,14057,14071,14081,14083,14087,14107,14143,
	14149,14153,14159,14173,14177,14197,14207,14221,14243,14249,14251,14281,14293,14303,14321,14323,
	14327,14341,14347,14369,14387,14389,14401,14407,14411,14419,14423,14431,14437,14447,14449,14461,
	14479,14489,14503,14519,14533,14537,14543,14549,14551,14557,14561,14563,14591,14593,14621,14627,
	14629,14633,14639,14653,14657,14669,14683,14699,14713,14717,14723,14731,14737,14741,14747,14753,
	14759,14767,14771,14779,14783,14797,14813,14821,14827,14831,14843,14851,14867,14869,14879,14887,
	14891,14897,14923,14929,14939,14947,14951,14957,14969,14983,15013,15017,15031,15053,15061,15073,
	15077,15083,15091,15101,15107,15121,15131,15137,15139,15149,15161,15173,15187,15193,15199,15217,
	15227,15233,15241,15259,15263,15269,15271,15277,15287,15289,15299,15307,15313,15319,15329,15331,
	15349,15359,15361,15373,15377,15383,15391,15401,15413,15427,15439,15443,15451,15461,15467,15473,
	15493,15497,15511,15527,15541,15551,15559,15569,15581,15583,15601,15607,15619,15629,15641,15643,
	15647,15649,15661,15667,15671,15679,15683,15727,15731,15733,15737,15739,15749,15761,15767,15773,
	15787,15791,15797,15803,15809,15817,15823,15859,15877,15881,15887,15889,15901,15907,15913,15919,
	15923,15937,15959,15971,15973,15991,16001,16007,16033,16057,16061,16063,16067,16069,16073,16087,
	16091,16097,16103,16111,16127,16139,16141,16183,16187,16189,16193,16217,16223,16229,16231,16249,
	16253,16267,16273,16301,16319,16333,16339,16349,16361,16363,16369,16381,16411,16417,16421,16427,
	16433,16447,16451,16453,16477,16481,16487,16493,16519,16529,16547,16553,16561,16567,16573,16603,
	16607,16619,16631,16633,16649,16651,16657,16661,16673,16691,16693,16699,16703,16729,16741,16747,
	16759,16763,16787,16811,16823,16829,16831,16843,16871,16879,16883,16889,16901,16903,16921,16927,
	16931,16937,16943,16963,16979,16981,16987,16993,17011,17021,17027,17029,17033,17041,17047,17053,
	17077,17093,17099,17107,17117,17123,17137,17159,17167,17183,17189,17191,17203,17207,17209,17231,
	17239,17257,17291,17293,17299,17317,17321,17327,17333,17341,17351,17359,17377,17383,17387,17389,
	17393,17401,17417,17419,17431,17443,17449,17467,17471,17477,17483,17489,17491,17497,17509,17519,
	17539,17551,17569,17573,17579,17581,17597,17599,17609,17623,17627,17657,17659,17669,17681,17683,
	17707,17713,17729,17737,17747,17749,17761,17783,17789,17791,17807,17827,17837,17839,17851,17863,0
};
/*******************************************************************************
* 함 수 명 : BN_MR_prime_test
*
* 함수인자 :
* *p - 입력받은 큰 수 p의 포인터
* iter - prime test 실행 횟수
* Return :
* TRUE - 소수 판정 성공
* FALSE - 소수 판정 실패
*
*-------------------------------------------------------------------------------
* 함수설명 : 큰 수 p에 대한 밀러라빈 소수 판정 함수
********************************************************************************/
SINT
BN_MR_prime_test(
	BN *p,
	SINT iter
	)
{
	SINT i = 0, j, check_s = 0;
	BN Copy_p, p_s, a, y, r, tmp;
	ULONG p_s_dat[MAX_BN_BUF_LEN], a_dat[MAX_BN_BUF_LEN], y_dat[MAX_BN_BUF_LEN],
		r_dat[MAX_BN_BUF_LEN], tmp_dat[MAX_BN_BUF_LEN];
	Copy_p.dat = p->dat;
	Copy_p.len = p->len;
	Copy_p.sig = p->sig;
	p_s.dat = p_s_dat;
	tmp.dat = tmp_dat;
	while (small_prime[i] != 0) {
		if (BN_mod_half_ULONG(&Copy_p, small_prime[i]) == 0) return FALSE;
		i++;
	}
	MAC_BN_INIT(a, a_dat, MPCONST_POS_SIG);
	MAC_BN_INIT(y, y_dat, MPCONST_POS_SIG);
	MAC_BN_INIT(r, r_dat, MPCONST_POS_SIG);
	BN_sub_ULONG(&p_s, &Copy_p, 1);
	for (i = 0; i<p_s.len; i++) {
		for (j = 31; j >= 0; j--) {
			if ((p_s.dat[i] << j) == 0) check_s++;
			else {
				i = 0xffffffff;
				break;
			}
		}
		if (i == 0xffffffff) break;
	}
	BN_shr(&r, &p_s, check_s);
	for (i = 0; i <= iter; i++) {
		a.dat[0] = small_prime[i];
		a.len = 1;
		a.sig = 1;
		BN_pow_mod(&y, &a, &r, &Copy_p);
		if ((BN_abs_comp(&p_s, &y) != 0) && (MAC_IS_BN_ONE(y) != 1)) {
			j = 1;
			while ((BN_abs_comp(&p_s, &y) != 0) && (j<check_s)) {
				BN_sqr_mod(&tmp, &y, &Copy_p);
				BN_copy(&y, &tmp);
				if (MAC_IS_BN_ONE(y)) return FALSE;
				j++;
			}
			if (BN_abs_comp(&p_s, &y) != 0) return FALSE;
		}
	}
	return TRUE;
}
/*******************************************************************************
* 함 수 명 : BN_gen_prime
*
* 함수인자 :
* *a - 출력받을 큰 수 a의 포인터
* *prng_ctx - BN_X9_PRNG_CTX의 포인터
* *b - 입력받은 큰 수 a의 포인터
* *c - 입력받은 큰 수 a의 포인터
* *d - 입력받은 큰 수 a의 포인터
* Return :
* 0 - 소수 생성 성공
* -1 - 소수 생성 실패
*
*-------------------------------------------------------------------------------
* 함수설명 : 소수를 생성하는 함수 (b<a<c),
* 소수의 판정은 밀러라빈 소수 판정을 사용함
********************************************************************************/
SINT
BN_gen_prime(
	BN *a,
	BN_X9_PRNG_CTX *prng_ctx,
	BN *b,
	BN *c,
	BN *d
	)
{
	/*
	Generating prime number 'a' between 'b' and 'c' divisible by 'd'
	*/
	BN tmp;
	ULONG tmp_dat[MAX_BN_BUF_LEN];
	/* Check wrong case */
	MAC_BN_INIT(tmp, tmp_dat, MPCONST_POS_SIG);
	/* Generate random number between b and c. */
	BN_X9_31_PRNG(a, prng_ctx, (c->len << 5));
	/* At first, make 'a' be a number between 'b' and 'c'. */
	/* a = (a mod(c-b+1) ) + b */
	BN_sub(&tmp, c, b);
	BN_add_ULONG(&tmp, &tmp, 1);
	BN_mod(a, a, &tmp);
	BN_add(a, a, b);
	/* Adjust so that a-1 is divisible by d. */
	/* a = a + 1 - (a mod d) */
	BN_mod(&tmp, a, d);
	BN_sub(a, a, &tmp);
	BN_add_ULONG(a, a, 1);
	/* After following process, 'a-1' remains a multiple of 'd' */
	/* Since we subtract a number less than 'd-1' from 'a', addition or
	subtraction of d make 'a' be inside interval at once. */
	if (BN_abs_comp(a, b) < 0)
		BN_add(a, a, d);
	if (BN_abs_comp(a, c) > 0)
		BN_sub(a, a, d);
	/* Search to c in steps of d. */
	/* Make upper bound of searching step which is c-d */
	BN_sub(&tmp, c, d);
	while (!BN_MR_prime_test(a, PRIME_TEST_NUM)) {
		if (BN_abs_comp(a, &tmp) > 0)
			return(-1);
		BN_add(a, a, d);
	}
	return(0);
}
/***************************/
/* X9.31 난수생성기 함수 */
/***************************/

/*******************************************************************************
* 함 수 명 : BN_X9_31_PRNG_CTX_init
*
* 함수인자 :
* *prng_ctx - BN_X9_PRNG_CTX의 포인터
* *prng_buf - BN_X9_PRNG_BUF의 포인터
* Return :
* 0 - 소수 생성 성공
* -1 - 소수 생성 실패
*
*-------------------------------------------------------------------------------
* 함수설명 : 난수생성 함수를 위한 BN_X9_PRNG_CTX 구조체에 메로리 할당 함수
********************************************************************************/

SINT
BN_X9_31_PRNG_CTX_init(
	BN_X9_PRNG_CTX *prng_ctx,
	BN_X9_PRNG_BUF *prng_buf
	)
{
	UCHAR sha1_in[SHA1_BLOCK_BYTES];
	// ULONG cur_time;
	ULONG t[20 + 1];
	// SINT i;
	/* Allocate memories to input context. */
	MAC_BN_INIT_MEM_CLR(prng_ctx->sgord, prng_buf->sgord_dat, 1);
	MAC_BN_INIT_MEM_CLR(prng_ctx->xseed, prng_buf->xseed_dat, 1);
	MAC_BN_INIT_MEM_CLR(prng_ctx->xkey, prng_buf->xkey_dat, 1);
	/* xkey value will not be evaluated here. It changes everytime when PRNG used by user. */
	/* Initialize xseed with the SHA1_DgstUnit */
	t[0] = 0x67452301;
	t[1] = 0xefcdab89;
	t[2] = 0x98badcfe;
	t[3] = 0x10325476;
	t[4] = 0xc3d2e1f0;
	K_DRBG_GetSysRandom(sha1_in, SHA1_BLOCK_BYTES);
	SHA1_dgst_unit(t, sha1_in);
	prng_ctx->xseed.dat[0] = t[0];
	prng_ctx->xseed.dat[1] = t[1];
	prng_ctx->xseed.dat[2] = t[2];
	prng_ctx->xseed.dat[3] = t[3];
	prng_ctx->xseed.dat[4] = t[4];
	prng_ctx->xseed.len = 5;
	/* Initialize a default xkey with the SHA1_DgstUnit */
	SHA1_dgst_unit(t, sha1_in);
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
* 함 수 명 : BN_X9_31_PRNG
*
* 함수인자 :
* *a - 출력받을 큰 수 a의 포인터
* *prng_ctx - BN_X9_PRNG_CTX의 포인터
* l - 생성할 난수의 길이 정보
* Return :
* 0 - 난수 생성 성공
* -1 - 실패 (입력 난수 길이가 0보다 작은 경우)
*
*-------------------------------------------------------------------------------
* 함수설명 : X9.31 난수생성기를 이용하여 l 비트 난수 p를 생성하는 함수
********************************************************************************/
SINT
BN_X9_31_PRNG(
	BN *p,
	BN_X9_PRNG_CTX *prng_ctx,
	SINT l
	)
{
	/*
	PRNG follows ANSI x9.31 standard.
	input 'xkey' will be updated for next call of this procedure
	*/
	BN *xseed, *xkey, *sgord;
	BN xval, x;
	ULONG x_dat[5 + 1], xval_dat[5 + 1], c_len, x_len, m, i;
	ULONG t[20 + 1];
	UCHAR c[SHA1_BLOCK_BYTES], x_cdat[20 + 1];
	UCHAR r[MAX_BN_BUF_LEN << 2], *pr;
	if (l <= 0) {
		return -1;
	}
	// 주소 copy
	xseed = &prng_ctx->xseed;
	xkey = &prng_ctx->xkey;
	sgord = &prng_ctx->sgord;
	pr = r;
	MAC_BN_INIT(x, x_dat, MPCONST_POS_SIG);
	MAC_BN_INIT(xval, xval_dat, MPCONST_POS_SIG);
	t[0] = 0x67452301;
	t[1] = 0xefcdab89;
	t[2] = 0x98badcfe;
	t[3] = 0x10325476;
	t[4] = 0xc3d2e1f0;
	m = (l + 159) / 160;
	for (i = 0; i < m; i++) {
		x.len = 5;
		xseed->len = 5;
		/* Step 4-b: xval = (xkey + xseed) mod 2^160 */
		BN_add(&xval, xkey, xseed);
		xval.len = 5;
		xval.dat[5] = 0;
		/* Step 4-c: x = G(t,xval) mod q */
		/* G-function from this point */
		BN2OSTR(c, &c_len, &xval);
		memset(c + c_len, 0, 64 - c_len);
		SHA1_dgst_unit(t, c);
		/* G-function to this point */
		x.dat[0] = t[4];
		x.dat[1] = t[3];
		x.dat[2] = t[2];
		x.dat[3] = t[1];
		x.dat[4] = t[0];
		x.len = 5;
		BN_mod(&x, &x, sgord);
		/* Step 4-d: xkey = (1 + xkey + x) mod 2^160 */
		BN_add_ULONG(xkey, xkey, 1);
		BN_add(xkey, xkey, &x);
		xkey->len = 5;
		BN2OSTR(x_cdat, &x_len, xkey);
		memcpy(pr, x_cdat, 20);
		pr += 20;
	}
	memset(r + (l >> 3), 0, sizeof(ULONG));
	OSTR2BN(p, r, (l >> 3));
	return 0;
}
/*******************************/
/* 큰 수를 위한 utility 함수 */
/*******************************/
/*******************************************************************************
* 함 수 명 : BN2OSTR
*
* 함수인자 :
* *hstr - 출력받을 octet string의 포인터
* *hstrlen - 출력받을 octet string의 길이 정보의 포인터
* *a - 입력받은 큰 수 a의 포인터
* Return :
* 0 - 성공
* -1 - 실패 (입력데이터 오류)
*
*-------------------------------------------------------------------------------
* 함수설명 : 큰 수 a를 octet 스트링 형태의 데이터로 출력하는 변수
********************************************************************************/
SINT
BN2OSTR(
	UCHAR *hstr,
	ULONG *hstrlen,
	BN *a
	)
{
	ULONG hstrind;
	ULONG hstrbnd;
	if ((a == (BN*)0) || (hstr == (SCHAR*)0))
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
* 함 수 명 : BN2OSTR
*
* 함수인자 :
* *a - 출력받을 큰 수 a의 포인터
* *hstr - 입력받은 octet string의 포인터
* *hstrlen - 입력받은 octet string의 길이 정보
* Return :
* 0 - 성공
*
*-------------------------------------------------------------------------------
* 함수설명 : octet 스트링 형태의 데이터를 큰 수 a의 형태로 변환하는 변수
********************************************************************************/
SINT
OSTR2BN(
	BN *a,
	UCHAR *hstr,
	ULONG hstrlen
	)
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
* 함 수 명 : BN_ASCII2OSTR
*
* 함수인자 :
* *hstr - 출력받을 octet string의 포인터
* *hstrlen - 출력받을 octet string의 길이 정보
* *ascii - 입력받은 아스키 코드 string의 포인터
* Return :
* 0 - 성공
*
*---------------------------------------------------------------------------------
* 함수설명 : 아스키코드 스트링 형태의 데이터를 octet 스트링 형태로 변환하는 변수
**********************************************************************************/
SINT
BN_ASCII2OSTR(
	UCHAR *bstr,
	ULONG *bstrlen,
	SCHAR *ascii
	)
{
	SINT i = 0;
	SINT j = 0;
	SINT l;
	UINT tmp;
	l = ((int)strlen(ascii) + 1) / 2;
	*bstrlen = l;
	if ((int)strlen(ascii) % 2)
	{
		if ((ascii[0] >= 'a') && (ascii[0] <= 'f'))
			bstr[i++] = ascii[0] - 'a' + 0xa;
		else
			bstr[i++] = ascii[0] - '0';
		j++;
	}
	for (; i < l; i++, j += 2) {
		sscanf(ascii + j, "%02X", &tmp);
		bstr[i] = tmp & 255;
	}
	return 0;
}
/*********************************************************************************
* 함 수 명 : STR2ULONG
*
* 함수인자 :
* *str - str으로 들어오는 데이터
* *data - ULONG타입의 데이터로 바꾸어 저장할 공간
* Return :
* 0 - 성공
*
*---------------------------------------------------------------------------------
* 함수설명 : 아스키코드 스트링 형태의 데이터를 ULONG타입의 데이터로 바꾸어 저장
**********************************************************************************/
SINT
STR2ULONG(UCHAR *str, ULONG* data)
{
	SINT i = 0;
	SINT j = 0;
	SINT len = 0;
	char temp[7];
	len = (int)strlen(str) - 8;
	for (; len >= 0; len -= 8)
		sscanf(str + len, "%08x", &data[j++]);
	len += 7;
	for (i = 7; 0 <= len; len--)
		temp[len] = str[len];
	sscanf(temp, "%08x", &data[j]);
	return 0;
}
