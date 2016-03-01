#include <string.h>
#include "KUCrypto2.h"

#define K1 0x5A827999
#define K2 0x6ED9EBA1
#define K3 0x8F1BBCDC
#define K4 0xCA62C1D6
#define INIT_H0 0x67452301
#define INIT_H1 0xEFCDAB89
#define INIT_H2 0x98BADCFE
#define INIT_H3 0x10325476
#define INIT_H4 0xC3D2E1F0
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
void SHA1_dgst_unit(UINT32 h[5], UINT8 blk[SHA1_BLOCK_BYTES])
{
	UINT32 A,B,C,D,E,W[80],t, tmp;
	UINT8 *pb;
	pb = blk;
	A = h[0];
	B = h[1];
	C = h[2];
	D = h[3];
	E = h[4];
	for (t=0; t<16; t++){
		W[t] = (UINT32)(*pb); pb++; W[t] <<= 8;
		W[t] |= (UINT32)(*pb); pb++; W[t] <<= 8;
		W[t] |= (UINT32)(*pb); pb++; W[t] <<= 8;
		W[t] |= (UINT32)(*pb); pb++;
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
void
	SHA11_init(SHA1_CTX *sha1_ctx)
{
	sha1_ctx->state[0] = INIT_H0;
	sha1_ctx->state[1] = INIT_H1;
	sha1_ctx->state[2] = INIT_H2;
	sha1_ctx->state[3] = INIT_H3;
	sha1_ctx->state[4] = INIT_H4;
	sha1_ctx->bits[0] = 0;
	sha1_ctx->bits[1] = 0;
}
void
	SHA11_update(SHA1_CTX *sha1_ctx, UINT8 *dat, UINT len)
{
	UINT32 i, n, offset;
	UINT8 *pd ;
	pd = NULL;
	/* Compute the bytes left from 64 bytes before stage of SHA1_Upde. */
	offset = (sha1_ctx->bits[0] >> 3) & 0x3F;
	n = (len << 3) & 0xffffffff;
	sha1_ctx->bits[0] += n;
	sha1_ctx->bits[0] &= 0xffffffff;
	sha1_ctx->bits[1] += (len >> 29);
	if (sha1_ctx->bits[0] < n) sha1_ctx->bits[1]++;
	n = (offset + len)>>6; /* n = (offset + len)/64 */
	pd = dat;
	if (n > 0){
		/* Before stage, the input will be filled to the offset. */
		memcpy(sha1_ctx->input + offset, pd, 64 - offset);
		SHA1_dgst_unit(sha1_ctx->state, sha1_ctx->input);
		n--;
		pd += 64 - offset;
		for (i=0; i<n; i++){
			SHA1_dgst_unit(sha1_ctx->state, pd);
			pd += 64;
		}
		n = (offset + len) % 64;
		offset = 0;
	}else{
		n = len;
	}
	memcpy(sha1_ctx->input + offset, pd, n);
}
void
	SHA11_final(SHA1_CTX *sha1_ctx, UINT8 Hash[SHA1_HASH_BYTES])
{
	UINT32 offset, n, *h;
	UINT8 *pi;
	h = sha1_ctx->state;
	pi = sha1_ctx->input;
	/* Compute the bytes left from 64 bytes before stage of SHA1_update. */
	offset = (sha1_ctx->bits[0] >> 3) & 0x3F;
	/* Pad the unused bytes. */
	pi += offset;
	memset(pi, 0, 64 - offset);
	*pi = 0x80;
	if ((64 - offset - 1) < 8){
		SHA1_dgst_unit(sha1_ctx->state, sha1_ctx->input);
		memset(sha1_ctx->input, 0, 64);
	}
	/* Add the length of 64-bits to the last 8 bytes. */
	pi = sha1_ctx->input + 56;
	n = sha1_ctx->bits[1];
	*pi = (n >> 24) & 0xFF; pi++;
	*pi = (n >> 16) & 0xFF; pi++;
	*pi = (n >> 8) & 0xFF; pi++;
	*pi = (n ) & 0xFF; pi++;
	n = sha1_ctx->bits[0];
	*pi = (n >> 24) & 0xFF; pi++;
	*pi = (n >> 16) & 0xFF; pi++;
	*pi = (n >> 8) & 0xFF; pi++;
	*pi = (n ) & 0xFF;
	/* Compute the last block. */
	SHA1_dgst_unit(sha1_ctx->state, sha1_ctx->input);
	memset(sha1_ctx->input, 0, 64);
	Hash[0] = (UINT8)((h[0] >> 24) & 0xFF);
	Hash[1] = (UINT8)((h[0] >> 16) & 0xFF);
	Hash[2] = (UINT8)((h[0] >> 8) & 0xFF);
	Hash[3] = (UINT8)((h[0] ) & 0xFF);
	Hash[4] = (UINT8)((h[1] >> 24) & 0xFF);
	Hash[5] = (UINT8)((h[1] >> 16) & 0xFF);
	Hash[6] = (UINT8)((h[1] >> 8) & 0xFF);
	Hash[7] = (UINT8)((h[1] ) & 0xFF);
	Hash[8] = (UINT8)((h[2] >> 24) & 0xFF);
	Hash[9] = (UINT8)((h[2] >> 16) & 0xFF);
	Hash[10] = (UINT8)((h[2] >> 8) & 0xFF);
	Hash[11] = (UINT8)((h[2] ) & 0xFF);
	Hash[12] = (UINT8)((h[3] >> 24) & 0xFF);
	Hash[13] = (UINT8)((h[3] >> 16) & 0xFF);
	Hash[14] = (UINT8)((h[3] >> 8) & 0xFF);
	Hash[15] = (UINT8)((h[3] ) & 0xFF);
	Hash[16] = (UINT8)((h[4] >> 24) & 0xFF);
	Hash[17] = (UINT8)((h[4] >> 16) & 0xFF);
	Hash[18] = (UINT8)((h[4] >> 8) & 0xFF);
	Hash[19] = (UINT8)((h[4] ) & 0xFF);
}
void
	SHA1_at_once(UINT8 *M, UINT len, UINT8 Hash[20])
{
	SHA1_CTX sha1_ctx;
	SHA11_init(&sha1_ctx);
	SHA11_update(&sha1_ctx, M, len);
	SHA11_final(&sha1_ctx, Hash);
}
