#include <stdlib.h>
#include <string.h>
#include "KUCrypto2.h"

#define CONV64(x) x
#define SHR(x,n) ((x) >> (n))
#define ROTR32(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROTR64(x,n) (((x) >> (n)) | ((x) << (64 - (n))))
#define SHA_CH(x,y,z) (((x) & (y)) | ((z) & ((x) | (y))))
#define SHA_MJ(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))

/*SHA-224*/
/* Hash constant words K for SHA-224 and SHA-256: */
static UINT32 K256[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
/* Initial hash value H for SHA-224: */
static UINT32 sha224_ihv[8] = {
	0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
	0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
};
/* Initial hash value H for SHA-256: */
static UINT32 sha256_ihv[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};
#define GET_UINT32(n,b,i) \
{ \
	(n) = ((UINT32) (b)[(i) ] << 24) \
	| ((UINT32) (b)[(i) + 1] << 16) \
	| ((UINT32) (b)[(i) + 2] << 8) \
	| ((UINT32) (b)[(i) + 3] ); \
	}
#define PUT_UINT32(n,b,i) \
{ \
	(b)[(i) ] = (UINT8) ((n) >> 24); \
	(b)[(i) + 1] = (UINT8) ((n) >> 16); \
	(b)[(i) + 2] = (UINT8) ((n) >> 8); \
	(b)[(i) + 3] = (UINT8) ((n) ); \
	}
/*
* SHA224를 사용하기 위해 초기화한다.
* @param ctx - 알고리즘 정보의 포인터
*
* @return
*
* @note
*/
void SHA2241_init(SHA224_CTX *ctx)
{
	memset(ctx, 0, sizeof(SHA224_CTX));
	memcpy(ctx->state, sha224_ihv, sizeof(UINT32) * 8);
	ctx->count[0] = ctx->count[1] = 0;
}
/*
* SHA224 중간값을 업데이트한다.
* @param ctx - 알고리즘 정보의 포인터
* @param input - 입력된 데이터
* @param length - 입력된 데이터의 길이
*
* @return
*
* @note
*/
void SHA2241_update(SHA224_CTX *ctx, UINT8 *input, UINT32 length)
{
	SHA2561_update(ctx, input, length);
}
/*
* SHA224 결과값을 업데이트한다.
* @param ctx - 알고리즘 정보의 포인터
* @param hash - 출력할 해시 데이터
*
* @return
*
* @note
*/
void SHA2241_final(SHA224_CTX *ctx, UINT8 hash[SHA224_HASH_BYTE_LEN])
{
	UINT8 tmpHash[SHA256_HASH_BYTE_LEN];
	SHA2561_final(ctx, tmpHash);
	memcpy(hash, tmpHash, SHA224_HASH_BYTE_LEN);
}
/*
* SHA224 해시 함수를 수행한다.
* @param input - 입력된 데이터
* @param length - 입력된 데이터의 길이
* @param hash - 출력할 해시 데이터
*
* @return
*
* @note
*/
void
	SHA224_hash( UINT8 *input,
	UINT32 inputLength,
	UINT8 *hash)
{
	SHA224_CTX ctx;
	SHA2241_init(&ctx);
	SHA2241_update(&ctx, input, inputLength);
	SHA2241_final(&ctx, hash);
}
/*SHA-256*/
/*
* SHA256 압축 함수를 수행한다.
* @param ctx - 알고리즘 정보의 포인터
* @param data - 입력된 데이터
*
* @return
*
* @note
*/
void SHA256_compress(SHA256_CTX *ctx, UINT8 data[SHA512_HASH_BYTE_LEN])
{
	UINT32 T1, T2, W256[16];
	UINT32 A, B, C, D, E, F, G, H;
	GET_UINT32(W256[ 0], data, 0);
	GET_UINT32(W256[ 1], data, 4);
	GET_UINT32(W256[ 2], data, 8);
	GET_UINT32(W256[ 3], data, 12);
	GET_UINT32(W256[ 4], data, 16);
	GET_UINT32(W256[ 5], data, 20);
	GET_UINT32(W256[ 6], data, 24);
	GET_UINT32(W256[ 7], data, 28);
	GET_UINT32(W256[ 8], data, 32);
	GET_UINT32(W256[ 9], data, 36);
	GET_UINT32(W256[10], data, 40);
	GET_UINT32(W256[11], data, 44);
	GET_UINT32(W256[12], data, 48);
	GET_UINT32(W256[13], data, 52);
	GET_UINT32(W256[14], data, 56);
	GET_UINT32(W256[15], data, 60);
#define F256_S2(x) (ROTR32(x, 2) ^ ROTR32(x,13) ^ ROTR32(x,22))
#define F256_S3(x) (ROTR32(x, 6) ^ ROTR32(x,11) ^ ROTR32(x,25))
#define F256_S0(x) (ROTR32(x, 7) ^ ROTR32(x,18) ^ SHR(x, 3))
#define F256_S1(x) (ROTR32(x,17) ^ ROTR32(x,19) ^ SHR(x,10))
#define R256(t) (W256[(t)&15] = F256_S1(W256[(t- 2)&15]) + W256[(t- 7)&15] + \
	F256_S0(W256[(t-15)&15]) + W256[(t-16)&15])
#define P256(a,b,c,d,e,f,g,h,x,K) \
	{ \
	T1 = h + F256_S3(e) + SHA_MJ(e,f,g) + K + x; \
	T2 = F256_S2(a) + SHA_CH(a,b,c); \
	d += T1; h = T1 + T2; \
	}
	A = ctx->state[0];
	B = ctx->state[1];
	C = ctx->state[2];
	D = ctx->state[3];
	E = ctx->state[4];
	F = ctx->state[5];
	G = ctx->state[6];
	H = ctx->state[7];
	P256(A, B, C, D, E, F, G, H, W256[ 0], K256[ 0]);
	P256(H, A, B, C, D, E, F, G, W256[ 1], K256[ 1]);
	P256(G, H, A, B, C, D, E, F, W256[ 2], K256[ 2]);
	P256(F, G, H, A, B, C, D, E, W256[ 3], K256[ 3]);
	P256(E, F, G, H, A, B, C, D, W256[ 4], K256[ 4]);
	P256(D, E, F, G, H, A, B, C, W256[ 5], K256[ 5]);
	P256(C, D, E, F, G, H, A, B, W256[ 6], K256[ 6]);
	P256(B, C, D, E, F, G, H, A, W256[ 7], K256[ 7]);
	P256(A, B, C, D, E, F, G, H, W256[ 8], K256[ 8]);
	P256(H, A, B, C, D, E, F, G, W256[ 9], K256[ 9]);
	P256(G, H, A, B, C, D, E, F, W256[10], K256[10]);
	P256(F, G, H, A, B, C, D, E, W256[11], K256[11]);
	P256(E, F, G, H, A, B, C, D, W256[12], K256[12]);
	P256(D, E, F, G, H, A, B, C, W256[13], K256[13]);
	P256(C, D, E, F, G, H, A, B, W256[14], K256[14]);
	P256(B, C, D, E, F, G, H, A, W256[15], K256[15]);
	P256(A, B, C, D, E, F, G, H, R256(16), K256[16]);
	P256(H, A, B, C, D, E, F, G, R256(17), K256[17]);
	P256(G, H, A, B, C, D, E, F, R256(18), K256[18]);
	P256(F, G, H, A, B, C, D, E, R256(19), K256[19]);
	P256(E, F, G, H, A, B, C, D, R256(20), K256[20]);
	P256(D, E, F, G, H, A, B, C, R256(21), K256[21]);
	P256(C, D, E, F, G, H, A, B, R256(22), K256[22]);
	P256(B, C, D, E, F, G, H, A, R256(23), K256[23]);
	P256(A, B, C, D, E, F, G, H, R256(24), K256[24]);
	P256(H, A, B, C, D, E, F, G, R256(25), K256[25]);
	P256(G, H, A, B, C, D, E, F, R256(26), K256[26]);
	P256(F, G, H, A, B, C, D, E, R256(27), K256[27]);
	P256(E, F, G, H, A, B, C, D, R256(28), K256[28]);
	P256(D, E, F, G, H, A, B, C, R256(29), K256[29]);
	P256(C, D, E, F, G, H, A, B, R256(30), K256[30]);
	P256(B, C, D, E, F, G, H, A, R256(31), K256[31]);
	P256(A, B, C, D, E, F, G, H, R256(32), K256[32]);
	P256(H, A, B, C, D, E, F, G, R256(33), K256[33]);
	P256(G, H, A, B, C, D, E, F, R256(34), K256[34]);
	P256(F, G, H, A, B, C, D, E, R256(35), K256[35]);
	P256(E, F, G, H, A, B, C, D, R256(36), K256[36]);
	P256(D, E, F, G, H, A, B, C, R256(37), K256[37]);
	P256(C, D, E, F, G, H, A, B, R256(38), K256[38]);
	P256(B, C, D, E, F, G, H, A, R256(39), K256[39]);
	P256(A, B, C, D, E, F, G, H, R256(40), K256[40]);
	P256(H, A, B, C, D, E, F, G, R256(41), K256[41]);
	P256(G, H, A, B, C, D, E, F, R256(42), K256[42]);
	P256(F, G, H, A, B, C, D, E, R256(43), K256[43]);
	P256(E, F, G, H, A, B, C, D, R256(44), K256[44]);
	P256(D, E, F, G, H, A, B, C, R256(45), K256[45]);
	P256(C, D, E, F, G, H, A, B, R256(46), K256[46]);
	P256(B, C, D, E, F, G, H, A, R256(47), K256[47]);
	P256(A, B, C, D, E, F, G, H, R256(48), K256[48]);
	P256(H, A, B, C, D, E, F, G, R256(49), K256[49]);
	P256(G, H, A, B, C, D, E, F, R256(50), K256[50]);
	P256(F, G, H, A, B, C, D, E, R256(51), K256[51]);
	P256(E, F, G, H, A, B, C, D, R256(52), K256[52]);
	P256(D, E, F, G, H, A, B, C, R256(53), K256[53]);
	P256(C, D, E, F, G, H, A, B, R256(54), K256[54]);
	P256(B, C, D, E, F, G, H, A, R256(55), K256[55]);
	P256(A, B, C, D, E, F, G, H, R256(56), K256[56]);
	P256(H, A, B, C, D, E, F, G, R256(57), K256[57]);
	P256(G, H, A, B, C, D, E, F, R256(58), K256[58]);
	P256(F, G, H, A, B, C, D, E, R256(59), K256[59]);
	P256(E, F, G, H, A, B, C, D, R256(60), K256[60]);
	P256(D, E, F, G, H, A, B, C, R256(61), K256[61]);
	P256(C, D, E, F, G, H, A, B, R256(62), K256[62]);
	P256(B, C, D, E, F, G, H, A, R256(63), K256[63]);
	ctx->state[0] += A;
	ctx->state[1] += B;
	ctx->state[2] += C;
	ctx->state[3] += D;
	ctx->state[4] += E;
	ctx->state[5] += F;
	ctx->state[6] += G;
	ctx->state[7] += H;
	memset(W256, 0, sizeof(UINT32) * 16);
}
/*
* SHA256 중간값을 업데이트한다.
* @param ctx - 알고리즘 정보의 포인터
* @param input - 입력된 데이터
* @param length - 입력된 데이터의 길이
*
* @return
*
* @note
*/
void SHA2561_init(SHA256_CTX *ctx)
{
	memset(ctx, 0, sizeof(SHA256_CTX));
	memcpy(ctx->state, sha256_ihv, sizeof(UINT32) * 8);
	ctx->count[0] = ctx->count[1] = 0;
}
/*
* SHA256 결과값을 업데이트한다.
* @param ctx - 알고리즘 정보의 포인터
* @param hash - 출력할 해시 데이터
*
* @return
*
* @note
*/
void SHA2561_update(SHA256_CTX *ctx, UINT8 *input, UINT32 length)
{
	UINT32 left, fill, remain;
	if (!length) return;
	remain = length;
	left = ctx->count[0] & 0x3F;
	fill = 64 - left;
	ctx->count[0] += remain;
	ctx->count[0] &= 0xFFFFFFFF;
	if (ctx->count[0] < remain)
		ctx->count[1]++;
	if (left && remain >= fill) {
		memcpy((void *) (ctx->buffer + left), (void *) input, fill);
		SHA256_compress(ctx, ctx->buffer);
		remain -= fill;
		input += fill;
		left = 0;
	}
	while (remain >= 64) {
		SHA256_compress(ctx, input);
		remain -= 64;
		input += 64;
	}
	if (remain) {
		memcpy((void *) (ctx->buffer + left), (void *) input, remain);
	}
}
static UINT8 sha256_padding[64] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
/*
* SHA256 결과값을 업데이트한다.
* @param input - 입력된 데이터
* @param length - 입력된 데이터의 길이
* @param hash - 출력할 해시 데이터
*
* @return
*
* @note
*/
void SHA2561_final(SHA256_CTX *ctx, UINT8 hash[SHA256_HASH_BYTE_LEN])
{
	UINT32 last, padn;
	UINT32 high, low;
	UINT8 msglen[8];
	high = (ctx->count[0] >> 29) | (ctx->count[1] << 3);
	low = (ctx->count[0] << 3);
	PUT_UINT32(high, msglen, 0);
	PUT_UINT32(low, msglen, 4);
	last = ctx->count[0] & 0x3F;
	padn = (last < 56) ? (56 - last) : (120 - last);
	SHA2561_update(ctx, sha256_padding, padn);
	SHA2561_update(ctx, msglen, 8);
	PUT_UINT32(ctx->state[0], hash, 0);
	PUT_UINT32(ctx->state[1], hash, 4);
	PUT_UINT32(ctx->state[2], hash, 8);
	PUT_UINT32(ctx->state[3], hash, 12);
	PUT_UINT32(ctx->state[4], hash, 16);
	PUT_UINT32(ctx->state[5], hash, 20);
	PUT_UINT32(ctx->state[6], hash, 24);
	PUT_UINT32(ctx->state[7], hash, 28);
	memset(ctx, 0, sizeof(SHA256_CTX));
}
/*
* SHA256 해시 함수를 수행한다.
* @param input - 입력된 데이터
* @param length - 입력된 데이터의 길이
* @param hash - 출력할 해시 데이터
*
* @return
*
* @note
*/
void
	SHA256_hash( UINT8 *input,
	UINT32 inputLength,
	UINT8 *hash)
{
	SHA256_CTX ctx;
	SHA2561_init(&ctx);
	SHA2561_update(&ctx, input, inputLength);
	SHA2561_final(&ctx, hash);
}
/* SHA-512 */
/* Hash constant words K for SHA-384 and SHA-512: */
static UINT64 K512[80] = {
	CONV64(0x428a2f98d728ae22), CONV64(0x7137449123ef65cd),
	CONV64(0xb5c0fbcfec4d3b2f), CONV64(0xe9b5dba58189dbbc),
	CONV64(0x3956c25bf348b538), CONV64(0x59f111f1b605d019),
	CONV64(0x923f82a4af194f9b), CONV64(0xab1c5ed5da6d8118),
	CONV64(0xd807aa98a3030242), CONV64(0x12835b0145706fbe),
	CONV64(0x243185be4ee4b28c), CONV64(0x550c7dc3d5ffb4e2),
	CONV64(0x72be5d74f27b896f), CONV64(0x80deb1fe3b1696b1),
	CONV64(0x9bdc06a725c71235), CONV64(0xc19bf174cf692694),
	CONV64(0xe49b69c19ef14ad2), CONV64(0xefbe4786384f25e3),
	CONV64(0x0fc19dc68b8cd5b5), CONV64(0x240ca1cc77ac9c65),
	CONV64(0x2de92c6f592b0275), CONV64(0x4a7484aa6ea6e483),
	CONV64(0x5cb0a9dcbd41fbd4), CONV64(0x76f988da831153b5),
	CONV64(0x983e5152ee66dfab), CONV64(0xa831c66d2db43210),
	CONV64(0xb00327c898fb213f), CONV64(0xbf597fc7beef0ee4),
	CONV64(0xc6e00bf33da88fc2), CONV64(0xd5a79147930aa725),
	CONV64(0x06ca6351e003826f), CONV64(0x142929670a0e6e70),
	CONV64(0x27b70a8546d22ffc), CONV64(0x2e1b21385c26c926),
	CONV64(0x4d2c6dfc5ac42aed), CONV64(0x53380d139d95b3df),
	CONV64(0x650a73548baf63de), CONV64(0x766a0abb3c77b2a8),
	CONV64(0x81c2c92e47edaee6), CONV64(0x92722c851482353b),
	CONV64(0xa2bfe8a14cf10364), CONV64(0xa81a664bbc423001),
	CONV64(0xc24b8b70d0f89791), CONV64(0xc76c51a30654be30),
	CONV64(0xd192e819d6ef5218), CONV64(0xd69906245565a910),
	CONV64(0xf40e35855771202a), CONV64(0x106aa07032bbd1b8),
	CONV64(0x19a4c116b8d2d0c8), CONV64(0x1e376c085141ab53),
	CONV64(0x2748774cdf8eeb99), CONV64(0x34b0bcb5e19b48a8),
	CONV64(0x391c0cb3c5c95a63), CONV64(0x4ed8aa4ae3418acb),
	CONV64(0x5b9cca4f7763e373), CONV64(0x682e6ff3d6b2b8a3),
	CONV64(0x748f82ee5defb2fc), CONV64(0x78a5636f43172f60),
	CONV64(0x84c87814a1f0ab72), CONV64(0x8cc702081a6439ec),
	CONV64(0x90befffa23631e28), CONV64(0xa4506cebde82bde9),
	CONV64(0xbef9a3f7b2c67915), CONV64(0xc67178f2e372532b),
	CONV64(0xca273eceea26619c), CONV64(0xd186b8c721c0c207),
	CONV64(0xeada7dd6cde0eb1e), CONV64(0xf57d4f7fee6ed178),
	CONV64(0x06f067aa72176fba), CONV64(0x0a637dc5a2c898a6),
	CONV64(0x113f9804bef90dae), CONV64(0x1b710b35131c471b),
	CONV64(0x28db77f523047d84), CONV64(0x32caab7b40c72493),
	CONV64(0x3c9ebe0a15c9bebc), CONV64(0x431d67c49c100d4c),
	CONV64(0x4cc5d4becb3e42b6), CONV64(0x597f299cfc657e2a),
	CONV64(0x5fcb6fab3ad6faec), CONV64(0x6c44198c4a475817)
};
/* Initial hash value H for SHA-384 */
static UINT64 sha384_ihv[8] = {
	CONV64(0xcbbb9d5dc1059ed8), CONV64(0x629a292a367cd507),
	CONV64(0x9159015a3070dd17), CONV64(0x152fecd8f70e5939),
	CONV64(0x67332667ffc00b31), CONV64(0x8eb44a8768581511),
	CONV64(0xdb0c2e0d64f98fa7), CONV64(0x47b5481dbefa4fa4)
};
/* Initial hash value H for SHA-512 */
static UINT64 sha512_ihv[8] = {
	CONV64(0x6a09e667f3bcc908), CONV64(0xbb67ae8584caa73b),
	CONV64(0x3c6ef372fe94f82b), CONV64(0xa54ff53a5f1d36f1),
	CONV64(0x510e527fade682d1), CONV64(0x9b05688c2b3e6c1f),
	CONV64(0x1f83d9abfb41bd6b), CONV64(0x5be0cd19137e2179)
};
#define GET_UINT64(n,b,i) \
{ \
	(n) = ((UINT64) (b)[(i) ] << 56) \
	| ((UINT64) (b)[(i) + 1] << 48) \
	| ((UINT64) (b)[(i) + 2] << 40) \
	| ((UINT64) (b)[(i) + 3] << 32) \
	| ((UINT64) (b)[(i) + 4] << 24) \
	| ((UINT64) (b)[(i) + 5] << 16) \
	| ((UINT64) (b)[(i) + 6] << 8) \
	| ((UINT64) (b)[(i) + 7] ); \
	}
#define PUT_UINT64(n,b,i) \
{ \
	(b)[(i) ] = (UINT8) ((n) >> 56); \
	(b)[(i) + 1] = (UINT8) ((n) >> 48); \
	(b)[(i) + 2] = (UINT8) ((n) >> 40); \
	(b)[(i) + 3] = (UINT8) ((n) >> 32); \
	(b)[(i) + 4] = (UINT8) ((n) >> 24); \
	(b)[(i) + 5] = (UINT8) ((n) >> 16); \
	(b)[(i) + 6] = (UINT8) ((n) >> 8); \
	(b)[(i) + 7] = (UINT8) ((n) ); \
	}
/*
* SHA512 압축 함수를 수행한다.
* @param ctx - 알고리즘 정보의 포인터
* @param data - 입력된 데이터
*
* @return
*
* @note
*/
void SHA512_compress(SHA512_CTX *ctx, UINT8 data[128])
{
	UINT64 T1, T2, W512[16];
	UINT64 A, B, C, D, E, F, G, H;
	GET_UINT64(W512[ 0], data, 0);
	GET_UINT64(W512[ 1], data, 8);
	GET_UINT64(W512[ 2], data, 16);
	GET_UINT64(W512[ 3], data, 24);
	GET_UINT64(W512[ 4], data, 32);
	GET_UINT64(W512[ 5], data, 40);
	GET_UINT64(W512[ 6], data, 48);
	GET_UINT64(W512[ 7], data, 56);
	GET_UINT64(W512[ 8], data, 64);
	GET_UINT64(W512[ 9], data, 72);
	GET_UINT64(W512[10], data, 80);
	GET_UINT64(W512[11], data, 88);
	GET_UINT64(W512[12], data, 96);
	GET_UINT64(W512[13], data, 104);
	GET_UINT64(W512[14], data, 112);
	GET_UINT64(W512[15], data, 120);
#define F512_S2(x) (ROTR64(x,28) ^ ROTR64(x,34) ^ ROTR64(x,39))
#define F512_S3(x) (ROTR64(x,14) ^ ROTR64(x,18) ^ ROTR64(x,41))
#define F512_S0(x) (ROTR64(x, 1) ^ ROTR64(x, 8) ^ SHR(x, 7))
#define F512_S1(x) (ROTR64(x,19) ^ ROTR64(x,61) ^ SHR(x, 6))
#define R512(t) (W512[(t)&15] = F512_S1(W512[(t- 2)&15]) + W512[(t- 7)&15] + \
	F512_S0(W512[(t-15)&15]) + W512[(t-16)&15])
#define P512(a,b,c,d,e,f,g,h,x,K) \
	{ \
	T1 = h + F512_S3(e) + SHA_MJ(e,f,g) + K + x; \
	T2 = F512_S2(a) + SHA_CH(a,b,c); \
	d += T1; h = T1 + T2; \
	}
	A = ctx->state[0];
	B = ctx->state[1];
	C = ctx->state[2];
	D = ctx->state[3];
	E = ctx->state[4];
	F = ctx->state[5];
	G = ctx->state[6];
	H = ctx->state[7];
	P512(A, B, C, D, E, F, G, H, W512[ 0], K512[ 0]);
	P512(H, A, B, C, D, E, F, G, W512[ 1], K512[ 1]);
	P512(G, H, A, B, C, D, E, F, W512[ 2], K512[ 2]);
	P512(F, G, H, A, B, C, D, E, W512[ 3], K512[ 3]);
	P512(E, F, G, H, A, B, C, D, W512[ 4], K512[ 4]);
	P512(D, E, F, G, H, A, B, C, W512[ 5], K512[ 5]);
	P512(C, D, E, F, G, H, A, B, W512[ 6], K512[ 6]);
	P512(B, C, D, E, F, G, H, A, W512[ 7], K512[ 7]);
	P512(A, B, C, D, E, F, G, H, W512[ 8], K512[ 8]);
	P512(H, A, B, C, D, E, F, G, W512[ 9], K512[ 9]);
	P512(G, H, A, B, C, D, E, F, W512[10], K512[10]);
	P512(F, G, H, A, B, C, D, E, W512[11], K512[11]);
	P512(E, F, G, H, A, B, C, D, W512[12], K512[12]);
	P512(D, E, F, G, H, A, B, C, W512[13], K512[13]);
	P512(C, D, E, F, G, H, A, B, W512[14], K512[14]);
	P512(B, C, D, E, F, G, H, A, W512[15], K512[15]);
	P512(A, B, C, D, E, F, G, H, R512(16), K512[16]);
	P512(H, A, B, C, D, E, F, G, R512(17), K512[17]);
	P512(G, H, A, B, C, D, E, F, R512(18), K512[18]);
	P512(F, G, H, A, B, C, D, E, R512(19), K512[19]);
	P512(E, F, G, H, A, B, C, D, R512(20), K512[20]);
	P512(D, E, F, G, H, A, B, C, R512(21), K512[21]);
	P512(C, D, E, F, G, H, A, B, R512(22), K512[22]);
	P512(B, C, D, E, F, G, H, A, R512(23), K512[23]);
	P512(A, B, C, D, E, F, G, H, R512(24), K512[24]);
	P512(H, A, B, C, D, E, F, G, R512(25), K512[25]);
	P512(G, H, A, B, C, D, E, F, R512(26), K512[26]);
	P512(F, G, H, A, B, C, D, E, R512(27), K512[27]);
	P512(E, F, G, H, A, B, C, D, R512(28), K512[28]);
	P512(D, E, F, G, H, A, B, C, R512(29), K512[29]);
	P512(C, D, E, F, G, H, A, B, R512(30), K512[30]);
	P512(B, C, D, E, F, G, H, A, R512(31), K512[31]);
	P512(A, B, C, D, E, F, G, H, R512(32), K512[32]);
	P512(H, A, B, C, D, E, F, G, R512(33), K512[33]);
	P512(G, H, A, B, C, D, E, F, R512(34), K512[34]);
	P512(F, G, H, A, B, C, D, E, R512(35), K512[35]);
	P512(E, F, G, H, A, B, C, D, R512(36), K512[36]);
	P512(D, E, F, G, H, A, B, C, R512(37), K512[37]);
	P512(C, D, E, F, G, H, A, B, R512(38), K512[38]);
	P512(B, C, D, E, F, G, H, A, R512(39), K512[39]);
	P512(A, B, C, D, E, F, G, H, R512(40), K512[40]);
	P512(H, A, B, C, D, E, F, G, R512(41), K512[41]);
	P512(G, H, A, B, C, D, E, F, R512(42), K512[42]);
	P512(F, G, H, A, B, C, D, E, R512(43), K512[43]);
	P512(E, F, G, H, A, B, C, D, R512(44), K512[44]);
	P512(D, E, F, G, H, A, B, C, R512(45), K512[45]);
	P512(C, D, E, F, G, H, A, B, R512(46), K512[46]);
	P512(B, C, D, E, F, G, H, A, R512(47), K512[47]);
	P512(A, B, C, D, E, F, G, H, R512(48), K512[48]);
	P512(H, A, B, C, D, E, F, G, R512(49), K512[49]);
	P512(G, H, A, B, C, D, E, F, R512(50), K512[50]);
	P512(F, G, H, A, B, C, D, E, R512(51), K512[51]);
	P512(E, F, G, H, A, B, C, D, R512(52), K512[52]);
	P512(D, E, F, G, H, A, B, C, R512(53), K512[53]);
	P512(C, D, E, F, G, H, A, B, R512(54), K512[54]);
	P512(B, C, D, E, F, G, H, A, R512(55), K512[55]);
	P512(A, B, C, D, E, F, G, H, R512(56), K512[56]);
	P512(H, A, B, C, D, E, F, G, R512(57), K512[57]);
	P512(G, H, A, B, C, D, E, F, R512(58), K512[58]);
	P512(F, G, H, A, B, C, D, E, R512(59), K512[59]);
	P512(E, F, G, H, A, B, C, D, R512(60), K512[60]);
	P512(D, E, F, G, H, A, B, C, R512(61), K512[61]);
	P512(C, D, E, F, G, H, A, B, R512(62), K512[62]);
	P512(B, C, D, E, F, G, H, A, R512(63), K512[63]);
	P512(A, B, C, D, E, F, G, H, R512(64), K512[64]);
	P512(H, A, B, C, D, E, F, G, R512(65), K512[65]);
	P512(G, H, A, B, C, D, E, F, R512(66), K512[66]);
	P512(F, G, H, A, B, C, D, E, R512(67), K512[67]);
	P512(E, F, G, H, A, B, C, D, R512(68), K512[68]);
	P512(D, E, F, G, H, A, B, C, R512(69), K512[69]);
	P512(C, D, E, F, G, H, A, B, R512(70), K512[70]);
	P512(B, C, D, E, F, G, H, A, R512(71), K512[71]);
	P512(A, B, C, D, E, F, G, H, R512(72), K512[72]);
	P512(H, A, B, C, D, E, F, G, R512(73), K512[73]);
	P512(G, H, A, B, C, D, E, F, R512(74), K512[74]);
	P512(F, G, H, A, B, C, D, E, R512(75), K512[75]);
	P512(E, F, G, H, A, B, C, D, R512(76), K512[76]);
	P512(D, E, F, G, H, A, B, C, R512(77), K512[77]);
	P512(C, D, E, F, G, H, A, B, R512(78), K512[78]);
	P512(B, C, D, E, F, G, H, A, R512(79), K512[79]);
	ctx->state[0] += A;
	ctx->state[1] += B;
	ctx->state[2] += C;
	ctx->state[3] += D;
	ctx->state[4] += E;
	ctx->state[5] += F;
	ctx->state[6] += G;
	ctx->state[7] += H;
	memset(W512, 0, sizeof(UINT64) * 16);
}
/*
* SHA512를 사용하기 위해 초기화한다.
* @param ctx - 알고리즘 정보의 포인터
*
* @return
*
* @note
*/
void SHA5121_init(SHA512_CTX *ctx)
{
	memset(ctx, 0, sizeof(SHA512_CTX));
	memcpy(ctx->state, sha512_ihv, sizeof(UINT64) * 8);
	ctx->count[0] = ctx->count[1] = 0;
}
/*
* SHA512 중간값을 업데이트한다.
* @param ctx - 알고리즘 정보의 포인터
* @param input - 입력된 데이터
* @param length - 입력된 데이터의 길이
*
* @return
*
* @note
*/
void SHA5121_update(SHA512_CTX *ctx, UINT8 *input, UINT32 length)
{
	UINT64 left, fill, remain;
	if (!length) return;
	remain = (UINT64) length;
	left = ctx->count[0] & 0x7F;
	fill = 128 - left;
	ctx->count[0] += remain;
	ctx->count[0] &= CONV64(0xFFFFFFFFFFFFFFFF);
	if (ctx->count[0] < remain)
		ctx->count[1]++;
	if (left && remain >= fill) {
		memcpy((void *) (ctx->buffer + left), (void *) input, (UINT32) fill);
		SHA512_compress(ctx, ctx->buffer);
		remain -= fill;
		input += fill;
		left = 0;
	}
	while (remain >= 128) {
		SHA512_compress(ctx, input);
		remain -= 128;
		input += 128;
	}
	if (remain) {
		memcpy((void *) (ctx->buffer + left), (void *) input, (UINT32) remain);
	}
}
static UINT8 sha512_padding[128] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
/*
* SHA512 결과값을 업데이트한다.
* @param ctx - 알고리즘 정보의 포인터
* @param hash - 출력할 해시 데이터
*
* @return
*
* @note
*/
void SHA5121_final(SHA512_CTX *ctx, UINT8 hash[64])
{
	UINT64 high, low;
	UINT32 last, padn;
	UINT8 msglen[16];
	high = (ctx->count[0] >> 61) | (ctx->count[1] << 3);
	low = (ctx->count[0] << 3);
	PUT_UINT64(high, msglen, 0);
	PUT_UINT64(low, msglen, 8);
	last = (UINT32) ctx->count[0] & 0x7F;
	padn = (last < 112) ? (112 - last) : (240 - last);
	SHA5121_update(ctx, sha512_padding, padn);
	SHA5121_update(ctx, msglen, 16);
	PUT_UINT64(ctx->state[0], hash, 0);
	PUT_UINT64(ctx->state[1], hash, 8);
	PUT_UINT64(ctx->state[2], hash, 16);
	PUT_UINT64(ctx->state[3], hash, 24);
	PUT_UINT64(ctx->state[4], hash, 32);
	PUT_UINT64(ctx->state[5], hash, 40);
	PUT_UINT64(ctx->state[6], hash, 48);
	PUT_UINT64(ctx->state[7], hash, 56);
	memset(ctx, 0, sizeof(SHA512_CTX));
}
/*
* SHA512 해시 함수를 수행한다.
* @param input - 입력된 데이터
* @param length - 입력된 데이터의 길이
* @param hash - 출력할 해시 데이터
*
* @return
*
* @note
*/
void
	SHA512_hash( UINT8 *input,
	UINT32 inputLength,
	UINT8 *hash)
{
	SHA512_CTX ctx;
	SHA5121_init(&ctx);
	SHA5121_update(&ctx, input, inputLength);
	SHA5121_final(&ctx, hash);
}
/* SHA-384 */
/*
* SHA384를 사용하기 위해 초기화한다.
* @param ctx - 알고리즘 정보의 포인터
*
* @return
*
* @note
*/
void SHA3841_init(SHA384_CTX *ctx)
{
	memset(ctx, 0, sizeof(SHA384_CTX));
	memcpy(ctx->state, sha384_ihv, sizeof(UINT64) * 8);
	ctx->count[0] = ctx->count[1] = 0;
}
/*
* SHA384 중간값을 업데이트한다.
* @param ctx - 알고리즘 정보의 포인터
* @param input - 입력된 데이터
* @param length - 입력된 데이터의 길이
*
* @return
*
* @note
*/
void SHA3841_update(SHA384_CTX *ctx, UINT8 *input, UINT32 length)
{
	SHA5121_update(ctx, input, length);
}
/*
* SHA384 결과값을 업데이트한다.
* @param ctx - 알고리즘 정보의 포인터
* @param hash - 출력할 해시 데이터
*
* @return
*
* @note
*/
void SHA3841_final(SHA384_CTX *ctx, UINT8 hash[SHA384_HASH_BYTE_LEN])
{
	UINT8 tmpHash[64];
	SHA5121_final(ctx, tmpHash);
	memcpy(hash, tmpHash, SHA384_HASH_BYTE_LEN);
}
/*
* SHA384 해시 함수를 수행한다.
* @param input - 입력된 데이터
* @param length - 입력된 데이터의 길이
* @param hash - 출력할 해시 데이터
*
* @return
*
* @note
*/
void
	SHA384_hash( UINT8 *input,
	UINT32 inputLength,
	UINT8 *hash)
{
	SHA384_CTX ctx;
	SHA3841_init(&ctx);
	SHA3841_update(&ctx, input, inputLength);
	SHA3841_final(&ctx, hash);
}
/*
* SHA224 HMAC을 수행한다.
* @param M - 입력된 데이터
* @param Mlen - 입력된 데이터의 길이
* @param key - 입력된 마스터키
* @param keylen - 입력된 마스터키의 길이
* @param MAC - 출력할 MAC
*
* @return
*
* @note
*/
void
	SHA224_hmac( UINT8 *M, UINT Mlen, UINT8 *key, UINT keylen,
	UINT8 MAC[SHA224_HASH_BYTE_LEN])
{
	SHA224_CTX sha224_ctx;
	UINT8 mackey[SHA224_HASH_BYTE_LEN];
	UINT8 ipad[SHA224_BLK_BYTE_LEN+16];
	UINT8 opad[SHA224_BLK_BYTE_LEN+16];
	UINT8 ihash[SHA224_BLK_BYTE_LEN+16];
	SINT i;
	/* Initializing with the key */
	memset(mackey, 0x00, SHA224_HASH_BYTE_LEN);
	if (keylen <= SHA224_HASH_BYTE_LEN) {
		memcpy(mackey, key, keylen);
	}else {
		SHA224_hash(key, keylen, mackey);
	}
	for (i=0; i<SHA224_HASH_BYTE_LEN; i++)
		ipad[i] = mackey[i] ^ 0x36;
	for (;i<SHA224_BLK_BYTE_LEN; i++) ipad[i] = 0x36;
	SHA2241_init(&sha224_ctx);
	SHA2241_update(&sha224_ctx, ipad, SHA224_BLK_BYTE_LEN);
	/* Updating with the message */
	SHA2241_update(&sha224_ctx,M,Mlen);
	/* Finalizing */
	SHA2241_final(&sha224_ctx, ihash);
	for (i=0; i<SHA224_HASH_BYTE_LEN; i++)
		opad[i] = mackey[i] ^ 0x5C;
	for (;i<SHA224_BLK_BYTE_LEN; i++) opad[i] = 0x5C;
	SHA2241_init(&sha224_ctx);
	SHA2241_update(&sha224_ctx, opad, SHA224_BLK_BYTE_LEN);
	SHA2241_update(&sha224_ctx, ihash, SHA224_HASH_BYTE_LEN);
	SHA2241_final(&sha224_ctx, MAC);
	return;
}
/*
* SHA256 HMAC을 수행한다.
* @param M - 입력된 데이터
* @param Mlen - 입력된 데이터의 길이
* @param key - 입력된 마스터키
* @param keylen - 입력된 마스터키의 길이
* @param MAC - 출력할 MAC
*
* @return
*
* @note
*/
void
	SHA256_hmac( UINT8 *M, UINT Mlen, UINT8 *key, UINT keylen,
	UINT8 MAC[SHA256_HASH_BYTE_LEN])
{
	SHA256_CTX sha256_ctx;
	UINT8 mackey[SHA256_HASH_BYTE_LEN];
	UINT8 ipad[SHA256_BLK_BYTE_LEN+16];
	UINT8 opad[SHA256_BLK_BYTE_LEN+16];
	UINT8 ihash[SHA256_BLK_BYTE_LEN+16];
	SINT i;
	/* Initializing with the key */
	memset(mackey, 0x00, SHA256_HASH_BYTE_LEN);
	if (keylen <= SHA256_HASH_BYTE_LEN) {
		memcpy(mackey, key, keylen);
	}else {
		SHA256_hash(key, keylen, mackey);
	}
	for (i=0; i<SHA256_HASH_BYTE_LEN; i++)
		ipad[i] = mackey[i] ^ 0x36;
	for (;i<SHA256_BLK_BYTE_LEN; i++) ipad[i] = 0x36;
	SHA2561_init(&sha256_ctx);
	SHA2561_update(&sha256_ctx, ipad, SHA256_BLK_BYTE_LEN);
	/* Updating with the message */
	SHA2561_update(&sha256_ctx,M,Mlen);
	/* Finalizing */
	SHA2561_final(&sha256_ctx, ihash);
	for (i=0; i<SHA256_HASH_BYTE_LEN; i++)
		opad[i] = mackey[i] ^ 0x5C;
	for (;i<SHA256_BLK_BYTE_LEN; i++) opad[i] = 0x5C;
	SHA2561_init(&sha256_ctx);
	SHA2561_update(&sha256_ctx, opad, SHA256_BLK_BYTE_LEN);
	SHA2561_update(&sha256_ctx, ihash, SHA256_HASH_BYTE_LEN);
	SHA2561_final(&sha256_ctx, MAC);
	return;
}
/*
* SHA384 HMAC을 수행한다.
* @param M - 입력된 데이터
* @param Mlen - 입력된 데이터의 길이
* @param key - 입력된 마스터키
* @param keylen - 입력된 마스터키의 길이
* @param MAC - 출력할 MAC
*
* @return
*
* @note
*/
void
	SHA384_hmac( UINT8 *M, UINT Mlen, UINT8 *key, UINT keylen,
	UINT8 MAC[SHA384_HASH_BYTE_LEN])
{
	SHA384_CTX sha384_ctx;
	UINT8 mackey[SHA384_HASH_BYTE_LEN];
	UINT8 ipad[SHA384_BLK_BYTE_LEN+16];
	UINT8 opad[SHA384_BLK_BYTE_LEN+16];
	UINT8 ihash[SHA384_BLK_BYTE_LEN+16];
	SINT i;
	/* Initializing with the key */
	memset(mackey, 0x00, SHA384_HASH_BYTE_LEN);
	if (keylen <= SHA384_HASH_BYTE_LEN) {
		memcpy(mackey, key, keylen);
	}else {
		SHA384_hash(key, keylen, mackey);
	}
	for (i=0; i<SHA384_HASH_BYTE_LEN; i++)
		ipad[i] = mackey[i] ^ 0x36;
	for (;i<SHA384_BLK_BYTE_LEN; i++) ipad[i] = 0x36;
	SHA3841_init(&sha384_ctx);
	SHA3841_update(&sha384_ctx, ipad, SHA384_BLK_BYTE_LEN);
	/* Updating with the message */
	SHA3841_update(&sha384_ctx,M,Mlen);
	/* Finalizing */
	SHA3841_final(&sha384_ctx, ihash);
	for (i=0; i<SHA384_HASH_BYTE_LEN; i++)
		opad[i] = mackey[i] ^ 0x5C;
	for (;i<SHA384_BLK_BYTE_LEN; i++) opad[i] = 0x5C;
	SHA3841_init(&sha384_ctx);
	SHA3841_update(&sha384_ctx, opad, SHA384_BLK_BYTE_LEN);
	SHA3841_update(&sha384_ctx, ihash, SHA384_HASH_BYTE_LEN);
	SHA3841_final(&sha384_ctx, MAC);
	return;
}
/*
* SHA512 HMAC을 수행한다.
* @param M - 입력된 데이터
* @param Mlen - 입력된 데이터의 길이
* @param key - 입력된 마스터키
* @param keylen - 입력된 마스터키의 길이
* @param MAC - 출력할 MAC
*
* @return
*
* @note
*/
void
	SHA512_hmac( UINT8 *M, UINT Mlen, UINT8 *key, UINT keylen,
	UINT8 MAC[SHA512_HASH_BYTE_LEN])
{
	SHA512_CTX sha512_ctx;
	UINT8 mackey[SHA512_HASH_BYTE_LEN];
	UINT8 ipad[SHA512_BLK_BYTE_LEN+16];
	UINT8 opad[SHA512_BLK_BYTE_LEN+16];
	UINT8 ihash[SHA512_BLK_BYTE_LEN+16];
	SINT i;
	/* Initializing with the key */
	memset(mackey, 0x00, SHA512_HASH_BYTE_LEN);
	if (keylen <= SHA512_HASH_BYTE_LEN) {
		memcpy(mackey, key, keylen);
	}else {
		SHA512_hash(key, keylen, mackey);
	}
	for (i=0; i<SHA512_HASH_BYTE_LEN; i++)
		ipad[i] = mackey[i] ^ 0x36;
	for (;i<SHA512_BLK_BYTE_LEN; i++) ipad[i] = 0x36;
	SHA5121_init(&sha512_ctx);
	SHA5121_update(&sha512_ctx, ipad, SHA512_BLK_BYTE_LEN);
	/* Updating with the message */
	SHA5121_update(&sha512_ctx,M,Mlen);
	/* Finalizing */
	SHA5121_final(&sha512_ctx, ihash);
	for (i=0; i<SHA512_HASH_BYTE_LEN; i++)
		opad[i] = mackey[i] ^ 0x5C;
	for (;i<SHA512_BLK_BYTE_LEN; i++) opad[i] = 0x5C;
	SHA5121_init(&sha512_ctx);
	SHA5121_update(&sha512_ctx, opad, SHA512_BLK_BYTE_LEN);
	SHA5121_update(&sha512_ctx, ihash, SHA512_HASH_BYTE_LEN);
	SHA5121_final(&sha512_ctx, MAC);
	return;
}
