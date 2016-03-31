#include "EBDerror.h"
#include "EBDCrypto.h"

#define SHA224_BLOCK_SIZE		64
#define SHA224_DIGEST_LENGTH	28
#define SHA224_INIT				SHA224_init
#define SHA224_UPDATE			SHA224_update
#define SHA224_FINAL			SHA224_final
#define SHA224_STATE_SIZE		sizeof(SHA224_INFO)

#define SHA256_BLOCK_SIZE		64
#define SHA256_DIGEST_LENGTH	32
#define SHA256_INIT				SHA256_init
#define SHA256_UPDATE			SHA256_update
#define SHA256_FINAL			SHA256_final
#define SHA256_STATE_SIZE		sizeof(SHA256_INFO)

#define SHA384_BLOCK_SIZE		128
#define SHA384_DIGEST_LENGTH	48
#define SHA384_INIT				SHA384_init
#define SHA384_UPDATE			SHA384_update
#define SHA384_FINAL			SHA384_final
#define SHA384_STATE_SIZE		sizeof(SHA384_INFO)

#define SHA512_BLOCK_SIZE		128
#define SHA512_DIGEST_LENGTH	64
#define SHA512_INIT				SHA512_init
#define SHA512_UPDATE			SHA512_update
#define SHA512_FINAL			SHA512_final
#define SHA512_STATE_SIZE		sizeof(SHA512_INFO)

#if defined(_MSC_VER) || defined(__WINDOWS__)
#define PUT64(n) n##ui64
#else
#define PUT64(n) n##ULL
#endif

#define MIN(x, y) ( ((x)<(y))?(x):(y) )

#define ROLc(x, y) ((((UINT)(x)<<(UINT)((y)&31)) | (((UINT)(x)&0xFFFFFFFFU)>>(UINT)(32-((y)&31)))) & 0xFFFFFFFFU)
#define RORc(x, y) (((((UINT)(x)&0xFFFFFFFFU)>>(UINT)((y)&31)) | ((UINT)(x)<<(UINT)(32-((y)&31)))) & 0xFFFFFFFFU)

#define OR(x,y)			(x|y)
#define AND(x,y)		(x&y)
#define XOR(x,y)		(x^y)

#define S(x, n)         RORc((x),(n))
#define R(x, n)         ((ULLONG)((x)>>(n)))

#define F(x,y,z)		(XOR(z,(AND(x,(XOR(y,z))))))
#define G(x,y,z)		(XOR(x,XOR(y,z)))
#define H(x,y,z)		(OR(AND(x,y),AND(z,OR(x,y))))

#define SHA256_BLOCK_SIZEx8		512
#define SHA512_BLOCK_SIZEx8		1024

#define S_512_old(x, n)   \
	(((x) >> ((ULLONG)(n)& PUT64(63))) | ((x) << ((ULLONG)(64 - ((n)&PUT64(63))))))

#define S_512(x,s)	(((x)>>s) | (x)<<(64-s))

#define R_512(x, n)         ((x)>>((ULLONG)n))

#define rnd_512(a,b,c,d,e,f,g,h,i)                    \
	temp0 = h + (S_512(e, 14) ^ S_512(e, 18) ^ S_512(e, 41)) + F(e, f, g) + K_512[i] + W[i];   \
	temp1 = (S_512(a, 28) ^ S_512(a, 34) ^ S_512(a, 39)) + H(a, b, c);                  \
	d += temp0;                                        \
	h = temp0 + temp1;

#define rnd_512_sum(a,b,c,d,e,f,g,h,i)                    \
	W[i] = (S_512(W[i - 2], 19) ^ S_512(W[i - 2], 61) ^ R_512(W[i - 2], 6)) + W[i - 7] + \
	(S_512(W[i - 15], 1) ^ S_512(W[i - 15], 8) ^ R_512(W[i - 15], 7)) + W[i - 16]; \
	temp0 = h + (S_512(e, 14) ^ S_512(e, 18) ^ S_512(e, 41)) + F(e, f, g) + K_512[i] + W[i];   \
	temp1 = (S_512(a, 28) ^ S_512(a, 34) ^ S_512(a, 39)) + H(a, b, c);                  \
	d += temp0;                                        \
	h = temp0 + temp1;

static const UINT SHA256_K[64] = {
	0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL,
	0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL,
	0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL,
	0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
	0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 0x983e5152UL,
	0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
	0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL,
	0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
	0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL,
	0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 0x19a4c116UL, 0x1e376c08UL,
	0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL,
	0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
	0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

static const ULLONG K_512[80] = {
	PUT64(0x428a2f98d728ae22), PUT64(0x7137449123ef65cd),
	PUT64(0xb5c0fbcfec4d3b2f), PUT64(0xe9b5dba58189dbbc),
	PUT64(0x3956c25bf348b538), PUT64(0x59f111f1b605d019),
	PUT64(0x923f82a4af194f9b), PUT64(0xab1c5ed5da6d8118),
	PUT64(0xd807aa98a3030242), PUT64(0x12835b0145706fbe),
	PUT64(0x243185be4ee4b28c), PUT64(0x550c7dc3d5ffb4e2),
	PUT64(0x72be5d74f27b896f), PUT64(0x80deb1fe3b1696b1),
	PUT64(0x9bdc06a725c71235), PUT64(0xc19bf174cf692694),
	PUT64(0xe49b69c19ef14ad2), PUT64(0xefbe4786384f25e3),
	PUT64(0x0fc19dc68b8cd5b5), PUT64(0x240ca1cc77ac9c65),
	PUT64(0x2de92c6f592b0275), PUT64(0x4a7484aa6ea6e483),
	PUT64(0x5cb0a9dcbd41fbd4), PUT64(0x76f988da831153b5),
	PUT64(0x983e5152ee66dfab), PUT64(0xa831c66d2db43210),
	PUT64(0xb00327c898fb213f), PUT64(0xbf597fc7beef0ee4),
	PUT64(0xc6e00bf33da88fc2), PUT64(0xd5a79147930aa725),
	PUT64(0x06ca6351e003826f), PUT64(0x142929670a0e6e70),
	PUT64(0x27b70a8546d22ffc), PUT64(0x2e1b21385c26c926),
	PUT64(0x4d2c6dfc5ac42aed), PUT64(0x53380d139d95b3df),
	PUT64(0x650a73548baf63de), PUT64(0x766a0abb3c77b2a8),
	PUT64(0x81c2c92e47edaee6), PUT64(0x92722c851482353b),
	PUT64(0xa2bfe8a14cf10364), PUT64(0xa81a664bbc423001),
	PUT64(0xc24b8b70d0f89791), PUT64(0xc76c51a30654be30),
	PUT64(0xd192e819d6ef5218), PUT64(0xd69906245565a910),
	PUT64(0xf40e35855771202a), PUT64(0x106aa07032bbd1b8),
	PUT64(0x19a4c116b8d2d0c8), PUT64(0x1e376c085141ab53),
	PUT64(0x2748774cdf8eeb99), PUT64(0x34b0bcb5e19b48a8),
	PUT64(0x391c0cb3c5c95a63), PUT64(0x4ed8aa4ae3418acb),
	PUT64(0x5b9cca4f7763e373), PUT64(0x682e6ff3d6b2b8a3),
	PUT64(0x748f82ee5defb2fc), PUT64(0x78a5636f43172f60),
	PUT64(0x84c87814a1f0ab72), PUT64(0x8cc702081a6439ec),
	PUT64(0x90befffa23631e28), PUT64(0xa4506cebde82bde9),
	PUT64(0xbef9a3f7b2c67915), PUT64(0xc67178f2e372532b),
	PUT64(0xca273eceea26619c), PUT64(0xd186b8c721c0c207),
	PUT64(0xeada7dd6cde0eb1e), PUT64(0xf57d4f7fee6ed178),
	PUT64(0x06f067aa72176fba), PUT64(0x0a637dc5a2c898a6),
	PUT64(0x113f9804bef90dae), PUT64(0x1b710b35131c471b),
	PUT64(0x28db77f523047d84), PUT64(0x32caab7b40c72493),
	PUT64(0x3c9ebe0a15c9bebc), PUT64(0x431d67c49c100d4c),
	PUT64(0x4cc5d4becb3e42b6), PUT64(0x597f299cfc657e2a),
	PUT64(0x5fcb6fab3ad6faec), PUT64(0x6c44198c4a475817)
};


static void SHA256_compute(SHA256_INFO *sha256, UCHAR *data);
static void SHA512_compute(SHA512_INFO *sha512, UCHAR *data);

/******************************SHA224****************************************/
SINT SHA224_init(SHA224_INFO *sha224)
{
	if (sha224 == NULL)
	{
		return ERR_INVALID_INPUT;
	}

	sha224->l1 = 0;
	sha224->l2 = 0;

	sha224->data[0] = 0xc1059ed8UL;
	sha224->data[1] = 0x367cd507UL;
	sha224->data[2] = 0x3070dd17UL;
	sha224->data[3] = 0xf70e5939UL;
	sha224->data[4] = 0xffc00b31UL;
	sha224->data[5] = 0x68581511UL;
	sha224->data[6] = 0x64f98fa7UL;
	sha224->data[7] = 0xbefa4fa4UL;

	return EBD_CRYPTO_SUCCESS;
}

SINT SHA224_update(SHA224_INFO *sha224, const UCHAR *data, SINT length)
{
	return SHA256_update(sha224, data, length);
}

SINT SHA224_final(SHA224_INFO *sha224, UCHAR *out)
{
	UCHAR buf[32];

	if(!sha224 || !out)
		return ERR_INVALID_INPUT;

	if (!(SHA256_final(sha224, buf)))
	{
		return ERR_FINAL_FAILURE;
	}
	memcpy(out, buf, 28);

	return EBD_CRYPTO_SUCCESS;
}

/******************************SHA256****************************************/
SINT SHA256_init(SHA256_INFO *sha256)
{
	if (sha256 == NULL)
	{
		return ERR_INVALID_INPUT;
	}

	sha256->l1 = 0;
	sha256->l2 = 0;
	sha256->data[0] = 0x6A09E667UL;
	sha256->data[1] = 0xBB67AE85UL;
	sha256->data[2] = 0x3C6EF372UL;
	sha256->data[3] = 0xA54FF53AUL;
	sha256->data[4] = 0x510E527FUL;
	sha256->data[5] = 0x9B05688CUL;
	sha256->data[6] = 0x1F83D9ABUL;
	sha256->data[7] = 0x5BE0CD19UL;

	return EBD_CRYPTO_SUCCESS;
}

SINT SHA256_update(SHA256_INFO *sha256, const UCHAR *data, SINT length)
{
	UINT n;

	if( !sha256 || !data || (length < 0) )
		return ERR_INVALID_INPUT;

	if (sha256->l2 > SHA256_BLOCK_SIZE)
		return ERR_INVALID_UNIT;

	while (length > 0) {

		if (!sha256->l2 && length >= SHA256_BLOCK_SIZE)
		{
			SHA256_compute(sha256, (UCHAR *)data);
			sha256->l1 += SHA256_BLOCK_SIZEx8;
			data += SHA256_BLOCK_SIZE;
			length -= SHA256_BLOCK_SIZE;

		}
		else
		{
			n = MIN((SHA256_BLOCK_SIZE - sha256->l2), (UINT)length);
			memcpy(sha256->buf + sha256->l2, data, n);
			data += n;
			sha256->l2 += n;
			length -= n;

			if (sha256->l2 == SHA256_BLOCK_SIZE)
			{
				SHA256_compute(sha256, sha256->buf);
				sha256->l2 = 0;
				sha256->l1 += SHA256_BLOCK_SIZEx8;
			}
		}
	}

	return EBD_CRYPTO_SUCCESS;
}

SINT SHA256_final(SHA256_INFO *sha256, UCHAR *out)
{
	SINT i, off = 0;

	if(!sha256 || !out)
		return ERR_INVALID_INPUT;

	if (sha256->l2 >= SHA256_BLOCK_SIZE)
	{
		return ERR_INVALID_UNIT;
	}

	sha256->l1 += sha256->l2 << 3;
	sha256->buf[sha256->l2++] = (UCHAR)0x80;

	if (sha256->l2 > 56) {
		memset(sha256->buf + sha256->l2, 0, 64 - (sha256->l2));
		sha256->l2 = SHA256_BLOCK_SIZE;
		SHA256_compute(sha256, sha256->buf);
		sha256->l2 = 0;
	}

	while (sha256->l2 < 56)
		sha256->buf[sha256->l2++] = 0;

	sha256->buf[56] = (UCHAR)(sha256->l1 >> 56);
	sha256->buf[57] = (UCHAR)(sha256->l1 >> 48);
	sha256->buf[58] = (UCHAR)(sha256->l1 >> 40);
	sha256->buf[59] = (UCHAR)(sha256->l1 >> 32);
	sha256->buf[60] = (UCHAR)(sha256->l1 >> 24);
	sha256->buf[61] = (UCHAR)(sha256->l1 >> 16);
	sha256->buf[62] = (UCHAR)(sha256->l1 >> 8);
	sha256->buf[63] = (UCHAR)(sha256->l1);

	SHA256_compute(sha256, sha256->buf);

	for (i = 0; i < 8; i++) {
		off = i << 2;
		(out + off)[3] = (UCHAR)(sha256->data[i]);
		(out + off)[2] = (UCHAR)(sha256->data[i] >> 8);
		(out + off)[1] = (UCHAR)(sha256->data[i] >> 16);
		(out + off)[0] = (UCHAR)(sha256->data[i] >> 24);
	}

	return EBD_CRYPTO_SUCCESS;
}

static void SHA256_compute(SHA256_INFO *sha256, UCHAR *data) {

	SINT i;
	UINT data_temp[8], W[64];
	UINT temp, t1, temp2;
	SINT off = 0;

	data_temp[0] = sha256->data[0];
	data_temp[1] = sha256->data[1];
	data_temp[2] = sha256->data[2];
	data_temp[3] = sha256->data[3];
	data_temp[4] = sha256->data[4];
	data_temp[5] = sha256->data[5];
	data_temp[6] = sha256->data[6];
	data_temp[7] = sha256->data[7];

	for (i = 0; i < 16; i++) {
		off = i << 2;
		W[i] = (((UINT)((data + off)[0] << 24)) |
			((UINT)((data + off)[1] << 16)) |
			((UINT)((data + off)[2] << 8)) |
			((UINT)((data + off)[3])));
	}

	for (i = 16; i < 64; i++)
		W[i] = (S(W[i - 2], 17) ^ S(W[i - 2], 19) ^ R(W[i - 2], 10)) +
		W[i - 7] + (S(W[i - 15], 7) ^ S(W[i - 15], 18) ^ R(W[i - 15], 3)) + W[i - 16];

	for (i = 0; i < 64; ++i) {
		t1 = data_temp[7] + (S(data_temp[4], 6) ^ S(data_temp[4], 11) ^ S(data_temp[4], 25))
			+ F(data_temp[4], data_temp[5], data_temp[6]) + SHA256_K[i] + W[i];
		temp2 = (S(data_temp[0], 2) ^ S(data_temp[0], 13) ^ S(data_temp[0], 22))
			+ H(data_temp[0], data_temp[1], data_temp[2]);
		data_temp[3] += t1;
		data_temp[7] = t1 + temp2;

		temp = data_temp[7];
		data_temp[7] = data_temp[6];
		data_temp[6] = data_temp[5];
		data_temp[5] = data_temp[4];
		data_temp[4] = data_temp[3];
		data_temp[3] = data_temp[2];
		data_temp[2] = data_temp[1];
		data_temp[1] = data_temp[0];
		data_temp[0] = temp;
	}

	sha256->data[0] += data_temp[0];
	sha256->data[1] += data_temp[1];
	sha256->data[2] += data_temp[2];
	sha256->data[3] += data_temp[3];
	sha256->data[4] += data_temp[4];
	sha256->data[5] += data_temp[5];
	sha256->data[6] += data_temp[6];
	sha256->data[7] += data_temp[7];
}


/******************************SHA384****************************************/
SINT SHA384_init(SHA384_INFO *sha384)
{
	if (sha384 == NULL) 
	{
		return ERR_INVALID_INPUT;
	}

	sha384->l1 = 0;
	sha384->l2 = 0;
	sha384->data[0] = PUT64(0xcbbb9d5dc1059ed8);
	sha384->data[1] = PUT64(0x629a292a367cd507);
	sha384->data[2] = PUT64(0x9159015a3070dd17);
	sha384->data[3] = PUT64(0x152fecd8f70e5939);
	sha384->data[4] = PUT64(0x67332667ffc00b31);
	sha384->data[5] = PUT64(0x8eb44a8768581511);
	sha384->data[6] = PUT64(0xdb0c2e0d64f98fa7);
	sha384->data[7] = PUT64(0x47b5481dbefa4fa4);

	return EBD_CRYPTO_SUCCESS;
}

SINT SHA384_update(SHA384_INFO *sha384, const UCHAR *data, SINT length)
{
	return SHA512_update(sha384, data, length);
}

SINT SHA384_final(SHA384_INFO *sha384, UCHAR *out)
{
	UCHAR buf[64];

	if(!sha384 || !out)
		return ERR_INVALID_INPUT;

	if (!(SHA512_final(sha384, buf)))
	{
		return ERR_FINAL_FAILURE;
	}

	memcpy(out, buf, 48);

	return EBD_CRYPTO_SUCCESS;
}

/******************************SHA512****************************************/
SINT SHA512_init(SHA512_INFO * sha512)
{
	if (sha512 == NULL) 
	{
		return ERR_INVALID_INPUT;
	}

	sha512->l1 = 0;
	sha512->l2 = 0;
	sha512->data[0] = PUT64(0x6a09e667f3bcc908);
	sha512->data[1] = PUT64(0xbb67ae8584caa73b);
	sha512->data[2] = PUT64(0x3c6ef372fe94f82b);
	sha512->data[3] = PUT64(0xa54ff53a5f1d36f1);
	sha512->data[4] = PUT64(0x510e527fade682d1);
	sha512->data[5] = PUT64(0x9b05688c2b3e6c1f);
	sha512->data[6] = PUT64(0x1f83d9abfb41bd6b);
	sha512->data[7] = PUT64(0x5be0cd19137e2179);

	return EBD_CRYPTO_SUCCESS;
}

SINT SHA512_update(SHA512_INFO *sha512, const UCHAR *data, SINT length)
{
	UINT n;

	if(!sha512 || !data || (length < 0))
		return ERR_INVALID_INPUT;

	if (sha512->l2 > SHA512_BLOCK_SIZE) 
	{
		return ERR_INVALID_INPUT;
	}

	while (length > 0)
	{
		if (!sha512->l2 && (length >= SHA512_BLOCK_SIZE))
		{
			SHA512_compute(sha512, (UCHAR *)data);
			sha512->l1 += SHA512_BLOCK_SIZEx8;
			data += SHA512_BLOCK_SIZE;
			length -= SHA512_BLOCK_SIZE;
		}
		else
		{
			n = MIN((SHA512_BLOCK_SIZE - sha512->l2), (UINT)length);

			memcpy(sha512->buf + sha512->l2, data, n);

			data += n;
			sha512->l2 += n;
			length -= n;

			if (sha512->l2 == SHA512_BLOCK_SIZE)
			{
				SHA512_compute(sha512, sha512->buf);
				sha512->l2 = 0;
				sha512->l1 += SHA512_BLOCK_SIZEx8;
			}
		}
	}
	return EBD_CRYPTO_SUCCESS;
}

SINT SHA512_final(SHA512_INFO *sha512, UCHAR *out)
{
	SINT i, off = 0;
	UCHAR *buf = sha512->buf;
	UINT n = sha512->l2;

	if(!sha512 || !out)
		return ERR_INVALID_INPUT;

	if (n >= SHA512_BLOCK_SIZE)
	{
		return ERR_INVALID_INPUT;
	}

	sha512->l1 += n << 3;
	buf[n++] = (UCHAR)0x80;

	if (n > 112) {
		memset(buf + n, 0x00, 128 - n);
		n = SHA512_BLOCK_SIZE;
		SHA512_compute(sha512, buf);
		n = 0;
	}

	memset(buf + n, 0x00, 120 - n);

	buf[120] = (UCHAR)(((sha512->l1) >> 56));
	buf[121] = (UCHAR)(((sha512->l1) >> 48));
	buf[122] = (UCHAR)(((sha512->l1) >> 40));
	buf[123] = (UCHAR)(((sha512->l1) >> 32));
	buf[124] = (UCHAR)(((sha512->l1) >> 24));
	buf[125] = (UCHAR)(((sha512->l1) >> 16));
	buf[126] = (UCHAR)(((sha512->l1) >> 8));
	buf[127] = (UCHAR)(((sha512->l1)));

	SHA512_compute(sha512, buf);

	for (i = 0; i < 8; i++) {
		off = i << 3;
		(out + off)[0] = (UCHAR)(((sha512->data[i]) >> 56));
		(out + off)[1] = (UCHAR)(((sha512->data[i]) >> 48));
		(out + off)[2] = (UCHAR)(((sha512->data[i]) >> 40));
		(out + off)[3] = (UCHAR)(((sha512->data[i]) >> 32));
		(out + off)[4] = (UCHAR)(((sha512->data[i]) >> 24));
		(out + off)[5] = (UCHAR)(((sha512->data[i]) >> 16));
		(out + off)[6] = (UCHAR)(((sha512->data[i]) >> 8));
		(out + off)[7] = (UCHAR)(((sha512->data[i])));
	}
	return EBD_CRYPTO_SUCCESS;
}

static void SHA512_compute(SHA512_INFO * sha512, UCHAR *data)
{
	ULLONG a, b, c, d, e, f, g, h, temp0, temp1;
	ULLONG W[80];
	SINT i, off = 0;

	a = sha512->data[0];
	b = sha512->data[1];
	c = sha512->data[2];
	d = sha512->data[3];
	e = sha512->data[4];
	f = sha512->data[5];
	g = sha512->data[6];
	h = sha512->data[7];

	for (i = 0; i < 16; i++)
	{
		off = i << 3;
		W[i] = (((ULLONG)((data + off)[0])) << 56) | (((ULLONG)((data + off)[1])) << 48) |
			(((ULLONG)((data + off)[2])) << 40) | (((ULLONG)((data + off)[3])) << 32) |
			(((ULLONG)((data + off)[4])) << 24) | (((ULLONG)((data + off)[5])) << 16) |
			(((ULLONG)((data + off)[6])) << 8) | (((ULLONG)((data + off)[7])));
	}

	for (i = 16; i < 80; i++)
	{
		W[i] = (S_512(W[i - 2], 19) ^ S_512(W[i - 2], 61) ^ R_512(W[i - 2], 6)) + W[i - 7] +
			(S_512(W[i - 15], 1) ^ S_512(W[i - 15], 8) ^ R_512(W[i - 15], 7)) + W[i - 16];
	}

	for (i = 0; i < 80; i += 8)
	{
		rnd_512(a, b, c, d, e, f, g, h, i + 0); rnd_512(h, a, b, c, d, e, f, g, i + 1);
		rnd_512(g, h, a, b, c, d, e, f, i + 2); rnd_512(f, g, h, a, b, c, d, e, i + 3);
		rnd_512(e, f, g, h, a, b, c, d, i + 4); rnd_512(d, e, f, g, h, a, b, c, i + 5);
		rnd_512(c, d, e, f, g, h, a, b, i + 6); rnd_512(b, c, d, e, f, g, h, a, i + 7);
	}

	sha512->data[0] += a;
	sha512->data[1] += b;
	sha512->data[2] += c;
	sha512->data[3] += d;
	sha512->data[4] += e;
	sha512->data[5] += f;
	sha512->data[6] += g;
	sha512->data[7] += h;
}

SINT sha224(UCHAR *input, SINT input_length, UCHAR *Digest)
{
	SHA224_INFO sha;
	SINT result;

	if( (result = SHA224_init(&sha)) != 1 )
		return result;

	if( (result = SHA224_update(&sha, input, input_length)) != 1 )
		return result;

	if( (result = SHA224_final(&sha, Digest)) != 1 )
		return result;

	memset(&sha, 0x00, sizeof(SHA224_INFO));
	return EBD_CRYPTO_SUCCESS;
}

SINT sha256(UCHAR *input, SINT input_length, UCHAR *Digest)
{
	SHA256_INFO sha;
	SINT result;

	if( (result = SHA256_init(&sha)) != 1 )
		return result;

	if( (result = SHA256_update(&sha, input, input_length)) != 1 )
		return result;

	if( (result = SHA256_final(&sha, Digest)) != 1 )
		return result;

	memset(&sha, 0x00, sizeof(SHA256_INFO));
	return EBD_CRYPTO_SUCCESS;
}

SINT sha384(UCHAR *input, SINT input_length, UCHAR *Digest)
{
	SHA384_INFO sha;
	SINT result;

	if( (result = SHA384_init(&sha)) != 1 )
		return result;

	if( (result = SHA384_update(&sha, input, input_length)) != 1 )
		return result;

	if( (result = SHA384_final(&sha, Digest)) != 1 )
		return result;

	memset(&sha, 0x00, sizeof(SHA384_INFO));
	return EBD_CRYPTO_SUCCESS;
}

SINT sha512(UCHAR *input, SINT input_length, UCHAR *Digest)
{
	SHA512_INFO sha;
	SINT result;

	if( (result = SHA512_init(&sha)) != 1 )
		return result;

	if( (result = SHA512_update(&sha, input, input_length)) != 1 )
		return result;

	if( (result = SHA512_final(&sha, Digest)) != 1 )
		return result;

	memset(&sha, 0x00, sizeof(SHA512_INFO));
	return EBD_CRYPTO_SUCCESS;
}