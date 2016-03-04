#include "EBDCrypto.h"


//------------------------------------------------
#define DRBG_ALGO_SHA224						0x22
#define DRBG_ALGO_SHA256						0x23
#define DRBG_ALGO_SHA384						0x24
#define DRBG_ALGO_SHA512						0x25

//------------------------------------------------
#define ALGO_SHA1_OUTLEN_IN_BYTES				20
#define ALGO_SHA224_OUTLEN_IN_BYTES				28
#define ALGO_SHA256_OUTLEN_IN_BYTES				32
#define ALGO_SHA384_OUTLEN_IN_BYTES				48
#define ALGO_SHA512_OUTLEN_IN_BYTES				64

//------------------------------------------------
#define ALGO_SHA1_SECURITY_STRENGTH_IN_BYTES	10
#define ALGO_SHA224_SECURITY_STRENGTH_IN_BYTES	14
#define ALGO_SHA256_SECURITY_STRENGTH_IN_BYTES	16
#define ALGO_SHA384_SECURITY_STRENGTH_IN_BYTES	24
#define ALGO_SHA512_SECURITY_STRENGTH_IN_BYTES	32

//------------------------------------------------
#define ALGO_SHA1_SEEDLEN_IN_BYTES				55
#define ALGO_SHA224_SEEDLEN_IN_BYTES			55
#define ALGO_SHA256_SEEDLEN_IN_BYTES			55
#define ALGO_SHA384_SEEDLEN_IN_BYTES			111
#define ALGO_SHA512_SEEDLEN_IN_BYTES			111


#define HD_MAX_V_LEN_IN_BYTES					111
#define HD_MAX_C_LEN_IN_BYTES					111
#define HD_MAX_SEEDLEN_IN_BYTES					111

//------------------------------------------------
#define HD_MIN_ENTROPY_INPUT_LEN_IN_BYTES			// Depends on SECURITY_STRENGTH of each algorithm

//------------------------------------------------
#define HD_MAX_NUM_INPUT_OF_BYTES_PER_REQUEST		0x10000			// 2^19 bits

//------------------------------------------------
// The following values are too huge to apply on the current architectures,
// thus we do not consider the maximum length of either input or entropy.
#define HD_MAX_ENTROPY_INPUT_LEN_IN_BYTES			0x100000000		// 2^35 bits
#define HD_MAX_PERSONALIZED_STRING_LEN_IN_BYTES	0x100000000		// 2^35 bits
#define HD_MAX_ADDITIONAL_INPUT_LEN_IN_BYTES		0x100000000		// 2^35 bits
#define HD_NUM_OF_REQUESTS_BETWEEN_RESEEDS			0x1000000000000UL// 2^48 bits

#define HD_DRBG_STATE_INITIALIZED_FLAG			0xEF21CD43

#define HD_DRBG_RESEED_REQUIRED					0xAA
#define HD_DRBG_RESEED_PROCESSED				0xBB

#define NON_PREDICTION_RESISTANCE				0x00
#define USE_PREDICTION_RESISTANCE				0xFF

#define h_octet_to_int(os) (((unsigned int)(os)[0] << 24) ^ ((unsigned int)(os)[1] << 16) ^ ((unsigned int)(os)[2] <<  8) ^ ((unsigned int)(os)[3]))
#define h_int_to_octet(os, i) { (os)[0] = (unsigned char)((i) >> 24); (os)[1] = (unsigned char)((i) >> 16); (os)[2] = (unsigned char)((i) >>  8); (os)[3] = (unsigned char)(i); }

#define H_MAX_NUM_OF_BYTES_TO_RETURN 16320
#define H_MAX_NUM_OF_BITS_TO_RETURN 130560

int Hash_df(char algo, unsigned char *input_string, int input_str_len, unsigned char *output, int outlen);

void value_increase(unsigned char *counter, int countlen)
{
	int i;
	
	for(i=countlen-1;i>=0;i--)
	{
		counter[i] = counter[i] + 1;
		if(counter[i] == 0x00)
			continue;
		else
			break;
	}
}

int ceiling(int n, int v){
    if(!(n%v))
        return n/v;
    else
        return (n/v) + 1;
}

int Hash_df(char algo, unsigned char *input_string, int input_str_len, unsigned char *output, int requested_num_of_bits)
{
	unsigned char *temp = NULL;
	unsigned char *buf = NULL;
	int retcode = 0;
	int i = 0;
	int templen = 0;
	int buflen = 0;
	int len = 0;
	int request_num_of_bytes;
	unsigned char counter = 1;

 	SHA224_INFO sha224;
 	SHA256_INFO sha256;
 	SHA384_INFO sha384;
 	SHA512_INFO sha512;

	if(requested_num_of_bits > H_MAX_NUM_OF_BITS_TO_RETURN )
		return 0;

	request_num_of_bytes = requested_num_of_bits / 8 + ((requested_num_of_bits % 8) != 0 ? 1 : 0);

	switch(algo)
	{
		case DRBG_ALGO_SHA224:
			//len = (int)ceil((float)requested_num_of_bits / (ALGO_SHA224_OUTLEN_IN_BYTES*8));
			len = ceiling(requested_num_of_bits, (ALGO_SHA224_OUTLEN_IN_BYTES*8));
			templen = ALGO_SHA224_OUTLEN_IN_BYTES;
			break;

		case DRBG_ALGO_SHA256:
			//len = (int)ceil((float)requested_num_of_bits / (ALGO_SHA256_OUTLEN_IN_BYTES*8));
			len = ceiling(requested_num_of_bits, (ALGO_SHA256_OUTLEN_IN_BYTES*8));
			templen = ALGO_SHA256_OUTLEN_IN_BYTES;
			break;

		case DRBG_ALGO_SHA384:
			//len = (int)ceil((float)requested_num_of_bits / (ALGO_SHA384_OUTLEN_IN_BYTES*8));
			len = ceiling(requested_num_of_bits, (ALGO_SHA384_OUTLEN_IN_BYTES*8));
			templen = ALGO_SHA384_OUTLEN_IN_BYTES;
			break;

		case DRBG_ALGO_SHA512:
			//len = (int)ceil((float)requested_num_of_bits / (ALGO_SHA512_OUTLEN_IN_BYTES*8));
			len = ceiling(requested_num_of_bits, (ALGO_SHA512_OUTLEN_IN_BYTES*8));
			templen = ALGO_SHA512_OUTLEN_IN_BYTES;
			break;

		default:
			goto FREE_AND_EXIT;
	}
	
	templen = templen * len;
	temp = (unsigned char *)malloc(templen);
	if(temp == NULL)
		goto FREE_AND_EXIT;

	buflen = input_str_len + 5;
	buf = (unsigned char *)malloc(buflen);
	if(buf == NULL)
		goto FREE_AND_EXIT;

	for(i=0;i<len;i++)
	{
		buf[0] = counter;
		h_int_to_octet(buf + 1, requested_num_of_bits);
		memcpy(buf+5, input_string, input_str_len);

		switch(algo)
		{
			case DRBG_ALGO_SHA224:
				SHA224_init(&sha224);
				SHA224_update(&sha224, buf, buflen);
				SHA224_final(&sha224, temp + (i * ALGO_SHA224_OUTLEN_IN_BYTES) );
				break;

			case DRBG_ALGO_SHA256:
				SHA256_init(&sha256);
				SHA256_update(&sha256, buf, buflen);
				SHA256_final(&sha256, temp + (i * ALGO_SHA256_OUTLEN_IN_BYTES) );
				break;

			case DRBG_ALGO_SHA384:
				SHA384_init(&sha384);
				SHA384_update(&sha384, buf, buflen);
				SHA384_final(&sha384, temp + (i * ALGO_SHA384_OUTLEN_IN_BYTES) );
				break;

			case DRBG_ALGO_SHA512:
				SHA512_init(&sha512);
				SHA512_update(&sha512, buf, buflen);
				SHA512_final(&sha512, temp + (i * ALGO_SHA512_OUTLEN_IN_BYTES) );
				break;

			default:
				goto FREE_AND_EXIT;
		}

		counter += 1;
	}

	memcpy(output,temp,request_num_of_bytes);

	if(requested_num_of_bits % 8 != 0)
		output[request_num_of_bytes-1] = temp[request_num_of_bytes-1] & (0x000000FF&(0xFF << (8-(requested_num_of_bits%8))));

	retcode = 1;
	
FREE_AND_EXIT:

	if(temp != NULL){
		memset(temp, 0x00, templen);
		free(temp);
	}
	if(buf != NULL){
		memset(buf, 0x00, buflen);
		free(buf);
	}

	return retcode;
}

int Addition(HASH_DRBG_STATE *state, unsigned char *V, int Vlen, unsigned char *w, int hashlen)
{
	int i, j;
	int carry = 0;
	unsigned char temp;

	j = 1;
	for(i=hashlen-1;i>=0;i--)
	{
		temp = V[Vlen-j];
		V[Vlen-j] = V[Vlen-j] + w[i] + carry;
		if( (V[Vlen-j] - carry) < temp)
			carry = 1;
		else
			carry = 0;

		j++;
	}
	while(carry && (j <= Vlen) )
	{
		V[Vlen-j] += carry;
		if(V[Vlen-j] == 0x00)
			carry = 1;
		else
			carry = 0;

		j++;
	}

	return 1;
}

int Hashgen(HASH_DRBG_STATE *state, int requested_num_of_bits, unsigned char *V, int Vlen, unsigned char *output)
{
	unsigned char *temp = NULL;
	unsigned char *data = NULL;
	int retcode = 0;
	int i = 0;
	int templen = 0;
	int datalen = 0;
	int m = 0;
	int request_num_of_bytes;
	
	SHA224_INFO sha224;
	SHA256_INFO sha256;
	SHA384_INFO sha384;
	SHA512_INFO sha512;

	request_num_of_bytes = requested_num_of_bits / 8 + ((requested_num_of_bits % 8) != 0 ? 1 : 0);

	switch(state->algo)
	{
	case DRBG_ALGO_SHA224:
		//m = (int)ceil((float)requested_num_of_bits / (ALGO_SHA224_OUTLEN_IN_BYTES*8));
		m = ceiling(requested_num_of_bits, (ALGO_SHA224_OUTLEN_IN_BYTES*8));
		templen = ALGO_SHA224_OUTLEN_IN_BYTES;
		break;

	case DRBG_ALGO_SHA256:
		//m = (int)ceil((float)requested_num_of_bits / (ALGO_SHA256_OUTLEN_IN_BYTES*8));
		m = ceiling(requested_num_of_bits, (ALGO_SHA256_OUTLEN_IN_BYTES*8));
		templen = ALGO_SHA256_OUTLEN_IN_BYTES;
		break;

	case DRBG_ALGO_SHA384:
		//m = (int)ceil((float)requested_num_of_bits / (ALGO_SHA384_OUTLEN_IN_BYTES*8));
		m = ceiling(requested_num_of_bits, (ALGO_SHA384_OUTLEN_IN_BYTES*8));
		templen = ALGO_SHA384_OUTLEN_IN_BYTES;
		break;

	case DRBG_ALGO_SHA512:
		//m = (int)ceil((float)requested_num_of_bits / (ALGO_SHA512_OUTLEN_IN_BYTES*8));
		m = ceiling(requested_num_of_bits, (ALGO_SHA512_OUTLEN_IN_BYTES*8));
		templen = ALGO_SHA512_OUTLEN_IN_BYTES;
		break;

	default:
		goto FREE_AND_EXIT;
	}


	templen = templen * m;
	temp = (unsigned char *)malloc(templen);
	if(temp == NULL)
		goto FREE_AND_EXIT;

	datalen = state->Vlen;
	data = (unsigned char *)malloc(datalen);
	if(data == NULL)
		goto FREE_AND_EXIT;

	memcpy(data, state->V, state->Vlen);

	for(i=0;i<m;i++)
	{

		switch(state->algo)
		{
		case DRBG_ALGO_SHA224:
			SHA224_init(&sha224);
			SHA224_update(&sha224, data, datalen);
			SHA224_final(&sha224, temp + (i * ALGO_SHA224_OUTLEN_IN_BYTES) );
			break;

		case DRBG_ALGO_SHA256:
			SHA256_init(&sha256);
			SHA256_update(&sha256, data, datalen);
			SHA256_final(&sha256, temp + (i * ALGO_SHA256_OUTLEN_IN_BYTES) );
			break;

		case DRBG_ALGO_SHA384:
			SHA384_init(&sha384);
			SHA384_update(&sha384, data, datalen);
			SHA384_final(&sha384, temp + (i * ALGO_SHA384_OUTLEN_IN_BYTES) );
			break;

		case DRBG_ALGO_SHA512:
			SHA512_init(&sha512);
			SHA512_update(&sha512, data, datalen);
			SHA512_final(&sha512, temp + (i * ALGO_SHA512_OUTLEN_IN_BYTES) );
			break;

		default:
			goto FREE_AND_EXIT;
		}

		value_increase(data, datalen);
	}

	memcpy(output,temp,request_num_of_bytes);

	if(requested_num_of_bits % 8 != 0)
		output[request_num_of_bytes-1] = temp[request_num_of_bytes-1] & (0x000000FF&(0xFF << (8-(requested_num_of_bits%8))));

	retcode = 1;

FREE_AND_EXIT:

	if(temp != NULL){
		memset(temp, 0x00, templen);
		free(temp);
	}
	if(data != NULL){
		memset(data, 0x00, datalen);
		free(data);
	}

	return retcode;
}


int HASH_DRBG_Instantiate(HASH_DRBG_STATE *state,
						 unsigned char  algo,
						 unsigned char* entropy_input, int entropylen,
						 unsigned char* nonce, int noncelen,
						 unsigned char* personalization_string, int stringlen,
						 unsigned char prediction_resistance_flag
						 )
{

	unsigned char	seed_material[HD_MAX_SEEDLEN_IN_BYTES];
	unsigned char*	seed_material_in = NULL;
	unsigned char*	ptr				 = NULL;
	unsigned char*  forC = NULL;
	int				seed_material_len = 0;
	int				retcode = 0;
	
	if(entropy_input == NULL)
	{
		return 0;
	}

	if(prediction_resistance_flag == USE_PREDICTION_RESISTANCE)
	{
		state->prediction_flag = USE_PREDICTION_RESISTANCE;
		state->reseed_flag = HD_DRBG_RESEED_REQUIRED;
	}
	else
	{
		state->prediction_flag = NON_PREDICTION_RESISTANCE;
		state->reseed_flag = HD_DRBG_RESEED_PROCESSED;
	}

	switch(algo)
	{
		//--------------------------------------------------------------
		case DRBG_ALGO_SHA224:

			if(entropylen < ALGO_SHA224_SECURITY_STRENGTH_IN_BYTES )
				return 0;

			state->seedlen = ALGO_SHA224_SEEDLEN_IN_BYTES;
			state->Vlen = ALGO_SHA224_SEEDLEN_IN_BYTES;
			state->Clen = ALGO_SHA224_SEEDLEN_IN_BYTES;
			break;

		//--------------------------------------------------------------
		case DRBG_ALGO_SHA256:

			if(entropylen < ALGO_SHA256_SECURITY_STRENGTH_IN_BYTES )
				return 0;

			state->seedlen = ALGO_SHA256_SEEDLEN_IN_BYTES;
			state->Vlen = ALGO_SHA256_SEEDLEN_IN_BYTES;
			state->Clen = ALGO_SHA256_SEEDLEN_IN_BYTES;
			break;

		//--------------------------------------------------------------
		case DRBG_ALGO_SHA384:

			if(entropylen < ALGO_SHA384_SECURITY_STRENGTH_IN_BYTES )
				return 0;

			state->seedlen = ALGO_SHA384_SEEDLEN_IN_BYTES;
			state->Vlen = ALGO_SHA384_SEEDLEN_IN_BYTES;
			state->Clen = ALGO_SHA384_SEEDLEN_IN_BYTES;
			break;

		//--------------------------------------------------------------
		case DRBG_ALGO_SHA512:

			if(entropylen < ALGO_SHA512_SECURITY_STRENGTH_IN_BYTES )
				return 0;

			state->seedlen = ALGO_SHA512_SEEDLEN_IN_BYTES;
			state->Vlen = ALGO_SHA512_SEEDLEN_IN_BYTES;
			state->Clen = ALGO_SHA512_SEEDLEN_IN_BYTES;
			break;


		default:
			return 0; // No Such Algorithm
	}

	state->algo = algo;

	memset(seed_material,0x00,HD_MAX_SEEDLEN_IN_BYTES);
	seed_material_len = entropylen;

	if(nonce != NULL && noncelen > 0) 	seed_material_len += (noncelen);
	if(personalization_string != NULL && stringlen > 0) 	seed_material_len += (stringlen);

	ptr = seed_material_in = (unsigned char*)malloc(seed_material_len);
	if(ptr == NULL)
		goto FREE_AND_EXIT;

	memcpy(ptr, entropy_input, entropylen);

	if(nonce != NULL && noncelen > 0)
	{
		ptr += entropylen;
		memcpy(ptr, nonce, noncelen);			
	}

	if(personalization_string != NULL && stringlen > 0)
	{
		ptr += noncelen;
		memcpy(ptr, personalization_string, stringlen);
	}

	if(!Hash_df(algo, seed_material_in, seed_material_len, seed_material, (state->seedlen * 8)))
	{
		goto FREE_AND_EXIT;
	}

	memset(state->V, 0x00, HD_MAX_SEEDLEN_IN_BYTES);
	memset(state->C, 0x00, HD_MAX_SEEDLEN_IN_BYTES);

	memcpy(state->V, seed_material, state->seedlen);
	//state->Vlen = state->seedlen;

	//----------
// 	fprintf(stderr, "\n====================\n");
// 	fprintf(stderr, "V in initiation");
// 	fprintf(stderr, "\n====================\n");
// 	printoctet(state->V, state->Vlen);
	//----------

	forC = (unsigned char*)malloc(state->Vlen + 1);
	if(forC == NULL)
		goto FREE_AND_EXIT;

	forC[0] = 0x00;
	memcpy(forC+1, state->V, state->Vlen);

	if(!Hash_df(algo, forC, state->Vlen + 1, state->C, (state->seedlen * 8)))
	{
		goto FREE_AND_EXIT;
	}
	//state->Clen = state->seedlen;

	//----------
// 	fprintf(stderr, "\n====================\n");
// 	fprintf(stderr, "C in initiation");
// 	fprintf(stderr, "\n====================\n");
// 	printoctet(state->C, state->Clen);
	//----------

	state->reseed_counter = 1;
	state->initialized_flag = HD_DRBG_STATE_INITIALIZED_FLAG;
	retcode = 1;

FREE_AND_EXIT:
	if(seed_material_in){
		memset(seed_material_in,0x00,seed_material_len);
		free(seed_material_in);
	}
	if(forC)
	{
		memset(forC,0x00,state->Vlen+1);
		free(forC);
	}
	memset(seed_material,0x00,HD_MAX_SEEDLEN_IN_BYTES);
	return retcode;
}


int HASH_DRBG_Generate(HASH_DRBG_STATE *state,
					  unsigned char* output, int requested_num_of_bits,
					  unsigned char* addtional_input, int addlen	
					  )
{
	unsigned char hashed[64];
	unsigned char reseed_ctr[6];
	int hashlen = 0;
	int request_num_of_bytes;

	int retcode = 0;
	unsigned char* temp = NULL;
	unsigned char* ptr = NULL;
	unsigned char* pre_w = NULL;
	int templen = 0;
	int pre_w_len = 0;

	SHA224_INFO sha224;
	SHA256_INFO sha256;
	SHA384_INFO sha384;
	SHA512_INFO sha512;
	
// 	fprintf(stderr, "\n\n*** ==================== ***\n");
// 	fprintf(stderr, "    Hash_DRBG_Generate");
// 	fprintf(stderr, "\n*** ==================== ***\n");

	if(state->initialized_flag != HD_DRBG_STATE_INITIALIZED_FLAG)
	{
		return 0; // HASH_DRBG_Instantiate(...) required
	}

	if(state->prediction_flag == USE_PREDICTION_RESISTANCE)
	{
		if(state->reseed_flag == HD_DRBG_RESEED_REQUIRED)
		{
			fprintf(stderr, "\nError :: reseed required\n");
			return -1; // RESEED_REQUIRED
		}
	}

	if(requested_num_of_bits <= 0)
	{
		return 0; // No length to generate
	}
	else
	{
		request_num_of_bytes = requested_num_of_bits / 8 + ((requested_num_of_bits % 8) != 0 ? 1 : 0);
	}

	if(state->reseed_counter >= HD_NUM_OF_REQUESTS_BETWEEN_RESEEDS)
	{
		return 0; // Reseed Required.
	}

	if(addtional_input != NULL && addlen > 0)
	{
		pre_w_len = addlen + state->Vlen + 1;
		pre_w = (unsigned char *)malloc(pre_w_len);
		if(pre_w == NULL)
			goto FREE_AND_EXIT;

		pre_w[0] = 0x02;
		memcpy(pre_w+1, state->V, state->Vlen);
		memcpy(pre_w+1+state->Vlen, addtional_input, addlen);

// 		//----------
// 		fprintf(stderr, "\n====================\n");
// 		fprintf(stderr, "0x02 || V || additional");
// 		fprintf(stderr, "\n====================\n");
// 		printoctet(pre_w, pre_w_len);
// 		//----------

		switch(state->algo)
		{
			case DRBG_ALGO_SHA224:
				SHA224_init(&sha224);
				SHA224_update(&sha224, pre_w, pre_w_len);
				SHA224_final(&sha224, hashed);
				hashlen = ALGO_SHA224_OUTLEN_IN_BYTES;
				break;

			case DRBG_ALGO_SHA256:
				SHA256_init(&sha256);
				SHA256_update(&sha256, pre_w, pre_w_len);
				SHA256_final(&sha256, hashed);
				hashlen = ALGO_SHA256_OUTLEN_IN_BYTES;
				break;

			case DRBG_ALGO_SHA384:
				SHA384_init(&sha384);
				SHA384_update(&sha384, pre_w, pre_w_len);
				SHA384_final(&sha384, hashed);
				hashlen = ALGO_SHA384_OUTLEN_IN_BYTES;
				break;

			case DRBG_ALGO_SHA512:
				SHA512_init(&sha512);
				SHA512_update(&sha512, pre_w, pre_w_len);
				SHA512_final(&sha512, hashed);
				hashlen = ALGO_SHA512_OUTLEN_IN_BYTES;
				break;

			default:
				goto FREE_AND_EXIT;
		}

// 		//----------
// 		fprintf(stderr, "\n====================\n");
// 		fprintf(stderr, "w");
// 		fprintf(stderr, "\n====================\n");
// 		printoctet(hashed, hashlen);
// 		//----------

		Addition(state, state->V, state->Vlen, hashed, hashlen);

// 		//----------
// 		fprintf(stderr, "\n====================\n");
// 		fprintf(stderr, "Step 2 new V");
// 		fprintf(stderr, "\n====================\n");
// 		printoctet(state->V, state->Vlen);
// 		//----------
	}

	//printoctet(state->V, state->Vlen);
	
	if(!Hashgen(state, requested_num_of_bits, state->V, state->Vlen, output))
	{
		goto FREE_AND_EXIT;
	}

	//----------
// 	fprintf(stderr, "\n====================\n");
// 	fprintf(stderr, "Output");
// 	fprintf(stderr, "\n====================\n");
// 	printoctet(output, request_num_of_bytes);
	//----------

	templen = state->Vlen+1;
	temp = (unsigned char *)malloc(templen);
	if(temp == NULL)
		goto FREE_AND_EXIT;

	temp[0] = 0x03;
	memcpy(temp+1, state->V, state->Vlen);

	switch(state->algo)
	{
		case DRBG_ALGO_SHA224:
			SHA224_init(&sha224);
			SHA224_update(&sha224, temp, templen);
			SHA224_final(&sha224, hashed);
			hashlen = ALGO_SHA224_OUTLEN_IN_BYTES;
			break;

		case DRBG_ALGO_SHA256:
			SHA256_init(&sha256);
			SHA256_update(&sha256, temp, templen);
			SHA256_final(&sha256, hashed);
			hashlen = ALGO_SHA256_OUTLEN_IN_BYTES;
			break;

		case DRBG_ALGO_SHA384:
			SHA384_init(&sha384);
			SHA384_update(&sha384, temp, templen);
			SHA384_final(&sha384, hashed);
			hashlen = ALGO_SHA384_OUTLEN_IN_BYTES;
			break;

		case DRBG_ALGO_SHA512:
			SHA512_init(&sha512);
			SHA512_update(&sha512, temp, templen);
			SHA512_final(&sha512, hashed);
			hashlen = ALGO_SHA512_OUTLEN_IN_BYTES;
			break;

		default:
			goto FREE_AND_EXIT;
	}

// 	//----------
// 	fprintf(stderr, "\n====================\n");
// 	fprintf(stderr, "H is");
// 	fprintf(stderr, "\n====================\n");
// 	printoctet(hashed, hashlen);
// 	//----------

	Addition(state, state->V, state->Vlen, hashed, hashlen);
	Addition(state, state->V, state->Vlen, state->C, state->Clen);

	reseed_ctr[0] = ((unsigned char *)&(state->reseed_counter))[5];
	reseed_ctr[1] = ((unsigned char *)&(state->reseed_counter))[4];
	reseed_ctr[2] = ((unsigned char *)&(state->reseed_counter))[3];
	reseed_ctr[3] = ((unsigned char *)&(state->reseed_counter))[2];
	reseed_ctr[4] = ((unsigned char *)&(state->reseed_counter))[1];
	reseed_ctr[5] = ((unsigned char *)&(state->reseed_counter))[0];
	
	Addition(state, state->V, state->Vlen, reseed_ctr, 6);

	//----------
// 	fprintf(stderr, "\n====================\n");
// 	fprintf(stderr, "new V");
// 	fprintf(stderr, "\n====================\n");
// 	printoctet(state->V, state->Vlen);
	//----------

	state->reseed_counter += 1;
	retcode = 1;

	if(state->reseed_counter == HD_NUM_OF_REQUESTS_BETWEEN_RESEEDS || state->prediction_flag == USE_PREDICTION_RESISTANCE)
		state->reseed_flag = HD_DRBG_RESEED_REQUIRED;

	//----------
// 	fprintf(stderr, "\n====================\n");
// 	fprintf(stderr, "reseed_counter : %d", state->reseed_counter);
// 	fprintf(stderr, "\n====================\n");
	//----------

FREE_AND_EXIT:
	memset(hashed, 0x00, 64);
	memset(reseed_ctr, 0x00, 6);
	memset(temp,0x00,templen);
	if(temp)
		free(temp);
	memset(pre_w,0x00,pre_w_len);
	if(pre_w)
		free(pre_w);
	return retcode;
}

int HASH_DRBG_Reseed(HASH_DRBG_STATE *state,
					unsigned char* entropy_input, int entropylen,
					unsigned char* additional_input, int addlen
					)
{

	unsigned char	seed_material[HD_MAX_SEEDLEN_IN_BYTES];
	unsigned char*	seed_material_in = NULL;
	unsigned char*	ptr			 = NULL;
	unsigned char*  forC = NULL;
	int				seed_material_len = 0;
	int				retcode = 0;
	
	if(entropy_input == NULL)
	{
		return 0;
	}

	if(state->initialized_flag != HD_DRBG_STATE_INITIALIZED_FLAG)
	{
		return 0; // HASH_DRBG_Instantiate(...) required
	}

// 	fprintf(stderr, "\n\n*** ==================== ***\n");
// 	fprintf(stderr, "    Hash_DRBG_Reseed");
// 	fprintf(stderr, "\n*** ==================== ***\n");

	switch(state->algo)
	{
		//--------------------------------------------------------------
	case DRBG_ALGO_SHA224:

		if(entropylen < ALGO_SHA224_SECURITY_STRENGTH_IN_BYTES )
			return 0;
		break;

		//--------------------------------------------------------------
	case DRBG_ALGO_SHA256:

		if(entropylen < ALGO_SHA256_SECURITY_STRENGTH_IN_BYTES )
			return 0;
		break;

		//--------------------------------------------------------------
	case DRBG_ALGO_SHA384:

		if(entropylen < ALGO_SHA384_SECURITY_STRENGTH_IN_BYTES )
			return 0;
		break;

		//--------------------------------------------------------------
	case DRBG_ALGO_SHA512:

		if(entropylen < ALGO_SHA512_SECURITY_STRENGTH_IN_BYTES )
			return 0;
		break;


	default:
		return 0; // No Such Algorithm
	}

	memset(seed_material,0x00,HD_MAX_SEEDLEN_IN_BYTES);
	seed_material_len = entropylen+1;
	seed_material_len += (state->Vlen);
	if(additional_input != NULL && addlen > 0)
		seed_material_len += (addlen);

	ptr = seed_material_in = (unsigned char*)malloc(seed_material_len);
	if(ptr == NULL)
		goto FREE_AND_EXIT;
	
	ptr[0] = 0x01;
	memcpy(++ptr, state->V, state->Vlen);
	ptr += state->Vlen;
	memcpy(ptr, entropy_input, entropylen);

	if(additional_input != NULL && addlen > 0)
	{
		ptr += entropylen;
		memcpy(ptr, additional_input, addlen);
	}

// 	//----------
// 	fprintf(stderr, "\n====================\n");
// 	fprintf(stderr, "Seed material");
// 	fprintf(stderr, "\n====================\n");
// 	printoctet(seed_material_in, seed_material_len);
// 	//----------

	if(!Hash_df(state->algo, seed_material_in, seed_material_len, seed_material, (state->seedlen * 8)))
	{
		goto FREE_AND_EXIT;
	}

	memset(state->V, 0x00, HD_MAX_SEEDLEN_IN_BYTES);
	memset(state->C, 0x00, HD_MAX_SEEDLEN_IN_BYTES);

	memcpy(state->V, seed_material, state->seedlen);
	//state->Vlen = state->seedlen;

	//----------
// 	fprintf(stderr, "\n====================\n");
// 	fprintf(stderr, "V in Reseed");
// 	fprintf(stderr, "\n====================\n");
// 	printoctet(state->V, state->Vlen);
	//----------

	forC = (unsigned char*)malloc(state->Vlen + 1);
	if(forC == NULL)
		goto FREE_AND_EXIT;

	forC[0] = 0x00;
	memcpy(forC+1, state->V, state->Vlen);

	if(!Hash_df(state->algo, forC, state->Vlen + 1, state->C, (state->seedlen * 8)))
	{
		goto FREE_AND_EXIT;
	}
	//state->Clen = state->seedlen;

	//----------
// 	fprintf(stderr, "\n====================\n");
// 	fprintf(stderr, "C in Reseed");
// 	fprintf(stderr, "\n====================\n");
// 	printoctet(state->C, state->Clen);
	//----------

	state->reseed_counter = 1;
	state->reseed_flag = HD_DRBG_RESEED_PROCESSED;
	retcode = 1;

FREE_AND_EXIT:
	if(seed_material_in){
		memset(seed_material_in,0x00,seed_material_len);
		free(seed_material_in);
	}
	if(forC)
	{
		memset(forC,0x00,state->Vlen+1);
		free(forC);
	}
	memset(seed_material,0x00,HD_MAX_SEEDLEN_IN_BYTES);
	return retcode;
}

int HASH_DRBG_clear(HASH_DRBG_STATE *drbg)
{
	memset(drbg, 0x00, sizeof(HASH_DRBG_STATE));

	return 1;
}

void PrintEntryData_hashdrbg(unsigned char *data, int len)
{
	int i;
	for(i=0;i<len;i++)
	{
		printf("%02X ", data[i]);

		if( (i+1) % 16 == 0)
			printf("\n");
	}
}

int HASH_DRBG_Random_Gen(unsigned char *output, int request_num_of_bits)
{
#define ENT_LEN 128

	HASH_DRBG_STATE drbg;
	unsigned char ent1[ENT_LEN];
	unsigned char ent2[ENT_LEN];
	unsigned char ent3[ENT_LEN];
	unsigned char ent4[ENT_LEN];
	unsigned char ent5[ENT_LEN];
	unsigned char ent6[ENT_LEN];
	unsigned char ent7[ENT_LEN];
	unsigned char ent8[ENT_LEN];
	unsigned char ent9[ENT_LEN];	
	unsigned char algo;

	FILE *fp;
	fp = fopen("/dev/urandom", "r");
	if(fp == NULL)
		return 0;
	fread(ent1, 1, ENT_LEN, fp);
	fread(ent2, 1, ENT_LEN, fp);
	fread(ent3, 1, ENT_LEN, fp);
	fread(ent4, 1, ENT_LEN, fp);
	fread(ent5, 1, ENT_LEN, fp);
	fread(ent6, 1, ENT_LEN, fp);
	fread(ent7, 1, ENT_LEN, fp);
	fread(ent8, 1, ENT_LEN, fp);
	fread(ent9, 1, ENT_LEN, fp);
	fread(&algo, 1, 1, fp);

	algo = (unsigned char)(((int)algo) * 4 / 256);

	fclose(fp);

	switch(algo)
	{
	case 0:
		algo = DRBG_ALGO_SHA224;
		break;

	case 1:
		algo = DRBG_ALGO_SHA256;
		break;

	case 2:
		algo = DRBG_ALGO_SHA384;
		break;

	case 3:
		algo = DRBG_ALGO_SHA512;
		break;
		
	default:
		return 0;
	}

	if(!HASH_DRBG_Instantiate(&drbg, algo, ent1, ENT_LEN, ent2, ENT_LEN, ent3, ENT_LEN, USE_PREDICTION_RESISTANCE))
		return 0;
		
	if(!HASH_DRBG_Reseed(&drbg, ent4, ENT_LEN, ent5, ENT_LEN))
		return 0;

	if(!HASH_DRBG_Generate(&drbg, output, request_num_of_bits, ent6, ENT_LEN))
		return 0;
		
	if(!HASH_DRBG_Reseed(&drbg, ent7, ENT_LEN, ent8, ENT_LEN))
		return 0;

	if(!HASH_DRBG_Generate(&drbg, output, request_num_of_bits, ent9, ENT_LEN))
		return 0;

	HASH_DRBG_clear(&drbg);

	return 1;

}
