#include "givtech_ebdcrypto.h"
#include "EBDCrypto.h"
#include "ca.h"

JNIEXPORT jint JNICALL Java_givtech_ebdcrypto_AES_nativeAESCBC (JNIEnv *env, jobject obj, jint encflag, jbyteArray userkey, jint key_offset, jint keylen, jbyteArray iv, jint iv_offset, jbyteArray input, jint input_offset, jint inlen, jbyteArray output, jint output_offset)
{
	UCHAR *native_userkey = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, userkey, 0);
	UCHAR *native_iv = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, iv, 0);
	UCHAR *native_input = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, input, 0);
	UCHAR *native_output = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, output, 0);

	int resultcode;

	resultcode = AES_CBC(encflag, native_userkey + key_offset, keylen, native_iv + iv_offset, native_input + input_offset, inlen, native_output + output_offset);

	(*env)->ReleasePrimitiveArrayCritical(env, userkey, native_userkey, 0);
	(*env)->ReleasePrimitiveArrayCritical(env, iv, native_iv, 0);
	(*env)->ReleasePrimitiveArrayCritical(env, input, native_input, 0);
	(*env)->ReleasePrimitiveArrayCritical(env, output, native_output, 0);

	return resultcode;
}

JNIEXPORT jint JNICALL Java_givtech_ebdcrypto_SHA2_nativesha224 (JNIEnv *env, jobject obj, jbyteArray input, jint input_offset, jint inlen, jbyteArray digest, jint output_offset)
{
	UCHAR *native_input = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, input, 0);
	UCHAR *native_digest = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, digest, 0);

	int resultcode;
	resultcode = sha224(native_input + input_offset, inlen, native_digest + output_offset);

	(*env)->ReleasePrimitiveArrayCritical(env, input, native_input, 0);
	(*env)->ReleasePrimitiveArrayCritical(env, digest, native_digest, 0);

	return resultcode;
}

JNIEXPORT jint JNICALL Java_givtech_ebdcrypto_SHA2_nativesha256 (JNIEnv *env, jobject obj, jbyteArray input, jint input_offset, jint inlen, jbyteArray digest, jint output_offset)
{
	UCHAR *native_input = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, input, 0);
	UCHAR *native_digest = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, digest, 0);

	int resultcode;
	resultcode = sha256(native_input + input_offset, inlen, native_digest + output_offset);

	(*env)->ReleasePrimitiveArrayCritical(env, input, native_input, 0);
	(*env)->ReleasePrimitiveArrayCritical(env, digest, native_digest, 0);

	return resultcode;
}

JNIEXPORT jint JNICALL Java_givtech_ebdcrypto_SHA2_nativesha384 (JNIEnv *env, jobject obj, jbyteArray input, jint input_offset, jint inlen, jbyteArray digest, jint output_offset)
{
	UCHAR *native_input = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, input, 0);
	UCHAR *native_digest = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, digest, 0);

	int resultcode;
	resultcode = sha384(native_input + input_offset, inlen, native_digest + output_offset);

	(*env)->ReleasePrimitiveArrayCritical(env, input, native_input, 0);
	(*env)->ReleasePrimitiveArrayCritical(env, digest, native_digest, 0);

	return resultcode;
}

JNIEXPORT jint JNICALL Java_givtech_ebdcrypto_SHA2_nativesha512 (JNIEnv *env, jobject obj, jbyteArray input, jint input_offset, jint inlen, jbyteArray digest, jint output_offset)
{
	UCHAR *native_input = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, input, 0);
	UCHAR *native_digest = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, digest, 0);

	int resultcode;
	resultcode = sha512(native_input + input_offset, inlen, native_digest + output_offset);

	(*env)->ReleasePrimitiveArrayCritical(env, input, native_input, 0);
	(*env)->ReleasePrimitiveArrayCritical(env, digest, native_digest, 0);

	return resultcode;
}

JNIEXPORT jint JNICALL Java_givtech_ebdcrypto_DRBG_nativeDRBGRandomGen (JNIEnv *env, jobject obj, jbyteArray output, jint output_offset, jint request_num_of_bits)
{
	UCHAR *native_output = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, output, 0);

	int resultcode;
	resultcode = HASH_DRBG_Random_Gen(native_output + output_offset, request_num_of_bits);

	(*env)->ReleasePrimitiveArrayCritical(env, output, native_output, 0);

	return resultcode;

}

JNIEXPORT jint JNICALL Java_givtech_ebdcrypto_ECDSA_nativeECDSAgenkeypair (JNIEnv *env, jobject obj, jbyteArray qx, jint qx_offset, jintArray qx_len, jbyteArray qy, jint qy_offset, jintArray qy_len, jbyteArray d, jint d_offset, jintArray d_len)
{
	UCHAR *native_qx = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, qx, 0);
	UINT *native_qx_len = (UINT *)(*env)->GetPrimitiveArrayCritical(env, qx_len, 0);
	UCHAR *native_qy = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, qy, 0);
	UINT *native_qy_len = (UINT *)(*env)->GetPrimitiveArrayCritical(env, qy_len, 0);
	UCHAR *native_d = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, d, 0);
	UINT *native_d_len = (UINT *)(*env)->GetPrimitiveArrayCritical(env, d_len, 0);

	ECDSA_INFO ecdsa;
	ULONG qxlen, qylen, dlen;

	int resultcode;

	ECDSA_init(&ecdsa, SHA256);
	resultcode = ECDSA_gen_key_pair(&ecdsa, native_qx + qx_offset, &qxlen, native_qy + qy_offset, &qylen, native_d + d_offset, &dlen);

	if(resultcode == 1)
	{
		native_qx_len[0] = qxlen;
		native_qy_len[0] = qylen;
		native_d_len[0] = dlen;
	}

	(*env)->ReleasePrimitiveArrayCritical(env, qx, native_qx, 0);
	(*env)->ReleasePrimitiveArrayCritical(env, qx_len, native_qx_len, 0);
	(*env)->ReleasePrimitiveArrayCritical(env, qy, native_qy, 0);
	(*env)->ReleasePrimitiveArrayCritical(env, qy_len, native_qy_len, 0);
	(*env)->ReleasePrimitiveArrayCritical(env, d, native_d, 0);
	(*env)->ReleasePrimitiveArrayCritical(env, d_len, native_d_len, 0);

	return resultcode;
}

JNIEXPORT jint JNICALL Java_givtech_ebdcrypto_ECDSA_nativeECDSAgeneratesignature (JNIEnv *env, jobject obj, jint hash_alg, jbyteArray d, jint d_offset, jint d_len, jbyteArray msg, jint msg_offset, jint msg_len, jbyteArray r, jint r_offset, jintArray r_len, jbyteArray s, jint s_offset, jintArray s_len)
{
	UCHAR *native_d = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, d, 0);
	UCHAR *native_msg = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, msg, 0);
	UCHAR *native_r = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, r, 0);
	UINT *native_r_len = (UINT *)(*env)->GetPrimitiveArrayCritical(env, r_len, 0);
	UCHAR *native_s = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, s, 0);
	UINT *native_s_len = (UINT *)(*env)->GetPrimitiveArrayCritical(env, s_len, 0);
	
	int resultcode;
	ULONG rlen, slen;

	while(1)
	{
		resultcode = ECDSA_generate_signature(hash_alg, native_d + d_offset, d_len, native_msg + msg_offset, msg_len, native_r + r_offset, &rlen, native_s + s_offset, &slen);
		if( (resultcode == 1) && (rlen == 32) && (slen == 32) )
		{
			native_r_len[0] = rlen;
			native_s_len[0] = slen;

			break;
		}
	}

	(*env)->ReleasePrimitiveArrayCritical(env, d, native_d, 0);
	(*env)->ReleasePrimitiveArrayCritical(env, msg, native_msg, 0);
	(*env)->ReleasePrimitiveArrayCritical(env, r, native_r, 0);
	(*env)->ReleasePrimitiveArrayCritical(env, r_len, native_r_len, 0);
	(*env)->ReleasePrimitiveArrayCritical(env, s, native_s, 0);
	(*env)->ReleasePrimitiveArrayCritical(env, s_len, native_s_len, 0);

	return resultcode;
}

JNIEXPORT jint JNICALL Java_givtech_ebdcrypto_ECDSA_nativeECDSAverifysignature (JNIEnv *env, jobject obj, jint hash_alg, jbyteArray qx, jint qx_offset, jint qx_len, jbyteArray qy, jint qy_offset, jint qy_len, jbyteArray msg, jint msg_offset, jint msg_len, jbyteArray r, jint r_offset, jint r_len, jbyteArray s, jint s_offset, jint s_len)
{
	UCHAR *native_qx = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, qx, 0);
	UCHAR *native_qy = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, qy, 0);
	UCHAR *native_msg = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, msg, 0);
	UCHAR *native_r = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, r, 0);
	UCHAR *native_s = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, s, 0);

	int resultcode;
	resultcode = ECDSA_verify_signature(hash_alg, native_qx + qx_offset, qx_len, native_qy + qy_offset, qy_len, native_msg + msg_offset, msg_len, native_r + r_offset, r_len, native_s + s_offset, s_len);

	(*env)->ReleasePrimitiveArrayCritical(env, qx, native_qx, 0);
	(*env)->ReleasePrimitiveArrayCritical(env, qy, native_qy, 0);
	(*env)->ReleasePrimitiveArrayCritical(env, msg, native_msg, 0);
	(*env)->ReleasePrimitiveArrayCritical(env, r, native_r, 0);
	(*env)->ReleasePrimitiveArrayCritical(env, s, native_s, 0);

	return resultcode;
}

JNIEXPORT jbyteArray JNICALL Java_givtech_ebdcrypto_GenerateCertCSR_nativeGenPubCSR (JNIEnv *env, jobject obj,
                                                                              jbyteArray username, jint username_offset, jint username_len,
                                                                              jbyteArray socialnum, jint socialnum_offset, jint socialnum_len,
                                                                              jbyteArray phonenum, jint phonenum_offset, jint phonenum_len,
                                                                              jbyteArray UsimID, jint UsimID_offset, jint UsimID_len,
                                                                              jbyteArray UserID, jint UserID_offset, jint UserID_len,
                                                                              jbyteArray Algorithm, jint Algorithm_offset, jint Algorithm_len,
                                                                              jbyteArray Pubkey_Qx, jint Pubkey_Qx_offset, jint Pubkey_Qx_len,
                                                                              jbyteArray Pubkey_Qy, jint Pubkey_Qy_offset, jint Pubkey_Qy_len)
{

    jbyteArray input;
    jbyteArray output;

    UCHAR *native_input = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, input, 0);
    UCHAR *native_output = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, output, 0);

    UCHAR *native_username = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, username, 0);
    UCHAR *native_socialnum = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, socialnum, 0);
    UCHAR *native_phonenum = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, phonenum, 0);
    UCHAR *native_UsimID = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, UsimID, 0);
    UCHAR *native_UserID = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, UserID, 0);
    UCHAR *native_Algorithm = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, Algorithm, 0);
    UCHAR *native_Pubkey_Qx = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, Pubkey_Qx, 0);
    UCHAR *native_Pubkey_Qy = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, Pubkey_Qy, 0);

    CERT_INFO cert;
    USER_INFO user;
    UCHAR * conf_location;
    SINT out_len;

    int resultcode;
    jbyteArray null = {'\0', };

    resultcode = Cert_init(&cert, conf_location);

    if(resultcode != 1) {
        return null;
    }

    user.len_userName = username_len;
    memcpy(user.userName, native_username + username_offset, (size_t) username_len);
    user.len_registrationNum = socialnum_len;
    memcpy(user.registrationNum, native_socialnum + socialnum_offset, (size_t) socialnum_len);
    user.len_phoneNum = phonenum_len;
    memcpy(user.phoneNum, native_phonenum + phonenum_offset, (size_t) phonenum_len);
    user.len_USIMID = UsimID_len;
    memcpy(user.USIMID, native_UsimID + UsimID_offset, (size_t) UsimID_len);
    user.len_userID = UserID_len;
    memcpy(user.userID, native_UserID + UserID_offset, (size_t) UserID_len);
    user.len_usedAlgorithm = Algorithm_len;
    memcpy(user.usedAlgorithm, native_Algorithm + Algorithm_offset, (size_t) Algorithm_len);
    user.len_pubKey_x = Pubkey_Qx_len;
    memcpy(user.pubKey_x, native_Pubkey_Qx + Pubkey_Qx_offset, (size_t) Pubkey_Qx_len);
    user.len_pubKey_y = Pubkey_Qy_len;
    memcpy(user.pubKey_y, native_Pubkey_Qy + Pubkey_Qy_offset, (size_t) Pubkey_Qy_len);

	out_len = strlen(native_output);

    resultcode = generate_PUB_CSR(&cert, &user, native_input, native_output, out_len, 0, 0);

    if(resultcode != 1) {
        return null;
    }

    (*env)->ReleasePrimitiveArrayCritical(env, input, native_input, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, output, native_output, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, username, native_username, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, socialnum, native_socialnum, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, phonenum, native_phonenum, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, UsimID, native_UsimID, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, UserID, native_UserID, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, Algorithm, native_Algorithm, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, Pubkey_Qx, native_Pubkey_Qx, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, Pubkey_Qy, native_Pubkey_Qy, 0);

    return output;

}