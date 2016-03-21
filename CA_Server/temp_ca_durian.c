#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h> 
#include <io.h>

#include "temp_ca_durian.h"
#include "EBDCrypto.h"

SINT Cert_init(CERT_INFO * cert, UCHAR * conf_location)
{
	//CERT_INFO * cert_data = (CERT_INFO *)malloc(sizeof(CERT_INFO));
	FILE * fp;
	SINT i;
    UCHAR len, code;
    UCHAR * data;
    
	//에러
	if (conf_location == NULL)
		return ERR_NO_FILE;

	//0으로 초기화
	memset(cert, 0, sizeof(cert));

	//파일열기
	fp = fopen((SCHAR *)conf_location, "rb");
    if (fp == NULL)
		return ERR_OPEN_FILE;
    
	//인증서 값 읽어와서 구조체에 저장
	while ((code = fgetc(fp)) != EOF) 
	{
		len = fgetc(fp);
		data = (UCHAR *)malloc(sizeof(UCHAR)*len);
        for(i=0; i<len; i++)
			data[i] = fgetc(fp);
        switch (code) {
            case CERT_VER :
				cert->len_Ver = len;
				cert->Ver = data[0];
				break;
            case CERT_SERIAL_NUMBER :
				cert->len_Cert_SN = len;
				memcpy(cert->Cert_SN, data, len);
                break;
			case CERT_ISSUER :
				cert->len_issuer = len;
				memcpy(cert->issuer, data, len);
				break;
            case CERT_VALID_FROM :
				cert->len_issueDate = len;
				memcpy(cert->issueDate, data, len);
				break;
            case CERT_VALID_TO :
				cert->len_expirationDate = len;
				memcpy(cert->expirationDate, data, len);
				break;
			case CERT_USER_NAME :
				cert->len_userName = len;
				memcpy(cert->userName, data, len);
				break;
			case CERT_REGISTRATION_NUMBER :
				cert->len_registrationNum = len;
				memcpy(cert->registrationNum, data, len);
				break;
			case CERT_PHONE_NUMBER :
				cert->len_phoneNum = len;
				memcpy(cert->phoneNum, data, len);
				break;
            case CERT_USIM_ID :
				cert->len_USIMID = len;
				memcpy(cert->USIMID, data, len);
				break;
            case CERT_USER_ID :
				cert->len_userID = len;
                memcpy(cert->userID, data, len);
				break;
            case CERT_USED_ALGORITHM :
				cert->len_usedAlgorithm = len;
				memcpy(cert->usedAlgorithm, data, len);
				break;
            case CERT_CA_PUBKEY :
				cert->len_pubKey = len;
				cert->len_pubKey_x = data[1];
				memcpy(cert->pubKey_x, data + 2, data[1]);
				cert->len_pubKey_y = data[35];
				memcpy(cert->pubKey_y, data + 36, data[35]);
                break;
            case CERT_SIGNATURE :
				cert->len_signature = len;
                memcpy(cert->signature, data, len);
                break;
            default :
                return ERR_CERT_TAG;
        }
		free(data);
    }
    fclose(fp);
    
    return 1;
}


SINT generate_PUB(CERT_INFO * cert, UCHAR * target)
{
	FILE * fp;

	fp = fopen((SCHAR *)target, "rb");
    if (fp == NULL)
		return ERR_OPEN_FILE;


	fclose(fp);
	return 1;
}


SINT generate_PUB_CSR(CERT_INFO * cert, USER_INFO * user, UCHAR * in, UCHAR * out, SINT out_len, SINT check_in, SINT check_out)
{
	FILE * fp1, * fp2;
	UCHAR * data;
	UCHAR len, code;
	SINT i;
	UCHAR temp_out[BUFSIZE * 6 + 64];
	SINT offset;

	//NULL로 초기화
	memset(out, 0, sizeof(out));
	memset(temp_out, 0, sizeof(temp_out));
	memset((UCHAR *)&out_len, 0, sizeof(out_len));
	//memset(cert, 0, sizeof(cert));


	// user구조체에 값이 없으면 에러(공개키값 빼고) ?다넣어줘야하는지...
	if (user->len_phoneNum == NULL || user->len_registrationNum == NULL || user->len_usedAlgorithm == NULL || user->len_userID == NULL || user->len_userName == NULL || user->len_USIMID == NULL)
		return ERR_INVALID_INPUT;

	// 공개키 값이 없는데 in 값도 없으면 에러 
	if ((user->len_pubKey_x == NULL || user->len_pubKey_y == NULL) && in == NULL)
		return ERR_INVALID_INPUT;
	
	// in 값이 있는데 check 값이 맞지 않으면 에러
	if (in != NULL && (check_in != 0 && check_in != 1))
		return ERR_INVALID_INPUT;

	// out 값이 없거나 check 값이 맞지 않으면 에러
	if (out == NULL || (check_out != 0 && check_out != 1))
		return ERR_INVALID_INPUT;

	// 공개키 값이 없을 경우
	if (user->len_pubKey_x == NULL || user->len_pubKey_y == NULL)
	{
		// in이 파일일 경우
		if (check_in == 1)
		{
			fp1 = fopen((SCHAR *)in, "rb");
			if (fp1 == NULL)
				return ERR_OPEN_FILE;

			while ((code = fgetc(fp1)) != EOF) 
			{
				len = fgetc(fp1);
				data = (UCHAR *)malloc(sizeof(UCHAR)*len);
				for(i=0; i<len; i++)
					data[i] = fgetc(fp1);
				switch (code) {
					case CERT_USER_NAME :
						user->len_userName = len;
						memcpy(user->userName, data, len);
						break;
					case CERT_REGISTRATION_NUMBER :
						user->len_registrationNum = len;
						memcpy(user->registrationNum, data, len);
						break;
					case CERT_PHONE_NUMBER :
						user->len_phoneNum = len;
						memcpy(user->phoneNum, data, len);
						break;
					case CERT_USIM_ID :
						user->len_USIMID = len;
						memcpy(user->USIMID, data, len);
						break;
					case CERT_USER_ID :
						user->len_userID = len;
						memcpy(user->userID, data, len);
						break;
					case CERT_USED_ALGORITHM :
						user->len_usedAlgorithm = len;
						memcpy(user->usedAlgorithm, data, len);
						break;
					case CERT_CA_PUBKEY :
						user->len_pubKey_x = data[1];
						memcpy(user->pubKey_x, data + 2, data[1]);

						user->len_pubKey_y = data[35];
						memcpy(user->pubKey_y, data + 36, data[35]);
						break;
					default :
						return ERR_CERT_TAG;
				}
				free(data);
			}
			fclose(fp1);
		}
		// in이 버퍼일 경우
		else
		{
			offset = 0;
			while((code = in[offset]) != EOF)
			{
				offset += 1;
				len = in[offset];
				offset += 1;
				switch (code) {
					case CERT_USER_NAME :
						user->len_userName = len;
						memcpy(user->userName, in + offset, len);
						offset += len;
						break;
					case CERT_REGISTRATION_NUMBER :
						user->len_registrationNum = len;
						memcpy(user->registrationNum, in + offset, len);
						offset += len;
						break;
					case CERT_PHONE_NUMBER :
						user->len_phoneNum = len;
						memcpy(user->phoneNum, in + offset, len);
						offset += len;
						break;
					case CERT_USIM_ID :
						user->len_USIMID = len;
						memcpy(user->USIMID, in + offset, len);
						offset += len;
						break;
					case CERT_USER_ID :
						user->len_userID = len;
						memcpy(user->userID, in + offset, len);
						offset += len;
						break;
					case CERT_USED_ALGORITHM :
						user->len_usedAlgorithm = len;
						memcpy(user->usedAlgorithm, in + offset, len);
						offset += len;
						break;
					case CERT_CA_PUBKEY :
						offset += 1;		//x_tag 건너 뛰기
						user->len_pubKey_x = in[offset];
						offset += 1;
						memcpy(user->pubKey_x, in + offset, user->len_pubKey_x);
						offset += user->len_pubKey_x;
						user->len_pubKey_y = in[offset];
						offset += 1;
						memcpy(user->pubKey_y, in + offset, user->len_pubKey_y);
						offset += user->len_pubKey_y;
						break;
					default :
						return ERR_CERT_TAG;
				}
			}
		}
	}


	// user구조체에 있는 값을 tlv형태로 변경해서 temp_out에 저장
	offset = 0;
	temp_out[offset] = CERT_USER_NAME;
	offset += 1;
	temp_out[offset] = user->len_userName;
	offset += 1;
	memcpy(temp_out + offset, user->userName,  user->len_userName);
	offset += user->len_userName;

	temp_out[offset] = CERT_REGISTRATION_NUMBER;
	offset += 1;
	temp_out[offset] = user->len_registrationNum;
	offset += 1;
	memcpy(temp_out + offset, user->registrationNum, user->len_registrationNum);
	offset += user->len_registrationNum;

	temp_out[offset] = CERT_PHONE_NUMBER;
	offset += 1;
	temp_out[offset] = user->len_phoneNum;
	offset += 1;
	memcpy(temp_out + offset, user->phoneNum, user->len_phoneNum);
	offset += user->len_phoneNum;

	temp_out[offset] = CERT_USIM_ID;
	offset += 1;
	temp_out[offset] = user->len_USIMID;
	offset += 1;
	memcpy(temp_out + offset, user->USIMID, user->len_USIMID);
	offset += user->len_USIMID;

	temp_out[offset] = CERT_USER_ID;
	offset += 1;
	temp_out[offset] = user->len_userID;
	offset += 1;
	memcpy(temp_out + offset, user->userID, user->len_userID);
	offset += user->len_userID;

	temp_out[offset] = CERT_USED_ALGORITHM;
	offset += 1;
	temp_out[offset] = user->len_usedAlgorithm;
	offset += 1;
	memcpy(temp_out + offset, user->usedAlgorithm, user->len_usedAlgorithm);
	offset += user->len_usedAlgorithm;

	temp_out[offset] = CERT_CA_PUBKEY;
	offset += 1;
	temp_out[offset] = 0x44;
	offset += 1;

	temp_out[offset] = CERT_CA_PUBKEY_X;
	offset += 1;
	temp_out[offset] = user->len_pubKey_x;
	offset += 1;
	memcpy(temp_out + offset, user->pubKey_x, user->len_pubKey_x);
	offset += user->len_pubKey_x;

	temp_out[offset] = CERT_CA_PUBKEY_Y;
	offset += 1;
	temp_out[offset] = user->len_pubKey_y;
	offset += 1;
	memcpy(temp_out + offset, user->pubKey_y, user->len_pubKey_y);
	offset += user->len_pubKey_y;


	//temp_out의 값을 out에 출력
		//파일일 경우
	if (check_out == 1)
	{
		fp2 = fopen((SCHAR *)out, "wb");
		if (fp2 == NULL)
			return ERR_OPEN_FILE;
		fwrite(temp_out, strlen((SCHAR *)temp_out), 1, fp2);
		out_len = NULL;
		fclose(fp2);
	}
		//버퍼일 경우
	else
	{
		memcpy(out, temp_out, strlen((SCHAR *)temp_out));
		out_len = strlen((SCHAR *)temp_out);
	}

	return 1;
}


SINT generate_signed_PUB(CERT_INFO * cert, UCHAR * in, UCHAR * out, UCHAR * salt, UINT salt_len, UINT iteration, SINT check_in, SINT check_out, SINT hash_alg, const UCHAR *d, ULONG d_len)
{
	FILE * fp;
	SINT offset;
	UCHAR code, len;
	UCHAR temp_out[BUFSIZE * 12];
	UCHAR r[32];
	ULONG * r_len;
	UCHAR s[32];
	ULONG * s_len;
	UINT ran;


	//0으로 초기화
	memset(temp_out, 0, sizeof(temp_out));
	memset(salt, 0, sizeof(salt));
	memset(r, 0, sizeof(r));
	memset(s, 0, sizeof(s));


	// cert의 ver, issuer, issuedate, expiredate는 적어도 잘 들어왔다는 가정, 나머지 값들이 안들어와있으면 in(CSR 데이터 저장된 곳)에서 받아오면 됨
	if (cert->len_Ver == NULL || cert->len_issuer == NULL || cert->len_issueDate == NULL || cert->len_expirationDate == NULL)
		return ERR_INVALID_INPUT;

	// input 값이 없으면 에러 
	if (cert == NULL || salt == NULL || iteration == NULL || salt_len == NULL)
		return ERR_INVALID_INPUT;
	
	// 구조체에 값이 없는데 in값도 없으면 에러
	if ((cert->len_userName == NULL || cert->len_registrationNum == NULL || cert->len_phoneNum == NULL || cert->len_USIMID == NULL || cert->len_userID == NULL || cert->len_usedAlgorithm == NULL || cert->len_pubKey_x == NULL || cert->len_pubKey_y == NULL) && in == NULL)
		return ERR_INVALID_INPUT;

	// in 값이 있는데 check 값이 맞지 않으면 에러
	if (in != NULL && (check_in != 0 && check_in != 1))
		return ERR_INVALID_INPUT;

	// out값이 없거나 check 값이 맞지 않으면 에러
	if (out == NULL && (check_out != 0 && check_out != 1))
		return ERR_INVALID_INPUT;
		

	// 구조체에 정보 없는 경우(특히 CSR정보가 없는 경우)
	if (cert->len_userName == NULL || cert->len_registrationNum == NULL || cert->len_phoneNum == NULL || cert->len_USIMID == NULL || cert->len_userID == NULL || cert->len_usedAlgorithm == NULL || cert->len_pubKey_x == NULL || cert->len_pubKey_y == NULL)
	{
		// 파일일 경우
		if (check_in == 1)
			Cert_init(cert, in);
		// 버퍼일 경우
		else
		{
			offset = 0;
			while((code = in[offset]) != EOF)
			{
				offset += 1;
				len = in[offset];
				offset += 1;
				switch (code) {
					case CERT_USER_NAME :
						cert->len_userName = len;
						memcpy(cert->userName, in + offset, len);
						offset += len;
					break;
					case CERT_REGISTRATION_NUMBER :
						cert->len_registrationNum = len;
						memcpy(cert->registrationNum, in + offset, len);
						offset += len;
						break;
					case CERT_PHONE_NUMBER :
						cert->len_phoneNum = len;
						memcpy(cert->phoneNum, in + offset, len);
						offset += len;
						break;
					case CERT_USIM_ID :
						cert->len_USIMID = len;
						memcpy(cert->USIMID, in + offset, len);
						offset += len;
						break;
					case CERT_USER_ID :
						cert->len_userID = len;
						memcpy(cert->userID, in + offset, len);
						offset += len;
						break;
					case CERT_USED_ALGORITHM :
						cert->len_usedAlgorithm = len;
						memcpy(cert->usedAlgorithm, in + offset, len);
						offset += len;
						break;
					case CERT_CA_PUBKEY :
						cert->len_pubKey = len;
						offset += 1;		//x_tag 건너 뛰기
						cert->len_pubKey_x = in[offset];
						offset += 1;
						memcpy(cert->pubKey_x, in + offset, cert->len_pubKey_x);
						offset += cert->len_pubKey_x;
						cert->len_pubKey_y = in[offset];
						offset += 1;
						memcpy(cert->pubKey_y, in + offset, cert->len_pubKey_y);
						offset += cert->len_pubKey_y;
						break;
					default :
						return ERR_CERT_TAG;
				}
			}
		}
	}
	

	/*
		DB(CERT_INFO * cert);   Cert_SN받아서 되돌려줌	
	*/
	


	///////////////////////////////////////// 서명값 제외하고 cert구조체에 모든 정보 다 들어감
	



	// 구조체 -> tlv
	part_cert2tlv(cert, temp_out, offset);

	/*
	offset = 0;
	temp_out[offset] = CERT_VER;
	offset += 1;
	temp_out[offset] = cert->len_Ver;
	offset += 1;
	memcpy(temp_out + offset, (UCHAR *)&cert->Ver,  cert->len_Ver);
	offset += cert->len_Ver;

	temp_out[offset] = CERT_SERIAL_NUMBER;
	offset += 1;
	temp_out[offset] = cert->len_Cert_SN;
	offset += 1;
	memcpy(temp_out + offset, cert->Cert_SN,  cert->len_Cert_SN);
	offset += cert->len_Cert_SN;

	temp_out[offset] = CERT_ISSUER;
	offset += 1;
	temp_out[offset] = cert->len_issuer;
	offset += 1;
	memcpy(temp_out + offset, cert->issuer,  cert->len_issuer);
	offset += cert->len_issuer;

	temp_out[offset] = CERT_VALID_FROM;
	offset += 1;
	temp_out[offset] = cert->len_issueDate;
	offset += 1;
	memcpy(temp_out + offset, cert->issueDate,  cert->len_issueDate);
	offset += cert->len_issueDate;

	temp_out[offset] = CERT_VALID_TO;
	offset += 1;
	temp_out[offset] = cert->len_expirationDate;
	offset += 1;
	memcpy(temp_out + offset, cert->expirationDate,  cert->len_expirationDate);
	offset += cert->len_expirationDate;

	temp_out[offset] = CERT_USER_NAME;
	offset += 1;
	temp_out[offset] = cert->len_userName;
	offset += 1;
	memcpy(temp_out + offset, cert->userName,  cert->len_userName);
	offset += cert->len_userName;

	temp_out[offset] = CERT_REGISTRATION_NUMBER;
	offset += 1;
	temp_out[offset] = cert->len_registrationNum;
	offset += 1;
	memcpy(temp_out + offset, cert->registrationNum, cert->len_registrationNum);
	offset += cert->len_registrationNum;

	temp_out[offset] = CERT_PHONE_NUMBER;
	offset += 1;
	temp_out[offset] = cert->len_phoneNum;
	offset += 1;
	memcpy(temp_out + offset, cert->phoneNum, cert->len_phoneNum);
	offset += cert->len_phoneNum;

	temp_out[offset] = CERT_USIM_ID;
	offset += 1;
	temp_out[offset] = cert->len_USIMID;
	offset += 1;
	memcpy(temp_out + offset, cert->USIMID, cert->len_USIMID);
	offset += cert->len_USIMID;

	temp_out[offset] = CERT_USER_ID;
	offset += 1;
	temp_out[offset] = cert->len_userID;
	offset += 1;
	memcpy(temp_out + offset, cert->userID, cert->len_userID);
	offset += cert->len_userID;

	temp_out[offset] = CERT_USED_ALGORITHM;
	offset += 1;
	temp_out[offset] = cert->len_usedAlgorithm;
	offset += 1;
	memcpy(temp_out + offset, cert->usedAlgorithm, cert->len_usedAlgorithm);
	offset += cert->len_usedAlgorithm;

	temp_out[offset] = CERT_CA_PUBKEY;
	offset += 1;
	temp_out[offset] = 0x44;
	offset += 1;

	temp_out[offset] = CERT_CA_PUBKEY_X;
	offset += 1;
	temp_out[offset] = cert->len_pubKey_x;
	offset += 1;
	memcpy(temp_out + offset, cert->pubKey_x, cert->len_pubKey_x);
	offset += cert->len_pubKey_x;

	temp_out[offset] = CERT_CA_PUBKEY_Y;
	offset += 1;
	temp_out[offset] = cert->len_pubKey_y;
	offset += 1;
	memcpy(temp_out + offset, cert->pubKey_y, cert->len_pubKey_y);
	offset += cert->len_pubKey_y;
	*/

	// 서명값 생성
	ECDSA_generate_signature(hash_alg, d, d_len, temp_out, strlen((SCHAR *)temp_out), r, r_len, s, s_len);
	cert->len_signature = *r_len + *s_len;
	memcpy(cert->signature, r, *r_len);
	memcpy(cert->signature + *r_len, s, *s_len);

	temp_out[offset] = CERT_SIGNATURE;
	offset += 1;
	temp_out[offset] = cert->len_signature;
	offset += 1;
	memcpy(temp_out + offset, cert->signature, cert->len_signature);

	////////////temp_out에 모든 정보 저장 (완전한 형태의 인증서 데이터)


	// out에 인증서 값 출력하기 
	// 파일일 경우
	if (check_out == 1)
	{
		fp = fopen((SCHAR *)out, "wb");
		if (fp == NULL)
			return ERR_OPEN_FILE;
		fwrite(temp_out, strlen((SCHAR *)temp_out), 1, fp);
		fclose(fp);
	}
	//버퍼일 경우
	else
		memcpy(out, temp_out, strlen((SCHAR *)temp_out));

	// salt값 생성
	srand(time(NULL));
	ran = rand()%5 + 12;
	HASH_DRBG_Random_Gen(salt, ran * 8);
	salt_len = ran;


	// iteration 값 생성
	do 
	{
		HASH_DRBG_Random_Gen((UCHAR *)&iteration, 16);
	} while((2048 > iteration) || (30000 < iteration));


	return 1;
}


SINT revoke_PUB(CERT_INFO * cert, SINT cert_SN, SINT hash_alg, const UCHAR *d, ULONG d_len)
{
	time_t ltime;
    struct tm *today;
	SCHAR currentTime[14];
	UCHAR temp_cTime_year[4];
	UCHAR temp_cTime[2];
	UCHAR temp_expTime_year[4];
	UCHAR temp_expTime[2];
	UCHAR temp_data[BUFSIZE * 12];
	UCHAR temp_temp_data[BUFSIZE * 12];
	SINT i, offset, check_file_exist;
	UCHAR r[32];
	ULONG * r_len;
	UCHAR s[32];
	ULONG * s_len;
	FILE * fp;


	// NULL로 초기화
	memset(cert, 0, BUFSIZE*11 + 80);
	memset(temp_data, 0, sizeof(temp_data));
	memset(temp_temp_data, 0, sizeof(temp_data));

	if (cert_SN == NULL || hash_alg == NULL || d == NULL || d_len == NULL)
		return ERR_INVALID_INPUT;


	/*
		DB검색하여 유효한 cert_sn인지 확인 -> 유효하지 않다면 에러 코드 리턴, 만약 이미 폐기되었다면 값 리턴

		유효한 경우 & 폐기되지 않았다면 DB에서 가져와서 cert구조체에 저장
	*/



	//현재시간 정보
	time(&ltime);
	today = localtime(&ltime);
	sprintf(currentTime, "%04d%02d%02d%02d%02d%02d", today->tm_year + 1900, today->tm_mon + 1, today->tm_mday, today->tm_hour, today->tm_min, today->tm_sec);



	// 시간값 검증
	if (strncmp((SCHAR *)cert->expirationDate, currentTime, 4) == -1)
		part_cert2tlv(cert, temp_data, offset);		// 폐기
	else if (strncmp((SCHAR *)cert->expirationDate, currentTime, 4) == 1)
	{	
		// 서명값 검증
		part_cert2tlv(cert, temp_temp_data, offset);
		if (ECDSA_verify_signature(hash_alg, cert->pubKey_x, cert->len_pubKey_x, cert->pubKey_y, cert->len_pubKey_y, temp_data, strlen((SCHAR *)temp_data), cert->signature, 32, cert->signature + 32, 32) != ERR_VERIFY_FAILURE)
			return VALID_CERT;		// 날짜도 ok, 서명값도 ok이니까 유효한 인증서
		else if (ECDSA_verify_signature(hash_alg, cert->pubKey_x, cert->len_pubKey_x, cert->pubKey_y, cert->len_pubKey_y, temp_data, strlen((SCHAR *)temp_data), cert->signature, 32, cert->signature + 32, 32) != ERR_VERIFY_FAILURE)
			part_cert2tlv(cert, temp_data, offset);		// 날짜는 ok이지만 서명값이 유효하지않으므로 폐기
	}
	else
	{
		for (i = 0; i < 5; i++)
		{
			if (strncmp((SCHAR *)cert->expirationDate +4 +2*i, currentTime +4 +2*i, 2) == -1)
			{
				part_cert2tlv(cert, temp_data, offset);		//폐기
				break;
			}
			else if (strncmp((SCHAR *)cert->expirationDate +4 +2*i, currentTime +4 +2*i, 4) == 1)
			{	
				// 서명값 검증
				if (ECDSA_verify_signature(hash_alg, cert->pubKey_x, cert->len_pubKey_x, cert->pubKey_y, cert->len_pubKey_y, temp_data, strlen((SCHAR *)temp_data), cert->signature, 32, cert->signature + 32, 32) != ERR_VERIFY_FAILURE)
					return VALID_CERT;		// 날짜도 ok, 서명값도 ok이니까 유효한 인증서
				else if (ECDSA_verify_signature(hash_alg, cert->pubKey_x, cert->len_pubKey_x, cert->pubKey_y, cert->len_pubKey_y, temp_data, strlen((SCHAR *)temp_data), cert->signature, 32, cert->signature + 32, 32) != ERR_VERIFY_FAILURE)
				{	
					part_cert2tlv(cert, temp_data, offset);		// 날짜는 ok이지만 서명값이 유효하지않으므로 폐기
					break;
				}
			}
			else
				continue;
		}
	}
	///////////////////////여기까지 폐기될 인증서를 temp_data에 tlv형태로 서명값 빼고 저장함

	// temp_data에 대한 서명 값 생성
	ECDSA_generate_signature(hash_alg, d, d_len, temp_data, strlen((SCHAR *)temp_data), r, r_len, s, s_len);

	// DB에 서명값 덮어쓰기
	memset(cert->signature, 0, sizeof(cert->signature));

	cert->len_signature = *r_len + *s_len;
	memcpy(cert->signature, r, *r_len);
	memcpy(cert->signature + *r_len, s, *s_len);

	temp_data[offset] = CERT_SIGNATURE;
	offset += 1;
	temp_data[offset] = cert->len_signature;
	offset += 1;
	memcpy(temp_data + offset, cert->signature, cert->len_signature);


	/*
		폐기되었다는 정보 DB에 저장
	*/


	// 인증서 파일있는지 검사 후 있으면 지우고 덮어쓰기
	check_file_exist = access("certification.data", 0);
	if (check_file_exist == 0)
	{
		fp = fopen("certification.data", "w+b");
		if (fp == NULL)
			return ERR_OPEN_FILE;
		fwrite(temp_data, strlen((SCHAR *)temp_data), 1, fp);
		fclose(fp);
	}

	return EXPIRE_CERT;
}

SINT part_cert2tlv(CERT_INFO * cert, UCHAR * temp_out, SINT offset)
{
	if (cert == NULL || temp_out == NULL || offset == NULL)
		return ERR_INVALID_INPUT;

	offset = 0;
	temp_out[offset] = CERT_VER;
	offset += 1;
	temp_out[offset] = cert->len_Ver;
	offset += 1;
	memcpy(temp_out + offset, (UCHAR *)&cert->Ver,  cert->len_Ver);
	offset += cert->len_Ver;

	temp_out[offset] = CERT_SERIAL_NUMBER;
	offset += 1;
	temp_out[offset] = cert->len_Cert_SN;
	offset += 1;
	memcpy(temp_out + offset, cert->Cert_SN,  cert->len_Cert_SN);
	offset += cert->len_Cert_SN;

	temp_out[offset] = CERT_ISSUER;
	offset += 1;
	temp_out[offset] = cert->len_issuer;
	offset += 1;
	memcpy(temp_out + offset, cert->issuer,  cert->len_issuer);
	offset += cert->len_issuer;

	temp_out[offset] = CERT_VALID_FROM;
	offset += 1;
	temp_out[offset] = cert->len_issueDate;
	offset += 1;
	memcpy(temp_out + offset, cert->issueDate,  cert->len_issueDate);
	offset += cert->len_issueDate;

	temp_out[offset] = CERT_VALID_TO;
	offset += 1;
	temp_out[offset] = cert->len_expirationDate;
	offset += 1;
	memcpy(temp_out + offset, cert->expirationDate,  cert->len_expirationDate);
	offset += cert->len_expirationDate;

	temp_out[offset] = CERT_USER_NAME;
	offset += 1;
	temp_out[offset] = cert->len_userName;
	offset += 1;
	memcpy(temp_out + offset, cert->userName,  cert->len_userName);
	offset += cert->len_userName;

	temp_out[offset] = CERT_REGISTRATION_NUMBER;
	offset += 1;
	temp_out[offset] = cert->len_registrationNum;
	offset += 1;
	memcpy(temp_out + offset, cert->registrationNum, cert->len_registrationNum);
	offset += cert->len_registrationNum;

	temp_out[offset] = CERT_PHONE_NUMBER;
	offset += 1;
	temp_out[offset] = cert->len_phoneNum;
	offset += 1;
	memcpy(temp_out + offset, cert->phoneNum, cert->len_phoneNum);
	offset += cert->len_phoneNum;

	temp_out[offset] = CERT_USIM_ID;
	offset += 1;
	temp_out[offset] = cert->len_USIMID;
	offset += 1;
	memcpy(temp_out + offset, cert->USIMID, cert->len_USIMID);
	offset += cert->len_USIMID;

	temp_out[offset] = CERT_USER_ID;
	offset += 1;
	temp_out[offset] = cert->len_userID;
	offset += 1;
	memcpy(temp_out + offset, cert->userID, cert->len_userID);
	offset += cert->len_userID;

	temp_out[offset] = CERT_USED_ALGORITHM;
	offset += 1;
	temp_out[offset] = cert->len_usedAlgorithm;
	offset += 1;
	memcpy(temp_out + offset, cert->usedAlgorithm, cert->len_usedAlgorithm);
	offset += cert->len_usedAlgorithm;

	temp_out[offset] = CERT_CA_PUBKEY;
	offset += 1;
	temp_out[offset] = 0x44;
	offset += 1;

	temp_out[offset] = CERT_CA_PUBKEY_X;
	offset += 1;
	temp_out[offset] = cert->len_pubKey_x;
	offset += 1;
	memcpy(temp_out + offset, cert->pubKey_x, cert->len_pubKey_x);
	offset += cert->len_pubKey_x;

	temp_out[offset] = CERT_CA_PUBKEY_Y;
	offset += 1;
	temp_out[offset] = cert->len_pubKey_y;
	offset += 1;
	memcpy(temp_out + offset, cert->pubKey_y, cert->len_pubKey_y);
	offset += cert->len_pubKey_y;

	return 1;
}