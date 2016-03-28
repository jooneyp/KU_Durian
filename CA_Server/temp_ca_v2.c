#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h> 
#include <io.h>

#include "temp_ca_durian.h"
#include "EBDCrypto.h"
#include "EBDerror.h"



void copydata_cert2user(CERT_INFO * cert, USER_INFO * user);

int main()
{
	/*
	// revoke �Լ� ����
	CERT_INFO * cert = (CERT_INFO *)malloc(sizeof(CERT_INFO));
	SCHAR * temp_SN;
	SINT cert_SN;
	SINT hash_alg;
	UCHAR * d;
	ULONG d_len;
	SINT return_value;

	temp_SN = "12340";
	cert_SN = atoi(temp_SN);
	hash_alg = 1;
	d = (UCHAR *)"privatekey";
	d_len = 10;
	*/


	CERT_INFO * temp_cert = (CERT_INFO *)malloc(sizeof(CERT_INFO));
	CERT_INFO * cert = (CERT_INFO *)malloc(sizeof(CERT_INFO));
	USER_INFO * user = (USER_INFO *)malloc(sizeof(USER_INFO));
	UCHAR * conf_location, * conf_location1, *conf_location2, * d;
	UCHAR salt[16];
	UCHAR in[BUFSIZE * 12];
	UCHAR out[BUFSIZE * 12];
	SINT return_value, out_len, hash_alg;
	UINT salt_len, iteration;
	ULONG d_len;
	FILE * fp;

	fp = fopen("hex.data", "rb");
	hash_alg = 1;
	d = (UCHAR *)"privatekey";
	d_len = 10;

	memset(in, 0, sizeof(in));
	memset(out, 0, sizeof(out));
	memset(cert, 0, sizeof(CERT_INFO));
	memset(user, 0, sizeof(USER_INFO));

	fread(in, 251, 1, fp);
	conf_location = (UCHAR *)"hex.data";
	conf_location1 = (UCHAR *)"hex_.data";
	conf_location2 = (UCHAR *)"hex_final.data";

	Cert_init(temp_cert, conf_location);
	
	copydata_cert2user(temp_cert, user);
	
	//ver, issuer, issuedate, expiredate
	cert->len_Ver = temp_cert->len_Ver;
	cert->Ver = temp_cert->Ver;
	cert->len_issuer = temp_cert->len_issuer;
	memcpy(cert->issuer, temp_cert->issuer, sizeof(cert->issuer));
	cert->len_issueDate = temp_cert->len_issueDate;
	memcpy(cert->issueDate, temp_cert->issueDate, sizeof(cert->issueDate));
	cert->len_expirationDate = temp_cert->len_expirationDate;
	memcpy(cert->expirationDate, temp_cert->expirationDate, sizeof(cert->expirationDate));




	generate_PUB_CSR(cert, user, conf_location, out, out_len, 1, 0);
	return_value  = generate_signed_PUB(cert, conf_location1, conf_location2, salt, salt_len, iteration, 1, 1, hash_alg, d, d_len);
	
	printf("return value : %d\n", return_value);
	
}
void copydata_cert2user(CERT_INFO * cert, USER_INFO * user)
{
	user->len_userName = cert->len_userName;
	memcpy(user->userName, cert->userName, BUFSIZE);
	user->len_registrationNum = cert->len_registrationNum;
	memcpy(user->registrationNum, cert->registrationNum, BUFSIZE);
	user->len_phoneNum = cert->len_phoneNum;
	memcpy(user->phoneNum, cert->phoneNum, BUFSIZE);
	user->len_USIMID = cert->len_USIMID;
	memcpy(user->USIMID,  cert->USIMID, BUFSIZE);
	user->len_userID = cert->len_userID;
	memcpy(user->userID, cert->userID, BUFSIZE);
	user->len_usedAlgorithm = cert->len_usedAlgorithm;
	memcpy(user->usedAlgorithm, cert->usedAlgorithm, BUFSIZE);
}



/////////////////////////////////////////////////


SINT Cert_init(CERT_INFO * cert, UCHAR * conf_location)
{
	FILE * fp;
	SINT i;
    UCHAR len;
	SINT code;
    UCHAR * data;
    
	//����
	if (conf_location == NULL)
		return ERR_NO_FILE;

	//0���� �ʱ�ȭ
	memset(cert, 0, sizeof(CERT_INFO));

	//���Ͽ���
	fp = fopen((SCHAR *)conf_location, "rb");
    if (fp == NULL)
		return ERR_OPEN_FILE;
    
	//������ �� �о�ͼ� ����ü�� ���� 
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


SINT Cert_init_buffer(CERT_INFO * cert, UCHAR * buff)
{
	//buff�� �ִ°� cert�� ����
	SINT offset, code;
	UCHAR len;

	offset = 0;
	while((code = buff[offset]) != NULL)
	{
		offset += 1;
		len = buff[offset];
		offset += 1;
		switch (code) 
		{
			case CERT_VER :
				cert->len_Ver = len;
				cert->Ver = buff[offset];
				offset += len;
				break;
		    case CERT_SERIAL_NUMBER :
				cert->len_Cert_SN = len;
				memcpy(cert->Cert_SN, buff + offset, len);
				offset += len;
				break;
			case CERT_ISSUER :
				cert->len_issuer = len;
				memcpy(cert->issuer, buff + offset, len);
				offset += len;
				break;
			case CERT_VALID_FROM :
				cert->len_issueDate = len;
				memcpy(cert->issueDate, buff + offset, len);
				offset += len;
				break;
			case CERT_VALID_TO :
				cert->len_expirationDate = len;
				memcpy(cert->expirationDate, buff + offset, len);
				offset += len;
				break;
			case CERT_USER_NAME :
				cert->len_userName = len;
				memcpy(cert->userName, buff + offset, len);
				offset += len;
				break;
			case CERT_REGISTRATION_NUMBER :
				cert->len_registrationNum = len;
				memcpy(cert->registrationNum, buff + offset, len);
				offset += len;
				break;
			case CERT_PHONE_NUMBER :
				cert->len_phoneNum = len;
				memcpy(cert->phoneNum, buff + offset, len);
				offset += len;
				break;
			case CERT_USIM_ID :
				cert->len_USIMID = len;
				memcpy(cert->USIMID, buff + offset, len);
				offset += len;
				break;
			case CERT_USER_ID :
				cert->len_userID = len;
				memcpy(cert->userID, buff + offset, len);
				offset += len;
				break;
			case CERT_USED_ALGORITHM :
				cert->len_usedAlgorithm = len;
				memcpy(cert->usedAlgorithm, buff + offset, len);
				offset += len;
				break;
			case CERT_CA_PUBKEY :
				cert->len_pubKey = len;
				offset += 1;		//x_tag �ǳ� �ٱ�
				cert->len_pubKey_x = buff[offset];
				offset += 1;
				memcpy(cert->pubKey_x, buff + offset, cert->len_pubKey_x);
				offset += cert->len_pubKey_x;
				offset += 1;		//y_tag �ǳ� �ٱ�
				cert->len_pubKey_y = buff[offset];
				offset += 1;
				memcpy(cert->pubKey_y, buff + offset, cert->len_pubKey_y);
				offset += cert->len_pubKey_y;
				break;
			case CERT_SIGNATURE :
				offset += len;
				break;
			default :
				return ERR_CERT_TAG;
				}
			}
	return 1;
}


SINT generate_PUB(CERT_INFO * cert, UCHAR * target)
{
	FILE * fp;
	ECDSA_INFO *ec_kcdsa;
	UCHAR *qx, *qy, *d;
	ULONG *qx_len, *qy_len, *d_len;

	fp = fopen((SCHAR *)target, "rb");
    if (fp == NULL)
		return ERR_OPEN_FILE;

	fclose(fp);
	return 1;
}


SINT generate_PUB_CSR(CERT_INFO * cert, USER_INFO * user, UCHAR * in, UCHAR * out, SINT out_len, SINT check_in, SINT check_out)
{
	//////////////////////////////////////////////////////////���� : in���� ����Ű ������ �������

	FILE * fp1, * fp2;
	UCHAR * data;
	UCHAR len;
	SINT i, code;
	UCHAR temp_out[BUFSIZE * 6 + 64];
	SINT offset, size;

	//NULL�� �ʱ�ȭ
	
	memset(temp_out, 0, sizeof(temp_out));
	memset((UCHAR *)&out_len, 0, sizeof(out_len));
	//memset(cert, 0, sizeof(CERT_INFO));


	// user����ü�� ���� ������ ����(����Ű�� ����) ��, ����Ű������ �� ����־����
	if (user->len_phoneNum == NULL || user->len_registrationNum == NULL || user->len_usedAlgorithm == NULL || user->len_userID == NULL || user->len_userName == NULL || user->len_USIMID == NULL)
		return ERR_INVALID_INPUT;

	// ����Ű ���� ���µ� in ���� ������ ���� 
	if ((user->len_pubKey_x == NULL || user->len_pubKey_y == NULL) && in == NULL)
		return ERR_INVALID_INPUT;
	
	// in ���� �ִµ� check ���� ���� ������ ����
	if (in != NULL && (check_in != 0 && check_in != 1))
		return ERR_INVALID_INPUT;

	// out ���� ���ų� check ���� ���� ������ ����
	if (out == NULL || (check_out != 0 && check_out != 1))
		return ERR_INVALID_INPUT;

	// ����Ű ���� ���� ���
	if (user->len_pubKey_x == NULL || user->len_pubKey_y == NULL)
	{
		// in�� ������ ���
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
				switch (code) 
				{
					case CERT_VER :
						break;
					case CERT_SERIAL_NUMBER :
						break;
					case CERT_ISSUER :
						break;
					case CERT_VALID_FROM :
						break;
					case CERT_VALID_TO :
						break;
					case CERT_USER_NAME :
						break;
					case CERT_REGISTRATION_NUMBER :
						break;
					case CERT_PHONE_NUMBER :
						break;
					case CERT_USIM_ID :
						break;
					case CERT_USER_ID :
						break;
					case CERT_USED_ALGORITHM :
						break;
					case CERT_CA_PUBKEY :
						user->len_pubKey_x = data[1];
						memcpy(user->pubKey_x, data + 2, data[1]);

						user->len_pubKey_y = data[35];
						memcpy(user->pubKey_y, data + 36, data[35]);
						break;
					case CERT_SIGNATURE :
						break;
					default :
						return ERR_CERT_TAG;
				}
				free(data);
			}
			fclose(fp1);
		}
		// in�� ������ ���
		else
		{
			memset(out, 0, sizeof(out));
			offset = 0;
			while((code = in[offset]) != NULL)
			{
				offset += 1;
				len = in[offset];
				offset += 1;
				switch (code) 
				{
					case CERT_VER :
						offset += len;
						break;
					case CERT_SERIAL_NUMBER :
						offset += len;
						break;
					case CERT_ISSUER :
						offset += len;
						break;
					case CERT_VALID_FROM :
						offset += len;
						break;
					case CERT_VALID_TO :
						offset += len;
						break;
					case CERT_USER_NAME :
						offset += len;
						break;
					case CERT_REGISTRATION_NUMBER :
						offset += len;
						break;
					case CERT_PHONE_NUMBER :
						offset += len;
						break;
					case CERT_USIM_ID :
						offset += len;
						break;
					case CERT_USER_ID :
						offset += len;
						break;
					case CERT_USED_ALGORITHM :
						offset += len;
						break;
					case CERT_CA_PUBKEY :
						offset += 1;		//x_tag �ǳ� �ٱ�
						user->len_pubKey_x = in[offset];
						offset += 1;
						memcpy(user->pubKey_x, in + offset, user->len_pubKey_x);
						offset += user->len_pubKey_x;
						offset += 1;		//y_tag �ǳ� �ٱ�
						user->len_pubKey_y = in[offset];
						offset += 1;
						memcpy(user->pubKey_y, in + offset, user->len_pubKey_y);
						offset += user->len_pubKey_y;
						break;
					case CERT_SIGNATURE :
						offset += len;
						break;
					default :
						return ERR_CERT_TAG;
				}
			}
		}
	}


	// user����ü�� �ִ� ���� tlv���·� �����ؼ� temp_out�� ����
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

	size = offset;


	//temp_out�� ���� out�� ���
		//������ ���
	if (check_out == 1)
	{
		fp2 = fopen((SCHAR *)out, "wb");
		if (fp2 == NULL)
			return ERR_OPEN_FILE;
		fwrite(temp_out, size, 1, fp2);
		out_len = NULL;
		fclose(fp2);
	}
		//������ ���
	else
	{
		memcpy(out, temp_out, size);
		out_len = size;
	}

	return 1;
}


SINT generate_signed_PUB(CERT_INFO * cert, UCHAR * in, UCHAR * out, UCHAR * salt, UINT salt_len, UINT iteration, SINT check_in, SINT check_out, SINT hash_alg, const UCHAR *d, ULONG d_len)
{
	FILE * fp, * fp1;
	SINT offset, size, total_size;
	UCHAR len;
	UCHAR temp_out[BUFSIZE * 12];
	UCHAR * data;
	UCHAR r[32];
	ULONG * r_len;
	UCHAR s[32];
	ULONG * s_len;
	UINT ran;
	SINT code, i;




	//0���� �ʱ�ȭ
	memset(temp_out, 0, sizeof(temp_out));
	memset(salt, 0, sizeof(salt));
	memset(r, 0, sizeof(r));
	memset(s, 0, sizeof(s));


	// cert�� ver, issuer, issuedate, expiredate�� ��� �� ���Դٴ� ����, ������ ������ �ȵ��������� in(CSR ������ ����� ��)���� �޾ƿ��� ��
	if (cert->len_Ver == NULL || cert->len_issuer == NULL || cert->len_issueDate == NULL || cert->len_expirationDate == NULL)
		return ERR_INVALID_INPUT;

	// input ���� ������ ���� 
	if (cert == NULL || salt == NULL)
		return ERR_INVALID_INPUT;
	
	// ����ü�� ���� ���µ� in���� ������ ����
	if ((cert->len_userName == NULL || cert->len_registrationNum == NULL || cert->len_phoneNum == NULL || cert->len_USIMID == NULL || cert->len_userID == NULL || cert->len_usedAlgorithm == 0 || cert->len_pubKey_x == NULL || cert->len_pubKey_y == NULL) && in == NULL)
		return ERR_INVALID_INPUT;

	// in ���� �ִµ� check ���� ���� ������ ����
	if (in != NULL && (check_in != 0 && check_in != 1))
		return ERR_INVALID_INPUT;

	// out���� ���ų� check ���� ���� ������ ����
	if (out == NULL && (check_out != 0 && check_out != 1))
		return ERR_INVALID_INPUT;
		

	// ����ü�� ���� ���� ���(Ư�� CSR������ ���� ���)
	if (cert->len_userName == NULL || cert->len_registrationNum == NULL || cert->len_phoneNum == NULL || cert->len_USIMID == NULL || cert->len_userID == NULL || cert->len_usedAlgorithm == NULL || cert->len_pubKey_x == NULL || cert->len_pubKey_y == NULL)
	{
		// ������ ���
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
				switch (code) 
				{
					case CERT_VER :
						break;
				    case CERT_SERIAL_NUMBER :
		                break;
					case CERT_ISSUER :
						break;
			        case CERT_VALID_FROM :
						break;
				    case CERT_VALID_TO :
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
						break;
					default :
						return ERR_CERT_TAG;
					}
					free(data);
				}
				fclose(fp1);
		}


		// ������ ���
		else
		{
			memset(out, 0, sizeof(out));
			offset = 0;
			while((code = in[offset]) != NULL)
			{
				offset += 1;
				len = in[offset];
				offset += 1;
				switch (code) 
				{
					case CERT_VER :
						offset += len;
						break;
				    case CERT_SERIAL_NUMBER :
						offset += len;
		                break;
					case CERT_ISSUER :
						offset += len;
						break;
			        case CERT_VALID_FROM :
						offset += len;
						break;
				    case CERT_VALID_TO :
						offset += len;
						break;
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
						offset += 1;		//x_tag �ǳ� �ٱ�
						cert->len_pubKey_x = in[offset];
						offset += 1;
						memcpy(cert->pubKey_x, in + offset, cert->len_pubKey_x);
						offset += cert->len_pubKey_x;
						offset += 1;		//y_tag �ǳ� �ٱ�
						cert->len_pubKey_y = in[offset];
						offset += 1;
						memcpy(cert->pubKey_y, in + offset, cert->len_pubKey_y);
						offset += cert->len_pubKey_y;
						break;
					case CERT_SIGNATURE :
						offset += len;
						break;
					default :
						return ERR_CERT_TAG;
				}
			}
		}
	}
	

	/*
		DB(CERT_INFO * cert);   Cert_SN�޾Ƽ� �ǵ�����	
	*/
	
	
	///////////////////////////////////////// ���� �����ϰ� cert����ü�� ��� ���� �� ��
	



	// ����ü -> tlv
	size = cert2tlv_exceptSign(cert, temp_out, offset);


	
	// ���� ����
	ECDSA_generate_signature(hash_alg, d, d_len, temp_out, size, r, r_len, s, s_len);
	cert->len_signature = *r_len + *s_len;
	memcpy(cert->signature, r, *r_len);
	memcpy(cert->signature + *r_len, s, *s_len);
	
	/*
	�׽�Ʈ
		cert->len_signature = 0x40;
		memcpy(cert->signature, "signatursignatursignatursignatur", 32);
		memcpy(cert->signature + 32, "signatursignatursignatursignatur", 32);
	*/


	temp_out[size] = CERT_SIGNATURE;
	size += 1;
	temp_out[size] = cert->len_signature;
	size += 1;
	memcpy(temp_out + size, cert->signature, cert->len_signature);
	size += cert->len_signature;

	////////////temp_out�� ��� ���� ���� (������ ������ ������ ������)
	total_size = size;

	// out�� ������ �� ����ϱ� 
	// ������ ���
	if (check_out == 1)
	{
		fp = fopen((SCHAR *)out, "wb");
		if (fp == NULL)
			return ERR_OPEN_FILE;
		fwrite(temp_out, total_size, 1, fp);
		fclose(fp);
	}
	//������ ���
	else
		memcpy(out, temp_out, total_size);

	// salt�� ����
	srand(time(NULL));
	ran = rand()%5 + 12;
	HASH_DRBG_Random_Gen(salt, ran * 8);
	salt_len = ran;


	// iteration �� ����
	
	do 
	{
		HASH_DRBG_Random_Gen((UCHAR *)&iteration, 16);
	} while((2048 > iteration) || (30000 < iteration));


	return 1;
}


SINT cert2tlv_exceptSign(CERT_INFO * cert, UCHAR * temp_out, SINT temp_offset)
{
	if (cert == NULL || temp_out == NULL)
		return ERR_INVALID_INPUT;

	temp_offset = 0;
	temp_out[temp_offset] = CERT_VER;
	temp_offset += 1;
	temp_out[temp_offset] = cert->len_Ver;
	temp_offset += 1;
	memcpy(temp_out + temp_offset, (UCHAR *)&cert->Ver,  cert->len_Ver);
	temp_offset += cert->len_Ver;

	temp_out[temp_offset] = CERT_SERIAL_NUMBER;
	temp_offset += 1;
	temp_out[temp_offset] = cert->len_Cert_SN;
	temp_offset += 1;
	memcpy(temp_out + temp_offset, cert->Cert_SN,  cert->len_Cert_SN);
	temp_offset += cert->len_Cert_SN;

	temp_out[temp_offset] = CERT_ISSUER;
	temp_offset += 1;
	temp_out[temp_offset] = cert->len_issuer;
	temp_offset += 1;
	memcpy(temp_out + temp_offset, cert->issuer,  cert->len_issuer);
	temp_offset += cert->len_issuer;

	temp_out[temp_offset] = CERT_VALID_FROM;
	temp_offset += 1;
	temp_out[temp_offset] = cert->len_issueDate;
	temp_offset += 1;
	memcpy(temp_out + temp_offset, cert->issueDate,  cert->len_issueDate);
	temp_offset += cert->len_issueDate;

	temp_out[temp_offset] = CERT_VALID_TO;
	temp_offset += 1;
	temp_out[temp_offset] = cert->len_expirationDate;
	temp_offset += 1;
	memcpy(temp_out + temp_offset, cert->expirationDate,  cert->len_expirationDate);
	temp_offset += cert->len_expirationDate;

	temp_out[temp_offset] = CERT_USER_NAME;
	temp_offset += 1;
	temp_out[temp_offset] = cert->len_userName;
	temp_offset += 1;
	memcpy(temp_out + temp_offset, cert->userName,  cert->len_userName);
	temp_offset += cert->len_userName;

	temp_out[temp_offset] = CERT_REGISTRATION_NUMBER;
	temp_offset += 1;
	temp_out[temp_offset] = cert->len_registrationNum;
	temp_offset += 1;
	memcpy(temp_out + temp_offset, cert->registrationNum, cert->len_registrationNum);
	temp_offset += cert->len_registrationNum;

	temp_out[temp_offset] = CERT_PHONE_NUMBER;
	temp_offset += 1;
	temp_out[temp_offset] = cert->len_phoneNum;
	temp_offset += 1;
	memcpy(temp_out + temp_offset, cert->phoneNum, cert->len_phoneNum);
	temp_offset += cert->len_phoneNum;

	temp_out[temp_offset] = CERT_USIM_ID;
	temp_offset += 1;
	temp_out[temp_offset] = cert->len_USIMID;
	temp_offset += 1;
	memcpy(temp_out + temp_offset, cert->USIMID, cert->len_USIMID);
	temp_offset += cert->len_USIMID;

	temp_out[temp_offset] = CERT_USER_ID;
	temp_offset += 1;
	temp_out[temp_offset] = cert->len_userID;
	temp_offset += 1;
	memcpy(temp_out + temp_offset, cert->userID, cert->len_userID);
	temp_offset += cert->len_userID;

	temp_out[temp_offset] = CERT_USED_ALGORITHM;
	temp_offset += 1;
	temp_out[temp_offset] = cert->len_usedAlgorithm;
	temp_offset += 1;
	memcpy(temp_out + temp_offset, cert->usedAlgorithm, cert->len_usedAlgorithm);
	temp_offset += cert->len_usedAlgorithm;

	temp_out[temp_offset] = CERT_CA_PUBKEY;
	temp_offset += 1;
	temp_out[temp_offset] = 0x44;
	temp_offset += 1;

	temp_out[temp_offset] = CERT_CA_PUBKEY_X;
	temp_offset += 1;
	temp_out[temp_offset] = cert->len_pubKey_x;
	temp_offset += 1;
	memcpy(temp_out + temp_offset, cert->pubKey_x, cert->len_pubKey_x);
	temp_offset += cert->len_pubKey_x;

	temp_out[temp_offset] = CERT_CA_PUBKEY_Y;
	temp_offset += 1;
	temp_out[temp_offset] = cert->len_pubKey_y;
	temp_offset += 1;
	memcpy(temp_out + temp_offset, cert->pubKey_y, cert->len_pubKey_y);
	temp_offset += cert->len_pubKey_y;

	return temp_offset;
}


SINT revoke_PUB(SINT cert_SN, UCHAR * reason, SINT hash_alg, const UCHAR *d, ULONG d_len)
{
	CERT_INFO * cert;
	UCHAR temp_data[BUFSIZE * 12];
	
	SINT i, offset, size, temp_offset, total_size, check_file_exist;
	UCHAR r[32];
	ULONG * r_len;
	UCHAR s[32];
	ULONG * s_len;
	FILE * fp;


	// NULL�� �ʱ�ȭ
	memset(cert, 0, BUFSIZE*11 + 80);
	memset(temp_data, 0, sizeof(temp_data));
	

	if (cert_SN == NULL || hash_alg == NULL || d == NULL || d_len == NULL)
		return ERR_INVALID_INPUT;

	/*
		DB�˻��Ͽ� ��ȿ�� cert_sn���� Ȯ�� -> ��ȿ���� �ʴٸ� ���� �ڵ� ����, ���� �̹� ���Ǿ��ٸ� �� ����

		��ȿ�� ��� & ������ �ʾҴٸ� DB���� �����ͼ� cert����ü�� ����
	*/


	size = cert2tlv_exceptSign(cert, temp_data, temp_offset);
	///////////////////////������� ���� �������� temp_data�� tlv���·� ���� ���� ������


	// temp_data�� ���� ���� �� ����
	ECDSA_generate_signature(hash_alg, d, d_len, temp_data, size, r, r_len, s, s_len);
	

	// DB�� ���� �����
	cert->len_signature = *r_len + *s_len;
	memcpy(cert->signature, r, *r_len);
	memcpy(cert->signature + *r_len, s, *s_len);
	

	/*
		DB�� ���� cert ���� ����
	*/


	// temp_data���� ���� ������ ���� ����
	temp_data[size] = CERT_SIGNATURE;
	size += 1;
	temp_data[size] = cert->len_signature;
	size += 1;
	memcpy(temp_data + size, cert->signature, cert->len_signature);
	size += cert->len_signature;

	total_size = size; 


	/*
		���Ǿ��ٴ� ����(index)  + ��� ���� DB�� ����  
	*/


	// ������ �����ִ��� �˻� �� ������ ����� �����
	check_file_exist = access("certification.data", 0);
	if (check_file_exist == 0)
	{
		fp = fopen("certification.data", "w+b");
		if (fp == NULL)
			return ERR_OPEN_FILE;
		fwrite(temp_data, total_size, 1, fp);
		fclose(fp);
	}

	return EXPIRE_CERT;
}


SINT check_cert_Station(SINT cert_SN, UCHAR * reason, SINT hash_alg, const UCHAR *d, ULONG d_len)
{
	CERT_INFO * cert;
	time_t ltime;
    struct tm *today;
	SCHAR currentTime[14];
	UCHAR temp_cTime_year[4];
	UCHAR temp_cTime[2];
	UCHAR temp_expTime_year[4];
	UCHAR temp_expTime[2];
	UCHAR temp_data[BUFSIZE * 12];
	SINT i, temp_offset, temp_size;

	/*
		DB�˻��Ͽ� ��ȿ�� cert_sn���� Ȯ�� -> ��ȿ���� �ʴٸ� ���� �ڵ� ����

		��ȿ�� ����϶� ������ ���� index������ return ������ ����
						������ ���� index������ DB���� �����ͼ� cert����ü�� ����
	*/

	//�ӽ÷� ������ �迭 0���� �ʱ�ȭ (�����˻��Ҷ� cert�� tlv���·� �迭�� �����ϱ� ���ؼ� ����)
	memset(temp_data, 0, sizeof(temp_data));


	//����ð� ����
	time(&ltime);
	today = localtime(&ltime);
	sprintf(currentTime, "%04d%02d%02d%02d%02d%02d", today->tm_year + 1900, today->tm_mon + 1, today->tm_mday, today->tm_hour, today->tm_min, today->tm_sec);



	// �ð��� ����
		// �⵵ �ʰ�
	if (strncmp((SCHAR *)cert->expirationDate, currentTime, 4) < 0)
	{
		revoke_PUB(cert_SN, (UCHAR *)"Over Time", hash_alg, d, d_len);
		return INVALID_CERT;		// ��ȿ���� ���� ������
	}
		// �⵵ ����
	else if (strncmp((SCHAR *)cert->expirationDate, currentTime, 4) > 0)
	{	
		// ���� ����
		temp_size = cert2tlv_exceptSign(cert, temp_data, temp_offset);
		if (ECDSA_verify_signature(hash_alg, cert->pubKey_x, cert->len_pubKey_x, cert->pubKey_y, cert->len_pubKey_y, temp_data, temp_size, cert->signature, 32, cert->signature + 32, 32) != ERR_VERIFY_FAILURE)
			return VALID_CERT;		// ��¥�� ok, ������ ok�̴ϱ� ��ȿ�� ������
		else if (ECDSA_verify_signature(hash_alg, cert->pubKey_x, cert->len_pubKey_x, cert->pubKey_y, cert->len_pubKey_y, temp_data, temp_size, cert->signature, 32, cert->signature + 32, 32) == ERR_VERIFY_FAILURE)
		{
			revoke_PUB(cert_SN, (UCHAR *)"Invaild Signature", hash_alg, d, d_len);
			return INVALID_CERT;		// ��ȿ���� ���� ������
		}
	}
		// �⵵ ��
	else
	{
			// ����..������ ��
		for (i = 0; i < 5; i++)
		{
				// �ð� �ʰ�
			if (strncmp((SCHAR *)cert->expirationDate +4 +2*i, currentTime +4 +2*i, 2) < 0)
			{
				revoke_PUB(cert_SN, (UCHAR *)"Over Time", hash_alg, d, d_len);
				return INVALID_CERT;		// ��ȿ���� ���� ������
			}
				// �ð� ����
			else if (strncmp((SCHAR *)cert->expirationDate +4 +2*i, currentTime +4 +2*i, 2) > 0)
			{	
				// ���� ����
				temp_size = cert2tlv_exceptSign(cert, temp_data, temp_offset);
				if (ECDSA_verify_signature(hash_alg, cert->pubKey_x, cert->len_pubKey_x, cert->pubKey_y, cert->len_pubKey_y, temp_data, temp_size, cert->signature, 32, cert->signature + 32, 32) != ERR_VERIFY_FAILURE)
					return VALID_CERT;		// ��¥�� ok, ������ ok�̴ϱ� ��ȿ�� ������
				else if (ECDSA_verify_signature(hash_alg, cert->pubKey_x, cert->len_pubKey_x, cert->pubKey_y, cert->len_pubKey_y, temp_data, temp_size, cert->signature, 32, cert->signature + 32, 32) != ERR_VERIFY_FAILURE)
				{
					revoke_PUB(cert_SN, (UCHAR *)"Invaild Signature", hash_alg, d, d_len);
					return INVALID_CERT;		// ��ȿ���� ���� ������
				}
			}
				// �ð� ��
			else
				continue;
		}
	}
}


SINT regenerate_cert(CERT_INFO * cert, SINT cert_SN, UCHAR * reason, SINT hash_alg, const UCHAR *d, ULONG d_len, UCHAR * in, UCHAR * out, UCHAR * salt, UINT salt_len, UINT iteration, SINT check_in, SINT check_out)
{
	if(cert_SN == 0 || reason == NULL || hash_alg == 0)
		return ERR_INVALID_INPUT;

	// ������ ����ó���� �Լ��ȿ� �� ����


	// �ش� cert_SN ���
	revoke_PUB(cert_SN, reason, hash_alg, d, d_len);


	// ���ο� ������ �߱�
	generate_signed_PUB(cert, in, out, salt, salt_len, iteration, check_in, check_out, hash_alg, d, d_len);

	return 1;
}
