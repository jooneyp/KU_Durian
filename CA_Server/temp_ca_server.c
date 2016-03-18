#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define	CERT_VER 					0x01
#define	CERT_SERIAL_NUMBER			0x03
#define	CERT_ISSUER					0x05
#define	CERT_VALID_FROM				0x10
#define	CERT_VALID_TO				0x11
#define CERT_USER_NAME				0x20
#define CERT_REGISTRATION_NUMBER	0x30
#define CERT_PHONE_NUMBER			0x40
#define CERT_USIM_ID				0x50
#define	CERT_USER_ID				0x60
#define CERT_USED_ALGORITHM			0x70
#define	CERT_CA_PUBKEY				0x80
#define	CERT_SIGNATURE				0x90


#define BUFSIZE						128

/*
1. Version
2. CERT_SN
3. 발급 기관
4. 발급 일자
5. 만료 일자
6. 사용자 이름
7. 주민번호 앞자리(8자리 숫자)
8. 전화번호
9. USIM ID
10. 사용자 ID
11. 사용 알고리즘
12. 공개키쌍
13. 1~12에 대한 서명값
*/

typedef struct Cert_v1 
{
	char ver[3];
	char Cert_SN[BUFSIZE];
	char issuer[BUFSIZE];
	char valFrom[BUFSIZE];
	char valTo[BUFSIZE];
	char userName[BUFSIZE];
	char registrationNum[BUFSIZE];
	char phoneNum[BUFSIZE];
	char USIMID[BUFSIZE];
	char userID[BUFSIZE];
	char usedAlgorithm[BUFSIZE];
	char CAPubKey[BUFSIZE];
	char signature[BUFSIZE*2];
} CERT_V1;


CERT_V1 tlv_to_cert(char * filename);
FILE cert_to_tlv(CERT_V1 * cert_data);
void printErr(char * err);
int make_CAsignature(char * Enc_of_cPub_PW, char* CI);
int make_verificationValue(char* Cert_SN, char* digitalSignature);
//int cert_issue();
//int cert_revoke();
//int cert_verify();
//int cert_reissue();
void read_hex(char * filename);
int hex_to_ascii(char c, char d);
int printCert(CERT_V1 * cert);
void print_data(const char *tittle, const void* data, long int len);

int main() 
{
    CERT_V1 * cert_data = (CERT_V1 *)malloc(sizeof(cert_data));

    char filename[] = "hex.data";
    *cert_data = tlv_to_cert(filename);
    cert_to_tlv(cert_data);

    printCert(cert_data);
    
    return 0;
}

CERT_V1 tlv_to_cert(char * filename) {
    CERT_V1 * cert_data = (CERT_V1 *) malloc ( sizeof (CERT_V1) );
	int i, len;
    char code;
    char * data;
    FILE * fp;
    fp = fopen(filename, "rb");
    if (fp == NULL) {
        printErr("FILE OPEN ERROR!\n");
    }
    while ((code = fgetc(fp)) != EOF) 
	{
		len = (char) fgetc(fp);
		data = (char *) malloc (sizeof(char) * len);
        for(i=0; i<len; i++)
			data[i] = fgetc(fp);
        switch (code) {
            case CERT_VER :
				strncpy(cert_data->ver, data, len);
                break;
            case CERT_SERIAL_NUMBER :
				strncpy(cert_data->Cert_SN, data, len);
                break;
			case CERT_ISSUER :
				strncpy(cert_data->issuer, data, len);
                break;
            case CERT_VALID_FROM :
				strncpy(cert_data->valFrom, data, len);
                break;
            case CERT_VALID_TO :
				strncpy(cert_data->valTo, data, len);
                break;
			case CERT_USER_NAME :
				strncpy(cert_data->userName, data, len);
				break;
			case CERT_REGISTRATION_NUMBER :
				strncpy(cert_data->registrationNum, data, len);
				break;
			case CERT_PHONE_NUMBER :
				strncpy(cert_data->phoneNum, data, len);
				break;
            case CERT_USIM_ID :
				strncpy(cert_data->USIMID, data, len);
                break;
            case CERT_USER_ID :
                strncpy(cert_data->userID, data, len);
                break;
            case CERT_USED_ALGORITHM :
				strncpy(cert_data->usedAlgorithm, data, len);
                break;
            case CERT_CA_PUBKEY :
                strncpy(cert_data->CAPubKey, data, len);
                break;
            case CERT_SIGNATURE :
                strncpy(cert_data->signature, data, len);
                break;
            default :
                printf("CODE ERROR!");
                exit(EXIT_FAILURE);
        }
		free(data);
    }
    fclose(fp);
    
    return * cert_data;
}

FILE cert_to_tlv(CERT_V1 * cert_data) {
    FILE * fp;
	int i;
	char len;
	unsigned char code_set[] = {CERT_VER, CERT_SERIAL_NUMBER, CERT_ISSUER, CERT_VALID_FROM, CERT_VALID_TO, CERT_USER_NAME, CERT_REGISTRATION_NUMBER, CERT_PHONE_NUMBER, CERT_USIM_ID, CERT_USER_ID, CERT_USED_ALGORITHM, CERT_CA_PUBKEY, CERT_SIGNATURE};
	

	fp = fopen("hex_.data", "wb");
    if (fp == NULL) 
	{
        printErr("MAKE FILE ERROR!\n");
    }

	fputc(code_set[0],fp);
	len = (char)strlen(cert_data->ver);
	fputc(len, fp);
	fwrite(cert_data->ver, len, 1, fp);

	fputc(code_set[1],fp);
	len = (char)strlen(cert_data->Cert_SN);
	fputc(len, fp);
	fwrite(cert_data->Cert_SN, len, 1, fp);

	fputc(code_set[2],fp);
	len = (char)strlen(cert_data->issuer);
	fputc(len, fp);
	fwrite(cert_data->issuer, len, 1, fp);
	
	fputc(code_set[3],fp);
	len = (char)strlen(cert_data->valFrom);
	fputc(len, fp);
	fwrite(cert_data->valFrom, len, 1, fp);

	fputc(code_set[4],fp);
	len = (char)strlen(cert_data->valTo);
	fputc(len, fp);
	fwrite(cert_data->valTo, len, 1, fp);

	fputc(code_set[5],fp);
	len = (char)strlen(cert_data->userName);
	fputc(len, fp);
	fwrite(cert_data->userName, len, 1, fp);

	fputc(code_set[6],fp);
	len = (char)strlen(cert_data->registrationNum);
	fputc(len, fp);
	fwrite(cert_data->registrationNum, len, 1, fp);

	fputc(code_set[7],fp);
	len = (char)strlen(cert_data->phoneNum);
	fputc(len, fp);
	fwrite(cert_data->phoneNum, len, 1, fp);

	fputc(code_set[8],fp);
	len = (char)strlen(cert_data->USIMID);
	fputc(len, fp);
	fwrite(cert_data->USIMID, len, 1, fp);

	fputc(code_set[9],fp);
	len = (char)strlen(cert_data->userID);
	fputc(len, fp);
	fwrite(cert_data->userID, len, 1, fp);

	fputc(code_set[10],fp);
	len = (char)strlen(cert_data->usedAlgorithm);
	fputc(len, fp);
	fwrite(cert_data->usedAlgorithm, len, 1, fp);

	fputc(code_set[11],fp);
	len = (char)strlen(cert_data->CAPubKey);
	fputc(len, fp);
	fwrite(cert_data->CAPubKey, len, 1, fp);

	fclose(fp);

	return * fp;
}

int make_CAsignature(char * Enc_of_cPub_PW, char* CI)
{
	/* First, make Cert_SN*/
		// TODO1 : make decryption function of Enc_of_cPub_PW
		// TODO2 : make function of gernerating Cert_SN, using hash function where input(c_pub, PW) -> output(Cert_SN)
	
	/* Second, CA signature */
		// TODO1 : make function of generatinf CA signature ; input(c_pub, Cert_SN, CI) -> output(CA signature)

	/* Third, add to DB*/
		// DB(mode, char* array) where mode = ?, array = c_pub + PW + Cert_SN + CI + CA signature

	return 0;
}

int make_verificationValue(char* Cert_SN, char* digitalSignature)
{
	// TODO : make verification Algorithm
	return 0;
}


void printErr(char * err) {
    printf("%s\n", err);
}

int hex_to_int(char c){
    int first = c / 16 - 3;
    int second = c % 16;
    int result = first*10 + second;
    if(result > 9) result--;
    return result;
}

int hex_to_ascii(char c, char d){
    int high = hex_to_int(c) * 16;
    int low = hex_to_int(d);
    return high+low;
}

int printCert(CERT_V1 * cert) 
{
	print_data("Cert Version         : ", cert->ver, strlen(cert->ver));
	print_data("Serial Number        : ", cert->Cert_SN, strlen(cert->Cert_SN));
    print_data("Issuer               : ", cert->issuer, strlen(cert->issuer));
	printf("Valid Date               : %s ~ %s\n", cert->valFrom, cert->valTo);
	print_data("User Name            : ", cert->userName, strlen(cert->userName));
	print_data("Registration Number  : ", cert->registrationNum, strlen(cert->registrationNum));
	print_data("Phone Number         : ", cert->phoneNum, strlen(cert->phoneNum));
	print_data("USIM ID              : ", cert->USIMID, strlen(cert->USIMID));
	print_data("User ID              : ", cert->userID, strlen(cert->userID));
	print_data("CA Public Key        : ", cert->CAPubKey, strlen(cert->CAPubKey));
    

    return 0;
}

void print_data(const char *tittle, const void* data, long int len)
{
	int i = 0;
	const unsigned char * p = (const unsigned char*)data;

	printf("%s", tittle);
	
	for(i = 0; i < len; i++){
		printf("%c", *p++);
	}
	printf("\n");
}
