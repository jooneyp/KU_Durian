#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define	CERT_VER 				0x01
#define	CERT_SERIAL_NUMBER		0x03
#define	CERT_TIMESTAMP			0x05
#define	CERT_USER_ID			0x10
#define	CERT_USER_CI			0x11
#define	CERT_ISSUER				0x20
#define	CERT_CA_PUBKEY			0x21
#define	CERT_VALID_FROM			0x30
#define	CERT_VALID_TO			0x31
#define	CERT_SIGNATURE			0x50

#define BUFSIZE					16

/*
typedef struct Cert_v1 {
    char CAPubKey[120];
    char pad1[1];
    char userID[BUFSIZE * 2];
    char pad2[1];
    char issuer[BUFSIZE * 2];
    char pad3[1];
    char serialNum[BUFSIZE];
    char pad4[1];
    char signature[BUFSIZE];
    char pad5[1];
    char timestamp[BUFSIZE];
    char valFrom[BUFSIZE];
    char valTo[BUFSIZE];
    char userCI[BUFSIZE];
    char pad6[1];
    char ver[1];
} CERT_V1;
*/

typedef struct Cert_v1 {
	char len_ver;
	char ver[1];
	char len_serialNum;
	char serialNum[BUFSIZE];
	char len_timestamp;
	char timestamp[BUFSIZE];
	char len_userID;
	char userID[BUFSIZE * 2];
	char len_userCI;
	char userCI[BUFSIZE];
	char len_issuer;
	char issuer[BUFSIZE * 2];
	char len_CAPubKey;
	char CAPubKey[120];
	char len_valFrom;
	char valFrom[BUFSIZE];
	char len_valTo;
	char valTo[BUFSIZE];
	char len_signature;
	char signature[BUFSIZE];
} CERT_V1;


CERT_V1 tlv_to_cert(char * filename);
FILE cert_to_tlv(CERT_V1 * cert_data);
void printErr(char * err);
int cert_issue();
int cert_revoke();
int cert_verify();
int cert_reissue();
void read_hex(char * filename);
int hex_to_ascii(char c, char d);
int printCert(CERT_V1 * cert);
void print_data(const char *tittle, const void* data, long int len);

int main() {
    CERT_V1 * cert_data = (CERT_V1 *) malloc ( sizeof (CERT_V1) );
    
    char * filename = "hex.data";
    * cert_data = tlv_to_cert(filename);
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
    while ((code = fgetc(fp)) != EOF) {
		len = (char) fgetc(fp);
        // printf("len : %d\n", len);
        data = (char *) malloc ( sizeof(char) * len );
        for(i=0; i<len; i++)
			data[i] = fgetc(fp);
        // printf("got : %s\n", data);
        switch (code) {
            case CERT_VER :
				cert_data->len_ver = len;
				strncpy(cert_data->ver, data, len);
                break;
            case CERT_SERIAL_NUMBER :
				cert_data->len_serialNum = len;
                strncpy(cert_data->serialNum, data, len);
                break;
            case CERT_TIMESTAMP :
				cert_data->len_timestamp = len;
                strncpy(cert_data->timestamp, data, len);
                break;
            case CERT_USER_ID :
				cert_data->len_userID = len;
                strncpy(cert_data->userID, data, len);
                break;
            case CERT_USER_CI :
				cert_data->len_userCI = len;
                strncpy(cert_data->userCI, data, len);
                break;
            case CERT_ISSUER :
				cert_data->len_issuer = len;
                strncpy(cert_data->issuer, data, len);
                break;
            case CERT_CA_PUBKEY :
				cert_data->len_CAPubKey = len;
                strncpy(cert_data->CAPubKey, data, len);
                break;
            case CERT_VALID_FROM :
				cert_data->len_valFrom = len;
                strncpy(cert_data->valFrom, data, len);
                break;
            case CERT_VALID_TO :
				cert_data->len_valTo = len;
                strncpy(cert_data->valTo, data, len);
                break;
            case CERT_SIGNATURE :
				cert_data->len_signature = len;
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
	int i, len;
	unsigned char code_set[] = {CERT_VER, CERT_SERIAL_NUMBER, CERT_TIMESTAMP, CERT_USER_ID, CERT_USER_CI, CERT_ISSUER, CERT_CA_PUBKEY, CERT_VALID_FROM, CERT_VALID_TO, CERT_SIGNATURE};
	

	fp = fopen("hex_.data", "wb");
    if (fp == NULL) 
	{
        printErr("MAKE FILE ERROR!\n");
    }

	fputc(code_set[0],fp);
	fwrite((char *)&cert_data->len_ver, sizeof(cert_data->len_ver), 1, fp);
	fwrite(cert_data->ver, cert_data->len_ver, 1, fp);

	fputc(code_set[1],fp);
	fwrite((char *)&cert_data->len_serialNum, sizeof(cert_data->len_serialNum), 1, fp);
	fwrite(cert_data->serialNum, cert_data->len_serialNum, 1, fp);

	fputc(code_set[2],fp);
	fwrite((char *)&cert_data->len_timestamp, sizeof(cert_data->len_timestamp), 1, fp);
	fwrite(cert_data->timestamp, cert_data->len_timestamp, 1, fp);
	
	fputc(code_set[3],fp);
	fwrite((char *)&cert_data->len_userID, sizeof(cert_data->len_userID), 1, fp);
	fwrite(cert_data->userID, cert_data->len_userID, 1, fp);

	fputc(code_set[4],fp);
	fwrite((char *)&cert_data->len_userCI, sizeof(cert_data->len_userCI), 1, fp);
	fwrite(cert_data->userCI, cert_data->len_userCI, 1, fp);

	fputc(code_set[5],fp);
	fwrite((char *)&cert_data->len_issuer, sizeof(cert_data->len_issuer), 1, fp);
	fwrite(cert_data->issuer, cert_data->len_issuer, 1, fp);

	fputc(code_set[6],fp);
	fwrite((char *)&cert_data->len_CAPubKey, sizeof(cert_data->len_CAPubKey), 1, fp);
	fwrite(cert_data->CAPubKey, cert_data->len_CAPubKey, 1, fp);

	fputc(code_set[7],fp);
	fwrite((char *)&cert_data->len_valFrom, sizeof(cert_data->len_valFrom), 1, fp);
	fwrite(cert_data->valFrom, cert_data->len_valFrom, 1, fp);

	fputc(code_set[8],fp);
	fwrite((char *)&cert_data->len_valTo, sizeof(cert_data->len_valTo), 1, fp);
	fwrite(cert_data->valTo, cert_data->len_valTo, 1, fp);
	/*
	fputc(code_set[9],fp);
	fwrite((char *)&cert_data->len_signature, sizeof(cert_data->len_signature), 1, fp);
	fwrite(cert_data->signature, cert_data->len_signature, 1, fp);
	*/
	fclose(fp);

	return * fp;
}

int cert_issue(char * ID) {
    // TODO : CI 생성
    // TODO : DB 입력
    // if (noerr) {
    //		if(!sendCert) {
    //			sendMsg
    //		}
    // } else {
    //		printErr();
    //}
    return 0;
}

int cert_revoke() {
    // TODO : userID,
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

int printCert(CERT_V1 * cert) {
	print_data("Cert Version    : ", cert->ver, cert->len_ver);
	print_data("Serial Number   : ", cert->serialNum, cert->len_serialNum);
    print_data("Timestamp       : ", cert->timestamp, cert->len_timestamp);
	print_data("User ID         : ", cert->userID, cert->len_userID);
	print_data("User CI         : ", cert->userCI, cert->len_userCI);
	print_data("Cert Issuer     : ", cert->issuer, cert->len_issuer);
	print_data("CA Public Key   : ", cert->CAPubKey, cert->len_CAPubKey);
    printf("Valid Date      : %s ~ %s\n", cert->valFrom, cert->valTo);

	/*
    printf("Cert Version    : %s\n", cert->ver);
    printf("Serial Number   : %s\n", cert->serialNum);
    printf("Timestamp       : %s\n", cert->timestamp);
    printf("User ID         : %s\n", cert->userID);
    printf("User CI         : %s\n", cert->userCI);
    printf("Cert Issuer     : %s\n", cert->issuer);
    printf("CA Public Key   : %s\n", cert->CAPubKey);
    printf("Valid Date      : %s ~ %s\n", cert->valFrom, cert->valTo);
//    printf("Signature       : %s\n", cert->signature);
    */
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
