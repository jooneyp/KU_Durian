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

int main() {
    CERT_V1 * cert_data = (CERT_V1 *) malloc ( sizeof (CERT_V1) );
    
    char * filename = "hex.data";
    * cert_data = tlv_to_cert(filename);
    
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
                strncpy(cert_data->ver, data, len+1);
                break;
            case CERT_SERIAL_NUMBER :
                strncpy(cert_data->serialNum, data, len);
                break;
            case CERT_TIMESTAMP :
                strncpy(cert_data->timestamp, data, len);
                break;
            case CERT_USER_ID :
                strncpy(cert_data->userID, data, len);
                break;
            case CERT_USER_CI :
                strncpy(cert_data->userCI, data, len);
                break;
            case CERT_ISSUER :
                strncpy(cert_data->issuer, data, len);
                break;
            case CERT_CA_PUBKEY :
                strncpy(cert_data->CAPubKey, data, len);
                break;
            case CERT_VALID_FROM :
                strncpy(cert_data->valFrom, data, len);
                break;
            case CERT_VALID_TO :
                strncpy(cert_data->valTo, data, len);
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
    printf("Cert Version    : %s\n", cert->ver);
    printf("Serial Number   : %s\n", cert->serialNum);
    printf("Timestamp       : %s\n", cert->timestamp);
    printf("User ID         : %s\n", cert->userID);
    printf("User CI         : %s\n", cert->userCI);
    printf("Cert Issuer     : %s\n", cert->issuer);
    printf("CA Public Key   : %s\n", cert->CAPubKey);
    printf("Valid Date      : %s ~ %s\n", cert->valFrom, cert->valTo);
//    printf("Signature       : %s\n", cert->signature);
    
    return 0;
}