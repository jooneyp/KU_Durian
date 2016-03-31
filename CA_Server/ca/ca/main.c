//
//  main.c
//  ca
//
//  Created by Jooney on 3/30/16.
//  Copyright © 2016 Jooney. All rights reserved.
//

#include <stdio.h>
#include "EBDCrypto.h"
#include "EBDerror.h"
#include "ca.h"
#include "DBConnector.h"

int main(int argc, const char * argv[]) {
    CERT_INFO cert;
    USER_INFO user;
    SINT result_code;
    UCHAR * conf = "/Users/jooney/Documents/Working Dir3/KU_Durian/CA_Server/cert.txt";
    UCHAR * input;
    UCHAR out_len;
    UCHAR * pub = "/Users/jooney/Downloads/publickey.txt";
    UCHAR output[BUFSIZE * 12];
    UCHAR conf_location[5000] = "\x01\x01\x02\x03\x05\x31\x32\x33\x34\x30\x05\x0f\x6b\x6f\x72\x65\x61\x75\x6e\x69\x76\x65\x72\x73\x69\x74\x79\x10\x0e\x32\x30\x31\x35\x31\x31\x31\x34\x31\x32\x33\x32\x31\x39\x11\x0e\x32\x30\x31\x36\x30\x33\x32\x34\x30\x39\x34\x35\x31\x32\x21\x09\x6c\x65\x65\x73\x75\x6e\x77\x6f\x6f\x30\x06\x39\x32\x31\x31\x31\x34\x40\x0b\x30\x31\x30\x34\x31\x30\x37\x31\x37\x32\x32\x50\x06\x55\x53\x49\x4d\x49\x44\x60\x07\x6c\x73\x77\x6f\x6f\x39\x32\x70\x05\x31\x2e\x32\x2e\x35\x80\x44\x81\x20\x70\x75\x62\x4b\x65\x79\x5f\x78\x70\x75\x62\x4b\x65\x79\x5f\x78\x70\x75\x62\x4b\x65\x79\x5f\x78\x70\x75\x62\x4b\x65\x79\x5f\x78\x82\x20\x70\x75\x62\x4b\x65\x79\x5f\x79\x70\x75\x62\x4b\x65\x79\x5f\x79\x70\x75\x62\x4b\x65\x79\x5f\x79\x70\x75\x62\x4b\x65\x79\x5f\x79\x90\x40\x73\x69\x67\x6e\x61\x74\x75\x72\x73\x69\x67\x6e\x61\x74\x75\x72\x73\x69\x67\x6e\x61\x74\x75\x72\x73\x69\x67\x6e\x61\x74\x75\x72\x73\x69\x67\x6e\x61\x74\x75\x72\x73\x69\x67\x6e\x61\x74\x75\x72\x73\x69\x67\x6e\x61\x74\x75\x72\x73\x69\x67\x6e\x61\x74\x75\x72\x70\x70";
    
    result_code = Cert_init_buffer(&cert, conf_location);
    
    printf("%d\n", result_code);
    
    user.len_userName = 6;
    memcpy(user.userName, "parkjy", 6);
    user.len_phoneNum = 11;
    memcpy(user.phoneNum, "01097662526", 11);
    user.len_registrationNum = 6;
    memcpy(user.registrationNum, "900104", 6);
    user.len_userID = 10;
    memcpy(user.userID, "parkjy1917", 10);
    user.len_USIMID = 12;
    memcpy(user.USIMID, "adsfasdfasdf", 12);
    user.len_usedAlgorithm = 4;
    memcpy(user.usedAlgorithm, "SHA1", 4);
    
    char pubbuf[1000] = "\x01\x01\x02\x03\x05\x31\x32\x33\x34\x30\x05\x0f\x6b\x6f\x72\x65\x61\x75\x6e\x69\x76\x65\x72\x73\x69\x74\x79\x10\x0e\x32\x30\x31\x35\x31\x31\x31\x34\x31\x32\x33\x32\x31\x39\x11\x0e\x32\x30\x31\x36\x30\x33\x32\x34\x30\x39\x34\x35\x31\x32\x21\x09\x6c\x65\x65\x73\x75\x6e\x77\x6f\x6f\x30\x06\x39\x32\x31\x31\x31\x34\x40\x0b\x30\x31\x30\x34\x31\x30\x37\x31\x37\x32\x32\x50\x06\x55\x53\x49\x4d\x49\x44\x60\x07\x6c\x73\x77\x6f\x6f\x39\x32\x70\x05\x31\x2e\x32\x2e\x35\x80\x44\x81\x20\x70\x75\x62\x4b\x65\x79\x5f\x78\x70\x75\x62\x4b\x65\x79\x5f\x78\x70\x75\x62\x4b\x65\x79\x5f\x78\x70\x75\x62\x4b\x65\x79\x5f\x78\x82\x20\x70\x75\x62\x4b\x65\x79\x5f\x79\x70\x75\x62\x4b\x65\x79\x5f\x79\x70\x75\x62\x4b\x65\x79\x5f\x79\x70\x75\x62\x4b\x65\x79\x5f\x79\x90\x40\x73\x69\x67\x6e\x61\x74\x75\x72\x73\x69\x67\x6e\x61\x74\x75\x72\x73\x69\x67\x6e\x61\x74\x75\x72\x73\x69\x67\x6e\x61\x74\x75\x72\x73\x69\x67\x6e\x61\x74\x75\x72\x73\x69\x67\x6e\x61\x74\x75\x72\x73\x69\x67\x6e\x61\x74\x75\x72\x73\x69\x67\x6e\x61\x74\x75\x72\x70\x70";
    printf("%s", pubbuf);
    
    result_code = generate_PUB_CSR(&cert, &user, pubbuf, output, out_len, 0, 0);
    
    printf("%d\n", result_code);
    
    return 0;
}
