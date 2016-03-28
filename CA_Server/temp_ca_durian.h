#include "EBDCrypto.h"

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
#define VALID_CERT					0x0D
#define INVALID_CERT				0x0E
#define EXPIRE_CERT					0x0F

#define ERR_INVALID_INPUT					0x10000001
#define ERR_INVALID_SN						0x10000011
#define ERR_VERIFY_FAILURE					0x40000006

#define ERR_NO_FILE					0x0A
#define ERR_OPEN_FILE				0x0B
#define ERR_CERT_TAG				0x0C



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
#define CERT_CA_PUBKEY_X			0x81
#define CERT_CA_PUBKEY_Y			0x82
#define	CERT_SIGNATURE				0x90


#define BUFSIZE						128

/*!
* \brief
* Certification System 지원 구조체
*/
typedef struct cert_conf_structure
{
	UCHAR len_Ver;
	UCHAR Ver;
	
	UCHAR len_Cert_SN;
	UCHAR Cert_SN[BUFSIZE];
	
	UCHAR len_issuer;
	UCHAR issuer[BUFSIZE];

	UCHAR len_issueDate;
	UCHAR issueDate[BUFSIZE];

	UCHAR len_expirationDate;
	UCHAR expirationDate[BUFSIZE];

	UCHAR len_userName;
	UCHAR userName[BUFSIZE];

	UCHAR len_registrationNum;
	UCHAR registrationNum[BUFSIZE];

	UCHAR len_phoneNum;
	UCHAR phoneNum[BUFSIZE];

	UCHAR len_USIMID;
	UCHAR USIMID[BUFSIZE];

	UCHAR len_userID;
	UCHAR userID[BUFSIZE];

	UCHAR len_usedAlgorithm;
	UCHAR usedAlgorithm[BUFSIZE];

	UCHAR len_pubKey;		// x좌표 tag : 1바이트 + x좌표 길이 : 1바이트 + x좌표 값 : 32바이트 + y좌표 tag : 1바이트 + y좌표 길이 : 1바이트 + y좌표 값 : 32바이트 = 68바이트 (0x44)이므로 항상 len_pubKey = 0x44 
	UCHAR len_pubKey_x;	// 0x20
	UCHAR pubKey_x[32];
	UCHAR len_pubKey_y;	// 0x20
	UCHAR pubKey_y[32];

	UCHAR len_signature;
	UCHAR signature[BUFSIZE];
}CERT_INFO;


/*!
* \brief
* 사용자 정보 저장 구조체
*/
typedef struct userinfo_structure
{
	UCHAR len_userName;
	UCHAR userName[BUFSIZE];
	UCHAR len_registrationNum;
	UCHAR registrationNum[BUFSIZE];
	UCHAR len_phoneNum;
	UCHAR phoneNum[BUFSIZE];
	UCHAR len_USIMID;
	UCHAR USIMID[BUFSIZE];
	UCHAR len_userID;
	UCHAR userID[BUFSIZE];
	UCHAR len_usedAlgorithm;
	UCHAR usedAlgorithm[BUFSIZE];
	UCHAR len_pubKey_x;
	UCHAR pubKey_x[32];
	UCHAR len_pubKey_y;
	UCHAR pubKey_y[32];
}USER_INFO;


SINT Cert_init(CERT_INFO * cert, UCHAR * conf_location);
/*!
* \brief
* 인증서 관리 체계 구조체 초기화 함수
* \param cert
* 인증서 관리 체계 운영을 위한 구조체 (인증서의 정보들을 저장할 구조체) 
* \param conf_location
* 설정 파일 위치
* \return
* -# ? : Success
* -# ? : Fail
*/


SINT Cert_init_buffer(CERT_INFO * cert, UCHAR * buff);
/*!
* \brief
* 인증서 관리 체계 구조체 초기화 함수
* \param cert
* 인증서 관리 체계 운영을 위한 구조체 (인증서의 정보들을 저장할 구조체) 
* \param conf_location
* 설정 버퍼
* \return
* -# ? : Success
* -# ? : Fail
*/


SINT generate_PUB(CERT_INFO * cert, UCHAR * target);
/*!
* \brief
* 공개키 파일 생성 함수
* \param cert
* 인증서 관리 체계 운영을 위한 구조체 (CERT_init으로 초기화 필요) 
* \param target
* 생성할 공개키 파일 위치
* \return
* -# ? : Success
* -# ? : Fail
*/


SINT generate_PUB_CSR(CERT_INFO * cert, USER_INFO * user, UCHAR * in, UCHAR * out, SINT out_len, SINT check_in, SINT check_out);
/*!
* \brief
* Root CA에 서명 요청할 공개키 정보 생성 함수
* \param cert
* 인증서 관리 체계 운영을 위한 구조체 (CERT_init으로 초기화 필요) 
* \param user
* 사용자 정보 저장 구조체
* \param in
* 공개키 값이 저장되어있는 파일 또는 버퍼
* \param out
* user의 값이 저장될 파일 또는 버퍼
* \param out_len
* out이 버퍼일 경우 out의 길이
* \param check_in
* in이 파일 경로이면 1, 버퍼이면 0
* \param check_out
* out이 파일 경로이면 1, 버퍼이면 0
* \return
* -# ? : Success
* -# ? : Fail

CSR 파일 구조 : (tlv) CERT_USER_NAME	-> CERT_REGISTRATION_NUMBER -> CERT_PHONE_NUMBER -> CERT_USIM_ID ->	CERT_USER_ID -> CERT_USED_ALGORITHM -> CERT_CA_PUBKEY -> CERT_CA_PUBKEY_X -> CERT_CA_PUBKEY_Y
*/


SINT generate_signed_PUB(CERT_INFO * cert, UCHAR * in, UCHAR * out, UCHAR * salt, UINT salt_len, UINT iteration, SINT check_in, SINT check_out, SINT hash_alg, const UCHAR *d, ULONG d_len);
/*!
* \brief
* 서명된 공개키 생성 함수
* \param cert
* 인증서 관리 체계 운영을 위한 구조체 (CERT_init으로 초기화 필요) 
* \param in
* CSR파일 위치
* \param out
* 서명된 공개키 파일 위치
* \param salt
* 생성된 salt값이 저장될 버퍼 
* \param salt_len
* salt버퍼에 저장된 데이터의 길이가 저장될 변수
* \param iteration
* 생성된 iteration 값이 저장될 변수
* \param check_in
* in이 파일 경로이면 1, 버퍼이면 0
* \param check_out
* out이 파일 경로이면 1, 버퍼이면 0
* \param hash_alg
* 해시 알고리즘 종류
* \param d
* 서명에 사용할 서버의 개인키
* \param d_len
* d버퍼에 들어있는 데이터 길이
* \return
* -# ? : Success
* -# ? : Fail
*/


SINT revoke_PUB(SINT cert_SN, UCHAR * reason, SINT hash_alg, const UCHAR *d, ULONG d_len);
/*!
* \brief
* 공개키 revoke 함수 
* \param cert_SN
* 폐지할 공개키 시리얼 넘버
* \param reason
* 폐지 사유
* \param hash_alg
* 사용된, 사용할 해쉬 함수 // 폐지될 인증서 서명 생성할 때 필요
* \param d
* 서명에 사용할 서버의 개인키
* \param d_len
* d버퍼에 들어있는 데이터 길이
* \return
* -# ? : Success
* -# ? : Fail
*/


SINT cert2tlv_exceptSign(CERT_INFO * cert, UCHAR * temp_out, SINT offset);
/*!
* \brief
* 인증서 구조체를 tlv형태로 버퍼에 저장
* \param cert
* 인증서 관리 체계 운영을 위한 구조체 (CERT_init으로 초기화 필요) 
* \param temp_out
* tlv형태의 데이터가 저장될 변수
* \param offset
* 변수 offset설정을 위한 값
* \return
* -# ? : Success
* -# ? : Fail
*/


SINT check_cert_Station(SINT cert_SN, UCHAR * reason, SINT hash_alg, const UCHAR *d, ULONG d_len);
/*!
* \brief
* 인증서가 유효한 것인지 체크
* \param cert_SN
* DB에서 cert_SN을 통해 인증서 찾기
* \param hash_alg
* 사용된, 사용할 해쉬 함수 // 서명 값 검증 시 필요
* \param d
* 서명검증에 사용할 서버의 개인키
* \param d_len
* d버퍼에 들어있는 데이터 길이
* \return
* -# ? : Success
* -# ? : Fail
*/


SINT regenerate_cert(CERT_INFO * cert, SINT cert_SN, UCHAR * reason, SINT hash_alg, const UCHAR *d, ULONG d_len, UCHAR * in, UCHAR * out, UCHAR * salt, UINT salt_len, UINT iteration, SINT check_in, SINT check_out);
/*
	1. cert에 새로 갱신할 때 필요한 인증서값 저장, cert_SN은 폐기되어야할 인증서 시리얼 넘버, reason은 폐기 사유
	2. revoke_PUB(SINT cert_SN, UCHAR * reason, SINT hash_alg, const UCHAR *d, ULONG d_len)를 통해 해당 cert_SN 폐기
	3. generate_signed_PUB(CERT_INFO * cert, UCHAR * in, UCHAR * out, UCHAR * salt, UINT salt_len, UINT iteration, SINT check_in, SINT check_out, SINT hash_alg, const UCHAR *d, ULONG d_len)을 통해 새로운 인증서 발급
		이때, in은 CSR정보가 저장된 곳
*/