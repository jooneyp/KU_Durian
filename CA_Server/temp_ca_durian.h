#include "EBDCrypto.h"

/*
1. Version
2. CERT_SN
3. �߱� ���
4. �߱� ����
5. ���� ����
6. ����� �̸�
7. �ֹι�ȣ ���ڸ�(8�ڸ� ����)
8. ��ȭ��ȣ
9. USIM ID
10. ����� ID
11. ��� �˰�����
12. ����Ű��
13. 1~12�� ���� ������
*/
#define ERR_INVALID_INPUT					0x10000001

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
* Certification System ���� ����ü
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

	UCHAR len_pubKey;		// x��ǥ tag : 1����Ʈ + x��ǥ ���� : 1����Ʈ + x��ǥ �� : 32����Ʈ + y��ǥ tag : 1����Ʈ + y��ǥ ���� : 1����Ʈ + y��ǥ �� : 32����Ʈ = 68����Ʈ (0x44)�̹Ƿ� �׻� len_pubKey = 0x44 
	UCHAR len_pubKey_x;	// 0x20
	UCHAR pubKey_x[32];
	UCHAR len_pubKey_y;	// 0x20
	UCHAR pubKey_y[32];

	UCHAR len_signature;
	UCHAR signature[BUFSIZE];
}CERT_INFO;


/*!
* \brief
* ����� ���� ���� ����ü
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
* ������ ���� ü�� ����ü �ʱ�ȭ �Լ�
* \param cert
* ������ ���� ü�� ��� ���� ����ü (�������� �������� ������ ����ü) 
* \param conf_location
* ���� ���� ��ġ �Ǵ� ����
* \return
* -# ? : Success
* -# ? : Fail
*/


SINT generate_PUB(CERT_INFO * cert, UCHAR * target);
/*!
* \brief
* ����Ű ���� ���� �Լ�
* \param cert
* ������ ���� ü�� ��� ���� ����ü (CERT_init���� �ʱ�ȭ �ʿ�) 
* \param target
* ������ ����Ű ���� ��ġ
* \return
* -# ? : Success
* -# ? : Fail
*/


SINT generate_PUB_CSR(CERT_INFO * cert, USER_INFO * user, UCHAR * in, UCHAR * out, SINT out_len, SINT check_in, SINT check_out);
/*!
* \brief
* Root CA�� ���� ��û�� ����Ű ���� ���� �Լ�
* \param cert
* ������ ���� ü�� ��� ���� ����ü (CERT_init���� �ʱ�ȭ �ʿ�) 
* \param user
* ����� ���� ���� ����ü
* \param in
* ����Ű ���� ����Ǿ��ִ� ���� �Ǵ� ����
* \param out
* user�� ���� ����� ���� �Ǵ� ����
* \param out_len
* out�� ������ ��� out�� ����
* \param check_in
* in�� ���� ����̸� 1, �����̸� 0
* \param check_out
* out�� ���� ����̸� 1, �����̸� 0
* \return
* -# ? : Success
* -# ? : Fail

CSR ���� ���� : (tlv) CERT_USER_NAME	-> CERT_REGISTRATION_NUMBER -> CERT_PHONE_NUMBER -> CERT_USIM_ID ->	CERT_USER_ID -> CERT_USED_ALGORITHM -> CERT_CA_PUBKEY -> CERT_CA_PUBKEY_X -> CERT_CA_PUBKEY_Y
*/


SINT generate_signed_PUB(CERT_INFO * cert, UCHAR * in, UCHAR * out, UCHAR * salt, UINT salt_len, UINT iteration, SINT check_in, SINT check_out, SINT hash_alg, const UCHAR *d, ULONG d_len);
/*!
* \brief
* ������ ����Ű ���� �Լ�
* \param cert
* ������ ���� ü�� ��� ���� ����ü (CERT_init���� �ʱ�ȭ �ʿ�) 
* \param in
* CSR���� ��ġ
* \param out
* ������ ����Ű ���� ��ġ
* \param salt
* ������ salt���� ����� ���� 
* \param salt_len
* salt���ۿ� ����� �������� ���̰� ����� ����
* \param iteration
* ������ iteration ���� ����� ����
* \param check_in
* in�� ���� ����̸� 1, �����̸� 0
* \param check_out
* out�� ���� ����̸� 1, �����̸� 0
* \param hash_alg
* �ؽ� �˰����� ����
* \param d
* ������ ����� ������ ����Ű
* \param d_len
* d���ۿ� ����ִ� ������ ����
* \return
* -# ? : Success
* -# ? : Fail
*/
