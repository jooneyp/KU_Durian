#ifndef HEADER_ERROR_H
#define HEADER_ERROR_H
//
#define EBD_CRYPTO_SUCCESS						1
#define EBD_CRYPTO_FAIL							0

#define ERR_MASK						0x0000FFFF  /*!< */
//
#define ERR_INIT_FAILURE				0x00000001	/*!< */
#define ERR_INIT_KEY_FAILURE			0x00000002	/*!< */
#define ERR_INVALID_INPUT				0x00000003	/*!< */
#define ERR_INVALID_ALGORITHM_ID		0x00000004	/*!< */
#define ERR_INVALID_OPERATION_MASK		0x00000005  /*!< */
#define ERR_INVALID_PADDING				0x00000006	/*!< */
#define ERR_CIPHER_ENCRYPT_FAILURE		0x00000007	/*!< */
#define ERR_CIPHER_DECRYPT_FAILURE		0x00000008	/*!< */
#define ERR_UPDATE_FAILURE				0x00000009	/*!< */
#define ERR_FINAL_FAILURE				0x0000000A  /*!< */
#define ERR_INVALID_UNIT				0x0000000B	/*!< */
#define ERR_DIVIDE_BY_ZERO				0x0000000C	/*!< */
#define ERR_SIGN_FAILURE				0x00000100	/*!< */
#define ERR_VERIFY_FAILURE				0x00000200	/*!< */
#define ERR_INVALID_ENCODE_MODE			0x00000300  /*!< */
#define ERR_MALLOC						0x00000400	/*!< */
#define ERR_BIGINT_MEM_EXPAND_FAILURE	0x00000500	/*!< */
#define ERR_SUB_OPEATION_FAILURE		0x00000600	/*!< */
#define ERR_RANDOM_GEN_FAILURE			0x00000700	/*!< */
#define ERR_ENCODING_FAILURE			0x00000800  /*!< */
#define ERR_DECODING_FAILURE			0x00000900	/*!< */
#define ERR_INVALID_RSA_ENCODING		0x00000A00	/*!< */
#define ERR_NO_PUBLIC_VALUE				0x00000B00	/*!< */
#define ERR_NO_PRIVATE_VALUE			0x00000C00	/*!< */
#define ERR_MESSAGE_TOO_LONG			0x00000D00  /*!< */
#define ERR_SIGNATURE_TOO_LONG			0x00000E00	/*!< */
#define ERR_NULL_XKEY_VALUE				0x00000F00	/*!< */
#define ERR_INPUT_BUF_TOO_SHORT			0x00001000	/*!< */
#define ERR_INVALID_PASSWORD			0x00001100	/*!< */
#define ERR_KEY_GEN_FAIL				0x00001200  /*!< */

#define ERR_INVALID_OUTPUT				0x00001300 
#define ERR_FAIL_FILE					0x00001400

#endif