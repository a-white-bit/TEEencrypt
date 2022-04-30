
#ifndef TA_TEEencrypt_H
#define TA_TEEencrypt_H


/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_TEEencrypt_UUID \
	{ 0xf6052d88, 0x0d9e, 0x4ebd, \
		{ 0xbe, 0x5d, 0xec, 0xdf, 0x55, 0x13, 0x41, 0x28} }

/* The function IDs implemented in this TA */
#define TA_TEEencrypt_CMD_MY_ENCRYPT_RSA	1
#define TA_TEEencrypt_CMD_MY_ENCRYPT		2
#define TA_TEEencrypt_CMD_MY_DECRYPT		3
#define TA_TEEencrypt_CMD_GENKEYS_RSA		4

#define ENC_MODE_RSA 		TA_TEEencrypt_CMD_MY_ENCRYPT_RSA
#define ENC_MODE_CEASAR 	TA_TEEencrypt_CMD_MY_ENCRYPT
#define ENC_MODE_DEC		TA_TEEencrypt_CMD_MY_DECRYPT

#endif /*TA_TEEencrypt_H*/
