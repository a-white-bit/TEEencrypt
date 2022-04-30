#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>
#include <TEEencrypt_ta.h>

int main(int argc, char *argv[])
{
	if (argc != 4){ printf("Invalid argument\n"); return 0; }
	int enc_mode;
	if (strcmp(argv[1], "-e") == 0)
	{
		if (strcmp(argv[3], "Ceasar") == 0) enc_mode = ENC_MODE_CEASAR;
		else if (strcmp(argv[3], "RSA") == 0) enc_mode = ENC_MODE_RSA;
		else { printf("Invalid argument\n"); return 0; }
	}
	else if (strcmp(argv[1], "-d") == 0) enc_mode = ENC_MODE_DEC;
	else { printf("Invalid argument\n"); return 0; }


	FILE *fp_read, *fp_write, *fp_read_key, *fp_write_key;
	fp_read_key = NULL;
	fp_write_key = NULL;

	fp_read = fopen(argv[2], "r");
	if (fp_read == NULL) { printf("File open Error\n"); return 0; }
	if (enc_mode == ENC_MODE_CEASAR)
	{
		fp_write = fopen("ciphertext.txt", "w");
		fp_write_key = fopen("encryptedkey.txt", "w");
		if (fp_write == NULL || fp_write_key == NULL)
		 { printf("File open Error\n"); return 0; }
	}
	else if (enc_mode == ENC_MODE_RSA)
	{
		fp_write = fopen("ciphertext_RSA.txt", "w");
		if (fp_write == NULL)
		 { printf("File open Error\n"); return 0; }
	}
	else if (enc_mode == ENC_MODE_DEC)
	{
		fp_read_key = fopen(argv[3], "r");
		fp_write = fopen("plaintext.txt", "w");
		if (fp_read_key == NULL || fp_write == NULL)
		 { printf("File open Error\n"); return 0; }
	}


	int size;
	char *buffer;
	char key[5];

	fseek(fp_read, 0, SEEK_END);
	size = ftell(fp_read);
	fseek(fp_read, 0, SEEK_SET);
	buffer = malloc(size);
	memset(buffer, 0, size);
	memset(key, 0, 5);

	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;

	res = TEEC_InitializeContext(NULL, &ctx);
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = buffer;
	op.params[0].tmpref.size = size;

	fread(buffer, size, 1, fp_read);
	memcpy(op.params[0].tmpref.buffer, buffer, size);
	if (enc_mode == ENC_MODE_CEASAR)
	{
		printf("====================Encryption(Ceasar)====================\n");
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_MY_ENCRYPT, &op,
					 &err_origin);
		memcpy(buffer, op.params[0].tmpref.buffer, size);
		printf("Cipertext : %s\n", buffer);
		fwrite(buffer, 1, size, fp_write);
		sprintf(key, "%d", op.params[1].value.a);
		//printf("key : %d\n", op.params[1].value.a);
		//printf("key size : %d\n", strlen(key));
		fwrite(key, 1, strlen(key), fp_write_key);
	}
	else if (enc_mode == ENC_MODE_RSA)
	{
		char buffer_rsa[1024/8];
		int size_rsa = 1024/8;
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
		printf("=====================Encryption(RSA)======================\n");
		op.params[1].tmpref.buffer = buffer_rsa;
		op.params[1].tmpref.size = size_rsa;
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_GENKEYS_RSA, NULL, NULL);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_MY_ENCRYPT_RSA, &op,
					 &err_origin);
		memcpy(buffer_rsa, op.params[1].tmpref.buffer, size);
		printf("Cipertext : %s\n", buffer);
		fwrite(buffer_rsa, 1, size_rsa, fp_write);
	}
	else if (enc_mode == ENC_MODE_DEC)
	{
		printf("========================Decryption========================\n");
		fread(key, 5, 1, fp_read_key);
		op.params[1].value.a = atoi(key);
		//printf("key : %d\n", op.params[1].value.a);
		//printf("key size : %d\n", strlen(key));
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_MY_DECRYPT, &op,
					 &err_origin);

		memcpy(buffer, op.params[0].tmpref.buffer, size);
		printf("Plaintext : %s\n", buffer);
		fwrite(buffer, 1, size, fp_write);
	}
    	free(buffer);
	fclose(fp_read);
	fclose(fp_write);
	if (fp_read_key != NULL) fclose(fp_read_key);
	if (fp_write_key != NULL) fclose(fp_write_key);
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
