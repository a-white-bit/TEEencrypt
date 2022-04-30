#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <TEEencrypt_ta.h>
#include <string.h>
#include <stdlib.h>

#define RSA_KEY_MAX 1024
unsigned int public_key;
unsigned int root_key;
TEE_Result RSA_create_key_pair(void *session);
struct rsa_session {
	TEE_OperationHandle op_handle;	/* RSA operation */
	TEE_ObjectHandle key_handle; /* Key handle */
};

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}


void TA_DestroyEntryPoint(void)
{
	// Nothing to do
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __maybe_unused param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	IMSG("Hello, This is TEEencrypt!\n");
	root_key = 5;

	struct rsa_session *sess;
	sess = TEE_Malloc(sizeof(*sess), 0);
	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	sess->key_handle = TEE_HANDLE_NULL;
	sess->op_handle = TEE_HANDLE_NULL;

	*sess_ctx = (void *)sess;
	DMSG(" Session %p: newly allocated\n", *sess_ctx);

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	struct rsa_session *sess;
	DMSG(" Session %p: release session", sess_ctx);
	sess = (struct rsa_session *)sess_ctx;

	/* Release the session resources
	   These tests are mandatories to avoid PANIC TA (TEE_HANDLE_NULL) */
	if (sess->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->key_handle);
	if (sess->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(sess->op_handle);
	TEE_Free(sess);

	IMSG("Goodbye!\n");
}

TEE_Result RSA_create_key_pair(void *session) {
	TEE_Result ret;
	int key_size = RSA_KEY_MAX;
	struct rsa_session *sess = (struct rsa_session *)session;
	
	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &sess->key_handle);
	DMSG("============= Transient object allocated. ============\n");

	ret = TEE_GenerateKey(sess->key_handle, key_size, (TEE_Attribute *)NULL, 0);
	DMSG("=================== Keys generated. ==================\n");
	return ret;
}

static TEE_Result my_encrypt(uint32_t param_types, TEE_Param params[4])
{
	char *buffer = (char *)params[0].memref.buffer;
	int size = params[0].memref.size;
	char *encrypted = malloc(size);
	memset(encrypted, 0, size);
	int enc_key;

	enc_key = root_key * public_key;
	params[1].value.a = enc_key;
	DMSG("========================Encryption========================\n");
	DMSG("public key: %d\n", public_key);
	DMSG("root key: %d\n", root_key);
	DMSG ("Plaintext: %s", buffer);
	memcpy(encrypted, buffer, size);

	for(int i=0; i<size; i++){
		if(encrypted[i]>='a' && encrypted[i] <='z'){
			encrypted[i] -= 'a';
			encrypted[i] += public_key;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'a';
		}
		else if (encrypted[i] >= 'A' && encrypted[i] <= 'Z') {
			encrypted[i] -= 'A';
			encrypted[i] += public_key;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'A';
		}
	}
	DMSG ("Ciphertext: %s", encrypted);
	memcpy(buffer, encrypted, size);
	free(encrypted);

	return TEE_SUCCESS;
}
static TEE_Result my_decrypt(uint32_t param_types, TEE_Param params[4])
{
	char *buffer = (char *)params[0].memref.buffer;
	int size = params[0].memref.size;
	char *decrypted = malloc(size);
	memset(decrypted, 0, size);
	int key = params[1].value.a / root_key;

	DMSG("========================Decryption========================\n");
	DMSG ("Ciphertext: %s", buffer);
	DMSG ("key: %d", key);
	memcpy(decrypted, buffer, size);

	for(int i=0; i<size; i++){
		if(decrypted[i]>='a' && decrypted[i] <='z'){
			decrypted[i] -= 'a';
			decrypted[i] -= key;
			decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
			decrypted[i] += 'a';
		}
		else if (decrypted[i] >= 'A' && decrypted[i] <= 'Z') {
			decrypted[i] -= 'A';
			decrypted[i] -= key;
			decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
			decrypted[i] += 'A';
		}
	}
	DMSG ("Plaintext: %s", decrypted);
	memcpy(buffer, decrypted, size);
	free(decrypted);

	return TEE_SUCCESS;
}

TEE_Result my_encrypt_rsa(void *session, uint32_t param_types, TEE_Param params[4])
{
	struct rsa_session *sess = (struct rsa_session *)session;
	char *buffer = (char *)params[0].memref.buffer;
	int size = params[0].memref.size;
	char *cipher = (char *)params[1].memref.buffer;
	int cipher_len = params[1].memref.size;
	TEE_ObjectInfo key_info;

	DMSG("==============Preparing encryption operation==============\n");
	TEE_GetObjectInfo1(sess->key_handle, &key_info);
	TEE_AllocateOperation(&(sess->op_handle), TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_ENCRYPT, key_info.keySize);
	DMSG("=============Operation allocated successfully.============\n");

	TEE_SetOperationKey(sess->op_handle, sess->key_handle);
    	DMSG("===============Operation key already set.=================\n");

	DMSG("Data to encrypt: %s\n", (char *) buffer);
	DMSG("data size: %d\n", size-1);

	TEE_AsymmetricEncrypt(sess->op_handle, (TEE_Attribute *)NULL, 0,
					buffer, size, cipher, &cipher_len);

	DMSG("Encrypted data: %s\n", cipher);
	DMSG("Cipher length: %d\n", cipher_len);
	DMSG("===============RSA Encryption successfully===============\n");
	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	switch (cmd_id) {
	case TA_TEEencrypt_CMD_GENKEYS_RSA:
		return RSA_create_key_pair(sess_ctx);
	case TA_TEEencrypt_CMD_MY_ENCRYPT:
		TEE_GenerateRandom(&public_key, sizeof(public_key));
		public_key = public_key % 26;
		return my_encrypt(param_types, params);
	case TA_TEEencrypt_CMD_MY_DECRYPT:
		return my_decrypt(param_types, params);
	case TA_TEEencrypt_CMD_MY_ENCRYPT_RSA:
		return my_encrypt_rsa(sess_ctx, param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
