#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <mbedtls/aes.h> /* Compile mbedtls first. */
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

/**
 * AES key/iv generator.
 * @param[out] key Buffer to store key/iv after generation.
 * @param[in] key_bytes Must be 16 or 32.
 * @return NULL: Failed. others: generated key/iv.
 */
unsigned char *aes_key_generator(unsigned char *key, size_t key_bytes)
{
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
	char *pers = "AES Initialization Vector";
	int ret = 0;

	if (!key || (key_bytes != 16 && key_bytes != 32))
		return NULL;

	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
				&entropy, (unsigned char *)pers, strlen(pers));
	if (!ret)
		ret = mbedtls_ctr_drbg_random(&ctr_drbg, key, key_bytes);

	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	if (ret)
		return NULL;

	return key;
}

/**
 * AES ECB encryption/decryption.
 * @param[in] mode MBEDTLS_AES_ENCRYPT or MBEDTLS_AES_DECRYPT.
 * @param[in] length The length of the input data,
 * input size must be a multiple of 16.
 * @param[in] key Encryption key.
 * @param[in] key_bits Must be 128, 192 or 256.
 * @param[in] input 16-byte input block.
 * @param[out] output 16-byte output block.
 * @return true: Succeeded. false: Failed.
 */
bool aes_ecb_crypt(int mode, size_t length,
		const unsigned char *key, unsigned int key_bits,
		const unsigned char *input, unsigned char *output)
{
	mbedtls_aes_context ctx;
	size_t round = length / 16;
	bool ret = true;

	if (!key || !input || !output)
		return false;

	if (length % 16)
		return false;

	if (mode != MBEDTLS_AES_ENCRYPT && mode != MBEDTLS_AES_DECRYPT)
		return false;

	if (key_bits != 128 && key_bits != 192 && key_bits != 256)
		return false;

	mbedtls_aes_init(&ctx);
	if (mode == MBEDTLS_AES_ENCRYPT) {
		if (mbedtls_aes_setkey_enc(&ctx, key, key_bits))
			ret = false;
	} else {
		if (mbedtls_aes_setkey_dec(&ctx, key, key_bits))
			ret = false;
	}

	if (ret) {
		for (size_t i = 0; i != round; i++) {
			if (mbedtls_aes_crypt_ecb(&ctx, mode,
					input + (i * 16), output + (i * 16))) {
				ret = false;
				break;
			}
		}
	}

	mbedtls_aes_free(&ctx);

	return ret;
}

/**
 * AES ECB encryption with pad.
 * @param[in] length The length of the input data.
 * @param[in] pad The pad character.
 * @param[in] key Encryption key.
 * @param[in] key_bits Must be 128, 192 or 256.
 * @param[in] input The input data stream.
 * @param[out] output The output data stream.
 * The output size must >= ceil(length / 16.0) * 16.
 * @return true: Succeeded. false: Failed.
 */
bool aes_ecb_encrypt_pad(size_t length, char pad,
		const unsigned char *key, unsigned int key_bits,
		const unsigned char *input, unsigned char *output)
{
	size_t remainder = length % 16;
	size_t buf_length = length + (16 - remainder);
	size_t pad_length = (remainder) ? (16 - remainder) : 0;
	unsigned char *in_buf = NULL;
	bool ret = true;

	in_buf = calloc(buf_length, 1);
	if (!in_buf)
		return false;

	memcpy(in_buf, input, length);
	memset(in_buf + length, pad, pad_length);
	ret = aes_ecb_crypt(MBEDTLS_AES_ENCRYPT,
			buf_length, key, key_bits, in_buf, output);

	free(in_buf);
	in_buf = NULL;

	return ret;
}

/**
 * AES ECB decryption with pad, pad will removed after being decrypted
 * according to the length of the output data.
 * @param[in] in_length The length of the input data,
 * input size must be a multiple of 16.
 * @param[in] out_length The expected length of the output data without pad.
 * @param[in] key Encryption key.
 * @param[in] key_bits Must be 128, 192 or 256.
 * @param[in] input The input data stream.
 * @param[out] output The output data stream.
 * The output size must >= ceil(length / 16.0) * 16.
 * @return true: Succeeded. false: Failed.
 */
bool aes_ecb_decrypt_pad(size_t in_length, size_t out_length,
		const unsigned char *key, unsigned int key_bits,
		const unsigned char *input, unsigned char *output)
{
	size_t pad_length = in_length - out_length;
	bool ret = true;

	if (pad_length < 0)
		return false;

	ret = aes_ecb_crypt(MBEDTLS_AES_DECRYPT,
			in_length, key, key_bits, input, output);

	memset(output + out_length, 0, pad_length);

	return ret;
}

/**
 * AES CBC encryption/decryption.
 * @param[in] mode MBEDTLS_AES_ENCRYPT or MBEDTLS_AES_DECRYPT.
 * @param[in] length The length of the input data,
 * input size must be a multiple of 16.
 * @param[in] key Encryption key.
 * @param[in] key_bits Must be 128, 192 or 256.
 * @param[in] iv Initialization vector.
 * @param[in] input The input data stream.
 * @param[out] output The output data stream.
 * @return true: Succeeded. false: Failed.
 */
bool aes_cbc_crypt(int mode, size_t length,
		const unsigned char *key, unsigned int key_bits,
		unsigned char iv[16], const unsigned char *input,
		unsigned char *output)
{
	mbedtls_aes_context ctx;
	bool ret = true;

	if (!key || !iv || !input || !output)
		return false;

	if (length % 16)
		return false;

	if (mode != MBEDTLS_AES_ENCRYPT && mode != MBEDTLS_AES_DECRYPT)
		return false;

	if (key_bits != 128 && key_bits != 192 && key_bits != 256)
		return false;

	mbedtls_aes_init(&ctx);
	if (mode == MBEDTLS_AES_ENCRYPT) {
		if (mbedtls_aes_setkey_enc(&ctx, key, key_bits))
			ret = false;
	} else {
		if (mbedtls_aes_setkey_dec(&ctx, key, key_bits))
			ret = false;
	}

	if (ret) {
		if (mbedtls_aes_crypt_cbc(
				&ctx, mode, length, iv, input, output))
			ret = false;
	}

	mbedtls_aes_free(&ctx);

	return ret;
}

/**
 * AES CBC encryption with pad.
 * @param[in] length The length of the input data.
 * @param[in] pad The pad character.
 * @param[in] key Encryption key.
 * @param[in] key_bits Must be 128, 192 or 256.
 * @param[in] iv Initialization vector.
 * @param[in] input The input data stream.
 * @param[out] output The output data stream.
 * The output size must >= ceil(length / 16.0) * 16.
 * @return true: Succeeded. false: Failed.
 */
bool aes_cbc_encrypt_pad(size_t length, char pad,
		const unsigned char *key, unsigned int key_bits,
		unsigned char iv[16], const unsigned char *input,
		unsigned char *output)
{
	size_t remainder = length % 16;
	size_t buf_length = length + (16 - remainder);
	size_t pad_length = (remainder) ? (16 - remainder) : 0;
	unsigned char *in_buf = NULL;
	bool ret = true;

	in_buf = calloc(buf_length, 1);
	if (!in_buf)
		return false;

	memcpy(in_buf, input, length);
	memset(in_buf + length, pad, pad_length);
	ret = aes_cbc_crypt(MBEDTLS_AES_ENCRYPT,
			buf_length, key, key_bits, iv, in_buf, output);

	free(in_buf);
	in_buf = NULL;

	return ret;
}

/**
 * AES CBC decryption with pad, pad will removed after being decrypted
 * according to the length of the output data.
 * @param[in] in_length The length of the input data,
 * input size must be a multiple of 16.
 * @param[in] out_length The expected length of the output data without pad.
 * @param[in] key Encryption key.
 * @param[in] key_bits Must be 128, 192 or 256.
 * @param[in] iv Initialization vector.
 * @param[in] input The input data stream.
 * @param[out] output The output data stream.
 * The output size must >= ceil(length / 16.0) * 16.
 * @return true: Succeeded. false: Failed.
 */
bool aes_cbc_decrypt_pad(size_t in_length, size_t out_length,
		const unsigned char *key, unsigned int key_bits,
		unsigned char iv[16], const unsigned char *input,
		unsigned char *output)
{
	size_t pad_length = in_length - out_length;
	bool ret = true;

	if (pad_length < 0)
		return false;

	ret = aes_cbc_crypt(MBEDTLS_AES_DECRYPT,
			in_length, key, key_bits, iv, input, output);

	memset(output + out_length, 0, pad_length);

	return ret;
}

/**
 * Test AES functions.
 * @param[in] argc Number of arguments.
 * @param[in] argv Array of arguments.
 * @return 0: Succeeded. others: Failed.
 */
int main(int argc, char *argv[])
{
	unsigned char input[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	unsigned char output[32] = {0};
	unsigned char key[] = "ZX*vGzJb!J^JX5LfeGvA8NJZ9DjfvSV#";
	unsigned char iv[16] = {0};
	unsigned char iv_2[16] = {0};
	size_t length = strlen((char *)input);

	printf("Original text: %s\n", input);
	printf("Test CTR_DRBG\n");
	if (aes_key_generator(iv, 16))
		memcpy(iv_2, iv, sizeof(iv_2));
	else
		exit(EXIT_FAILURE);

	printf("iv:");
	for (size_t i = 0; i != sizeof(iv); i++)
		printf(" 0x%02x", iv[i]);

	printf("\nTest AES256 ECB\n");
	if (!aes_ecb_encrypt_pad(length, 0, key, 256, input, output))
		exit(EXIT_FAILURE);

	memset(input, 0, sizeof(input));
	if (!aes_ecb_decrypt_pad(sizeof(output),
			length, key, 256, output, input))
		exit(EXIT_FAILURE);

	printf("ECB plaintext: %s\n", input);

	printf("Test AES256 CBC\n");
	memset(output, 0, sizeof(output));
	if (!aes_cbc_encrypt_pad(length, 0,
				key, 256, iv, input, output))
		exit(EXIT_FAILURE);

	memset(input, 0, sizeof(input));
	if (!aes_cbc_decrypt_pad(sizeof(output),
			length, key, 256, iv_2, output, input))
		exit(EXIT_FAILURE);

	printf("CBC plaintext: %s\n", input);

	return 0;
}
