#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/bignum.h>
#include <mbedtls/rsa.h>

/**
 * Write MPI to buffer.
 * @param[in] prefix The prefix of MPI.
 * @param[in] mpi The source MPI.
 * @param[out] buf The buffer to store MPI.
 * @param[in] buf_size The buffer size.
 * @param[in] radix The numeric base of the output string.
 * @return true: Succeeded. false: Failed.
 */
static size_t rsa_mpi_write_buffer(const char *prefix,
		const mbedtls_mpi *mpi, char *buf, size_t buf_size, int radix)
{
	size_t output_length = 0;
	size_t str_length = 0;
	size_t prefix_length = 0;
	char str[MBEDTLS_MPI_RW_BUFFER_SIZE] = {0};

	if (!mpi)
		return 0;

	if (buf_size < sizeof(str))
		return 0;

	if (radix < 2 || radix > 16)
		return 0;

	memset(str, 0, sizeof(str));

	if (mbedtls_mpi_write_string(mpi, radix, str,
				sizeof(str) - 2, &output_length))
		return 0;

	if (!prefix)
		prefix = "";

	prefix_length = strlen(prefix);
	str_length = strlen(str);
	str[str_length++] = '\r';
	str[str_length++] = '\n';
	snprintf(buf, buf_size, "%.*s%.*s",
			(int)prefix_length, prefix, (int)str_length, str);

	return strlen(buf);
}

/**
 * Write RSA key to files.
 * @param[in] rsa The RSA context.
 * @param[out] priv The file path to store a private key.
 * @param[out] pub The file path to store a public key.
 * @return true: Succeeded. false: Failed.
 */
static bool rsa_key_write_file(mbedtls_rsa_context *rsa,
			const char *priv, const char *pub)
{
	mbedtls_mpi N;
	mbedtls_mpi P;
	mbedtls_mpi Q;
	mbedtls_mpi D;
	mbedtls_mpi E;
	mbedtls_mpi DP;
	mbedtls_mpi DQ;
	mbedtls_mpi QP;
	FILE *public_file  = NULL;
	FILE *private_file = NULL;
	bool ret = false;

	if (!rsa || !priv || !pub)
		return false;

	mbedtls_mpi_init(&N);
	mbedtls_mpi_init(&P);
	mbedtls_mpi_init(&Q);
	mbedtls_mpi_init(&D);
	mbedtls_mpi_init(&E);
	mbedtls_mpi_init(&DP);
	mbedtls_mpi_init(&DQ);
	mbedtls_mpi_init(&QP);

	if (mbedtls_rsa_export(rsa, &N, &P, &Q, &D, &E) ||
			mbedtls_rsa_export_crt(rsa, &DP, &DQ, &QP))
		goto err_file;

	public_file = fopen(pub, "wb+");
	if (!public_file)
		goto err_file;

	if (mbedtls_mpi_write_file("N = ", &N, 16, public_file))
		goto err_file;

	if (mbedtls_mpi_write_file("E = ", &E, 16, public_file))
		goto err_file;

	private_file = fopen(priv, "wb+");
	if (!priv)
		goto err_file;

	if (mbedtls_mpi_write_file("N = ", &N, 16, private_file))
		goto err_file;

	if (mbedtls_mpi_write_file("E = ", &E, 16, private_file))
		goto err_file;

	if (mbedtls_mpi_write_file("D = ", &D, 16, private_file))
		goto err_file;

	if (mbedtls_mpi_write_file("P = ", &P, 16, private_file))
		goto err_file;

	if (mbedtls_mpi_write_file("Q = ", &Q, 16, private_file))
		goto err_file;

	if (mbedtls_mpi_write_file("DP = ", &DP, 16, private_file))
		goto err_file;

	if (mbedtls_mpi_write_file("DQ = ", &DQ, 16, private_file))
		goto err_file;

	if (mbedtls_mpi_write_file("QP = ", &QP, 16, private_file))
		goto err_file;

	ret = true;
err_file:
	if (public_file) {
		fclose(public_file);
		public_file = NULL;
	}

	if (private_file) {
		fclose(private_file);
		private_file = NULL;
	}

	mbedtls_mpi_free(&N);
	mbedtls_mpi_free(&P);
	mbedtls_mpi_free(&Q);
	mbedtls_mpi_free(&D);
	mbedtls_mpi_free(&E);
	mbedtls_mpi_free(&DP);
	mbedtls_mpi_free(&DQ);
	mbedtls_mpi_free(&QP);

	return ret;
}

/**
 * Write RSA keys to buffers.
 * @param[in] rsa The RSA context.
 * @param[out] priv The buffer to store a private key.
 * @param[in] priv_size The size of the private key buffer.
 * @param[out] pub The buffer to store a public key.
 * @param[in] pub_size The size of the public key buffer.
 * @return true: Succeeded. false: Failed.
 */
static bool rsa_key_write_buffer(
		mbedtls_rsa_context *rsa, char *priv,
		size_t priv_size, char *pub, size_t pub_size)
{
	mbedtls_mpi N;
	mbedtls_mpi P;
	mbedtls_mpi Q;
	mbedtls_mpi D;
	mbedtls_mpi E;
	mbedtls_mpi DP;
	mbedtls_mpi DQ;
	mbedtls_mpi QP;
	size_t total = 0;
	size_t output = 0;
	bool ret = false;

	if (!rsa || !priv || !pub)
		return false;

	mbedtls_mpi_init(&N);
	mbedtls_mpi_init(&P);
	mbedtls_mpi_init(&Q);
	mbedtls_mpi_init(&D);
	mbedtls_mpi_init(&E);
	mbedtls_mpi_init(&DP);
	mbedtls_mpi_init(&DQ);
	mbedtls_mpi_init(&QP);

	if (mbedtls_rsa_export(rsa, &N, &P, &Q, &D, &E) ||
			mbedtls_rsa_export_crt(rsa, &DP, &DQ, &QP))
		goto err_buffer;

	output = rsa_mpi_write_buffer(
			"N = ", &N, pub, pub_size, 16);
	if (!output)
		goto err_buffer;

	total += output;
	output = rsa_mpi_write_buffer(
			"E = ", &E, pub + total, pub_size - total, 16);
	if (!output)
		goto err_buffer;

	total = 0;
	output = rsa_mpi_write_buffer(
			"N = ", &N, priv, priv_size, 16);
	if (!output)
		goto err_buffer;

	total += output;
	output = rsa_mpi_write_buffer(
			"E = ", &E, priv + total,
			priv_size - total, 16);
	if (!output)
		goto err_buffer;

	total += output;
	output = rsa_mpi_write_buffer(
			"D = ", &D, priv + total,
			priv_size - total, 16);
	if (!output)
		goto err_buffer;

	total += output;
	output = rsa_mpi_write_buffer(
			"P = ", &P, priv + total,
			priv_size - total, 16);
	if (!output)
		goto err_buffer;

	total += output;
	output = rsa_mpi_write_buffer(
			"Q = ", &Q, priv + total,
			priv_size - total, 16);
	if (!output)
		goto err_buffer;

	total += output;
	output = rsa_mpi_write_buffer(
			"DP = ", &DP, priv + total,
			priv_size - total, 16);
	if (!output)
		goto err_buffer;

	total += output;
	output = rsa_mpi_write_buffer(
			"DQ = ", &DQ, priv + total,
			priv_size - total, 16);
	if (!output)
		goto err_buffer;

	total += output;
	output = rsa_mpi_write_buffer(
			"QP = ", &QP, priv + total,
			priv_size - total, 16);
	if (!output)
		goto err_buffer;

	ret = true;
err_buffer:
	mbedtls_mpi_free(&N);
	mbedtls_mpi_free(&P);
	mbedtls_mpi_free(&Q);
	mbedtls_mpi_free(&D);
	mbedtls_mpi_free(&E);
	mbedtls_mpi_free(&DP);
	mbedtls_mpi_free(&DQ);
	mbedtls_mpi_free(&QP);

	return ret;
}

/**
 * RSA key generator.
 * @param[out] priv The file path or buffer to store a private key.
 * @param[in] priv_size The size of the private key buffer.
 * @param[out] pub The file path or buffer to store a public key.
 * @param[in] pub_size The size of the public key buffer.
 * @param[in] key_bits Size of the public key in bits.
 * @param[in] padding MBEDTLS_RSA_PKCS_V15 or MBEDTLS_RSA_PKCS_V21.
 * @param[in] hash_id MBEDTLS_RSA_PKCS_V21 hash identifier.
 * @param[in] output_to_file true: Output the private and public key to files.
 * false: Output the private and public key to buffers.
 * @return true: Succeeded. false: Failed.
 */
bool rsa_key_generator(char *priv, size_t priv_size, char *pub,
			size_t pub_size, size_t key_bits,
			int padding, int hash_id, bool output_to_file)
{
	mbedtls_rsa_context rsa;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *pers = "RSA Key Generator";
	bool ret = false;

	if (!priv || !pub)
		return false;

	if (key_bits != 2048 && key_bits != 4096)
		return false;

	if (padding != MBEDTLS_RSA_PKCS_V15 && padding != MBEDTLS_RSA_PKCS_V21)
		return false;

	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_rsa_init(&rsa, padding, hash_id);

	if (mbedtls_ctr_drbg_seed(&ctr_drbg,
				mbedtls_entropy_func, &entropy,
				(const unsigned char *)pers, strlen(pers)))
		goto err_genkey;

	if (mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random,
				&ctr_drbg, key_bits, 65537))
		goto err_genkey;

	if (output_to_file) {
		if (!rsa_key_write_file(&rsa, priv, pub))
			goto err_genkey;
	} else {
		if (!rsa_key_write_buffer(&rsa, priv,
				priv_size, pub, pub_size))
			goto err_genkey;
	}

	ret = true;
err_genkey:
	mbedtls_rsa_free(&rsa);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	return ret;
}

/**
 * RSA encryption.
 * @param[out] output Cyphertext.
 * @param[in] input Plaintext.
 * @param[in] length The input length.
 * @param[in] key The key file path.
 * @param[in] padding MBEDTLS_RSA_PKCS_V15 or MBEDTLS_RSA_PKCS_V21.
 * @return true: Succeeded. false: Failed.
 */
bool rsa_encrypt(unsigned char *output, unsigned char *input,
		size_t length, char *key, int padding)
{
	FILE *file = NULL;
	bool ret = false;
	mbedtls_rsa_context rsa;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_mpi N;
	mbedtls_mpi E;
	const char *pers = "RSA Encryption";

	if (!output || !input || !key)
		return false;

	mbedtls_rsa_init(&rsa, padding, MBEDTLS_MD_SHA256);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	mbedtls_mpi_init(&N);
	mbedtls_mpi_init(&E);

	if (mbedtls_ctr_drbg_seed(&ctr_drbg,
				mbedtls_entropy_func, &entropy,
				(const unsigned char *)pers, strlen(pers)))
		goto err_encrypt;

	file = fopen(key, "rb");
	if (!file)
		goto err_encrypt;

	if (mbedtls_mpi_read_file(&N, 16, file))
		goto err_encrypt;

	if (mbedtls_mpi_read_file(&E, 16, file))
		goto err_encrypt;

	if (mbedtls_rsa_import(&rsa, &N, NULL, NULL, NULL, &E))
		goto err_encrypt;

	if (mbedtls_rsa_pkcs1_encrypt(&rsa,
				mbedtls_ctr_drbg_random,
				&ctr_drbg, MBEDTLS_RSA_PUBLIC,
				length, input, output))
		goto err_encrypt;

	ret = true;
err_encrypt:
	if (file) {
		fclose(file);
		file = NULL;
	}

	mbedtls_mpi_free(&N);
	mbedtls_mpi_free(&E);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_rsa_free(&rsa);

	return ret;
}

/**
 * RSA decryption.
 * @param[out] output Plaintext.
 * @param[in] out_size The maximum output length.
 * @param[in] out_length The length of the output plaintext.
 * @param[in] input Cyphertext.
 * @param[in] key The key file path.
 * @param[in] padding MBEDTLS_RSA_PKCS_V15 or MBEDTLS_RSA_PKCS_V21.
 * @return true: Succeeded. false: Failed.
 */
bool rsa_decrypt(unsigned char *output,
		size_t out_size, size_t *out_length,
		unsigned char *input, char *key, int padding)
{
	FILE *file = NULL;
	bool ret = false;
	mbedtls_rsa_context rsa;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_mpi N;
	mbedtls_mpi P;
	mbedtls_mpi Q;
	mbedtls_mpi D;
	mbedtls_mpi E;
	const char *pers = "RSA Decryption";

	if (!output || !input || !key)
		return false;

	mbedtls_rsa_init(&rsa, padding, MBEDTLS_MD_SHA256);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	mbedtls_mpi_init(&N);
	mbedtls_mpi_init(&P);
	mbedtls_mpi_init(&Q);
	mbedtls_mpi_init(&D);
	mbedtls_mpi_init(&E);

	if (mbedtls_ctr_drbg_seed(&ctr_drbg,
				mbedtls_entropy_func, &entropy,
				(const unsigned char *) pers, strlen(pers)))
		goto err_decrypt;

	file = fopen(key, "rb");
	if (!file)
		goto err_decrypt;

	if (mbedtls_mpi_read_file(&N, 16, file))
		goto err_decrypt;

	if (mbedtls_mpi_read_file(&E, 16, file))
		goto err_decrypt;

	if (mbedtls_mpi_read_file(&D, 16, file))
		goto err_decrypt;

	if (mbedtls_mpi_read_file(&P, 16, file))
		goto err_decrypt;

	if (mbedtls_mpi_read_file(&Q, 16, file))
		goto err_decrypt;

	if (mbedtls_rsa_import(&rsa, &N, &P, &Q, &D, &E))
		goto err_decrypt;

	if (mbedtls_rsa_complete(&rsa))
		goto err_decrypt;

	if (mbedtls_rsa_pkcs1_decrypt(&rsa, mbedtls_ctr_drbg_random,
				&ctr_drbg, MBEDTLS_RSA_PRIVATE,
				out_length, input, output, out_size))
		goto err_decrypt;

	ret = true;
err_decrypt:
	if (file) {
		fclose(file);
		file = NULL;
	}

	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_rsa_free(&rsa);
	mbedtls_mpi_free(&N);
	mbedtls_mpi_free(&P);
	mbedtls_mpi_free(&Q);
	mbedtls_mpi_free(&D);
	mbedtls_mpi_free(&E);

	return ret;
}

/**
 * Test to generate RSA keys to buffers.
 * @return true: Succeeded. false: Failed.
 */
static bool test_rsa_key_generator_buffer(void)
{
	char priv[8192] = {0};
	char pub[4096] = {0};

	printf("Key: %u bits, padding: %s, hash identifier: %s\n",
			2048, "MBEDTLS_RSA_PKCS_V15", "N/A");
	if (rsa_key_generator(priv, sizeof(priv),
			pub, sizeof(pub), 2048,
			MBEDTLS_RSA_PKCS_V15, 0, false)) {
		printf("private key:\n");
		printf("%.*s", (int)sizeof(priv), priv);
		printf("public key:\n");
		printf("%.*s", (int)sizeof(pub), pub);
	} else {
		return false;
	}

	memset(priv, 0, sizeof(priv));
	memset(pub, 0, sizeof(pub));
	printf("Key: %u bits, padding: %s, hash identifier: %s\n",
			2048, "MBEDTLS_RSA_PKCS_V21", "MBEDTLS_MD_SHA256");
	if (rsa_key_generator(priv, sizeof(priv),
			pub, sizeof(pub), 2048,
			MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256, false)) {
		printf("private key:\n");
		printf("%.*s", (int)sizeof(priv), priv);
		printf("public key:\n");
		printf("%.*s", (int)sizeof(pub), pub);
	} else {
		return false;
	}

	memset(priv, 0, sizeof(priv));
	memset(pub, 0, sizeof(pub));
	printf("Key: %u bits, padding: %s, hash identifier: %s\n",
			4096, "MBEDTLS_RSA_PKCS_V15", "N/A");
	if (rsa_key_generator(priv, sizeof(priv),
			pub, sizeof(pub), 4096,
			MBEDTLS_RSA_PKCS_V15, 0, false)) {
		printf("private key:\n");
		printf("%.*s", (int)sizeof(priv), priv);
		printf("public key:\n");
		printf("%.*s", (int)sizeof(pub), pub);
	} else {
		return false;
	}

	memset(priv, 0, sizeof(priv));
	memset(pub, 0, sizeof(pub));
	printf("Key: %u bits, padding: %s, hash identifier: %s\n",
			4096, "MBEDTLS_RSA_PKCS_V21", "MBEDTLS_MD_SHA256");
	if (rsa_key_generator(priv, sizeof(priv),
			pub, sizeof(pub), 4096,
			MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256, false)) {
		printf("private key:\n");
		printf("%.*s", (int)sizeof(priv), priv);
		printf("public key:\n");
		printf("%.*s", (int)sizeof(pub), pub);
	} else {
		return false;
	}

	return true;
}

/**
 * Test to generate RSA keys to files.
 * @return true: Succeeded. false: Failed.
 */
static bool test_rsa_key_generator_file(void)
{
	char *private_2048_v15 = "rsa_2048_private_v15.txt";
	char *public_2048_v15 = "rsa_2048_public_v15.txt";
	char *private_2048_v21 = "rsa_2048_private_v21.txt";
	char *public_2048_v21 = "rsa_2048_public_v21.txt";
	char *private_4096_v15 = "rsa_4096_private_v15.txt";
	char *public_4096_v15 = "rsa_4096_public_v15.txt";
	char *private_4096_v21 = "rsa_4096_private_v21.txt";
	char *public_4096_v21 = "rsa_4096_public_v21.txt";

	printf("Key: %u bits, padding: %s, hash identifier: %s\n",
			2048, "MBEDTLS_RSA_PKCS_V15", "N/A");
	if (rsa_key_generator(private_2048_v15, 0,
			public_2048_v15, 0, 2048,
			MBEDTLS_RSA_PKCS_V15, 0, true)) {
		printf("private file: %s, public file: %s\n",
					private_2048_v15, public_2048_v15);
	} else {
		return false;
	}

	printf("Key: %u bits, padding: %s, hash identifier: %s\n",
			2048, "MBEDTLS_RSA_PKCS_V21", "MBEDTLS_MD_SHA256");
	if (rsa_key_generator(private_2048_v21, 0, public_2048_v21, 0, 2048,
			MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256, true)) {
		printf("private file: %s, public file: %s\n",
					private_2048_v21, public_2048_v21);
	} else {
		return false;
	}

	printf("Key: %u bits, padding: %s, hash identifier: %s\n",
			4096, "MBEDTLS_RSA_PKCS_V15", "N/A");
	if (rsa_key_generator(private_4096_v15, 0, public_4096_v15, 0, 4096,
			MBEDTLS_RSA_PKCS_V15, 0, true)) {
		printf("private file: %s, public file: %s\n",
					private_4096_v15, public_4096_v15);
	} else {
		return false;
	}

	printf("Key: %u bits, padding: %s, hash identifier: %s\n",
			4096, "MBEDTLS_RSA_PKCS_V21", "MBEDTLS_MD_SHA256");
	if (rsa_key_generator(private_4096_v21, 0, public_4096_v21, 0, 4096,
			MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256, true)) {
		printf("private file: %s, public file: %s\n",
					private_4096_v21, public_4096_v21);
	} else {
		return false;
	}

	return true;
}

/**
 * Test RSA key generator.
 * @return true: Succeeded. false: Failed.
 */
bool test_rsa_key_generator(void)
{
	if (!test_rsa_key_generator_buffer())
		return false;

	if (!test_rsa_key_generator_file())
		return false;

	return true;
}

/**
 * Test RSA encryption/decryption.
 * @return true: Succeeded. false: Failed.
 */
bool test_rsa_crypt(void)
{
	char *private_2048_v15 = "rsa_2048_private_v15.txt";
	char *public_2048_v15 = "rsa_2048_public_v15.txt";
	char *private_2048_v21 = "rsa_2048_private_v21.txt";
	char *public_2048_v21 = "rsa_2048_public_v21.txt";
	char *private_4096_v15 = "rsa_4096_private_v15.txt";
	char *public_4096_v15 = "rsa_4096_public_v15.txt";
	char *private_4096_v21 = "rsa_4096_private_v21.txt";
	char *public_4096_v21 = "rsa_4096_public_v21.txt";
	char *origin = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	unsigned char cyphertext[64] = {0};
	unsigned char plaintext[64] = {0};
	size_t length = 0;

	printf("Origin data: %s\n", origin);
	printf("Key: %u bits, padding: %s\n",
			2048, "MBEDTLS_RSA_PKCS_V15");
	if (!rsa_encrypt(cyphertext, (unsigned char *)origin,
			strlen(origin), public_2048_v15,
			MBEDTLS_RSA_PKCS_V15))
		return false;

	if (!rsa_decrypt(plaintext, sizeof(plaintext),
			&length, cyphertext,
			private_2048_v15, MBEDTLS_RSA_PKCS_V15))
		return false;

	printf("Plaintext: %.*s\n", (int)length, plaintext);
	memset(plaintext, 0, sizeof(plaintext));

	printf("Key: %u bits, padding: %s\n",
			2048, "MBEDTLS_RSA_PKCS_V21");
	if (!rsa_encrypt(cyphertext, (unsigned char *)origin,
			strlen(origin), public_2048_v21,
			MBEDTLS_RSA_PKCS_V21))
		return false;

	if (!rsa_decrypt(plaintext, sizeof(plaintext),
			&length, cyphertext,
			private_2048_v21, MBEDTLS_RSA_PKCS_V21))
		return false;

	printf("Plaintext: %.*s\n", (int)length, plaintext);
	memset(plaintext, 0, sizeof(plaintext));

	printf("Key: %u bits, padding: %s\n",
			4096, "MBEDTLS_RSA_PKCS_V15");
	if (!rsa_encrypt(cyphertext, (unsigned char *)origin,
			strlen(origin), public_4096_v15,
			MBEDTLS_RSA_PKCS_V15))
		return false;

	if (!rsa_decrypt(plaintext, sizeof(plaintext),
			&length, cyphertext,
			private_4096_v15, MBEDTLS_RSA_PKCS_V15))
		return false;

	printf("Plaintext: %.*s\n", (int)length, plaintext);
	memset(plaintext, 0, sizeof(plaintext));

	printf("Key: %u bits, padding: %s\n",
			4096, "MBEDTLS_RSA_PKCS_V21");
	if (!rsa_encrypt(cyphertext, (unsigned char *)origin,
			strlen(origin), public_4096_v21,
			MBEDTLS_RSA_PKCS_V21))
		return false;

	if (!rsa_decrypt(plaintext, sizeof(plaintext),
			&length, cyphertext,
			private_4096_v21, MBEDTLS_RSA_PKCS_V21))
		return false;

	printf("Plaintext: %.*s\n", (int)length, plaintext);
	memset(plaintext, 0, sizeof(plaintext));

	return true;
}
