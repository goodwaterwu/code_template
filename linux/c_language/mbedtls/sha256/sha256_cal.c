#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <mbedtls/sha256.h> /* Compile mbedtls first. */

/**
 * Calculate SHA256 value of an input data stream.
 * @param[in] input The input data stream.
 * @param[in] length The length of input data stream.
 * @param[out] output The output SHA256 string.
 * @return NULL: Failed. others: SHA256.
 */
unsigned char *sha256_stream(const unsigned char *input,
		size_t length, unsigned char output[32])
{
	mbedtls_sha256_context ctx;

	if (!input || length == 0)
		return NULL;

	mbedtls_sha256_init(&ctx);
	mbedtls_sha256_starts(&ctx, 0);
	mbedtls_sha256_update(&ctx, input, length);
	mbedtls_sha256_finish(&ctx, output);
	mbedtls_sha256_free(&ctx);

	return output;
}

/**
 * Calculate SHA256 value of an input data stream.
 * @param[in] path The input file path.
 * @param[out] output The output SHA256 string.
 * @return NULL: Failed. others: SHA256.
 */
unsigned char *sha256_file(const char *path, unsigned char output[32])
{
	mbedtls_sha256_context ctx;
	FILE *fp = NULL;
	size_t read = 0;
	unsigned char buf[128] = {0};

	if (!path)
		return NULL;

	fp = fopen(path, "r");
	if (!fp)
		return NULL;

	mbedtls_sha256_init(&ctx);
	mbedtls_sha256_starts(&ctx, 0);

	read = fread(buf, 1, sizeof(buf), fp);

	while (read > 0) {
		mbedtls_sha256_update(&ctx, buf, read);
		read = fread(buf, 1, sizeof(buf), fp);
	}

	fclose(fp);
	fp = NULL;
	mbedtls_sha256_finish(&ctx, output);
	mbedtls_sha256_free(&ctx);

	return output;
}

/**
 * Test SHA256 functions.
 * @param[in] argc Number of arguments.
 * @param[in] argv Array of arguments.
 * @return 0: Succeeded. 1: Failed.
 */
int main(int argc, char *argv[])
{
	char path[PATH_MAX] = {0};
	unsigned char input[32] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	unsigned char output[32] = {0};

	printf("Test SHA256 source from data stream: %s\n", input);
	if (!sha256_stream(input, strlen((char *)input), output))
		exit(EXIT_FAILURE);

	printf("sha256: ");
	for (size_t i = 0; i != sizeof(output); i++)
		printf("%02x", output[i]);

	printf("\nInput test file: ");
	if (scanf("%s", path) == EOF)
		exit(EXIT_FAILURE);

	printf("Test SHA256 source from a file: %s\n", path);
	if (!sha256_file(path, output))
		exit(EXIT_FAILURE);

	printf("sha256: ");
	for (size_t i = 0; i != sizeof(output); i++)
		printf("%02x", output[i]);

	printf("\n");

	return 0;
}
