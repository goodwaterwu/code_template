#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/** 
 * @brief Linear search.
 *
 * A linear search implementation.
 * Time: O(n) Space: O(1)
 * @param values An array which contains numbers.
 * @param n Size of the array.
 * @param key The value to be searched.
 * @return The index of key.
 */
int linear(int *values, int n, int key)
{
	for (int i = 0; i != n; i++) {
		if (values[i] == key)
			return i;
	}

	return -1;
}

int main(int argc, char *argv[])
{
	int values[] = { -1, -3, 0, 3, 1, -2, -4, -5, 2 };
	int size = sizeof(values) / sizeof(int);
	int key = -5;
	int ret = 0;

	printf("Array: ");
	for (int i = 0; i != size; i++) {
		printf("%i ", values[i]);
	}
	printf("\n");
	printf("Key: %d\n", key);

	ret = linear(values, size, key);
	if (ret >= 0)
		printf("Found %d on the index of the array: %d\n", key, ret);
	else
		printf("Couldn't find %d in the array\n", key);

	return 0;
}
