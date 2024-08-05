#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/** 
 * @brief Binary search.
 *
 * A binary search implementation.
 * Time: O(n) Space: O(1)
 * @param arr A sorted array which contains numbers.
 * @param low The lowest index of the search range.
 * @param high The highest index of the search range.
 * @param key The value to be searched.
 * @return The index of key.
 */
int binary_search(int *arr, int low, int high, int key)
{
	while (low <= high) {
		int middle = low + (high - low) / 2;

		if (arr[middle] == key)
			return middle;

		if (arr[middle] < key)
			low = middle + 1;
		else
			high = middle - 1;
	}

	return -1;
}

int main(int argc, char *argv[])
{
	int arr[] = { -5, -4, -3, -2, -1, 0, 1, 2, 3 };
	int size = sizeof(arr) / sizeof(int);
	int key = 1;
	int ret = 0;

	printf("Array: ");
	for (int i = 0; i != size; i++) {
		printf("%i ", arr[i]);
	}
	printf("\n");
	printf("Key: %d\n", key);

	ret = binary_search(arr, 0, size - 1, key);
	if (ret >= 0)
		printf("Found %d on the index of the array: %d\n", key, ret);
	else
		printf("Couldn't find %d in the array\n", key);

	return 0;
}
