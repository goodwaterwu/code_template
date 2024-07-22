#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/**
 * @brief Selection sort.
 *
 * A selection sort implementation.
 * Time: O(n^2) Space: O(1)
 * @param arr An array which contains numbers.
 * @param size Size of the array.
 * @return The sorted array.
 */
int *selection(int *arr, int size)
{
	/* i means the ith round */
	for (int i = 0; i < size - 1; i++) {
		int min_index = i;
		int tmp = arr[i];

		/* Select the smallest one */
		for (int j = i + 1; j < size; j++) {
			if (arr[j] < arr[min_index])
				min_index = j;
		}
		/* Swap ith and min value */
		arr[i] = arr[min_index];
		arr[min_index] = tmp;
	}

	return arr;
}

int main(int argc, char *argv[])
{
	int arr[] = { -1, -3, 0, 1, 3, -3, -5, 2 };
	int size = sizeof(arr) / sizeof(int);

	printf("Unsorted array: ");
	for (int i = 0; i != size; i++) {
		printf("%i ", arr[i]);
	}
	printf("\n");

	selection(arr, size);

	printf("Sorted array: ");
	for (int i = 0; i != size; i++) {
		printf("%i ", arr[i]);
	}
	printf("\n");

	return 0;
}
