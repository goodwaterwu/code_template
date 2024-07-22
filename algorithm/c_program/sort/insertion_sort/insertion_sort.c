#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/**
 * @brief Insertion sort.
 *
 * A insertion sort implementation.
 * Time: O(n^2) Space: O(1)
 * @param arr An array which contains numbers.
 * @param size Size of the array.
 * @return The sorted array.
 */
int *insertion_sort(int *arr, int size)
{
	/* i means an unsorted number */
	for (int i = 1; i < size; i++) {
		int key_index = i;
		/* j means a sorted number */
		for (int j = i - 1; j >= 0; j--) {
			if (arr[key_index] < arr[j]) {
				int tmp = arr[key_index];

				arr[key_index] = arr[j];
				arr[j] = tmp;
				key_index = j; /* new index of key */
			}
		}
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

	insertion_sort(arr, size);

	printf("Sorted array: ");
	for (int i = 0; i != size; i++) {
		printf("%i ", arr[i]);
	}
	printf("\n");

	return 0;
}
