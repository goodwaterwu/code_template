#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/**
 * @brief Bubble sort.
 *
 * A bubble sort implementation.
 * Time: O(n^2) Space: O(1)
 * @param arr An array which contains numbers.
 * @param size Size of the array.
 * @return The sorted array.
 */
int *bubble_sort(int *arr, int size)
{
	/* i means ith round */
	for (int i = 0; i < size - 1; i++) {
		/* j means the index of an unsorted number to be compared */
		for (int j = 0; j < size - i - 1; j++) {
			if (arr[j] > arr[j + 1]) {
				int tmp = arr[j];

				arr[j] = arr[j + 1];
				arr[j + 1] = tmp;
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

	bubble_sort(arr, size);

	printf("Sorted array: ");
	for (int i = 0; i != size; i++) {
		printf("%i ", arr[i]);
	}
	printf("\n");

	return 0;
}
