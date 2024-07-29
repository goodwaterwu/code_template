#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/**
 * @brief Swap two integers.
 *
 * Swap the value of two integers.
 * @param a First number to be swapped.
 * @param b Second number to be swapped.
 */
void swap(int *a, int *b)
{
	int tmp = *a;

	*a = *b;
	*b = tmp;
}

/**
 * @brief Partition data.
 *
 * Put the highest index of value to a proper position.
 * @param arr An array which contains numbers.
 * @param low The lowest index to be sorted.
 * @param high The highest index to be sorted.
 * @return The sorted index of last value.
 */
int partition(int *arr, int low, int high)
{
	int index = low;

	for (int i = low; i < high; i++) {
		/* Find a value smaller than last value and swap the value with value[index] */
		if (arr[i] < arr[high])
			swap(&arr[index++], &arr[i]);
	}
	/* Put last value to a proper position */
	swap(&arr[index], &arr[high]);

	return index;
}

/**
 * @brief Quick sort.
 *
 * A quick sort implementation.
 * Time: O(nlogn) Space: O(1)
 * @param arr An array which contains numbers.
 * @param low The lowest index to be sorted.
 * @param high The highest index to be sorted.
 * @return The sorted array.
 */
int *quick_sort(int *arr, int low, int high)
{
	if (low < high) {
		/* Get the sorted index of last value */
		int index = partition(arr, low, high);

		/* Quick sort left data */
		quick_sort(arr, low, index - 1);
		/* Quick sort right data */
		quick_sort(arr, index + 1, high);
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

	quick_sort(arr, 0, size - 1);

	printf("Sorted array: ");
	for (int i = 0; i != size; i++) {
		printf("%i ", arr[i]);
	}
	printf("\n");

	return 0;
}
