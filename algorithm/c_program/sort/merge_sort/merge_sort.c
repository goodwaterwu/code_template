#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * @brief Merge two arrays.
 *
 * A merge sort implementation.
 * Time: O(nlogn) Space: O(n)
 * @param arr An array which contains numbers.
 * @param l The start index of the array.
 * @param m The middle index of the array.
 * @param r The end index of the array.
 * @return The sorted array.
 */
int *merge(int *arr, int l, int m, int r)
{
	int *left = NULL;
	int *right = NULL;
	int n1 = m - l + 1;
	int n2 = r - m;
	int i = 0;
	int j = 0;
	int k = l;

	left = (int *)calloc(sizeof(int), n1);
	if (!left)
		exit(EXIT_FAILURE);

	right = (int *)calloc(sizeof(int), n2);
	if (!right) {
		free(left);
		exit(EXIT_FAILURE);
	}

	memcpy(left, arr + l, sizeof(int) * n1);
	memcpy(right, arr + m + 1, sizeof(int) * n2);

	/* Compare left and right and assign the smaller one to the array */
	while (i < n1 && j < n2)
		arr[k++] = (left[i] < right[j]) ? left[i++] : right[j++];

	/* Assign the remaining left to the array */
	while (i < n1)
		arr[k++] = left[i++];

	/* Assign the remaining right to the array */
	while (j < n2)
		arr[k++] = right[j++];

	free(left);
	free(right);

	return arr;
}

/**
 * @brief Merge sort.
 *
 * A merge sort implementation.
 * Time: O(nlogn) Space: O(n)
 * @param arr An array which contains numbers.
 * @param l The start index of the array.
 * @param r The end index of the array.
 * @return The sorted array.
 */
int *merge_sort(int *arr, int l, int r)
{
	if (l < r) {
		int m = l + (r - l) / 2;

		merge_sort(arr, l, m); /* Merge left part */
		merge_sort(arr, m + 1, r); /* Merge right part */
		merge(arr, l, m, r); /* Merge left and right together */
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

	merge_sort(arr, 0, size - 1);

	printf("Sorted array: ");
	for (int i = 0; i != size; i++) {
		printf("%i ", arr[i]);
	}
	printf("\n");

	return 0;
}
