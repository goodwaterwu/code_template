#include <stdio.h>
#include <stdlib.h>

int compare(const void *a, const void *b)
{
	return (*(int *)a - *(int *)b);
}

void *search(const void *key, void *arr, size_t number, size_t size)
{
	qsort(arr, number, size, compare);

	return bsearch(key, arr, number, size, compare);
}

int main(int argc, char *argv[])
{
	int key = 0;
	int num[] = { 3, -1, 0, 5, -8, 0, -2, -1, 3, 4 };
	size_t size = sizeof(int);
	size_t number = sizeof(num) / size;

	printf("array: ");
	for (int i = 0; i != sizeof(num) / sizeof(int); i++)
		printf("%d ", num[i]);
	printf("\nInput a key: ");
	if (scanf("%d", &key) == EOF) {
		printf("Should input a number!\n");
		return EXIT_FAILURE;
	}

	if (search(&key, num, number, size))
		printf("%d exists!\n", key);
	else
		printf("%d doesn't exist!\n", key);

	return 0;
}
