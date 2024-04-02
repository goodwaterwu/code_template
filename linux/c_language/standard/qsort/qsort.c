#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

int ascending(const void *a, const void *b)
{
	return (*(int *)a - *(int *)b);
}

int descending(const void *a, const void *b)
{
	return (*(int *)b - *(int *)a);
}

void sort(void *arr, size_t number, size_t size, bool increase)
{
	qsort(arr, number, size, (increase) ? ascending : descending);
}

int main(int argc, char *argv[])
{
	int num[] = { 3, -1, 0, 5, -8, 0, -2, -1, 3, 4 };
	size_t size = sizeof(int);
	size_t number = sizeof(num) / size;

	sort(num, number, size, 1);
	printf("ascending: ");
	for (int i = 0; i != number; i++)
		printf("%d ", num[i]);

	sort(num, number, size, 0);
	printf("\ndecending: ");
	for (int i = 0; i != number; i++)
		printf("%d ", num[i]);

	printf("\n");

	return 0;
}
