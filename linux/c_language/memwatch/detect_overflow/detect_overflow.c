#include <stdio.h>
#include <stdlib.h>
#include "memwatch.h"

#define SIZE 10

int main(int argc, char *argv[])
{
	char *p = calloc(sizeof(char), SIZE);

	for (int i = 0; i <= SIZE; i++)
		p[i] = i;

	free(p);
	p = NULL;

	return 0;
}
