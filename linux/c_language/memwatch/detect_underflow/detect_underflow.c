#include <stdio.h>
#include <stdlib.h>
#include "memwatch.h"

#define SIZE 10

int main(int argc, char *argv[])
{
	char *p = calloc(sizeof(char), SIZE);

	*(p - sizeof(char)) = 0;

	free(p);
	p = NULL;

	return 0;
}
