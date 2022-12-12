#include <stdio.h>
#include <stdlib.h>

#define SIZE 10

int main(int argc, char *argv[])
{
	char *p = (char *)calloc(sizeof(char), SIZE);

	p[SIZE] = 0;
	free(p);
	p = NULL;

	return 0;
}
