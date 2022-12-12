#include <stdio.h>
#include <stdlib.h>

#define SIZE 10

int main(int argc, char *argv[])
{
	char *p = (char *)calloc(sizeof(char), SIZE);

	free(p);
	p[0] = 0;

	return 0;
}
