#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>
#include <execinfo.h>

#define BT_BUF_SIZE 128

void help(char *argv[])
{
	printf("%s <recursive_times>\n\n", argv[0]);
	exit(EXIT_FAILURE);
}

void func2(void)
{
	int size = 0;
	void *buffer[BT_BUF_SIZE] = {0};

	size = backtrace(buffer, BT_BUF_SIZE);
	printf("backtrace() returned %d addresses\n", size);
	backtrace_symbols_fd(buffer, size, STDOUT_FILENO);
}

void func1(uint32_t recursion)
{
	if (recursion > 1)
		func1(recursion - 1);
	else
		func2();
}

int main(int argc, char *argv[])
{
	if (argc < 2)
		help(argv);

	func1(atoi(argv[1]));

	return 0;
}
