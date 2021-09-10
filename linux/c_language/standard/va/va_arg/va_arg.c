#include <stdio.h>
#include <stdarg.h>

void list(size_t groups, ...)
{
	va_list args;

	va_start(args, groups);

	for (size_t i = 0; i != groups; i++) {
		size_t id = va_arg(args, size_t);
		char *name = va_arg(args, char *);

		printf("id: %lu name: %s\n", id, name);
	}

	va_end(args);
}

int main(int argc, char *argv[])
{
	list(3, 1, "Victor", 2, "Mary", 3, "John");
	return 0;
}
