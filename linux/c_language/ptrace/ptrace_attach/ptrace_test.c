#include <stdio.h>
#include <unistd.h>

#define TIMEOUT 20

int main(int argc, char *argv[])
{
	for (int i = 0; i != TIMEOUT; i++) {
		printf("timer: %02d\n", i);
		sleep(1);
	}

        return 0;
}
