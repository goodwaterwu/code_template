#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#define CMD_SIZE 32

static void help(char *prog)
{
    printf("Usage: %s [-i] [-h]\n", prog);
    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
    const char *value = NULL;
    char cmd[CMD_SIZE] = "ifconfig ";
    int opt = 0;
    int ret = 0;

    while ((opt = getopt(argc, argv, "i:h")) != -1) {
        switch (opt) {
        case 'i':
            value = optarg;
            break;
        case 'h':
        default:
            help(argv[0]);
            break;
        }

        strcat(cmd, value);
        strcat(cmd, " ");
    }

    ret = system(cmd);

    return WIFEXITED(ret) ? WEXITSTATUS(ret) : -1;
}
