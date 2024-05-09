#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#define CMD_SIZE 32

static struct option long_options[] = {
    {"interface", required_argument, 0, 'i'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
};

static void help(char *prog)
{
    printf("Usage: %s [--%s|-%c] [--%s|-%c]\n",
        prog,
        long_options[0].name, long_options[0].val,
        long_options[1].name, long_options[1].val);
    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
    const char *value = NULL;
    char cmd[CMD_SIZE] = "ifconfig ";
    int ret = 0;

    while (1) {
        char c = 0;
        int option_index = 0;

        c = getopt_long(argc, argv, "i:h",
                 long_options, &option_index);

        if (c == -1)
            break;

        switch (c) {
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
