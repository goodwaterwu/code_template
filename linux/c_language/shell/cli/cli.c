#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>

#define MAX_ARGS 20
#define PROMPT "CLI> "
#define CMD_SIZE 256

typedef int (*cmd_fn_t)(char **);

struct cmd
{
    char *cmd_name;
    char *cmd_help;
    cmd_fn_t cmd_func;
};

static int cmd_help(char *args[]);
static int cmd_return_code(char *args[]);
static int cmd_ifconfig(char *args[]);

static struct cmd cli_cmd[] = {
    {
        .cmd_name = "?",
        .cmd_help = "List all commands",
        .cmd_func = cmd_help
    },
    {
        .cmd_name = "help",
        .cmd_help = "List all commands",
        .cmd_func = cmd_help
    },
    {
        .cmd_name = "return_code",
        .cmd_help = "Print last return code",
        .cmd_func = cmd_return_code
    },
    {
        .cmd_name = "ifconfig",
        .cmd_help = "ifconfig [interface] -> Show network interfaces",
        .cmd_func = cmd_ifconfig
    }
};

static int ret;

static int cmd_help(char *args[])
{
    for (size_t i = 0; i < sizeof(cli_cmd) / sizeof(struct cmd); i++) {
        printf("%-32s%s\n",cli_cmd[i].cmd_name, cli_cmd[i].cmd_help);
    }

    return 0;
}

static int cmd_return_code(char *args[])
{
    printf("%d\n", ret);

    return 0;
}

static int cmd_ifconfig(char *args[])
{
    char command[CMD_SIZE] = "ifconfig";
    char *iface = args[1];

    if (iface) {
        strcat(command, " ");
        strcat(command, iface);
    }

    return system(command);
}

static void free_args(char **args, int count)
{
    for (size_t i = 0; i != count; i++) {
        if (args[i]) {
            free(args[i]);
            args[i] = NULL;
        }
    }
}

int main(int argc, char *argv[])
{
    char *buf = NULL;
    size_t buf_size = 0;

    signal(SIGINT, SIG_IGN); /* Ignore Ctrl-C */
    signal(SIGTSTP, SIG_IGN); /* Ignore Ctrl-Z */

    while (1) {
        static char *args[MAX_ARGS] = {NULL};
        bool found = false;
        char *token = NULL;
        int count = 0;

        printf(PROMPT);
        fflush(stdout);
        if (getline(&buf, &buf_size, stdin) == -1) {
            free(buf);
            buf = NULL;
            exit(1); /* Exit on Ctrl-D */
        }

        token = strtok(buf, " \t\n");
        while (token != NULL && count <= MAX_ARGS) {
            args[count] = strdup(token);
            if (args[count] == NULL) {
                perror("Memory allocation failed");
                free_args(args, count);
                exit(1);
            }

            count++;
            token = strtok(NULL, " \t\n");
        }

        /* For an empty command. */
        if (!count)
            goto free_buf;

        for (int i = 0; i != sizeof(cli_cmd) / sizeof(struct cmd); i++) {
            if (!strncmp(args[0], cli_cmd[i].cmd_name, strlen(args[0]))) {
                ret = cli_cmd[i].cmd_func(args);
                found = true;
                break;
            }
        }

        if (!found)
            printf("Command '%s' not found\n", args[0]);

        free_args(args, count);
free_buf:
        free(buf);
        buf = NULL;
    }

    return 0;
}
