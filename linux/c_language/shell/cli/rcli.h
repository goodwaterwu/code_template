#ifndef RCLI_CMD_H
#define RCLI_CMD_H

#include <stdio.h>

typedef struct {
    const char *name;
    const char *description;
    int (*handler)(const char **args, int arg_count);
} Command;

/* Command handlers declarations */
int cmd_help(const char **args, int arg_count);
int cmd_echo(const char **args, int arg_count);
int cmd_version(const char **args, int arg_count);
int cmd_result(const char **args, int arg_count);

/* Helper functions */
const Command *find_command(const char *name);
const Command *get_commands(void);
int get_command_count(void);

#endif
