#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "rcli.h"

#define MAX_INPUT_SIZE 1024
#define MAX_TOKENS 64
#define PROMPT "RCLI> "

/* Add global variable to store last command output */
static char last_command_output[MAX_INPUT_SIZE] = "";

/* Add global variable to store last command result */
static bool last_command_result = true;  // Default to true

/* Command implementations */
int cmd_help(const char **args, int arg_count) {
    printf("Available commands:\n");
    for (int i = 0; i < get_command_count(); i++) {
        const Command *cmd = &get_commands()[i];
        printf("  %-10s - %s\n", cmd->name, cmd->description);
    }
    return true;
}

int cmd_echo(const char **args, int arg_count) {
    for (int i = 1; i < arg_count; i++) {
        printf("%s ", args[i]);
    }
    printf("\n");
    return true;
}

int cmd_version(const char **args, int arg_count) {
    printf("RCLI Version 1.0\n");
    return true;
}

int cmd_result(const char **args, int arg_count) {
    printf("Last command result: %s\n", last_command_result ? "true" : "false");
    return true;
}

/* Command registry */
static const Command commands[] = {
    {"help", "Show this help message", cmd_help},
    {"echo", "Echo the given arguments", cmd_echo},
    {"version", "Show RCLI version", cmd_version},
    {"result", "Show the result of the last command", cmd_result},
};

const Command *find_command(const char *name) {
    for (int i = 0; i < get_command_count(); i++) {
        if (strcmp(commands[i].name, name) == 0) {
            return &commands[i];
        }
    }
    return NULL;
}

const Command *get_commands(void) {
    return commands;
}

int get_command_count(void) {
    return sizeof(commands) / sizeof(commands[0]);
}

/* Free tokenized memory */
void free_tokens(char **tokens, int token_count)
{
    for (int i = 0; i < token_count; i++)
    {
        free(tokens[i]);
    }
    free(tokens);
}

/* Tokenization function improvements */
char **tokenize(const char *line, int *token_count) {
    char **tokens = malloc(MAX_TOKENS * sizeof(char*));
    if (!tokens) {
        *token_count = 0;
        return NULL;
    }

    /* Create a modifiable copy of the input */
    char *line_copy = strdup(line);
    if (!line_copy) {
        free(tokens);
        *token_count = 0;
        return NULL;
    }

    char *token = strtok(line_copy, " \t\n");
    *token_count = 0;

    while (token != NULL && *token_count < MAX_TOKENS) {
        tokens[*token_count] = strdup(token);
        if (!tokens[*token_count]) {
            free_tokens(tokens, *token_count);
            free(line_copy);
            *token_count = 0;
            return NULL;
        }
        (*token_count)++;
        token = strtok(NULL, " \t\n");
    }

    free(line_copy);
    return tokens;
}

int main() {
    char input[MAX_INPUT_SIZE];
    
    printf("Welcome to RCLI! Type 'help' for available commands.\n");

    while (1) {
        printf(PROMPT);
        fflush(stdout);

        if (!fgets(input, MAX_INPUT_SIZE, stdin)) {
            continue;
        }

        /* Remove trailing newline */
        input[strcspn(input, "\n")] = 0;

        if (strlen(input) == 0) {
            continue;
        }

        int token_count;
        char **tokens = tokenize(input, &token_count);
        if (!tokens) {
            fprintf(stderr, "Memory allocation failed\n");
            continue;
        }

        if (token_count > 0) {
            if (strcmp(tokens[0], "exit") == 0 && token_count == 1) {
                free_tokens(tokens, token_count);
                break;
            }

            const Command *cmd = find_command(tokens[0]);
            if (cmd) {
                last_command_result = cmd->handler((const char**)tokens, token_count);
            } else {
                printf("Unknown command: %s\nType 'help' for available commands.\n", tokens[0]);
            }
        }

        free_tokens(tokens, token_count);
    }

    printf("Goodbye!\n");
    return 0;
}
