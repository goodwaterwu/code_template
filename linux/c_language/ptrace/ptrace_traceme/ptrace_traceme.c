#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char *argv[])
{
        long long count = 0; /* Instruction count */
        int status = 0; /* Child process return value */
        pid_t pid = 0; /* Child process id */

        puts("Wait for the child process...");

	pid = fork();
        if (pid == -1) {
                perror("fork");
		exit(EXIT_FAILURE);
	}

	if (pid) { /* Parent process */
                wait(&status); 
                while (WIFSTOPPED(status)) { /* status == 1407 */
                        count++;
                        if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) != 0)
                                perror("ptrace");
                        wait(&status);
		}
	} else { /* Child process */
		ptrace(PTRACE_TRACEME, 0, 0, 0);
                execl("/usr/bin/echo", "echo", "Hello ptrace", NULL);
	}

        printf("Number of instructions: %lld\n", count);

        return 0;
}
