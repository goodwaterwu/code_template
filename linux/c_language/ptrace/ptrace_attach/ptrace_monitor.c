#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <asm/ptrace.h>

void help(char *name)
{
	printf("%s <pid>\n", name);
	exit(EXIT_FAILURE);
}

void dump_regs(struct pt_regs regs)
{
	/* Only support x86_64 */
	printf("++++++++++++++++++++\n");
	printf("r15: 0x%lx\n", regs.r15);
	printf("r14: 0x%lx\n", regs.r14);
	printf("r13: 0x%lx\n", regs.r13);
	printf("r12: 0x%lx\n", regs.r12);
	printf("rbp: 0x%lx\n", regs.rbp);
	printf("rbx: 0x%lx\n", regs.rbx);
	printf("r11: 0x%lx\n", regs.r11);
	printf("r10: 0x%lx\n", regs.r10);
	printf("r9: 0x%lx\n", regs.r9);
	printf("r8: 0x%lx\n", regs.r8);
	printf("rax: 0x%lx\n", regs.rax);
	printf("rcx: 0x%lx\n", regs.rcx);
	printf("rdx: 0x%lx\n", regs.rdx);
	printf("rsi: 0x%lx\n", regs.rsi);
	printf("rdi: 0x%lx\n", regs.rdi);
	printf("++++++++++++++++++++\n");
}

int main(int argc, char *argv[])
{
	struct pt_regs regs;
        int status = 0; /* Child process return value */
        pid_t pid = 0; /* Child process id */

	if (argc < 2) {
		help(argv[0]);
	}

	pid = atoi(argv[1]);
        printf("pid of monitored process: %d\n", pid);

	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL)) {
		printf("Cannot monitor process: %d errno: %#x\n", pid, errno);
		exit(EXIT_FAILURE);
	}

        while (waitpid(pid, &status, 0)) {
		if (ptrace(PTRACE_GETREGS, pid, &regs, NULL) != 0) {
			if (WIFEXITED(status)) {
				dump_regs(regs);
				break;
			} else {
				if (ptrace(PTRACE_CONT, pid, NULL, NULL) != 0) {
					perror("ptrace");
					exit(EXIT_FAILURE);
				}
			}
		}
	}

	ptrace(PTRACE_DETACH, pid, 0, 0);

        return 0;
}
