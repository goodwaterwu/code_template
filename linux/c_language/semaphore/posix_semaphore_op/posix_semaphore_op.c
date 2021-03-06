#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <semaphore.h>

#define SEM "/sem"

#define error_log(msg) \
	do { \
		perror(msg); \
		exit(EXIT_FAILURE); \
	} while (0)

#define error_en(en, msg) \
	do { \
		errno = en; \
		perror(msg); \
		exit(EXIT_FAILURE); \
	} while (0)

#define NUM_OF_THREAD 3

static int global_variable;
static sem_t *sem;

static void *new_thread(void *arg)
{
	int automatic_variable = 0;

	printf("Thread %zu created\n", (size_t)arg);

	for (int i = 0; i != 10; i++) {
		if (sem_wait(sem) == -1)
			error_log("Wait semaphore failed");

		automatic_variable = global_variable;
		sleep(1); /* Expire time slice. */
		automatic_variable++;
		global_variable = automatic_variable;

		if (sem_post(sem) == -1)
			error_log("Post semaphore failed");

		printf("thread: %zu global_variable: %d\n",
				(size_t)arg, global_variable);
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	void *result = NULL;
	int flags = O_CREAT;
	int perms = S_IRUSR | S_IWUSR;
	pthread_t t[NUM_OF_THREAD];

	sem = sem_open(SEM, flags, perms, 1);
	if (sem == SEM_FAILED)
		error_log("Semaphore create failed");

	printf("Semaphore created\n");

	for (size_t i = 0; i != NUM_OF_THREAD; i++) {
		ret = pthread_create(&t[i], NULL, new_thread, (void *)i);
		if (ret)
			error_en(ret, "Thread create failed");
	}

	for (size_t i = 0; i != NUM_OF_THREAD; i++) {
		ret = pthread_join(t[i], &result);
		if (ret)
			error_en(ret, "Thread join failed");
	}

	printf("global_variable = %d\n", global_variable);

	if (sem_close(sem) == -1)
		error_log("Semaphore close failed");

	printf("Semaphore closed\n");

	if (sem_unlink(SEM) == -1)
		error_log("Semaphore unlink failed");

	printf("Semaphore unlinked\n");

	return 0;
}
