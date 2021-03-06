#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/shm.h>

#define error_en(msg) \
	do { \
		perror(msg); \
		exit(EXIT_FAILURE); \
	} while (0)

#define MSG "Hello shared memory"
#define BUF_SIZE 1024

struct shm_msg {
	int count;
	char buf[BUF_SIZE];
};

int main(int argc, char *argv[])
{
	char buf[32] = {0};
	int id = 0;
	int flags = IPC_CREAT;
	int perms = S_IRUSR | S_IWUSR;
	key_t key = 0;
	char *tmp = "/tmp/shm-XXXXXX";
	void *addr = NULL;
	struct shm_msg snd_msg;
	struct shm_msg rcv_msg;

	memcpy(buf, tmp, strlen(tmp));

	if (mkstemp(buf) == -1)
		error_en("Create shm file failed");

	printf("shm file: %s\n", buf);

	key = ftok(buf, 1);
	if (key == -1)
		error_en("Create key failed");

	id = shmget(key, sizeof(struct shm_msg), flags | perms);
	if (id == -1)
		error_en("Create shared memory failed");

	printf("Shared memory id: %d\n", id);

	addr = shmat(id, NULL, 0);
	if (addr == (void *)-1)
		perror("Attach shared memory failed");

	snd_msg.count = sizeof(MSG);
	memcpy(snd_msg.buf, MSG, snd_msg.count);
	memcpy(addr, &snd_msg, sizeof(struct shm_msg));
	printf("Sent: %s len: %d\n", snd_msg.buf, snd_msg.count);

	if (shmdt(addr) == -1)
		perror("Detach shared memory failed");

	addr = shmat(id, NULL, 0);
	if (addr == (void *)-1)
		perror("Attach shared memory failed");

	memcpy(&rcv_msg, addr, sizeof(struct shm_msg));
	printf("Received: %s len: %d\n", rcv_msg.buf, rcv_msg.count);

	if (shmctl(id, IPC_RMID, NULL) == -1)
		error_en("Delete shared memory id failed");

	return 0;
}
