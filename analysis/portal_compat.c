#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>

#define ASHMEM_NAME_LEN 256
#define ASHMEM_SET_NAME _IOW(0x77, 1, char[ASHMEM_NAME_LEN])

struct local_sched_attr {
	uint32_t size;
	uint32_t policy;
	uint64_t flags;
	int32_t nice;
	uint32_t priority;
	uint64_t runtime;
	uint64_t deadline;
	uint64_t period;
};

static void result(const char *name, int ok, long value)
{
	printf("%-24s %s value=%ld errno=%d (%s)\n", name,
	       ok ? "OK" : "FAIL", value, errno, strerror(errno));
}

int main(void)
{
	int fd;
	int a = 1, b = 0;
	struct timespec zero = {0, 0};
	errno = 0;
	long ret = syscall(SYS_futex, &a,
	                   FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG,
	                   0, &zero, &b, 0);
	result("futex_wait_requeue_pi", ret == -1 && errno == EAGAIN, ret);

	errno = 0;
	ret = syscall(SYS_futex, &a,
	              FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG,
	              1, 0, &b, 1);
	result("futex_cmp_requeue_pi", ret == 0, ret);

	struct local_sched_attr attr = {.size = sizeof(attr)};
	errno = 0;
	ret = syscall(SYS_sched_getattr, 0, &attr, sizeof(attr), 0);
	result("sched_getattr", ret == 0, ret);

	fd_set empty;
	FD_ZERO(&empty);
	errno = 0;
	ret = pselect(0, &empty, NULL, NULL, &zero, NULL);
	result("pselect", ret == 0, ret);

	errno = 0;
	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_ICMP);
	result("icmp_dgram_socket", fd >= 0, fd);
	if (fd >= 0)
		close(fd);

	errno = 0;
	fd = open("/dev/ashmem", O_RDWR | O_CLOEXEC);
	result("open_ashmem", fd >= 0, fd);
	if (fd >= 0) {
		char name[ASHMEM_NAME_LEN] = "portal-ghostlock-compat";
		errno = 0;
		ret = ioctl(fd, ASHMEM_SET_NAME, name);
		result("ashmem_set_name", ret == 0, ret);
		close(fd);
	}

	errno = 0;
	void *reserve = mmap(NULL, 64ULL << 30, PROT_NONE,
	                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
	                     -1, 0);
	result("reserve_64g_va", reserve != MAP_FAILED, (long)reserve);
	if (reserve != MAP_FAILED)
		munmap(reserve, 64ULL << 30);

	pid_t child = fork();
	if (child == 0) {
		pause();
		_exit(0);
	}
	if (child > 0) {
		char path[64];
		snprintf(path, sizeof(path), "/proc/%d/mem", child);
		errno = 0;
		fd = open(path, O_RDWR | O_CLOEXEC);
		result("open_child_mem", fd >= 0, fd);
		if (fd >= 0)
			close(fd);
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
	} else {
		result("fork", 0, child);
	}
	return 0;
}
