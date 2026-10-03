#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/falloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define WARM_SIZE (64ULL * 1024 * 1024)

static long long usec_since(const struct timespec *start,
                            const struct timespec *end) {
  return (long long)(end->tv_sec - start->tv_sec) * 1000000LL +
         (end->tv_nsec - start->tv_nsec) / 1000LL;
}

int main(void) {
  const char *path = "/data/local/tmp/ext4-fault-gate-probe.bin";
  long page_size = sysconf(_SC_PAGESIZE);
  int fd = open(path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
  if (fd < 0) {
    perror("open");
    return 1;
  }
  if (ftruncate(fd, (off_t)WARM_SIZE) != 0 ||
      posix_fallocate(fd, 0, (off_t)WARM_SIZE) != 0) {
    perror("allocate");
    return 1;
  }

  unsigned char *map = mmap(NULL, WARM_SIZE, PROT_READ | PROT_WRITE,
                            MAP_SHARED, fd, 0);
  if (map == MAP_FAILED) {
    perror("mmap");
    return 1;
  }

  for (int pass = 0; pass < 4; pass++) {
    volatile uint64_t sum = 0;
    for (size_t off = 0; off < WARM_SIZE; off += (size_t)page_size) {
      if (pass == 0) {
        map[off] = (unsigned char)(off / (size_t)page_size);
      }
      sum += map[off];
    }
    if (pass == 0 && msync(map, WARM_SIZE, MS_SYNC) != 0) {
      perror("msync");
      return 1;
    }

    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    errno = 0;
    long ret = syscall(SYS_fallocate, fd,
                       FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE,
                       0, (off_t)WARM_SIZE);
    int saved_errno = errno;
    clock_gettime(CLOCK_MONOTONIC, &end);
    printf("pass=%d ret=%ld errno=%d usec=%lld sum=%llu\n",
           pass, ret, saved_errno, usec_since(&start, &end),
           (unsigned long long)sum);
  }

  munmap(map, WARM_SIZE);

  const size_t truncate_sizes[] = {
    64ULL * 1024 * 1024,
    128ULL * 1024 * 1024,
    256ULL * 1024 * 1024,
  };
  for (size_t pass = 0;
       pass < sizeof(truncate_sizes) / sizeof(truncate_sizes[0]); pass++) {
    size_t size = truncate_sizes[pass];
    if (ftruncate(fd, 0) != 0 || ftruncate(fd, (off_t)size) != 0 ||
        posix_fallocate(fd, 0, (off_t)size) != 0) {
      perror("truncate allocate");
      return 1;
    }
    unsigned char *truncate_map = mmap(NULL, size, PROT_READ,
                                       MAP_SHARED, fd, 0);
    if (truncate_map == MAP_FAILED) {
      perror("truncate mmap");
      return 1;
    }
    volatile uint64_t sum = 0;
    for (size_t off = 0; off < size; off += (size_t)page_size) {
      sum += truncate_map[off];
    }

    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    errno = 0;
    int ret = ftruncate(fd, page_size);
    int saved_errno = errno;
    clock_gettime(CLOCK_MONOTONIC, &end);
    printf("truncate_mib=%zu ret=%d errno=%d usec=%lld sum=%llu\n",
           size / (1024 * 1024), ret, saved_errno,
           usec_since(&start, &end), (unsigned long long)sum);
    munmap(truncate_map, size);
  }

  close(fd);
  return 0;
}
