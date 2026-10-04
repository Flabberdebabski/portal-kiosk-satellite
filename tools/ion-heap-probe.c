#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

typedef int ion_user_handle_t;

struct ion_allocation_data {
  size_t len;
  size_t align;
  unsigned int heap_id_mask;
  unsigned int flags;
  ion_user_handle_t handle;
};

struct ion_handle_data {
  ion_user_handle_t handle;
};

struct ion_fd_data {
  ion_user_handle_t handle;
  int fd;
};

#define ION_IOC_MAGIC 'I'
#define ION_IOC_ALLOC _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE _IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)
#define ION_IOC_SHARE _IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)

int main(void) {
  int ion = open("/dev/ion", O_RDWR | O_CLOEXEC);
  if (ion < 0) {
    ion = open("/dev/ion", O_RDONLY | O_CLOEXEC);
  }
  if (ion < 0) {
    fprintf(stderr, "open /dev/ion: %s\n", strerror(errno));
    return 1;
  }
  printf("ion fd=%d access=%s\n", ion,
         (fcntl(ion, F_GETFL) & O_ACCMODE) == O_RDONLY ? "read" : "rw");

  int successes = 0;
  for (unsigned int heap = 0; heap < 32; heap++) {
    struct ion_allocation_data alloc = {
      .len = 0x4000,
      .align = 0x4000,
      .heap_id_mask = 1U << heap,
      .flags = 0,
      .handle = 0,
    };
    errno = 0;
    int ret = ioctl(ion, ION_IOC_ALLOC, &alloc);
    if (ret != 0) {
      printf("heap=%u alloc=-1 errno=%d\n", heap, errno);
      continue;
    }

    struct ion_fd_data share = {.handle = alloc.handle, .fd = -1};
    errno = 0;
    int share_ret = ioctl(ion, ION_IOC_SHARE, &share);
    int share_errno = errno;
    void *map = MAP_FAILED;
    if (share_ret == 0) {
      map = mmap(NULL, alloc.len, PROT_READ | PROT_WRITE, MAP_SHARED,
                 share.fd, 0);
      if (map != MAP_FAILED) {
        memset(map, (int)(0x40 + heap), alloc.len);
      }
    }
    printf("heap=%u alloc=0 handle=%d len=0x%zx align=0x%zx "
           "share=%d share_errno=%d fd=%d mmap=%s mmap_errno=%d\n",
           heap, alloc.handle, alloc.len, alloc.align, share_ret,
           share_errno, share.fd, map == MAP_FAILED ? "fail" : "ok", errno);
    successes++;

    if (map != MAP_FAILED) {
      munmap(map, alloc.len);
    }
    if (share.fd >= 0) {
      close(share.fd);
    }
    struct ion_handle_data free_data = {.handle = alloc.handle};
    (void)ioctl(ion, ION_IOC_FREE, &free_data);
  }
  close(ion);
  return successes ? 0 : 2;
}
