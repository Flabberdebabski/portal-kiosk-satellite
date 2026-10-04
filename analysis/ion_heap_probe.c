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

struct ion_handle_data { ion_user_handle_t handle; };
struct ion_fd_data { ion_user_handle_t handle; int fd; };

#define ION_IOC_MAGIC 'I'
#define ION_IOC_ALLOC _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE  _IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)
#define ION_IOC_SHARE _IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)

int main(void) {
  int ion = open("/dev/ion", O_RDWR | O_CLOEXEC);
  if (ion < 0) { perror("open /dev/ion"); return 1; }

  for (unsigned int id = 0; id < 32; id++) {
    struct ion_allocation_data alloc = {
      .len = 0x4000, .align = 0x4000, .heap_id_mask = 1U << id,
    };
    errno = 0;
    int ret = ioctl(ion, ION_IOC_ALLOC, &alloc);
    if (ret != 0) {
      printf("heap=%u alloc=%d errno=%d (%s)\n", id, ret, errno,
             strerror(errno));
      continue;
    }

    struct ion_fd_data share = { .handle = alloc.handle, .fd = -1 };
    errno = 0;
    int sret = ioctl(ion, ION_IOC_SHARE, &share);
    void *map = MAP_FAILED;
    if (sret == 0)
      map = mmap(NULL, alloc.len, PROT_READ | PROT_WRITE, MAP_SHARED,
                 share.fd, 0);
    printf("heap=%u alloc=0 handle=%d share=%d fd=%d mmap=%p errno=%d (%s)\n",
           id, alloc.handle, sret, share.fd, map, errno, strerror(errno));
    if (map != MAP_FAILED) {
      memset(map, (int)(0x40 + id), alloc.len);
      msync(map, alloc.len, MS_SYNC);
      munmap(map, alloc.len);
    }
    if (share.fd >= 0) close(share.fd);
    struct ion_handle_data free_data = { .handle = alloc.handle };
    ioctl(ion, ION_IOC_FREE, &free_data);
  }
  close(ion);
  return 0;
}
