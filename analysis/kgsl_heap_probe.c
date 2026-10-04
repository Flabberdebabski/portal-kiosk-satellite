#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define KGSL_IOC_TYPE 0x09
#define KGSL_MEMFLAGS_USE_CPU_MAP 0x10000000U
#define KGSL_MEMALIGN_SHIFT 16

struct kgsl_gpumem_alloc_id {
  unsigned int id;
  unsigned int flags;
  size_t size;
  size_t mmapsize;
  unsigned long gpuaddr;
  unsigned long pad[2];
};

struct kgsl_gpumem_free_id { unsigned int id; unsigned int pad; };

#define IOCTL_KGSL_GPUMEM_ALLOC_ID \
  _IOWR(KGSL_IOC_TYPE, 0x34, struct kgsl_gpumem_alloc_id)
#define IOCTL_KGSL_GPUMEM_FREE_ID \
  _IOWR(KGSL_IOC_TYPE, 0x35, struct kgsl_gpumem_free_id)

int main(void) {
  int fd = open("/dev/kgsl-3d0", O_RDWR | O_CLOEXEC);
  if (fd < 0) { perror("open kgsl"); return 1; }
  for (unsigned align = 12; align <= 16; align++) {
    struct kgsl_gpumem_alloc_id a = {
      .flags = KGSL_MEMFLAGS_USE_CPU_MAP | (align << KGSL_MEMALIGN_SHIFT),
      .size = 0x4000,
    };
    errno = 0;
    int ret = ioctl(fd, IOCTL_KGSL_GPUMEM_ALLOC_ID, &a);
    if (ret) {
      printf("align=%u alloc=%d errno=%d (%s)\n", align, ret, errno,
             strerror(errno));
      continue;
    }
    off_t off = (off_t)a.id << 12;
    errno = 0;
    void *map = mmap(NULL, a.mmapsize, PROT_READ | PROT_WRITE, MAP_SHARED,
                     fd, off);
    printf("align=%u id=%u flags=%08x size=%zu mmapsize=%zu gpu=%lx "
           "off=%llx map=%p errno=%d (%s)\n", align, a.id, a.flags,
           a.size, a.mmapsize, a.gpuaddr, (long long)off, map, errno,
           strerror(errno));
    if (map != MAP_FAILED) {
      memset(map, (int)(0x40 + align), a.mmapsize);
      munmap(map, a.mmapsize);
    }
    struct kgsl_gpumem_free_id f = { .id = a.id };
    ioctl(fd, IOCTL_KGSL_GPUMEM_FREE_ID, &f);
  }
  close(fd);
  return 0;
}
