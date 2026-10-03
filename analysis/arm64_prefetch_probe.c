#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline uint64_t ticks(void) {
  uint64_t value;
  __asm__ volatile("isb; mrs %0, cntvct_el0" : "=r"(value) :: "memory");
  return value;
}

static inline uint64_t frequency(void) {
  uint64_t value;
  __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(value));
  return value;
}

static inline uint64_t probe_once(uintptr_t address) {
  uint64_t begin = ticks();
  __asm__ volatile(
      "prfm pldl1keep, [%0]\n"
      "prfm pldl2keep, [%0]\n"
      "dsb sy\n"
      "isb\n"
      :: "r"(address) : "memory");
  return ticks() - begin;
}

/*
 * CNTVCT advances only once every ~52 ns on this target.  A single PRFM is
 * therefore too short to time reliably.  These batches amplify any page-table
 * walk difference by touching distinct pages while retaining one timer pair.
 */
static inline uint64_t probe_batch(uintptr_t address, uintptr_t stride,
                                   unsigned count) {
  uint64_t begin = ticks();
  uintptr_t cursor = address;
  for (unsigned i = 0; i < count; ++i) {
    __asm__ volatile("prfm pldl1keep, [%0]" :: "r"(cursor) : "memory");
    cursor += stride;
  }
  __asm__ volatile("dsb sy; isb" ::: "memory");
  return ticks() - begin;
}

static int compare_u64(const void *a, const void *b) {
  uint64_t aa = *(const uint64_t *)a;
  uint64_t bb = *(const uint64_t *)b;
  return (aa > bb) - (aa < bb);
}

int main(int argc, char **argv) {
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(0, &set);
  int affinity_ret = sched_setaffinity(0, sizeof(set), &set);
  int affinity_errno = affinity_ret ? errno : 0;

  if (argc > 1 && !strcmp(argv[1], "scan")) {
    if (argc != 7) {
      fprintf(stderr, "usage: %s scan START END WINDOW STRIDE SAMPLES\n",
              argv[0]);
      return 2;
    }
    uintptr_t start = (uintptr_t)strtoull(argv[2], NULL, 0);
    uintptr_t end = (uintptr_t)strtoull(argv[3], NULL, 0);
    uintptr_t window = (uintptr_t)strtoull(argv[4], NULL, 0);
    uintptr_t scan_stride = (uintptr_t)strtoull(argv[5], NULL, 0);
    unsigned samples = (unsigned)strtoul(argv[6], NULL, 0);
    if (!window || !scan_stride || !samples || samples > 256 || end <= start ||
        window % scan_stride) {
      fprintf(stderr, "invalid scan arguments\n");
      return 2;
    }
    uint64_t batch_count64 = window / scan_stride;
    if (batch_count64 > 65536) {
      fprintf(stderr, "scan batch is too large\n");
      return 2;
    }
    unsigned batch_count = (unsigned)batch_count64;
    uint64_t values[256];
    printf("cntfrq=%" PRIu64 " affinity_ret=%d affinity_errno=%d mode=scan "
           "window=0x%" PRIxPTR " stride=0x%" PRIxPTR
           " count=%u samples=%u\n", frequency(), affinity_ret,
           affinity_errno, window, scan_stride, batch_count, samples);
    for (uintptr_t address = start; address < end; address += window) {
      for (unsigned i = 0; i < samples; ++i)
        values[i] = probe_batch(address, scan_stride, batch_count);
      qsort(values, samples, sizeof(values[0]), compare_u64);
      uint64_t sum = 0;
      unsigned lo = samples / 8;
      unsigned hi = samples - samples / 8;
      for (unsigned i = lo; i < hi; ++i)
        sum += values[i];
      printf("%016" PRIxPTR " min=%" PRIu64 " p25=%" PRIu64
             " med=%" PRIu64 " p75=%" PRIu64 " max=%" PRIu64
             " trimavg=%.2f\n", address, values[0], values[samples / 4],
             values[samples / 2], values[(samples * 3) / 4],
             values[samples - 1], (double)sum / (hi - lo));
      if (address > UINTPTR_MAX - window)
        break;
    }
    return 0;
  }

  const char *mode = argc > 1 ? argv[1] : "";
  uintptr_t stride = 0x200000;
  unsigned count = 64;
  int first_address = 1;
  if (!strcmp(mode, "batch")) {
    if (argc < 5) {
      fprintf(stderr, "usage: %s batch STRIDE COUNT ADDRESS...\n", argv[0]);
      return 2;
    }
    stride = (uintptr_t)strtoull(argv[2], NULL, 0);
    count = (unsigned)strtoul(argv[3], NULL, 0);
    if (count == 0 || count > 65536) {
      fprintf(stderr, "invalid count\n");
      return 2;
    }
    first_address = 4;
  }

  printf("cntfrq=%" PRIu64 " affinity_ret=%d affinity_errno=%d mode=%s "
         "stride=0x%" PRIxPTR " count=%u\n", frequency(), affinity_ret,
         affinity_errno,
         first_address == 4 ? "batch" : "once", stride, count);
  for (int arg = first_address; arg < argc; ++arg) {
    char *end = NULL;
    uintptr_t address = (uintptr_t)strtoull(argv[arg], &end, 0);
    if (end == argv[arg] || *end) {
      fprintf(stderr, "invalid address: %s\n", argv[arg]);
      return 2;
    }

    enum { SAMPLES = 4096 };
    uint64_t values[SAMPLES];
    for (int warm = 0; warm < 64; ++warm) {
      (void)(first_address == 4 ? probe_batch(address, stride, count)
                                : probe_once(address));
    }
    for (int i = 0; i < SAMPLES; ++i) {
      values[i] = first_address == 4 ? probe_batch(address, stride, count)
                                     : probe_once(address);
    }
    qsort(values, SAMPLES, sizeof(values[0]), compare_u64);
    uint64_t sum = 0;
    for (int i = SAMPLES / 20; i < SAMPLES - SAMPLES / 20; ++i) {
      sum += values[i];
    }
    printf("%016" PRIxPTR " min=%" PRIu64 " p05=%" PRIu64
           " p25=%" PRIu64 " med=%" PRIu64 " p75=%" PRIu64
           " p95=%" PRIu64 " max=%" PRIu64 " trimavg=%.2f\n",
           address, values[0], values[SAMPLES / 20], values[SAMPLES / 4],
           values[SAMPLES / 2], values[SAMPLES * 3 / 4],
           values[SAMPLES - SAMPLES / 20 - 1], values[SAMPLES - 1],
           (double)sum / (SAMPLES - 2 * (SAMPLES / 20)));
  }
  return 0;
}
