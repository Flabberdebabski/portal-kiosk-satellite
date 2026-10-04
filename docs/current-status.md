# Current exploit status

The Portal Go's installed 4.9.227 kernel is vulnerable to GhostLock. The
build-specific port now has a deterministic stale `rt_mutex_waiter` copy from
native `sendmmsg`, a verified priority-120 real waiter on `proc_uid_lock`, and
a working constrained kernel write through the vulnerable dequeue path.

The current boot's randomized `_text` can be recovered without the fragile
first exploit stage. Android's bundled `simpleperf` records raw kernel PCs;
the frequent `el0_svc_naked+0x34` sample identifies the runtime base. The
exploit accepts that verified address through `GHOSTLOCK_KASLR_BASE` and uses
canonical KASLR-adjusted addresses for `proc_uid_lock` and write targets.

The constrained write is proven. A held diagnostic redirected the boot-ID
sysctl data pointer to the reclaimed-page candidate and read back its first 16
bytes. The scheduler operation returned zero before the later legitimate
`run-as` waiter panicked in `rb_next()` while traversing the deliberately
damaged mutex tree.

The constrained write did not corrupt a successfully reclaimed fake table.
The held socket diagnostic found no modified payload among all queued data.
Exact allocator analysis explains why: the UNIX socket task-fragment cache
allocates order-3 pages, with an order-0 fallback, while the freed `mm_struct`
slab is order-2. A 16 KiB send consumes half an order-3 allocation; it does not
request an order-2 page.

The replacement route uses `/dev/kgsl-3d0`. A shell-accessible
`KGSL_IOC_GPUMEM_ALLOC_ID` request for 16 KiB with alignment exponent 14
returns a writable 16 KiB mapping. The exact driver takes the no-pool path on
this device and calls `alloc_pages(..., 2)`, matching the target slab. The
exploit now drains and retains KGSL order-2 allocations before freeing the
target, immediately allocates and maps the reclaim set after the free, copies
the fake object graph into every mapping, and inspects offset `0x1008` after
the scheduler write. A clean collision is therefore directly observable
before any ashmem open.

The first corrected sendmmsg run returned zero from `sched_setattr`. It then
spent 0.38 seconds on the obsolete socket scan and the finite ext4 gate expired
before the KGSL verifier ran. A second run with a 512 MiB gate established that
the scheduler syscall itself remains blocked until the gate expires, so a
larger file delays both events without creating post-write time. The scheduler
consumer now scans the already populated KGSL mappings immediately on return,
before any syscall, log operation, or cross-thread wakeup. Its return line
includes `kgsl_hit`: positive identifies an owner-zero fake table, negative a
matching table with a nonzero owner, and zero no observed collision.

The first run with that fast scan rebooted after the owner-chain timeout but
before the consumer emitted its return line. Exact KGSL source then showed its
page-allocation VMAs use `VM_DONTCOPY`; a watcher created in the forked child
therefore faulted before the next attempt reached the timeout. The watcher now
runs in the pre-fork parent, which owns the KGSL mappings and remains alive in
`waitpid` throughout the trigger. It scans on a spare CPU while `sched_setattr`
is blocked and emits a minimal `KGSL_WATCH_HIT` marker on observing the write.
The child skips its mapping scan in this mode. The corrected watcher observed
no collision among 2,048 mappings during a complete constrained-write run.
The reclaim sequence had allocated all KGSL pages before the later marker
close that drains a frozen CPU-partial slab. It now uses an early batch after
the target close and performs the remaining KGSL allocations immediately
after that drain, covering both ways the target slab can reach buddy.
KGSL assembles these 16 KiB buffers from 8 KiB allocation chunks on this
driver family. The watcher therefore checks the constrained word's in-page
offset in all four virtual page slots, so a split or rearranged target page is
observable even when it cannot yet hold the complete fake object graph.
That all-slot scan also missed with 64 MiB allocated across both stages, which
shows the target remains in the `mm_struct` cache. An optional cache-cycle now
refills the old partial slabs with fresh address spaces, moves allocation to
later slabs, and frees the fresh objects in order. The later frees overflow
CPU partial storage after the target becomes an early empty slab; KGSL then
runs at this additional discard boundary. The first test placed this cycle
after the large proc_uid gate and was stopped when clone page-table copying
made the device unresponsive. Refill tasks are now reaped one at a time, and
the proc_uid gate is built only after cache cycling and KGSL capture. A
20-slab corrected run completed normally but still produced no KGSL hit across
4,096 buffers. Because the fake graph nevertheless completes the scheduler
operation, a concurrent parent watcher now peeks and scans the entire UNIX
socket payload for the constrained word instead of assuming one fragment
offset.

After that checkpoint, the remaining sequence is:

1. Complete the held KGSL collision verification on the next responsive boot.
2. Use the configfs-based primitive to read the canonical `memstart_addr` and
   configure the live direct-map translation.
3. Patch the running `adbd` credentials and set SELinux permissive with the
   existing bounded configfs writes.
4. Open a fresh root ADB shell.
5. Call Meta's protected audio service with
   `setAudioProcessingParam(3001, 0)`, followed by the NS and AGC parameters
   if required.
6. Verify microphone capture during speaker playback and determine whether
   the setting must be reapplied after audio-service or device restarts.

Hardware echo cancellation remains enabled.
