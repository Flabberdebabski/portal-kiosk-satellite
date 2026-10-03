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

The next boundary is reliable socket-page reclamation. An attempted ashmem
FOPS pivot reached `misc_open()`, but the fake table's owner field contained
`0xc`; `try_module_get()` faulted on that value. The page had been reused by
the large proc-lock gate setup instead of retaining the socket payload. The
gate's 64 GiB of shared mappings is now prepared while the leaked `mm_struct`
is still pinned, before the target slab page is freed and immediately sprayed.
The next live checkpoint will verify arbitrary kernel read/write and stop
before credential mutation.

After that checkpoint, the remaining sequence is:

1. Use the configfs-based primitive to read the canonical `memstart_addr` and
   configure the live direct-map translation.
2. Patch the running `adbd` credentials and set SELinux permissive with the
   existing bounded configfs writes.
3. Open a fresh root ADB shell.
4. Call Meta's protected audio service with
   `setAudioProcessingParam(3001, 0)`, followed by the NS and AGC parameters
   if required.
5. Verify microphone capture during speaker playback and determine whether
   the setting must be reapplied after audio-service or device restarts.

Hardware echo cancellation remains enabled.
