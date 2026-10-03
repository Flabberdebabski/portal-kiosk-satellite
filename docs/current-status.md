# Current exploit status

The installed `remove_waiter` implementation is vulnerable to GhostLock. The
Portal-specific port has established:

- Exact task offsets, including `pi_lock` at `0x8fc` and `pi_blocked_on` at
  `0x918`
- Full 256 GiB direct-map scanning plus exact current-boot `memstart_addr`
  recovery from the kernel memory-layout log
- Reliable order-2 slab reclaim with the full socket spray
- Exact stale waiter placement at syscall stack offset `-0x288`
- A coherent complete-waiter copy from native `sendmmsg` while it sleeps in
  `sk_stream_wait_memory`
- A verified real priority-120 top waiter on the kernel's `proc_uid_lock`

The active route points the forged waiter's lock field at the exact direct-map
alias of `proc_uid_lock`. A nice-19 `/proc/uid` enumeration owns that mutex and
blocks while copying to an ext4 page fault. A pre-forked `run-as` process then
switches directly to the debuggable helper app's UID and queues through kernel
UID registration. The holder's priority changing from 139 to 120 proves that
the real waiter is present.

Signal return now completes before this lock gate starts. The stale waiter
parks at a userspace barrier; after the real waiter is verified, the barrier
releases it directly into `sendmmsg`. The consumer accepts only
`sk_stream_wait_memory`, performs no synchronous disk logging in the critical
interval, and rechecks the holder's donated priority immediately before
`sched_setattr`. The scheduler-disabled control passed with priority 120 and
both the holder and truncate still active.

The first live run with this ordering disconnected ADB and rebooted the Portal.
Its ramoops record is the immediate next input. Network access is back, but the
Portal's TCP ADB switch must be toggled before the record can be collected. The
fault PC will show whether execution advanced past the previous
`rt_mutex_adjust_prio_chain+0x1c0` NULL dereference into `rb_erase` or a later
invariant.

After the constrained write is stable, the remaining sequence is:

1. Redirect `ashmem_misc.fops`, verify bounded kernel read/write, and restore
   the original pointer.
2. Locate and inspect the live `adbd` task and credential layout.
3. Apply the existing bounded credential and SELinux changes.
4. Open a fresh root ADB shell.
5. Call Meta's protected audio service with
   `setAudioProcessingParam(3001, 0)` and disable the related NS/AGC parameters
   if necessary.
6. Verify the microphone signal during speaker playback and test whether the
   setting survives capture restarts or needs a boot-time reapplication.

Hardware echo cancellation remains enabled.
