# Current exploit status

The installed `remove_waiter` implementation is vulnerable to GhostLock. The Portal-specific port has established:

- Exact task offsets, including `pi_lock` at `0x8fc` and `pi_blocked_on` at `0x918`
- Full 256 GiB direct-map scanning and runtime `memstart_addr` recovery
- Reliable order-2 slab reclaim with the full socket spray
- Exact stale waiter placement at syscall stack offset `-0x288`
- Exact `PTRACE_SETREGSET` overlap at FPSIMD input offset `0x118`
- A candidate constrained write into the direct-map alias of `ashmem_misc.fops`

The lifetime blocker is resolved with native `sendmmsg`. Its nested
`sockaddr_storage` starts at syscall entry SP-0x290; placing an eight-byte
prefix before the complete forged waiter covers the stale object at SP-0x288.
A full connected TCP send buffer then holds the calling thread in
`sk_stream_wait_memory` while the remote scheduler operation consumes the
coherent copy. The equal-priority control reached that wchan, completed
`sched_setattr` successfully, and returned without a crash.

The equal-priority placement control is stable. The first live FOPS attempt
also exposed a return-path constraint: after changing the task to priority
121, the forged waiter became the fake lock's top waiter and triggered an
unsafe wakeup. Keeping the existing priority-130 sentinel on top by changing
the task to priority 139 avoids that branch, but the following live attempt
lost shell service before its final trace could be retained.

The retained trace from the boot-id proof showed that `sched_setattr` entered
but did not return, while the boot ID remained unchanged. This confines the
stall to acquisition of the reclaimed-page fake mutex before `rb_erase`.

Ramoops disproved the partial-copy route: signal return overwrote the stale
waiter's lock field with a userspace pointer before `sendmmsg` ran. The active
build instead points the complete forged waiter at the kernel's statically
initialized `msm_bus_dbg_cllist_lock`. That idle BSS `rt_mutex` has a valid
unlocked spinlock and does not depend on reclaimed-page contents. The
ownerless return wakes `init_task`, which is already runnable. This dirties
the debug lock's waiter tree, so a proof run must be followed by reboot and a
live primitive must restore the lock immediately. Once that checkpoint
succeeds, the planned order is:

1. Verify arbitrary kernel read and write and restore `ashmem_misc.fops`.
2. Dump the live `adbd` credential layout without modifying it.
3. Apply the existing bounded `adbd` credential and SELinux change.
4. Open a fresh root ADB shell.
5. Call Meta's protected audio service with `setAudioProcessingParam(3001, 0)`.
6. Verify the microphone signal during speaker playback and test capture restart behavior.
