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

The next run uses the proven one-left-child graph to replace
`ashmem_misc.fops` with the reclaimed fake table. Once the FOPS checkpoint
succeeds, the planned order is:

1. Verify arbitrary kernel read and write and restore `ashmem_misc.fops`.
2. Dump the live `adbd` credential layout without modifying it.
3. Apply the existing bounded `adbd` credential and SELinux change.
4. Open a fresh root ADB shell.
5. Call Meta's protected audio service with `setAudioProcessingParam(3001, 0)`.
6. Verify the microphone signal during speaker playback and test capture restart behavior.
