# Portal Go root and audio control research

This repository tracks the build-specific work to obtain temporary privileged execution on a Facebook Portal Go and disable its hardware echo cancellation at the system level.

## Target

- Device: Facebook Portal Go, `terry`
- Address during authorized testing: `192.168.1.72:5555`
- Build: `Facebook/terry_prod/terry:10/QKQ1.210213.001/5051355900018050:user/prod-keys`
- Kernel: Linux `4.9.227-perf+`
- Security state: locked bootloader, green Verified Boot and SELinux enforcing

The microphone array is processed by the DBMD7/STAX voice DSP before Android receives audio. Meta's protected audio service exposes `AEC_ENABLE` as parameter `3001`, but ordinary apps and the ADB shell cannot call it. The current root route adapts GhostLock, CVE-2026-43499, to this exact kernel build.

## Repository layout

- `exploit/`: Portal-specific GhostLock source and exact-build target constants
- `analysis/`: offset extraction and kernel analysis helpers
- `docs/findings.md`: chronological investigation record
- `artifacts/`: manifest for large local firmware, kernel and crash artifacts that are intentionally excluded from Git

## Build

Install Android NDK r28.2 at the path used by `exploit/Makefile` or pass `NDK` explicitly:

```sh
make -C exploit -B NDK=/path/to/android-ndk
```

The output is `exploit/build/preload-portal-terry-5051355900018050.so`.

## Current state

The exact installed kernel is vulnerable and the exploit can reclaim the required order-2 `mm_struct` slab page. The active work is making the stale `rt_mutex_waiter` replacement remain coherent long enough for the remote priority adjustment to perform the constrained `rb_erase` write. Root and the system-wide AEC change have not been achieved yet.

This code is tied to the fingerprint and kernel listed above. A mismatch can panic the device.
