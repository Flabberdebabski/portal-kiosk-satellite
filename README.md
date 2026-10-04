# Portal Go root and audio control research

This repository tracks the build-specific work to obtain temporary privileged execution on a Facebook Portal Go and disable its hardware echo cancellation at the system level.

## Target

- Device: Facebook Portal Go, `terry`
- Address during authorized testing: `192.168.1.72:5555`
- Build: `Facebook/terry_prod/terry:10/QKQ1.210213.001/5051355900018050:user/prod-keys`
- Kernel: Linux `4.9.227-perf+`
- Security state: locked bootloader, green Verified Boot and SELinux enforcing

The microphone array is processed by the DBMD7/STAX voice DSP before Android receives audio. Meta's protected audio service exposes `AEC_ENABLE` as parameter `3001`, but ordinary apps and the ADB shell cannot call it. The root route adapts GhostLock, CVE-2026-43499, to this exact kernel build and invokes the private service from the temporary privileged process.

## Repository layout

- `exploit/`: Portal-specific GhostLock source and exact-build target constants
- `analysis/`: offset extraction and kernel analysis helpers
- `tools/PortalAudioCtl.java`: direct Binder client for Meta's private audio service
- `docs/findings.md`: chronological investigation record
- `artifacts/`: manifest for large local firmware, kernel and crash artifacts that are intentionally excluded from Git

## Build

Install Android NDK r28.2 at the path used by `exploit/Makefile` or pass `NDK` explicitly:

```sh
make -C exploit -B NDK=/path/to/android-ndk
```

The output is `exploit/build/preload-portal-terry-5051355900018050.so`.

## Current state

The exact installed kernel is vulnerable. The exploit now reclaims the correct order-3 `mm_struct` slab, obtains arbitrary kernel read/write, patches its own credentials to UID 0 with full capabilities, and sets SELinux permissive. On October 3, 2026, it successfully set `AEC_ENABLE` (parameter `3001`) and `NS_MODE` (parameter `4001`) to `0.0`, with both values confirmed by readback. This disables hardware AEC and the separate residual-echo suppression mode for the active audio-service lifetime.

The privileged action can also persist `persist.adb.tcp.port=5555` in Android's property store. A normal Android reboot restored wireless ADB automatically without a host-side `adb tcpip` command. Audio parameters are not yet applied automatically after a reboot; the exploit or a future boot hook must set them again.

This code is tied to the fingerprint and kernel listed above. A mismatch can panic the device.
