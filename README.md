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
- `helper/`: native boot-time audio watchdog and the earlier APK prototype
- `analysis/`: offset extraction and kernel analysis helpers
- `tools/install_audio_persistence.py`: build-specific installer and two-reboot verifier
- `tools/PortalAudioCtl.java`: direct Binder client for Meta's private audio service
- `docs/findings.md`: chronological investigation record
- `artifacts/`: manifest for large local firmware, kernel and crash artifacts that are intentionally excluded from Git

## Build

Install Android NDK r28.2 at the path used by `exploit/Makefile` or pass `NDK` explicitly:

```sh
make -C exploit -B NDK=/path/to/android-ndk
```

The output is `exploit/build/preload-portal-terry-5051355900018050.so`.

Build the persistent native helper with:

```sh
make -C helper native
```

## Persistent audio disable

The installed solution loads `libportal_audio_persist.so` inside Meta's
`com.facebook.portal.aiservice` process at every process start. Its watchdog
uses the service's own Binder identity to keep these DSP parameters at zero:

- `AEC_ENABLE` (`3001`)
- `NS_MODE` (`4001`), including residual-echo suppression

Run the installer from a host with wireless ADB already connected:

```sh
python3 tools/install_audio_persistence.py --serial 192.168.1.72:5555
```

The installer refuses any fingerprint other than the supported build, stages
fresh binaries, derives that boot's randomized kernel addresses, retries the
GhostLock reclaim if needed, and verifies the watchdog across two distinct
reboots. Attempt logs are written to a timestamped directory under `/tmp`.

The persistent files are placed in the AI service's private
`lib-compressed` directory. `libcoldstart_1.so` has its `libdl.so` dependency
slot changed to the equal-length name `libpa.so`; the original is retained as
`libcoldstart_1.portal-original.so`. The helper keeps `libdl.so` as a normal
dependency, so the original cold-start library still resolves its symbols.

## Current state

The exact installed kernel is vulnerable. The exploit now reclaims the correct order-3 `mm_struct` slab, obtains arbitrary kernel read/write, patches its own credentials to UID 0 with full capabilities, and sets SELinux permissive. On October 3, 2026, it successfully set `AEC_ENABLE` (parameter `3001`) and `NS_MODE` (parameter `4001`) to `0.0`, with both values confirmed by readback. This disables hardware AEC and the separate residual-echo suppression mode for the active audio-service lifetime.

The privileged action can also persist `persist.adb.tcp.port=5555` in Android's property store. A normal Android reboot restored wireless ADB automatically without a host-side `adb tcpip` command.

On October 4, 2026, the hardened native watchdog was installed and verified on
two successive cold service starts with boot IDs
`30d9a2c6-9bd2-4ec7-bd6c-88ccf915f266` and
`72d69b44-bd45-4ba6-8494-da4515f396ee`. On both boots it read back parameters
3001 and 4001 as `0`. On the second boot Meta reset NS mode to `5`; the
watchdog detected the change and restored it to `0` on its next pass. It checks
once per second during startup and for 30 clean passes after any correction,
then every five seconds in steady state. This demonstrates both boot
persistence and repair of later service-side rewrites.

This code is tied to the fingerprint and kernel listed above. A mismatch can panic the device.
