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
- `tools/provision_portal.py`: action-based provisioner and two-reboot verifier
- `tools/PortalAudioCtl.java`: direct Binder client for Meta's private audio service
- `tools/PortalAccountCtl.java`: local Meta account and identity-database cleanup
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

Run the provisioner from a host with wireless ADB already connected. With no
action flag it retains the original behavior and provisions audio; `--audio`
selects it explicitly when combining actions:

```sh
python3 tools/provision_portal.py --serial 192.168.1.72:5555 --audio
```

The provisioner refuses any fingerprint other than the supported build, stages
fresh binaries, derives that boot's randomized kernel addresses, retries the
GhostLock reclaim if needed, and verifies the watchdog across two distinct
reboots. Attempt logs are written to a timestamped directory under `/tmp`.

To provision the already-active Kiosk Satellite admin as Android's Device
Owner at the same time, add `--device-owner`:

```sh
python3 tools/provision_portal.py \
  --serial 192.168.1.72:5555 --audio --device-owner
```

Android's normal `dpm set-device-owner` command rejects this Portal because it
already has Meta accounts. The privileged action instead installs the Android
10 owner record only after confirming that
`me.jxl.kiosk_satellite/.KioskAdminReceiver` is an active admin and that no
other owner record exists. It snapshots the original policy under
`/data/local/tmp/portal-device-owner-backup`, preserves the system policy
file's ownership and SELinux label, and commits the owner file with `fsync`
and an atomic rename. The provisioner then requires DevicePolicyManager to report
Kiosk Satellite as owner of user 0 and `ro.device_owner=true` after two
distinct boots. A later run recognizes the existing owner and exits without
rewriting it or invoking the exploit.

The persistent files are placed in the AI service's private
`lib-compressed` directory. `libcoldstart_1.so` has its `libdl.so` dependency
slot changed to the equal-length name `libpa.so`; the original is retained as
`libcoldstart_1.portal-original.so`. The helper keeps `libdl.so` as a normal
dependency, so the original cold-start library still resolves its symbols.

## Persistent OTA disable

The same provisioner can disable Meta's automatic firmware-update path:

```sh
python3 tools/provision_portal.py \
  --serial 192.168.1.72:5555 --disable-updates
```

This disables `com.facebook.aloha.otaui` and
`com.facebook.aloha.alohaotasetup` for user 0 and atomically installs a local
MobileConfig override for
`sessionless_aloha_ota_daemon:firmware_ota_update_enable=false`. The override
file is owned by the original MobileConfig app UID, retains the app-data
SELinux label, and is loaded after server configuration. The installer refuses
to replace an unrelated existing override file. It records an absent-file
marker under `/data/local/tmp/portal-ota-backup`, then requires both the native
daemon's false gate and Meta's `source: OVERRIDE` log on two fresh boots.

The native `otad` and Android `update_engine` processes still exist because
both are shared system infrastructure. With the firmware-update gate pinned
false, `otad` remains idle and does not discover or install a package.

## Reversible debloat profile

The conservative debloat profile disables six user-facing or telemetry
packages while retaining the Portal camera, audio, identity, presence, media,
app-management and WebView services:

- `com.facebook.aloha.analytics`
- `com.facebook.aloha.app.messenger`
- `com.facebook.aloha.app.whatsapp`
- `com.facebook.aloha.app.portalfeed`
- `com.facebook.alohaapps.superframe`
- `com.facebook.alohaapps.contacts`

Apply it with:

```sh
python3 tools/provision_portal.py \
  --serial 192.168.1.72:5555 --debloat
```

This operation uses Android's per-user package state and does not launch the
kernel exploit. Before changing anything, it records whether every package was
enabled, disabled, or absent in
`/data/local/tmp/portal-debloat-backup-v1.tsv`. It then verifies the disabled
set, both cameras, AI service, Home activity and WebView provider across two
reboots. Restore exactly those saved package states with:

```sh
python3 tools/provision_portal.py \
  --serial 192.168.1.72:5555 --restore-bloat
```

Action flags are independent. For a fresh device that needs every supported
customization, combine them in one run:

```sh
python3 tools/provision_portal.py --serial 192.168.1.72:5555 \
  --audio --device-owner --disable-updates --debloat --remove-meta-accounts \
  --optimize-presence
```

## Presence-preserving AI optimization

Kiosk Satellite uses AIService's `Notify people presence` log as the Portal's
LED-free presence signal. The optional presence profile keeps that detector,
the AIService camera client, tracking, and pose estimation running while it
turns off four downstream Smart Camera workloads:

- background segmentation
- liveness scoring
- color-based re-identification
- face-recognition-based re-identification

Apply the profile while somebody is in front of the Portal so the live
verifier can observe a new presence heartbeat:

```sh
python3 tools/provision_portal.py \
  --serial 192.168.1.72:5555 --optimize-presence
```

The privileged installer atomically writes AIService's private
`settings_config.xml` with the app's UID, GID, and SELinux label. If a settings
file already exists and was not created by this project, the installer saves
it and refuses to replace it. Otherwise it records that the file was absent
under `/data/local/tmp/portal-presence-backup`. Every verification boot
requires AIService to own an active camera client, retain the CAMERA AppOp,
load all four values as false, and emit the exact presence log Kiosk Satellite
consumes.

Restore the saved file, or remove the project-owned file when none existed,
with:

```sh
python3 tools/provision_portal.py \
  --serial 192.168.1.72:5555 --restore-presence-profile
```

On the tested Portal, six equal-length samples averaged 47.8% of one CPU core
before the profile and 22.1% afterward. The background-detector thread alone
had averaged 11.6%; after the change, its worker and the liveness worker were
absent. These measurements are workload samples rather than a benchmark, but
the same exact presence heartbeat passed on two clean boots.

## Remove Meta accounts

The account-removal action clears the four Portal-specific Android account
types and prevents the firmware from creating them again:

```sh
python3 tools/provision_portal.py \
  --serial 192.168.1.72:5555 --remove-meta-accounts
```

The privileged action removes the AccountManager records and the matching
rows in Meta's two local identity databases. It then disables only the four
authenticator service components in
`com.facebook.alohaservices.alohausers`. The package itself stays enabled so
MobileConfig, the OTA override, camera support, and other shared Portal
services continue to work.

Before the first change, the provisioner records the account type/name
inventory in `/data/local/tmp/portal-meta-accounts-before-v1.tsv` and copies
it into the host log directory. This inventory does not contain tokens or a
full database backup, so it is evidence of the former identities rather than
an automatic restore point. The provisioner treats a later run as idempotent
when no target accounts remain and all four authenticators are disabled. It
still verifies that state, the retained package, both cameras, AI Service,
Home, and WebView on two new boots.

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

On October 4, 2026, Kiosk Satellite version `2026.10.6` was also provisioned
as Device Owner for user 0. Android loaded it as
`ComponentInfo{me.jxl.kiosk_satellite/me.jxl.kiosk_satellite.KioskAdminReceiver}`
and set `ro.device_owner=true`. That state survived normal reboots with boot
IDs `31327449-dca9-47ab-919c-8608945b6eb1` and
`73b06f93-35bc-47f5-bb99-ff324ca27c7e`.

On October 4, 2026, automatic firmware updates were disabled and verified
after normal reboot to boot ID `5757afe1-3d74-46f9-a245-10239d30571e`.
`dumpsys facebook.aloha.otaservice` reported idle state, no downloaded JSON
manifest, and `kFirmwareOtaUpdateEnable=false`; Meta's MobileConfig client
reported the exact parameter value as `source: OVERRIDE`. Both OTA packages
remained disabled. Device Owner, persistent wireless ADB, and the audio
watchdog all passed on the same boot.

On October 4, 2026, the conservative debloat profile was applied and survived
two clean boots with IDs `c43f3691-0874-445b-bf85-1e55907194dc` and
`401c4711-17d7-4990-bfbe-544243306f25`. None of the six disabled app processes
remained running. Both cameras, AI Service, Kiosk Satellite Home, Portal
WebView, Device Owner, wireless ADB, the OTA block, and the audio watchdog
remained healthy.

On October 4, 2026, all four Portal-specific Meta accounts were removed and
their four authenticator components were disabled. The shared `alohausers`
package remained enabled. Verification boots
`8db565c4-f7c2-40dc-9df5-aba6b4a98390` and
`8762d7c6-1db1-400f-9559-8df8dc9f5f33` both reported zero target accounts,
two camera devices, a running AI service, Kiosk Satellite Home, and the Portal
WebView provider. SELinux returned to enforcing after the exploit boot.

On October 4, 2026, the presence-preserving AI profile was installed and
verified on clean boot IDs `64e187d4-1999-4152-83ba-f66d763dcf86` and
`57488e98-61b0-45be-9128-4447503e8c1e`. AIService loaded all four disabled
workload settings, retained its active camera client and CAMERA permission,
and emitted `Notify people presence` on both boots. Sampled AIService CPU fell
from 47.8% to 22.1% of one core while Kiosk Satellite's log-based presence
source remained available.

This code is tied to the fingerprint and kernel listed above. A mismatch can panic the device.
