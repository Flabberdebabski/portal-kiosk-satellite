# Meta Portal Root and Provisioning for Kiosk Satellite

This project prepares abandoned Meta Portal devices for use with
[Kiosk Satellite](https://github.com/jxlarrea/kiosk-satellite) through a
guarded command-line provisioner for durable system changes that Android and
Meta's firmware do not normally allow.

## Available features

- **[Temporary, scoped root provisioning](#how-the-root-exploit-works):**
  performs otherwise inaccessible system changes, then reboots normally with
  SELinux enforcing instead of leaving a general root daemon running.
- **[Complete kiosk profile](#6-run-the-provisioner):** applies the tested
  audio, Device Owner, update-blocking, debloat, account-removal, and presence
  settings with one command, reducing setup time and configuration mistakes.
- **[System-wide hardware AEC and noise-suppression control](#1-disable-hardware-echo-cancellation-and-noise-suppression):**
  stops the Portal's voice DSP from suppressing microphone input while its
  speakers play, improving simultaneous playback and listening for every
  Android app. The paired rollback restores Meta's original loader and
  processing defaults.
- **[Kiosk Satellite Device Owner provisioning](#2-make-kiosk-satellite-the-device-owner):**
  grants Android's strongest kiosk policy role so Kiosk Satellite can manage
  the device more reliably than an ordinary device-admin app.
- **[Automatic firmware-update blocking](#3-disable-automatic-meta-firmware-updates):**
  keeps an abandoned Portal on its known compatible build and prevents an
  unexpected Meta update from breaking provisioning. The paired rollback
  restores the original OTA configuration and packages.
- **[Conservative Meta app debloat](#4-disable-unused-meta-applications):**
  disables six unused communication, feed, display, contact, and telemetry
  packages to reduce background work while retaining camera, presence, media,
  WebView, and kiosk services. Its rollback restores every package's saved
  state.
- **[Local Meta-account removal](#5-remove-local-meta-accounts):** removes
  obsolete Portal identity data and prevents its authenticators from
  recreating those accounts, improving privacy without disabling the shared
  services used by the camera and configuration stack.
- **[Presence-pipeline optimization](#6-reduce-aiservice-cpu-use-while-preserving-presence-detection):**
  disables optional Smart Camera segmentation, liveness, and re-identification
  workloads while retaining the LED-free person-detection log consumed by
  Kiosk Satellite. The tested profile cut AIService CPU use by roughly half
  and includes an exact rollback.
- **[Device-local Shizuku startup](#8-install-shizuku-with-automatic-startup):**
  installs the official [Shizuku](https://github.com/RikkaApps/Shizuku)
  manager and starts its service with Android's ADB-shell identity after every
  reboot, giving compatible apps privileged APIs without rerunning the root
  exploit or leaving another computer online.
- **[Filtering Private DNS](#7-use-a-filtering-private-dns-resolver):** routes
  DNS through a user-selected DNS-over-TLS resolver, allowing unwanted Meta
  endpoints to be filtered without modifying system certificates or
  installing a broad root firewall. The original DNS settings can be restored.
- **[Read-only device status](#status-report):** reports target compatibility,
  SELinux, Kiosk Satellite, Device Owner, audio, OTA, debloat, account,
  presence, DNS, and provisioning-manifest state without exploiting or
  rebooting the device.
- **[Dry-run planning](#dry-run-planning):** previews actions, required
  binaries and host tools, exploit use, reboot count, and current state without
  changing the Portal.
- **[Private backup bundles](#backup-bundles):** saves diagnostics and
  reversible configuration snapshots in a mode-0600 archive with SHA-256
  hashes, making maintenance and rollback evidence easier to preserve.
- **[Interrupted-run recovery](#interrupted-run-recovery):** records pending
  work on the Portal, removes stale staged files, and safely resumes the
  validated action set after a host failure or power interruption.
- **[Exact model and firmware safeguards](#supported-models):** matches both
  the device codename and complete firmware fingerprint before any kernel
  write, preventing offsets for one Portal build from being used on another.
- **[Automatic retry and two-boot verification](#running-and-troubleshooting):**
  retries race-sensitive exploit attempts from clean boots and accepts changes
  only after their requested behavior passes on two distinct normal boots.

Support is intentionally build-specific. One Portal Go firmware is currently
supported; the repository is organized so more Portal models and firmware
builds can be added as their kernel layouts and system services are verified.

## How the root exploit works

The project adapts GhostLock,
[CVE-2026-43499](https://www.cve.org/CVERecord?id=CVE-2026-43499), to a
specific Portal kernel. The host provisioner confirms the device model and full
firmware fingerprint, reboots into a clean state, derives the randomized kernel
addresses for that boot, and starts the exploit through a staged native
library. The exploit obtains temporary kernel read/write access, gives its own
process root credentials, and performs only the selected provisioning actions.

Afterward, the device reboots normally. SELinux returns to enforcing, and the
exploit does not install `su`, a root shell, or a general root daemon. Features
that must survive reboot use narrowly scoped configuration files, the native
audio watchdog, or a dedicated loopback-ADB helper installed by the privileged
process. The provisioner then checks the requested behavior on two distinct
boots.

Kernel exploitation is race-sensitive. An unsuccessful attempt may reboot or
temporarily freeze the Portal; the provisioner retries from a clean boot. The
tool refuses to run its build-specific kernel writes if the model or firmware
fingerprint does not match a supported target.

## Requirements

### Host computer

- A Linux x86_64 host on the same network as the Portal
- Git, GNU Make, Python 3.9 or newer, and Android Debug Bridge (`adb`)
- Android NDK r28.2 (`28.2.13676358`)
- A Java Development Kit with `javac` and `jar`
- Android SDK Platform 36 and an Android Build Tools installation containing
  `aapt`, `d8`, `zipalign`, and `apksigner` when using `--shizuku`
- Internet access to download the pinned official Shizuku APK, or a local APK
  supplied with `--shizuku-apk PATH`

The Python provisioner uses only the standard library; there are no Python
packages to install.

### Portal

- A model and exact firmware build listed under [Supported models](#supported-models)
- Developer access with authorized wireless ADB on TCP port 5555
- Wireless ADB configured to return after a normal reboot
- A stable network connection and external power for several automatic reboots
- Kiosk Satellite installed and configured
- Kiosk Satellite's device-admin receiver enabled before using
  `--device-owner`

`--optimize-presence` verifies the retained camera-to-world-model pipeline
automatically after each reboot. It does not require anyone to remain in view.

## Supported models

| Model | Codename | Android | Supported firmware fingerprint | Kernel | Status |
| --- | --- | --- | --- | --- | --- |
| Meta Portal Go | `terry` | 10 | `Facebook/terry_prod/terry:10/QKQ1.210213.001/5051355900018050:user/prod-keys` | `4.9.227-perf+` | Tested |

Other Portal models and other Portal Go firmware builds are not yet supported.
Do not substitute target constants from a similar device. Kernel addresses and
object layouts must be derived and verified for every exact build.

## Step-by-step installation

### 1. Install the host tools

Install Git, Make, Python, ADB, a JDK, and the Android command-line tools using
your Linux distribution and Android SDK manager. Install NDK version
`28.2.13676358`, Android Platform 36, and a Build Tools version that provides
`d8`.

### 2. Clone the repository

```sh
git clone https://github.com/jxlarrea/portal-root.git
cd portal-root
```

### 3. Configure the Android toolchain

Point the build at the SDK installed on the host. Adjust the Build Tools
version if the installed `d8` is in a different directory.

```sh
export ANDROID_SDK_ROOT="$HOME/Android/Sdk"
export NDK="$ANDROID_SDK_ROOT/ndk/28.2.13676358"
export ANDROID_JAR="$ANDROID_SDK_ROOT/platforms/android-36/android.jar"
export BUILD_TOOLS="$ANDROID_SDK_ROOT/build-tools/37.0.0"
export D8="$ANDROID_SDK_ROOT/build-tools/37.0.0/d8"
```

The provisioner builds the files required by the selected actions. To check
the core exploit build before touching a device, run:

```sh
make -C exploit -j2 all
```

### 4. Connect to the Portal

Set the Portal's current IP address and connect over wireless ADB:

```sh
export PORTAL_IP=192.168.1.100  # replace with your Portal's address
adb connect "$PORTAL_IP:5555"
adb -s "$PORTAL_IP:5555" get-state
```

The final command must print `device`. Confirm the model and complete firmware
fingerprint before continuing:

```sh
adb -s "$PORTAL_IP:5555" shell getprop ro.product.device
adb -s "$PORTAL_IP:5555" shell getprop ro.build.fingerprint
```

Compare both values with the supported-model table. The provisioner performs
the same check and stops before exploitation if either value differs.

Before provisioning, reboot once and confirm that wireless ADB returns without
changing the address or authorizing the host again:

```sh
adb -s "$PORTAL_IP:5555" reboot
# Wait until the Portal finishes booting.
adb connect "$PORTAL_IP:5555"
adb -s "$PORTAL_IP:5555" get-state
```

The provisioner cannot continue through its verification reboots if ADB is
only enabled for the current boot.

### 5. Prepare Kiosk Satellite

Download and install Kiosk Satellite manually from the
[Kiosk Satellite repository](https://github.com/jxlarrea/kiosk-satellite), then
open it once. The provisioner deliberately does not download, install, or
update the Kiosk Satellite APK. This keeps application releases under the
user's control.

If Kiosk Satellite will become the Device Owner, enable its device-admin
receiver through its setup flow first. You can inspect the loaded policy with:

```sh
adb -s "$PORTAL_IP:5555" shell dumpsys device_policy
```

The provisioner requires
`me.jxl.kiosk_satellite/.KioskAdminReceiver` to appear as an enabled admin and
refuses to replace an existing Device Owner belonging to another application.

### 6. Run the provisioner

For the complete tested Kiosk Satellite profile, run:

```sh
python3 tools/provision_portal.py --serial "$PORTAL_IP:5555" \
  --profile kiosk
```

The `kiosk` profile expands to the audio, Device Owner, update blocking,
debloat, Meta-account removal, and presence optimization actions. You may add
`--privacy-dns HOSTNAME` when you operate a DNS-over-TLS filtering resolver,
or `--shizuku` when apps on the Portal need Shizuku's shell-level APIs.

The Portal will reboot several times. Leave it powered and do not close the
terminal. A completed run ends with `PROVISION_OK` and two different boot IDs.
Attempt logs are saved under a timestamped directory in `/tmp`; use
`--log-dir PATH` to choose another location.

Every action is optional. Select only the flags needed for a particular
device. The sections below explain each action, its prerequisites, and its
available rollback.

## Provisioning actions

| Action | Flag | Uses root | Automated rollback |
| --- | --- | --- | --- |
| Apply the complete tested kiosk profile | `--profile kiosk` | Yes | Use the individual rollback flags |
| Disable hardware audio processing | `--audio` | Yes | `--restore-audio` |
| Make Kiosk Satellite Device Owner | `--device-owner` | Yes, on first setup | No |
| Disable automatic firmware updates | `--disable-updates` | Yes | `--enable-updates` |
| Disable unused Meta applications | `--debloat` | No | `--restore-bloat` |
| Remove local Meta accounts | `--remove-meta-accounts` | Yes | No |
| Reduce AIService presence workload | `--optimize-presence` | Yes | `--restore-presence-profile` |
| Use a filtering Private DNS resolver | `--privacy-dns HOSTNAME` | No | `--restore-privacy-dns` |
| Install Shizuku with automatic startup | `--shizuku` | Yes | `--remove-shizuku` |

Flags can be combined in one command. Combining privileged actions performs
them during the same successful exploit run and verifies all requested states
after reboot. For clarity, use explicit action flags: running the provisioner
without one retains its legacy behavior and is equivalent to selecting
`--audio`.

### 1. Disable hardware echo cancellation and noise suppression

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --audio
```

The Portal's microphone array passes through a DBMD7/STAX voice DSP before
Android receives it. This action installs a native watchdog inside Meta's
AIService and keeps these private DSP parameters at zero:

- `AEC_ENABLE` (`3001`)
- `NS_MODE` (`4001`), including residual-echo suppression

The change is system-wide, so every Android application receives audio without
those two processing stages. The watchdog reapplies the values after AIService
starts and repairs later firmware-side changes. The provisioner confirms both
readbacks on two boots.

Restore Meta's original AIService loader, remove the watchdog, and restore the
firmware's AEC and NS parameter defaults with:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --restore-audio
```

The restore uses the original loader saved during the first installation and
refuses to replace an unrelated file.

### 2. Make Kiosk Satellite the Device Owner

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --device-owner
```

This gives Kiosk Satellite Android's Device Owner role for user 0. Device Owner
allows the kiosk to apply stronger device policies than an ordinary device
admin. Kiosk Satellite must already be installed and its
`KioskAdminReceiver` must already be active.

Meta accounts normally cause Android's `dpm set-device-owner` command to reject
the operation. The privileged installer writes the Android 10 owner record
only after checking that no other Device Owner exists. It saves the original
policy state under `/data/local/tmp/portal-device-owner-backup` and verifies
both DevicePolicyManager and `ro.device_owner=true` after reboot. There is no
automated Device Owner removal action in the provisioner.

### 3. Disable automatic Meta firmware updates

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --disable-updates
```

This disables Meta's two OTA user-interface packages and installs a local
MobileConfig override setting `firmware_ota_update_enable=false`. Shared update
infrastructure remains installed, but the native OTA daemon stays idle and
does not discover or install firmware.

The provisioner verifies the disabled packages and requires Meta's own service
to report the value from the local override on two boots. It refuses to replace
an unrelated existing override. The original file state is recorded under
`/data/local/tmp/portal-ota-backup`.

Restore that exact override state and re-enable both OTA packages with:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --enable-updates
```

### 4. Disable unused Meta applications

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --debloat
```

The conservative debloat profile disables these packages for user 0:

- Meta Analytics
- Messenger
- WhatsApp
- Portal Feed
- Superframe
- Meta Contacts

It retains the camera, audio, identity, presence, media, app-management, and
WebView services needed by the Portal and Kiosk Satellite. This action uses
normal Android package controls and does not need the kernel exploit when run
by itself.

Before changing package state, the provisioner saves the exact enabled,
disabled, or absent state of every package in
`/data/local/tmp/portal-debloat-backup-v1.tsv`. Restore those saved states with:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --restore-bloat
```

Both commands verify the retained camera, AIService, Kiosk Home, and WebView
paths across two reboots.

### 5. Remove local Meta accounts

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --remove-meta-accounts
```

This removes the Portal-specific proxy SSO, platform-login, hardware, and
private-owner accounts from Android AccountManager and Meta's local identity
databases. It then disables only their four authenticator components so the
firmware cannot immediately recreate the accounts. The shared `alohausers`
package stays enabled because camera support, MobileConfig, and other Portal
services still use it.

The original account type and name inventory is saved at
`/data/local/tmp/portal-meta-accounts-before-v1.tsv` and copied into the host
log directory. Tokens and full database contents are not backed up, so this
action has no automated restore. Repeated runs are safe: once the accounts are
gone and the authenticators are disabled, the tool only verifies the state.

### 6. Reduce AIService CPU use while preserving presence detection

Run:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --optimize-presence
```

Kiosk Satellite reads AIService's `Notify people presence` log to use the
Portal's person detector without activating an application camera and its
on-screen camera LED. This profile keeps that detector, AIService's camera
client, tracking, and pose estimation active while disabling four downstream
Smart Camera workloads:

- background segmentation
- liveness scoring
- color-based re-identification
- face-recognition-based re-identification

The provisioner requires an active AIService camera client, an allowed CAMERA
AppOp, live analysis and region-of-interest frame delivery, a loaded frame
processor, populated pose-estimator metrics, and all four settings loaded as
false on every verification boot. Those checks cover the same retained path
that updates AIService's world model and emits `Notify people presence`, so the
two-reboot verification can run unattended. An actual presence event is
reported as additional evidence when one occurs, but it is not required for a
successful run. On the tested Portal Go, matched samples reduced average
AIService CPU use from 47.8% to 22.1% of one core while the presence signal
continued to work.

The original settings-file state is stored under
`/data/local/tmp/portal-presence-backup`. Restore it with:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --restore-presence-profile
```

The installer and restore action use atomic file replacement, preserve the
app's ownership and SELinux label, and refuse to overwrite an unrelated edit.

### 7. Use a filtering Private DNS resolver

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --privacy-dns dns.example.net
```

Replace `dns.example.net` with the DNS-over-TLS hostname of a resolver you
control or trust. The provisioner configures Android's strict Private DNS mode;
the resolver supplies the block list. This can reduce connections to unwanted
Meta endpoints without modifying system certificates or installing a broad
root firewall. Confirm that the resolver permits the services Kiosk Satellite
needs before applying it fleet-wide.

The first run saves both original Android settings. Restore them with:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --restore-privacy-dns
```

### 8. Install Shizuku with automatic startup

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --shizuku
```

This downloads the pinned official Shizuku release, verifies its SHA-256
digest, and installs it with a small Portal boot helper. Meta's required APK
certificate verifier accepts only Meta-approved signing certificates, so the
provisioner temporarily disables that verifier around the two local installs,
restores its original state, waits for Package Manager to save it, and checks
the result after reboot.

The Portal runs Android 10, where upstream Shizuku cannot automatically start
ADB mode after boot. The helper solves that limitation entirely on the device:
it receives Android's normal boot broadcast, connects to the Portal's existing
ADB daemon at `127.0.0.1:5555`, authenticates with a key generated for that
Portal, and runs Shizuku's own starter. The temporary-root action authorizes
only that public key. The host's ADB private key is never copied to the Portal.

Shizuku runs as Android user `shell` (UID 2000), which is the normal Shizuku
ADB privilege level; it is not a persistent UID-0 root service. Once
installation completes, no host computer or network connection is needed for
startup. Wireless ADB must remain enabled locally because the helper uses its
loopback listener. The two-boot verifier requires `shizuku_server` to run as
`shell` after both ordinary reboots.

To use a Shizuku APK you downloaded yourself, run:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --shizuku --shizuku-apk ./shizuku.apk
```

Remove the manager, boot helper, running server, and the helper's authorized
ADB key with:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --remove-shizuku
```

## Inspection, backups, and recovery

### Status report

Print a read-only JSON report without exploiting or rebooting the Portal:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --status
```

The report includes exact target support, boot and SELinux state, Kiosk
Satellite version and Device Owner state, audio and OTA markers, debloat and
account status, the live presence pipeline, Private DNS, Shizuku package and
server state, and the last provisioning manifest.

### Dry-run planning

Preview an action or the full profile without changing the device:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --profile kiosk --dry-run
```

The plan identifies required build outputs, host tools, exploit use, estimated
minimum reboots, and the current state.

### Backup bundles

Create a private diagnostic and configuration archive before making changes:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --backup ./backups
```

`--backup` may also accompany a provisioning command. The resulting mode-0600
archive contains status, relevant Android service dumps, reversible device
snapshots, and a SHA-256 manifest. It can contain account names and device
configuration, so store it as sensitive data.

### Interrupted-run recovery

Every mutating run writes a state manifest at
`/data/local/tmp/portal-provision-state-v1.json`. It records the exact target,
firmware fingerprint, selected actions, Git revision, artifact hashes, state,
and verification boot IDs. If power or the host fails during a run, reconnect
ADB and resume the pending action set with:

```sh
python3 tools/provision_portal.py \
  --serial "$PORTAL_IP:5555" --recover
```

Recovery first removes stale staged files. It resumes only a validated pending
manifest; for a completed run or a device with no manifest, it prints status
and exits without changing the configuration.

## Running and troubleshooting

The default maximum is 12 exploit attempts. Change it with `--attempts N`,
where `N` is between 1 and 100. A failed race normally causes a clean reboot
and another attempt. If the Portal remains unresponsive, power-cycle it, wait
for wireless ADB to return, and rerun the same command; completed provisioning
actions are designed to be repeatable.

Use `--skip-build` only when the required outputs have already been built and
have not changed. Display every available option with:

```sh
python3 tools/provision_portal.py --help
```

Each successful run verifies the requested state on two distinct boots. Read
the final `PROVISION_OK` line and keep the attempt directory when diagnosing a
failure.

## Repository layout

- `exploit/`: GhostLock source, privileged provisioning actions, and
  exact-build target definitions
- `helper/`: persistent native audio watchdog and the earlier helper APK
- `shizuku-helper/`: device-local loopback-ADB launcher for Shizuku
- `tools/provision_portal.py`: user-facing build, installation, retry, and
  two-reboot verification tool
- `tools/portal_targets.py`: exact model and firmware registry used before any
  build-specific kernel write
- `tools/PortalAccountCtl.java`: privileged local-account cleanup helper
- `analysis/`: kernel offset extraction and device-analysis utilities
- `docs/current-status.md`: current implementation and validation details
- `docs/findings.md`: chronological reverse-engineering and test record
- `artifacts/`: manifest for large local firmware and crash artifacts excluded
  from Git

## Development status

The supported Portal Go configuration has been tested with SELinux enforcing
after reboot. Hardware AEC and residual-echo suppression stay disabled,
Kiosk Satellite loads as Device Owner, the OTA gate remains false, the
conservative debloat set and Meta-account removal persist, and AIService keeps
emitting the presence log with the reduced workload.

See [the current status](docs/current-status.md) for implementation evidence
and [the investigation log](docs/findings.md) for the complete research
history. This project currently has no generic exploit path for unlisted Portal
models or firmware builds.
