# Meta Portal Root and Provisioning for Kiosk Satellite

This project prepares abandoned Meta Portal devices for use with Kiosk
Satellite. It provides a guarded, command-line provisioner for system changes
that Android and Meta's firmware do not normally allow, including disabling
hardware echo cancellation, making Kiosk Satellite the Device Owner, blocking
firmware updates, removing unused Meta software and accounts, and reducing
AIService CPU use without losing the Portal's LED-free presence detector.

Support is intentionally build-specific. One Portal Go firmware is currently
supported; the repository is organized so more Portal models and firmware
builds can be added as their kernel layouts and system services are verified.

## How the root exploit works

The project adapts GhostLock, CVE-2026-43499, to a specific Portal kernel. The
host provisioner confirms the device model and full firmware fingerprint,
reboots into a clean state, derives the randomized kernel addresses for that
boot, and starts the exploit through a staged native library. The exploit
obtains temporary kernel read/write access, gives its own process root
credentials, and performs only the selected provisioning actions.

Afterward, the device reboots normally. SELinux returns to enforcing, and the
exploit does not install `su`, a root shell, or a general root daemon. Features
that must survive reboot use narrowly scoped configuration files or the native
audio watchdog installed by the privileged process. The provisioner then
checks the requested behavior on two distinct boots.

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
  `d8` when using `--remove-meta-accounts`

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

For `--optimize-presence`, keep a person in view when the Portal finishes each
reboot. The verifier must observe the same `Notify people presence` log that
Kiosk Satellite consumes.

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

The repository is private, so GitHub authentication must already be configured
for the account that has access.

### 3. Configure the Android toolchain

Point the build at the SDK installed on the host. Adjust the Build Tools
version if the installed `d8` is in a different directory.

```sh
export ANDROID_SDK_ROOT="$HOME/Android/Sdk"
export NDK="$ANDROID_SDK_ROOT/ndk/28.2.13676358"
export ANDROID_JAR="$ANDROID_SDK_ROOT/platforms/android-36/android.jar"
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

Install Kiosk Satellite and open it once. If Kiosk Satellite will become the
Device Owner, enable its device-admin receiver through its setup flow first.
You can inspect the loaded policy with:

```sh
adb -s "$PORTAL_IP:5555" shell dumpsys device_policy
```

The provisioner requires
`me.jxl.kiosk_satellite/.KioskAdminReceiver` to appear as an enabled admin and
refuses to replace an existing Device Owner belonging to another application.

### 6. Run the provisioner

For a dedicated Kiosk Satellite Portal using every currently supported
customization, keep a person in front of the device and run:

```sh
python3 tools/provision_portal.py --serial "$PORTAL_IP:5555" \
  --audio \
  --device-owner \
  --disable-updates \
  --debloat \
  --remove-meta-accounts \
  --optimize-presence
```

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
| Disable hardware audio processing | `--audio` | Yes | No |
| Make Kiosk Satellite Device Owner | `--device-owner` | Yes, on first setup | No |
| Disable automatic firmware updates | `--disable-updates` | Yes | No |
| Disable unused Meta applications | `--debloat` | No | `--restore-bloat` |
| Remove local Meta accounts | `--remove-meta-accounts` | Yes | No |
| Reduce AIService presence workload | `--optimize-presence` | Yes | `--restore-presence-profile` |

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
readbacks on two boots. There is currently no provisioner flag to uninstall
the audio watchdog.

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
`/data/local/tmp/portal-ota-backup`. There is currently no automated restore
flag for the OTA configuration.

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

Keep a person in view during the verification boots, then run:

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
AppOp, all four settings loaded as false, and the exact presence log on every
verification boot. On the tested Portal Go, matched samples reduced average
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
- `tools/provision_portal.py`: user-facing build, installation, retry, and
  two-reboot verification tool
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
