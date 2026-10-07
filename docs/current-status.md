# Current exploit status

The Portal Go's installed 4.9.227 kernel is vulnerable to GhostLock. The
build-specific route now completes the full chain on firmware
`5051355900018050`: a native `sendmmsg` stack copy supplies the stale
`rt_mutex_waiter`, the target order-3 `mm_struct` slab is reclaimed by a UNIX
stream allocation, and the constrained `rb_erase` write redirects ashmem file
operations to a controlled table.

The resulting configfs primitive provides arbitrary kernel read/write. It has
successfully located the exploit process in the task list, changed its UID,
EUID and FSUID to zero, installed full capability masks, and changed
`selinux_enforcing` from 1 to 0. The active trigger keeps the damaged
`proc_uid_lock` gates alive; releasing them can still panic and reboot the
device, so this remains a temporary per-boot root route.

The current boot's randomized `_text` is recovered with Android's bundled
`simpleperf`. A `cpu-clock` callchain address ending in `0x3d7e` is
`el0_svc_naked+0x34`; subtracting `0x3d7e` gives the runtime kernel base passed
through `GHOSTLOCK_KASLR_BASE`.

Privileged provisioning is self-contained on a factory-reset device. Before
the first clean reboot, the host installs the no-permission debuggable package
`dev.portal.exploitsentinel`, verifies its `run-as` path, and passes that exact
package to the `proc_uid` priority-inheritance trigger. The package is removed
after a successful attempt sequence and by best-effort cleanup after failure.
The earlier hard-coded `me.jxl.portalreadprobe` dependency was a development
artifact and has been removed.

CPU affinity setup now snapshots Android's original allowed CPU mask before
the exploit narrows any thread. A requested CPU that is offline or excluded by
the device cpuset falls back to that original mask. This keeps the optional
watcher schedulable on Portal configurations that do not expose CPU 7 and
avoids terminating the exploit on `sched_setaffinity(...): EINVAL`.

PackageManager component changes made during the privileged process now delay
their final success marker for 15 seconds and call `sync()` before the host
reboots. Android reports `pm disable` success before it asynchronously writes
`package-restrictions.xml`; without that window, a clean device could lose all
197 cloud-component disables and the three Meta-authenticator disables at the
first reboot. Package-level debloat already used the same host-side settlement
window.

Meta's installed Binder stubs establish the exact private audio protocol:

- Service manager: `com.facebook.IAudioServiceManager`
- Manager descriptor: `com.facebook.alohasdk.IAudioServiceManager`
- Manager transaction 3: `getAudioService(connection)`
- Audio descriptor: `com.facebook.alohasdk.IAudioService`
- Audio transaction 3: `getAudioProcessingParam(int)`
- Audio transaction 4: `setAudioProcessingParam(int, float)`

`tools/PortalAudioCtl.java` implements that protocol. On October 3, 2026, the
root process called `setAudioProcessingParam(3001, 0.0)` for `AEC_ENABLE` and
the service read back `0.0`. This is the first verified system-wide hardware
AEC disable on the target. An ordinary UID-2000 invocation of the same client
still fails with the expected `PLATFORM_AUDIO` permission denial.

The same root process also set `NS_MODE` parameter 4001 from `5.0` to `0.0`.
Readback confirmed both changes in one run:

```
PORTAL_AUDIO_CTL_OK id=3001 before=NaN requested=0.0 after=0.0 match=true
PORTAL_AUDIO_CTL_OK id=4001 before=5.0 requested=0.0 after=0.0 match=true
```

This disables the separate residual-echo suppression mode as well as AEC.

Persistence is now installed in the AI service's private native-library
directory. The guaranteed startup chain is
`libaddressspace.so -> libcoldstart.so -> libcoldstart_1.so`. The last library's
equal-length `libdl.so` dependency string is patched to `libpa.so`, which loads
the native watchdog while preserving `libdl.so` as one of the watchdog's own
dependencies. The original library is backed up alongside it as
`libcoldstart_1.portal-original.so`.

The watchdog retries service acquisition after failures, reads and verifies
both parameters, and checks them once per second during startup or after a
correction, then every five seconds in steady state. It only logs corrections,
failures and recovery rather than filling logcat on every healthy pass. On
October 4, 2026, it loaded automatically on two successive boots:

```
boot 30d9a2c6-9bd2-4ec7-bd6c-88ccf915f266: 3001=0, 4001=0
boot 72d69b44-bd45-4ba6-8494-da4515f396ee: 3001=0, 4001=0
```

On the second recorded boot Meta changed NS mode back to `5`; the next
watchdog pass observed `before=5 after=0 ok=1`. The initial watchdog build had
also repaired this rewrite on both of its verification boots. This verifies
that the helper handles both reboot persistence and later parameter rewrites.
The obsolete ordinary APK helper was removed after native persistence was
verified. Acoustic A/B capture remains to be measured.

Kiosk Satellite is now Android's Device Owner for system user 0. The installed
package is `me.jxl.kiosk_satellite` version `2026.10.6` and its active admin is
`.KioskAdminReceiver`. Normal `dpm set-device-owner` provisioning could not be
used because the Portal already contains four Meta accounts. The optional
`--device-owner` installer action therefore writes Android 10's
`/data/system/device_owner_2.xml` from the temporary privileged process, but
only after verifying the active admin in `/data/system/device_policies.xml`
and refusing any pre-existing different owner.

Before the write, the installer saves the original policy and a marker that
the owner file was absent under
`/data/local/tmp/portal-device-owner-backup`. It copies the policy file's
system ownership and SELinux label to a mode-0600 temporary owner file, calls
`fsync`, atomically renames it, and syncs `/data/system`. DevicePolicyManager
then loaded the owner on boot and applied its default
`no_add_managed_profile` restriction. The four existing Meta accounts were not
removed or modified.

The loaded owner was verified with both `dumpsys device_policy` and
`ro.device_owner=true` after boot IDs
`31327449-dca9-47ab-919c-8608945b6eb1` and
`73b06f93-35bc-47f5-bb99-ff324ca27c7e`. The latter boot also independently
verified the audio watchdog. The installer recognizes both Android's shorthand
component spelling and its normalized `ComponentInfo{package/package.Class}`
spelling, so repeated `--device-owner` runs are idempotent and do not launch
the exploit once ownership is established.

An optional privileged action writes `persist.adb.tcp.port=5555` directly to
Android's protobuf persistent-property store and sets the live
`service.adb.tcp.port` property. The direct write preserves the property's
SELinux label and uses a mode-0600 temporary file, `fsync`, and atomic rename.
On October 3, 2026, the Portal rebooted from boot ID
`2b34b396-83d4-41e0-8f2b-382e202bbfb9` to
`ff0bcffb-66d9-49a0-bfdc-06713ffa00fb`; wireless ADB returned without any
host-side enable command. After boot, `persist.adb.tcp.port` read `5555`,
SELinux was enforcing, and ADB was enabled. The transient
`service.adb.tcp.port` property was empty, which does not prevent adbd from
listening when the persistent property is present.

Automatic firmware updates are now disabled through Meta's own MobileConfig
precedence layer. Exact APK analysis identified unit
`sessionless_aloha_ota_daemon` (5014), parameter
`firmware_ota_update_enable` (36), and the app-private override file
`files/mobileconfig/mc_overrides.json`. The privileged installer writes only
that false override with UID/GID 10044, the original app-data SELinux label,
`fsync`, and an atomic rename. It refuses to replace an unrelated existing
override file and records that the file was originally absent under
`/data/local/tmp/portal-ota-backup`.

The dedicated UI packages `com.facebook.aloha.otaui` and
`com.facebook.aloha.alohaotasetup` are also disabled for user 0. The broader
`com.facebook.aloha.platformmobileconfig` service remains enabled because
disabling it disrupted other Portal services. Static analysis found the
native daemon's `otad.nodemon` property, but Android's property service rejects
that nonpersistent default property even from the temporary privileged
process, so it is not part of the installed solution.

After normal reboot to boot ID
`5757afe1-3d74-46f9-a245-10239d30571e`, the daemon was idle, had no downloaded
JSON manifest, and reported `kFirmwareOtaUpdateEnable=false`. Meta's own client
logged the exact parameter as `latestBoolean: false, source: OVERRIDE`, proving
the durable local override was active rather than merely observing the
server's current false value. Both OTA packages remained disabled. The same
boot also verified Device Owner, wireless ADB on port 5555, and audio parameters
3001/4001 at zero.

The host tool is now `tools/provision_portal.py`. Its actions are independent,
and `--profile kiosk` selects the complete tested set. Audio and OTA changes
have exact `--restore-audio` and `--enable-updates` rollbacks; debloat,
presence, and Private DNS also have paired restore actions. With no action
flag, the tool retains the former audio-provisioning default. Private DNS uses
normal Android controls. Debloat now invokes GhostLock because retained Meta
packages require privileged component-level changes in addition to the six
ordinary package-state changes.

The conservative debloat set contains Meta Analytics, Messenger, WhatsApp,
Portal Feed, Superframe, and Meta Contacts. The first application records each
package's original enabled, disabled, or absent state in
`/data/local/tmp/portal-debloat-backup-v1.tsv`; restore applies those exact
states. A 15-second settle period and `sync` are required before reboot because
Android reports new package states before its asynchronous
`package-restrictions.xml` write is durable.

The debloat state survived clean boots
`c43f3691-0874-445b-bf85-1e55907194dc` and
`401c4711-17d7-4990-bfbe-544243306f25`. All six packages remained disabled and
none of their application processes were present. Both cameras, AI Service,
Kiosk Satellite Home, Portal WebView, Device Owner, wireless ADB, the OTA block,
and the audio watchdog remained healthy. The final watchdog startup again read
AEC 3001 and NS mode 4001 as zero and corrected Meta's later NS rewrite from 5
to 0.

The Portal-specific Meta user accounts are now removed. Static and live
inspection identified three user account types in
`com.facebook.alohaservices.alohausers`: proxy SSO, platform login, and private
owner. Meta's official owner-removal flow requires a valid server user
context, while its public `CLEAR_ACCOUNT` receiver only clears proxy SSO. The
privileged local path therefore removes the Android AccountManager records,
clears the identity rows in `aloha_users_db` and `aloha_users_database`, and
disables those three authenticator components. The separate hardware-identity
authenticator stays enabled because disabling it caused platform instability.

The original type/name inventory is retained at
`/data/local/tmp/portal-meta-accounts-before-v1.tsv`. The shared `alohausers`
package remains enabled for MobileConfig and other platform services. Clean
boots `8db565c4-f7c2-40dc-9df5-aba6b4a98390` and
`8762d7c6-1db1-400f-9559-8df8dc9f5f33` each reported zero target accounts and
all three user authenticators disabled. Both cameras, AI Service, Kiosk Satellite
Home, and Portal WebView remained available; SELinux was enforcing. Repeated
`--remove-meta-accounts` runs recognize the completed state and perform only
the two-reboot verification.

AIService supplies Kiosk Satellite's LED-free presence source through the
exact `Notify people presence` log. The optional presence profile disables
background segmentation, liveness scoring, color re-identification, and face
re-identification while leaving tracking and pose estimation enabled. It also
disables AIService hardware cropping so pose estimation continues to receive
the full camera scene after the background detector stops. The installer
writes AIService's private `settings_config.xml` atomically with its original
app-data ownership and SELinux label, records the original state under
`/data/local/tmp/portal-presence-backup`, and refuses to overwrite an unrelated
settings file. Its restore action also refuses to replace a settings file
changed after installation.

The first four-setting profile reduced AIService from a 47.8% baseline to
22.1% of one CPU core, but field testing found that its hardware region of
interest could collapse the dewarped scene from 3962 to about 1896 pixels
wide. The corrected five-setting profile adds
`enable_hardware_cropping=false`. On clean boots
`caeb7900-2966-4766-a562-7ae01840f445` and
`c8d086e7-b265-40df-8ab5-57193df064bd`, AIService loaded all five values,
retained its active camera client and allowed CAMERA AppOp, processed both
frame streams, and exposed only the full 4032-by-3016 Android crop with no
active Meta dewarp crop. The background and liveness workers remained absent.
A five-minute post-boot sample used 35.5% of one CPU core, compared with the
earlier 47.8% stock baseline and 22.1% cropped profile.
Kiosk Satellite field testing after the final reboot confirmed that presence
coverage again spans the full scene with the background detector still off.

Presence verification is unattended. AIService logs live analysis and
region-of-interest frame delivery, and its shell-readable `CameraService` dump
exposes both the loaded `AlohaFrameProcessor` and populated
`PoseEstimatorManagerMetrics`. Static tracing shows pose results are written
to `WorldModelManager`, whose listener emits the same `Notify people presence`
event consumed by Kiosk Satellite when the model contains a person. The
verifier therefore requires the camera client, CAMERA AppOp, both frame
streams, the frame processor, pose metrics, all five profile values, Meta's
`Disabled hardware cropping` confirmation, and no active dewarp crop after
each reboot. It records a real presence event when one happens but does not
require a person to be in view.

This unattended contract passed clean boots
`3fda320e-05a2-447c-88e8-a9ad3319dceb` and
`b9d4ba78-94ca-4ea7-bef0-90824d49db81`. Both also happened to emit a real
presence event. The optimization and its verifier require no post-reboot user
interaction.

The provisioner now has a read-only `--status` report, mutation-free
`--dry-run`, mode-0600 `--backup` archives with SHA-256 manifests, and
`--recover` for a pending provisioning manifest. Every mutating operation
records its target key, exact firmware fingerprint, action map, Git revision,
artifact hashes, and two verification boot IDs at
`/data/local/tmp/portal-provision-state-v1.json`. Exact-build selection is
centralized in `tools/portal_targets.py`; an unlisted device or fingerprint
cannot reach a build-specific kernel write.

The optional `--privacy-dns HOSTNAME` action uses Android's strict
DNS-over-TLS mode and leaves domain policy to the selected resolver. The first
run saves both original settings, and `--restore-privacy-dns` restores them.
Installation passed boots `ca89c119-f6e9-4ba1-ba83-47dae48a9b1b` and
`8cc1f564-389d-4cae-b349-ab81c9cbaf26`; rollback passed
`efd9e1d0-a5ea-465b-baab-1de5bcba40d5` and
`65b4686d-621d-4dec-8c4c-12a0f5af25c1` with both original settings absent.

The native audio and OTA rollbacks were exercised together. Audio parameters
3001/4001 read back at firmware defaults 1/5, the original AIService loader
matched its saved copy, the watchdog was absent, the original OTA override
state was restored, and both OTA packages were enabled on boots
`6731347b-a944-475b-8f46-1d9dcb14d5e5` and
`7b4f92c5-281b-4ea5-baf1-eac6cafe9932`. Reinstallation then restored the
desired kiosk state on boots `0e5edea7-bb6d-4193-b050-dc6717236160` and
`e278180d-2958-4c59-a008-05e2c441f125`: audio readbacks were zero, the OTA
gate was false from `source: OVERRIDE`, and the unattended presence verifier
passed. SELinux was enforcing after every verification reboot.

## Third-party application updates

Meta's registered package-verification agent rejects correctly signed
non-Meta APKs. A Kiosk Satellite `2026.10.7` self-update reached Package
Manager through a healthy Shizuku server, but `com.facebook.appverifier`
compared the KS certificate with Meta's private certificate set, logged
`App certificate rejected`, and returned
`INSTALL_FAILED_VERIFICATION_FAILURE`.

The independent `--allow-app-updates` action saves the current
`package_verifier_enable` value and verifier-package state, sets the global
value to `0`, and disables `com.facebook.appverifier` for user 0. Package
disablement is the durable control if Meta rewrites the global setting.
Android's normal matching-signature and version checks remain active. The
action works with the normal package installer, Device Owner, the KS update
helper, and Shizuku. It is included in `--profile kiosk` but does not install
or require Shizuku. `--restore-app-verifier` restores both saved states.

An already-installed non-Meta helper then reinstalled successfully with no
Facebook verifier event. The setting survived clean verification boots
`be358d6b-4a95-47be-aa3d-e5ce0cb01b90` and
`63da4d22-c086-4f25-b410-18bdae844e5c`. Kiosk Satellite was updated to
`2026.10.7`, Meta's verifier package remained enabled, and the device-local
Shizuku helper started `shizuku_server` as shell after the final reboot.

Later field testing found the setting had returned to `1`, causing the
`2026.10.11` Kiosk Satellite self-update to fail with the same verifier error.
The strengthened package-disable implementation passed clean boots
`f2e85940-fba4-4897-9518-51675c1a4ab8` and
`3f5b8b08-18f7-40aa-aa32-b3e08efb60b4`. On the final boot the setting was
`0`, the Meta verifier package was disabled, and Shizuku was running as shell.
Installing the exact arm64 `2026.10.11` release through shell Package Manager
then succeeded; the device reported Kiosk Satellite version code 309 and kept
its persistent HOME role.

## Device-local Shizuku

The optional `--shizuku` action installs the pinned official Shizuku
`13.6.0.r1086.2650830c` APK plus `dev.portal.shizukuhelper`. Android 10 does
not support upstream Shizuku's automatic ADB-mode startup. The helper receives
`BOOT_COMPLETED`, authenticates to the already persistent ADB listener at
`127.0.0.1:5555` with a per-device key, and invokes Shizuku's installed native
starter. The private key remains mode 0600 in the helper's application data;
the exploit authorizes only its public key. This is Shizuku's normal UID 2000
shell mode, not persistent root, and no host process is involved after setup.

Meta's required `com.facebook.appverifier` rejects non-Meta certificates. The
provisioner disables it only for each local package installation, restores its
previous package state in a shell cleanup trap, then waits 15 seconds and calls
`sync` before any reboot. The verifier was enabled and durable on clean boot
`74c8f741-b55d-4b85-954a-2f2b45030da8`.

The first formal two-boot run started `shizuku_server` as user `shell` on boot
IDs `8c94eb85-cb0e-476d-af15-abd02e41d804` and
`caa1c1cc-ef32-46e7-85e1-a6422795902b`. A further clean reboot to
`74c8f741-b55d-4b85-954a-2f2b45030da8` again delivered the helper's normal
boot receiver and started the server on its first loopback attempt with
SELinux enforcing. The final rebuilt helper artifact repeated that result on
boot `411d1d93-4625-476d-bf88-4e1d76581595`. Repeat installation read and
reused the same private/public key pair. `--remove-shizuku` removes the
authorized helper key, both packages, and any running server.

## Targeted Meta component debloat and optional analysis cap

The debloat profile now preserves its six package-level removals and also
controls 198 individual components inside retained Meta packages. The tested
safe state disables 196 components: 143 scheduled/background workers, 16
bug-reporting components, 15 diagnostics components, 12 Firebase components,
eight MQTT components, and two push components. PackageManager state is saved
before mutation and restored exactly by `--restore-bloat`.

Two components are recorded but deliberately exempted:
`com.facebook.alohaservices.alohausers/com.facebook.mqttlite.MqttService` and
`com.facebook.aloha.system.device/com.facebook.fbns.standalone.service.RegisteredMqttSystemBroadcastReceiver`.
Both enable themselves immediately before a bind or start. Forcing either off
caused a repeat service failure/restart cycle, so component state is not a safe
way to suppress the final firmware-owned MQTT connection. Network DNS or
firewall policy remains the safe control for `mqtt-mini.facebook.com`.

Live network attribution on October 7, 2026 separated the remaining Meta
traffic. `57.144.162.1` and `157.240.14.35` were rotating `facebook.com`
addresses reached by `/vendor/bin/ping-service -t 60`; the daemon probes the
gateway, `1.1.1.1`, and `facebook.com` every cycle. Its init declaration is
unconditional, and disabling `com.facebook.aloha.wifidiagnostic` did not stop
the native probes. `57.144.162.145` corresponded to the repeatedly reconnecting
DGW realtime transport in the retained `alohausers` process. The native OTA
daemon also continued attempting `graph.facebook.com` even while the local
firmware-update gate reported false.

The tested Android per-UID metered blacklist did not stop `alohausers` because
AIService keeps it in a visible service state. All experimental package,
metered-network, and UID-policy changes were restored. The device's active
network advertised the local resolvers plus `1.1.1.1`, and Android validated
the latter as opportunistic Private DNS. A local block list is therefore only
reliable when the network advertises no unfiltered fallback resolver. A
source-specific router firewall rule or exclusive filtering DNS remains the
safe durable control; fixed destination IPs are not stable enough to encode in
the provisioner.

Meta's arbitrary analysis throttle is backed by
`/settings/aloha/enable_analysis_throttle` and
`/settings/aloha/analysis_throttle_fps` in AIService's preferences database.
Persisting the values is insufficient: `AlohaFrameProcessor` only receives the
rate when Meta's hidden debug activity pauses. The optional
`--presence-fps-cap FPS` action therefore stores the values with temporary
root and installs `dev.portal.presencehelper`, which briefly launches and
pauses that activity once after boot, then exits. Before activation,
the privileged helper also pins the five tested full-scene profile preferences
to false so the debug activity cannot re-enable hardware cropping.

Android 10 rejected the helper's direct background activity launch. The final
helper instead authenticates to the already-persistent ADB daemon only at
`127.0.0.1:5555` with its own per-device key, runs the two `am start` commands
as shell, and exits. Temporary root appends that public key without replacing
the user's ADB keys. Presence rollback removes both the package and its saved
authorized key; no Shizuku installation or external host is required at boot.

The live 2 FPS experiment logged `Setting AI Processing FPS 2.000000` and
reduced steady AIService CPU samples from roughly 30-37% of one core to mostly
6-19%, with transient spikes. Camera service metadata continued to advertise
the normal `[8, 30]` target range; the throttle is applied to Meta's downstream
analysis callback rather than the camera sensor. Kiosk Satellite's RTSP path
uses its own Camera2 request and encoder, so the analysis cap does not impose a
2 FPS limit on RTSP output. Final acceptance requires two reboot passes with
the helper activation, selected analysis rate, full-scene request, both Meta
frame streams, and populated pose metrics all present.

The combined profile passed clean boots
`05bb2ca3-7517-4256-9981-2351b20e2456` and
`bcba4923-4c5f-4dc4-bf91-f2465a6967ce`. Both held all 196 component disables,
loaded all five full-scene values, reported `Setting AI Processing FPS
2.000000`, kept analysis and ROI frames plus populated pose metrics, and had no
active Meta dewarp crop. The helper service was absent after activation,
confirming that it exits instead of polling. Camera metadata on the final boot
still requested `[8, 30]` FPS with a 41.8 ms observed frame duration.
Kiosk Satellite's live RTSP endpoint returned H.264 at 640 by 480; a ten-second
probe decoded 56 frames across 9.98 seconds, or 5.5 FPS, while Meta analysis
remained capped at 2 FPS.

A third ordinary reboot to `41aa8497-07d8-483a-90e5-e2c52012abb0` repeated
the 2 FPS activation and full-scene/component checks. The presence helper had
exited, SELinux was enforcing, Shizuku was running as shell, and
`com.facebook.appverifier` remained enabled after the helper installation.

## Camera auxiliary-stream result

Live instrumentation confirmed that AIService gates its 2048-by-1536 private
auxiliary stream on the `portal.software.smart_camera` system feature. Removing
that stream left only the 640-by-480 analysis surface, but Kiosk Satellite then
triggered a Qualcomm camera-provider restart when it opened the virtual camera.
The provider reported camera errors and AIService stopped producing the
presence event consumed by Kiosk Satellite. The apparent CPU reduction came
from the broken camera pipeline.

The experimental hook was removed and the stock auxiliary stream restored.
Reducing only AIService's analysis surface from 1024 by 768 to 640 by 480 did
not produce a material CPU reduction, so the ineffective `--lightweight-camera`
option is no longer exposed. The supported controls remain the full-scene
presence profile and optional analysis callback frame-rate cap.

## Account-free Kiosk Satellite home

After the local Meta owner account was removed, Portal firmware selected
`AlohaInvalidOwnerHomeActivity` and displayed its obsolete account-error screen
over Kiosk Satellite. The new non-root `--kiosk-home` action sends the protected
`home.enabled` setting through Kiosk Satellite's ADB-only provisioning activity.
As Device Owner, Kiosk Satellite enables its `HomeAlias` and installs it as the
persistent preferred HOME activity. `--profile kiosk` now includes this step;
`--restore-kiosk-home` releases it.

The live device resolved HOME to `me.jxl.kiosk_satellite/.HomeAlias` on both
clean verification boots `441ba1cc-e5fe-4f61-87ef-d97884b0354f` and
`77394ed3-943a-4351-bdb2-e38e66d1506e`. Kiosk Satellite was the foreground HOME
task after the final boot, both Meta camera streams and the Kiosk Satellite
camera client were active, and the persistent audio watchdog again verified
AEC and NS at zero.

## Bootloader and recovery research

The Portal Go exposes Qualcomm fastboot over USB as product `terry`, but the
retail device remains locked and reports `get_unlock_ability: 0`. Meta's added
unlock command uses a device-bound 344-byte request: a fixed header and two
32-byte device values followed by a 2048-bit RSA signature. ABL verifies that
signature before it changes the authoritative unlock permission stored through
the secure/RPMB path. The public firmware and installed Meta applications do
not contain the corresponding signer.

Writing the similarly named byte in the raw `devinfo` partition was tested and
disproved. Fastboot continued to report unlock ability 0 because the retail
secure-device path does not use that raw fallback. The experimental byte was
subsequently restored to its exact original 4 KiB image; the verified restored
SHA-256 is
`ccc2e8089b5aae8a2e854ea25e8dc9d250f008cbf239f58931637df6baced8df`.
The experimental host option and device staging files were removed.

Two other Qualcomm boot-chain paths are absent on this build. The `toolsfv`
partition is zero-filled and XBL is configured to load its signed embedded ABL
firmware volume. ABL also selects AVB 2 at compile time, so removing or
renaming `vbmeta` would make the slot fail verification rather than enter an
unverified fallback mode.

The exact full OTA payload was parsed according to Android's
[`DeltaArchiveManifest`](https://android.googlesource.com/platform/system/update_engine/+/refs/heads/main/update_metadata.proto).
It contains 21 normal target partitions and no EDL Firehose or service
programmer. The recovery image reconstructed from that manifest matches its
signed SHA-256 and contains Android 10 userspace fastboot. Its `fastbootd`
rejects download, flash, erase, slot, and logical-partition mutations while the
device is locked; the bundled vendor fastboot HAL is the AOSP mock and provides
no alternate Meta unlock operation.

The remaining EDL route requires a Firehose programmer accepted by Meta's
secure-boot root. No Meta-signed QCS605/SDM710 programmer has been found in the
OTA, public Meta source, or public firmware artifacts. Entering EDL without
one would add recovery risk without enabling a write. The current result is
therefore temporary Android kernel privilege with durable data-partition
provisioning, not a bootloader or AVB unlock.
