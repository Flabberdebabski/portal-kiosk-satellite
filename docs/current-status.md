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
