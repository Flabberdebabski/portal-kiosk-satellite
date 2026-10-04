Portal Go system-wide AEC investigation, October 2, 2026

RESULT
AEC was not disabled. No working system-wide change was found using the existing ADB shell or an ordinary installed app. This does not prove that privileged access can never be obtained.

DEVICE
192.168.1.72:5555, PortalGo / terry
Facebook/terry_prod/terry:10/QKQ1.210213.001/5051355900018050:user/prod-keys
Shell UID 2000, SELinux Enforcing, ro.debuggable=0, verified boot green, bootloader locked.

NEW FINDINGS
1. A public older terry firmware dump provides the vendor libraries and native service binaries that the current device denies to both shell and an ordinary app. The analyzed dump is version 5051319600009050, not the device's exact version. Static findings therefore require on-device validation.
Source: https://dumps.tadiphone.dev/dumps/facebook/terry

2. TuningManagerService has setStaxParam(int appType, int parameter, float/int value), plus tuning load and restore methods. Its native vendor Binder interface is com.facebook.vendor.audio.ITuningManagerService. Direct access to /dev/vndbinder is denied to shell by SELinux. A copied vndservice binary falls back to the regular Binder driver, so a successful service listing does not mean vendor Binder access worked. Audit logs explicitly confirm the denial.

3. The tuning service contains an Audio Weaver TCP server gated by persist.vendor.audio.stax.awe.server.enable, default false. A direct attempt to set it to true failed. The related persist.vendor.audio.stax_enable_debug property is also protected. The server was not enabled. It is a tuning entry point, not itself an AEC-off switch.

4. The separate com.facebook.alohasdk.audio.IAudioDebugServiceManager exposes collection and file retrieval through a callback Binder. It is a diagnostic API, not an AEC setter. An attempt to bind with a real callback failed, with an explicit SELinux denial of Binder transfer from shell to audiodebug_domain. The daemon remained alive with the original PID 3552.

5. All three known AudioServiceManager binding variants were checked. Synchronous bind2 and getAudioService throw SecurityException for missing com.facebook.alohasdk.permission.PLATFORM_AUDIO. Legacy one-way bind returns no service and logs the same permission check. A successful one-way transact is not a successful bind.

6. /dev/stax-ctrl is system:audio, mode 0660, SELinux audio_device. Shell is not in the audio group. Vendor binaries and HAL libraries were also inaccessible to a temporary ordinary app and its run-as context.

7. audio_parameter_updates is an AudioService cache used to reapply AudioSystem parameters after service recovery. It is not a DSP control socket.

8. Installed aiservice code defines NS_MODE bits for statistical suppression (1), data-driven suppression (2) and residual echo suppression (4). It initializes STATISTICAL_PLUS_RESIDUAL_ECHO. This is distinct from AEC_ENABLE. Disabling linear AEC alone would not necessarily disable residual echo suppression. No parameter values were read or changed successfully on this device.

9. Installed packages were checked for DEBUGGABLE. No Meta app was debuggable. The only debuggable package found was the temporary read probe created during this investigation.

LIMITS
No new acoustic A/B recordings were made. The earlier pink-noise results were not independently remeasured. No bootloader unlock, exploit, firmware flash, reboot or system partition modification was attempted. No microphone gain workaround was added. The repository was not changed.

ARTIFACTS
firmware/: older firmware binaries, symbols and annotated disassembly
ai/, services/, analytics/, settings/: decompiled installed APKs
bugreport.zip, bugreport.txt: current device diagnostics, kept locally
final-audio-state.txt: audio state and relevant SELinux audit entries
BindProbe.java, DebugBindProbe.java, ReadProbe.java: local probe source

ACCESS NEEDED
A verified privileged execution path that can access the DSP control device or a Meta-authorized audio service is still needed. Persistent changes would additionally need testing across capture restarts and reboot. No claim is made that a root command alone would bypass SELinux or provide persistence.


FOLLOW-UP INVESTIGATION, October 2, 2026

DSP processing is still not disabled. No DSP parameter was changed in this follow-up.

10. CVE-2024-31317 is patched in the exact installed framework, despite
ro.build.version.security_patch reporting 2020-08-05. Pulled the device's
/system/framework/framework.jar and decompiled android.os.ZygoteProcess.
maybeSetApiBlacklistExemptions explicitly rejects newline, carriage return and
NUL at lines 449-454 of ZygoteProcess.java. This matches the published fix.
The community unmetaportal account-cleanup technique relies on this bug and
therefore does not provide an access path on this build. No injection payload
was applied. hidden_api_blacklist_exemptions remains null.
Reference: https://rtx.meta.security/exploitation/2024/06/03/Android-Zygote-injection.html

11. The installed AI APK exports AiInternalControlService and
SmartCameraInternalControlService without manifest-level permissions, but their
Binder methods enforce ACCESS_SMART_CAMERA_CONTROL_SERVICE through Meta's
SmartCameraIPCPermissionManager. Exported does not mean callable without the
internal permission checks. AiInternalControlService only accepts the
voice_activity_detection session property in this build. It does not expose a
raw DSP parameter setter. The native AudioService setters remain separate.
Evidence: ai-manifest.txt and ai/sources/com/facebook/alohaapp/app/services/smartcamera/service/.

12. Traced all direct calls to fb_tms_set_stax_param_float/int in the older
firmware audio HAL. They handle speaker volumes, battery level, board
temperature and significant motion. These are not arbitrary microphone DSP
parameter forwarding paths. The older HAL still cannot establish the exact
current firmware's behavior. No speculative AudioSystem parameter was set.

13. A new read-only shell helper attempted to bind AiInternalControlService
and request its version. The app_process command exited 137 with Killed before
printing a binding result. This attempt does not establish that service binding
or its permission check succeeded or failed. Static checks in item 11 are the
evidence for the service restrictions. Source: ControlServiceProbe.java.
The temporary dex was removed from /data/local/tmp afterward.

14. Direct tinymix access still fails with Failed to open mixer. No custom
native dump handler was found in the older AudioServiceManager or tuning service
symbols and current dumpsys calls returned no useful control interface.

No firmware flash, bootloader unlock, reboot, persistent setting change,
repository edit or acoustic A/B test was performed in this follow-up.
Remaining requirement: a working privileged execution path or an accessible
vendor interface that can read and write the actual capture DSP parameters.


ADDITIONAL INVESTIGATION, October 2, 2026, 19:09-19:25 UTC

AEC was not disabled. No DSP parameter was successfully read or changed.

15. Reconfirmed the connected target is PortalGo / terry at 192.168.1.72:5555,
firmware 5051355900018050, shell UID 2000, SELinux Enforcing, verified boot
green and bootloader locked.

16. Tested legacy com.facebook.aloha.AlohaService, separate from
IAudioServiceManager. Transaction 15 (getAudioProcessingParam) returned
exception code -1. Transaction 29 (setProperty) attempting to enable
persist.vendor.audio.stax.awe.server.enable also returned -1. Logcat explicitly
reported missing com.facebook.alohasdk.permission.USE_PLATFORM_SDK for that
attempt. The property was empty before and after. No tuning server was enabled.
An older firmware alohamanager binary additionally contains a
SET_VENDOR_PROPERTY check and property-prefix filtering. This older binary is
supporting static evidence, not proof of exact current implementation.

17. Traced installed AI app noise suppression code. C2QL.A0D initializes
STATISTICAL_PLUS_RESIDUAL_ECHO. A0J has a DISABLED branch but it is private and
the discovered caller passes the fixed enabled mode. No accessible off control
was found. Public high/low methods adjust suppression limits, not the AEC
switch. The only references to AEC_ENABLE in the decompiled AI Java sources
are the parameter enumeration.

18. Copied the current libvraudio.so. Its service exposes spatial playback
worlds, sound positions, room reverb and playback controls. No capture DSP
parameter setter was found in its exported interface.

19. The actual DSP is exposed through dbmd_7-spi, dbmdx-stax and dbmdx-codec
under /sys/bus/spi/devices/spi32766.0. /dev/dbmdx-1 through -3 and
/dev/stax-ctrl are system:audio mode 0660. Shell cannot access the inspected
sysfs attributes, including /sys/devices/virtual/misc/stax-ctrl/version.
No module parameter directory was present for dbmdx_core or dbmdx_stax.
No writable shell control was found. No driver writes were attempted.

20. Copied the installed vendor.facebook.hardware.alohamanagervendor@1.0.so.
Its nonstandard HIDL method is hasBeenReceivedBefore, not an audio setter.
lshal debug of IAlohaManagerVendor/default reported no service or no permission
to connect. The service is listed but listing does not establish access.

No app was installed, no recording was made, no service was stopped and no
firmware was flashed. No reboot, exploit or bootloader unlock was attempted.
The failed property write left the value unchanged. Repository files were
not edited. New artifacts are device.apk and decompiled device/, the current
framework jars and native interface libraries plus the older alohamanager
binary and its disassembly in firmware/.


CONTINUED RESEARCH, October 2, 2026, through 20:22 UTC

21. CVE-2024-0044 installer/run-as forgery: exact current Android 10
PackageManager Settings.writePackageListLPrInternal does not put the installer
package name in packages.list. The documented Android 12/13 attack route is
absent. No payload was submitted. See PackageSettings.java.

22. Current retail MobileConfig providers export debug_only_* query paths,
but debug_only_set_overridden_configs and debug_only_service_command are
empty handlers. The ordinary read query attempted returned no result.
The Settings Debug page can be opened with MAIN action and
extra_settings_location_ordinal=9. Its MobileConfig button did not open the
editor. The editor code separately checks the internal-debug MC flag.
SettingsContentProvider additionally checks ACCESS_SETTINGS internally.

23. Found official Meta Portal 4.9 kernel source:
https://github.com/facebookincubator/Portal-Kernel/tree/portal-msm-4.9-kernel-master
Commit b4577154e48224e7ee1fe07a59656c10e7ea8b7e, published June 24, 2026,
build label 3051355900000000. Makefile is 4.9.227, matching the running kernel
version, but source-to-installed-binary identity has NOT been established.
The source includes CVE-2019-2215 poll cleanup, CVE-2022-20421 reference
cleanup, CVE-2023-20938/21255 failure-boundary fix and CVE-2023-33107 GPU
range-overflow checks. Do not infer exact device patch status from this alone.
The published GPU interface has no modern timeline or VBO interface used by
CVE-2022-22057 and CVE-2024-23380.

24. Built and ran a native access diagnostic, no malformed requests or exploit.
/dev/kgsl-3d0 opens from shell. Read-only KGSL queries report chip 0x06010501
and version fields 3.14 / 3.1. /dev/stax-ctrl, /dev/dbmdx-1 and
/dev/snd/controlC0 all return EACCES. A harmless one-entry BPF array-map
creation also returns EACCES. Source: kernel-access-probe.c.
Published stax driver exposes ioctl blobs but no alternative bypass sysfs knob.

25. Current /vendor/etc/audio_effects.conf comments out the Qualcomm AEC/NS
implementations. AudioFlinger lists no loaded AEC or NS effect, so the
Android AudioEffect interface does not expose this DSP processing.
Pulled all 17 current /vendor/etc/audio/terry files to current-tuning/.
Current DSP module binaries remain unreadable to shell.

26. Fresh acoustic baseline reproduced suppression using temporary MicProbe:
MIC, 16kHz mono, media14: quiet -37.5/-47.6 dBFS, playback -72.1/-72.5.
Test spkr_vol=-96 sent AFTER playback began: quiet -47.9, playback -73.7.
HAL logs confirm receiving the key, but no improvement. Restored spkr_vol
to -12.5, which is the existing media14 render level confirmed in logs.
No recordings were stored, only level statistics.

27. Older TMS disassembly shows supported voice_call_type values
0,4,5,6,7,8 map to capture parameter30011 values 0,1,4,5,2,6.
Live voice_call_type=8 produced a successful TMS capture parameter write
(apptype=0, parameter30011, value6), disproving an inference that an empty
shell getprop value means capture processing is unconfigured. Properties can
be unreadable to shell. Profile8 test: quiet -51.4, playback -73.3.
Restored voice_call_type=0. Other supported profiles are being tested.
The earlier statement no DSP parameters were changed applies to previous
rounds, not these temporary profile tests. AEC_ENABLE was not written.

28. Completed additional profile tests, MIC 16kHz mono, media14:
voice_call_type=7 (DSP value2): quiet -54.4, playback -74.6 dBFS.
voice_call_type=6 (DSP value5): quiet -52.6, playback -73.9 dBFS.
voice_call_type=5 (DSP value4): quiet -54.7, playback -72.5 dBFS.
Each command was sent before capture and again after playback started.
TMS logs confirm actual writes to capture parameter30011 and restoration
to value0 after every run. None disabled speaker-correlated suppression.
The baseline and test statistics do not establish speech intelligibility
during music because there was no independent speech source.

29. Cleanup: MicProbe uninstalled successfully, native diagnostic and UI
XML removed from /data/local/tmp, KS relaunched. Media volume was restored
to14. No AEC_ENABLE or NS_MODE write, kernel exploit, reboot, bootloader
unlock or firmware flash was performed. No repository edits.
Logs: profile-test-log.txt. Temporary helper sources retained locally.
Current result: hardware echo cancellation has NOT been disabled.


CONTINUED RESEARCH, October 2, 2026, through 21:50 local time

30. Extracted the exact installed kernel from Meta OTA build
5051355900018050 and reconstructed its ELF and kallsyms. The public Portal
4.9 source accepts the running config with no diff. Generated structure
offsets and compared 53 exploit symbols against the installed kernel with no
mismatches. The installed remove_waiter implementation is vulnerable to the
CVE-2026-43499 GhostLock primitive. CVE-2024-31317 is patched in the exact
framework and is not the selected route.

31. Ported the public NVIDIA Shield GhostLock implementation to the exact
Portal build. The Portal requires signal-return stack stamping because its
multicast setsockopt stack frame does not overlap the stale futex waiter. A
safe signal-return self-test passed. A compatibility probe also confirmed the
required futex, scheduler, ping socket, ashmem, configfs, virtual-address and
/proc/pid/mem behavior.

32. Corrected KernelSnitch for the Portal 4.9 private futex-key layout, which
stores mm before address. The kernel also randomizes memstart_addr, so a narrow
scan beginning at PAGE_OFFSET cannot find mm_struct on most boots. Added an
exact slab-tiled scan of the full 256 GiB linear-map window. It successfully
leaked mm_struct at ffffffcd2ae33b80 and reclaimed its order-2 slab page at
ffffffcd2ae30000.

33. The first successful page leak reached the GhostLock signal-return trigger
while the payload still used the old ffffffc0 direct-map assumption. The
Portal rebooted before a KASLR pointer or privilege change was obtained.
Network ADB disabled at reboot as documented for this device. The Portal and
Kiosk Satellite returned normally on the network and the Kiosk web service at
port 2324 responds. Port 5555 remains closed until ADB is enabled over USB.

34. Added per-run direct-map calculation from the leaked mm_struct address.
The allocator normally places mm_struct slabs in the Normal zone beginning at
physical 0x100000000. For the successful leak this resolves memstart_addr to
fffffff400000000 and the kernel image linear alias to ffffffcc80080000, which
explains the stale-alias reboot. Added GHOSTLOCK_STOP_AFTER_PAGE so the live
alias can be verified after ADB is restored without entering the GhostLock
trigger. The rebuilt preload SHA-256 is
e3961489472f78db03bc863809df65dec5a920410f3517a14555e8639ffed421.

Current result: hardware echo cancellation remains enabled. The next step is
to restore ADB over USB, run page-only alias verification, inspect pstore and
then retry the KASLR stage with the runtime alias.


CONTINUED RESEARCH, October 2, 2026, through 22:15 local time

35. Two independent page-only runs on boot eac7a910-8ad3-45f8-a025-c26a85f35b19
leaked mm_struct at fffffff7043bad80 and fffffff70a1c3b80. Both resolved
memstart_addr to ffffffca00000000 and the kernel image linear alias to
fffffff680080000. Both exited before the GhostLock trigger with UID 2000.
This confirms the runtime alias calculation across separate allocations.

36. A fixed-base, stop-after-FOPS run on the next allocation resolved
memstart_addr to ffffffc9c0000000 and the kernel alias to fffffff6c0080000.
The Portal rebooted during the signal-return route before arbitrary read/write
or cleanup completed. Kiosk Satellite and its port 2324 service recovered.
UID, SELinux and audio processing were not changed.

37. Source review found two causes in the unvalidated Portal FOPS route. The
signal-return variant ignored GHOSTLOCK_SLIDE_FOPS_ROUTE and retained the
boot-ID leak write target. The fixed-base path also skipped initialization of
the consumer delay, allowing sched_setattr to race before rt_sigreturn copied
the forged waiter onto the kernel stack. The exact disassembly confirms the
stale waiter at syscall stack offset -0x238 and the FPSIMD copy destination at
-0x270, so the existing 0x38 vregs offset is correct.

38. Corrected the FOPS signal-return target, added a 50 ms post-handler delay
and restored the equivalent delay in the alternate main route. Added a
scratch-only rb_erase checkpoint that writes only inside the reclaimed page
and skips ashmem open. The rebuilt preload SHA-256 is
2ec0871389cf54044a104e02b64ca0019b5c7109d941e10041ba2aed73556333.

Current result: hardware echo cancellation remains enabled. Network ADB is
off after the reboot. The next run should use the scratch-only checkpoint
after ADB is restored over USB, then proceed to the cleanup-verified FOPS
checkpoint only if that route returns cleanly.

39. The full reclaim spray reached the signal-return stamp cleanly, proving
the prior low-volume spray had not reliably replaced the freed slab. Source
tracing then showed that PAGE_PAYLOAD_FOPS performs its first constrained
write during FUTEX_CMP_REQUEUE_PI, before the signal-return trigger. The
so-called scratch route changed only the later write, leaving ashmem fops
pointing at the reclaimed page until reboot. Added a pre-signal CFI path that
verifies arbitrary read/write, restores boot-ID and ashmem fops and holds the
waiter asleep without entering the later PI-chain trigger. The rebuilt preload
SHA-256 is c74368774e4201c1be629c24d1f9a51c7bdd3fbbdba1dff059e5085d49fc36c1.

Current result: hardware echo cancellation remains enabled. Network ADB must
be restored once more. The next checkpoint now restores the temporary global
pointer before holding the still-sleeping waiter.

40. The pre-signal checkpoint held the waiter safely and kept the Portal,
Kiosk Satellite and network ADB stable. CFI stopped at step 4 because ashmem
still exposed its original operations. The initial rb_erase write used the
runtime linear alias of ashmem_misc.fops. Changed this target to the known
writable canonical .data address, leaving runtime aliases only for the
reclaimed page itself. Added logging of the exact readback on a future miss.
The held process was released with a normal reboot. The rebuilt preload
SHA-256 is 76f602797858478ec79f9f402fc00d2b121592b500951f601e6be27aaaedc6ee.

Current result: hardware echo cancellation remains enabled. The Portal and
Kiosk Satellite recovered normally. Network ADB requires USB enablement for
the canonical-target checkpoint.

41. The canonical-target pre-signal run also stopped at CFI step 4. The
ashmem read returned zero bytes and the expected fake table was absent. This
proves the initial requeue does not perform the constrained write. The write
occurs during the later priority adjustment. Review also found the earlier
scratch mode redirected only the signal-frame node while the reclaimed-page
node still targeted ashmem. Updated scratch mode so both rb-tree removals
write only inside the reclaimed page. The held process was released with a
normal reboot. The rebuilt preload SHA-256 is
019120a2e60761515ec8c2fd876934fb44f67f9a036a2c077094321dd73a8c82.

Current result: hardware echo cancellation remains enabled. The next run is
the first fully isolated test of whether the post-signal priority chain itself
returns safely without modifying ashmem.

42. The fully isolated scratch run still rebooted after the signal-return
stamp, proving the failure is inside rt_mutex_adjust_prio_chain rather than an
ashmem user racing the temporary pointer. With nice 1, the stale waiter has
priority 121 and displaces the fake sentinel at priority 130. That enters the
fake owner's incomplete pi_waiters and scheduler state. Added a controlled
GHOSTLOCK_SIGRETURN_NICE setting. Nice 19 gives the stale waiter priority 139,
so the sentinel stays on top. The constrained rb_erase still runs, while the
owner update branch becomes a no-op and the chain can return after observing
fake_task.pi_blocked_on as NULL. The rebuilt preload SHA-256 is
d8f3f1837cd08e57e2f1a7a63ae31b52cd403e27071226b8ade2ca20166e8de7.

Current result: hardware echo cancellation remains enabled. Network ADB must
be restored for the isolated nice-19 branch test.

43. The isolated nice-19 run still rebooted after the signal-return stamp.
Added independent control of the forged waiter's priority and extended the
nice control to zero. The next diagnostic uses SCHED_BATCH nice 0 and forged
waiter priority 120. Those equal values make rt_mutex_adjust_pi return before
locking the fake mutex or removing either rb-tree node. A clean return will
confirm signal-frame placement and isolate the failure to the tree-write path.
The rebuilt preload SHA-256 is
7216259b6e74a34e9d11e415d0eb148ddffc68409b7694cce8832cadea6e8a81.

Current result: hardware echo cancellation remains enabled. Network ADB must
be restored for the equal-priority early-exit probe.

44. The equal-priority probe also rebooted after the signal-return stamp.
This does not yet distinguish a bad stack overlap from a sched_setattr path
whose effective kernel priority differs from the requested nice value. Added
GHOSTLOCK_SIGRETURN_NO_SCHED. It performs the same rt_sigreturn FPSIMD copy,
then the consumer acknowledges the trigger without making any scheduler
syscall. A clean return will prove the stack placement itself is safe. The
rebuilt preload SHA-256 is
dcf7fbd8b6280b2ae95aff6db7ec7cc1a1ee083ebe55c585ffb3618d62e1784c.

Current result: hardware echo cancellation remains enabled. Network ADB must
be restored for the no-scheduler signal-return control.

45. Exact call-chain disassembly initially identified all three frames but the
recorded sum was wrong by 0x100. The corrected stale waiter is at syscall
SP-0x288: sys_futex uses 0x80 bytes, do_futex uses 0x140,
futex_wait_requeue_pi uses 0x1a0 and its rt_mutex_waiter begins at frame offset
0xd8. rt_sigreturn starts its FPSIMD copy at SP-0x270, so it misses the first
0x18 bytes of the waiter and cannot stamp the complete object. The pselect and
multicast routes also cannot stamp the complete waiter.

46. Found an exact unprivileged replacement in PTRACE_SETREGSET for a stopped
descendant. The installed call chain uses sys_ptrace 0x50, arch_ptrace 0x10,
ptrace_request 0xe0, ptrace_regset 0x40 and fpr_set 0x280. fpr_set copies a
0x210-byte user FPSIMD state beginning at syscall SP-0x3a0. The corrected stale
waiter therefore begins at offset 0x118 in the copy and fits completely. Implemented a
ptrace route that prepares a traced child before creating the dangling waiter,
stamps the waiter through NT_PRFPREG and supports a post-route hold so cleanup
cannot cause a false reboot during validation.

Current result: hardware echo cancellation remains enabled. The corrected
ptrace route is built and ready for a no-scheduler live-hold test once network
ADB is available.

47. The first ptrace route passed its no-scheduler live-hold control. The
traced descendant stopped normally, PTRACE_SETREGSET returned zero with an
iovec length of 0x210. The consumer acknowledged the copy without entering
sched_setattr. The waiter returned to userspace and the process remained alive
at the explicit post-route checkpoint. The Portal stayed responsive, SELinux
remained enforcing, ADB stayed connected and Kiosk Satellite returned HTTP
200. Later arithmetic review showed that this control wrote at offset 0x18,
which is 0x100 below the actual waiter. It proves the ptrace copy itself is
stable but does not validate waiter replacement.

Current result: hardware echo cancellation remains enabled. The next test is
the equal-priority scheduler probe through the corrected ptrace route after a
normal reboot clears the held dangling state.

48. The equal-priority scheduler probe through the first ptrace implementation
entered sched_setattr and rebooted Android. Kiosk Satellite recovered with
HTTP 200 and network ADB returned to its normal disabled-after-reboot state.
Rechecking the installed prologues exposed an arithmetic error: 0x80 + 0x140 +
0x1a0 - 0xd8 is 0x288, not 0x388. The real waiter starts at syscall SP-0x288,
so the ptrace FPSIMD payload belongs at offset 0x118 from its SP-0x3a0 copy
destination. Updated the implementation and comments to use offset 0x118.

Current result: hardware echo cancellation remains enabled. The next run is a
no-scheduler live-hold control at the corrected offset 0x118. Only after that
stays stable should the equal-priority scheduler probe be repeated.

49. The corrected offset 0x118 passed the no-scheduler live-hold control.
PTRACE_SETREGSET returned zero with an iovec length of 0x210, the waiter
returned to userspace and the process reached the explicit post-route hold.
The Portal remained responsive, SELinux stayed enforcing, ADB reported device
and Kiosk Satellite returned HTTP 200. A normal reboot cleared the held
dangling state and Kiosk Satellite recovered normally. Added an explicit
GHOSTLOCK_PTRACE_MATCH_TASK_PRIO diagnostic that derives the waiter priority
and scheduler update from the target thread's observed policy and nice value.
The normal ptrace and FOPS routes retain their forged priority defaults.

Current result: hardware echo cancellation remains enabled. Network ADB needs
USB enablement for the corrected equal-priority scheduler probe.

50. The corrected equal-priority probe passed. The waiter thread reported
SCHED_OTHER, nice 0 and kernel priority 120. PTRACE_SETREGSET stamped priority
120 at offset 0x118, the consumer forced a SCHED_BATCH policy change and
sched_setattr returned zero. The process reached the post-route hold. SELinux
remained enforcing, ADB stayed connected and Kiosk Satellite returned HTTP
200. This validates the complete waiter replacement and the exact
rt_mutex_adjust_pi early-return comparison on the installed build.

Current result: hardware echo cancellation remains enabled. The next
checkpoint uses the corrected ptrace placement with nice 19 and redirects the
rb_erase write entirely into the reclaimed page. This keeps the original
ashmem operations pointer untouched while validating the PI-chain return.

51. The first corrected-offset scratch run reached the scheduler trigger but
did not return and Android restarted. Kiosk Satellite stayed available or
recovered with HTTP 200. The failure is explained by transitive PI donation:
the nice 0 owner waits on f_pi_chain and donates effective priority 120 to the
target waiter. sched_setattr(nice 19) therefore leaves task->prio at 120. The
reinserted stale waiter outranks the priority-130 sentinel and enters the fake
owner's deliberately incomplete pi_waiters state. Added controls to set both
the waiter and owner threads to nice 19 before either PI lock is taken. With
both sides at effective priority 139, the priority-130 sentinel remains the
top waiter after rb_erase and the fake-owner update branch should stay a no-op.

Current result: hardware echo cancellation remains enabled. The next scratch
checkpoint must set GHOSTLOCK_SLIDE_WAITER_NICE=19 and
GHOSTLOCK_SLIDE_OWNER_NICE=19 along with GHOSTLOCK_SIGRETURN_NICE=19.

52. The all-nice-19 scratch run still restarted Android, but the separate
equal-priority control proved the priority model. With both PI participants at
nice 19, /proc reported priority 39 and inferred task->prio 139 after the
cycle formed. A priority-139 ptrace stamp then made sched_setattr return zero
through the early-exit branch and reached the live hold. The remaining scratch
failure is therefore after fake-lock acquisition, not priority donation.
Added GHOSTLOCK_SLIDE_NO_OWNER for the next isolated route. With the
priority-130 sentinel remaining top across the priority-139 reinsertion, an
ownerless fake lock returns directly after the scratch-only rb_erase and
avoids all fake task_struct accesses.

Current result: hardware echo cancellation remains enabled. The next scratch
checkpoint adds GHOSTLOCK_SLIDE_NO_OWNER=1 to the three nice-19 controls.

53. Added GHOSTLOCK_RB_ERASE_NO_CHILD to split fake-lock and tree validation
from the one-child constrained write. In this diagnostic the forged stale
node is red with no children, so rb_erase only clears a pointer inside the
reclaimed page. Combined with the ownerless lock and unchanged sentinel top,
the chain should return without a rebalance, wakeup or fake task access. A
successful no-child hold will prove fake-lock acquisition and basic tree
reinsertion before restoring the scratch child pointer.

54. The first ownerless no-child attempt became unresponsive during setup,
before the waiter logged its scheduler state or created the ptrace tracee.
Kiosk Satellite timed out briefly and then recovered with HTTP 200 after the
Portal restarted. This attempt did not reach the PI-chain diagnostic. Added
GHOSTLOCK_RECLAIM_ORDER2_ONLY so the immediate and burst reclaim stages use
the exact order-2 fragment layout that matches the freed mm_struct slab page.
The earlier mixed spray alternated those exact fragments with larger sends,
which left only half of the immediate reclaim attempts with the verified
base-relative payload layout.

55. The ptrace stack stamper did not honor GHOSTLOCK_RB_ERASE_NO_CHILD. The
first two purported no-child runs therefore repeated the known one-child
scratch graph. Added the missing branch and explicit stamp logging. The first
actual no-child run logged a zero left child and still restarted the Portal
after sched_setattr entered the forged lock path.

56. Verified the installed rb-tree color encoding and exact rb_erase
disassembly. Linux uses low bit 0 for red and low bit 1 for black. The stale
node's aligned parent value already marks it red and the sentinel value 1
already marks the one-node root black. A temporary diagnostic reversed these
colors and was discarded. The corrected no-child graph now uses aligned local
scratch as the red node's synthetic parent while retaining the black sentinel.
The remaining leading explanation is that the freed order-2 slab page was not
occupied by the expected socket fragment. CONFIG_PSTORE_RAM is enabled, so
the next step is to collect the persistent fault PC before changing reclaim
geometry again.

Current result: hardware echo cancellation remains enabled. Network ADB needs
USB enablement after the last kernel restart so pstore can be collected.

57. Android bugreport can retrieve the ramoops console even though Meta's
SELinux policy denies both the shell and BootReceiver direct access to
/sys/fs/pstore/console-ramoops-0. The first recovered panic is at
rt_mutex_adjust_prio_chain+0x1c0, the load of
lock->waiters.rb_leftmost->lock. The stale waiter is still present but its
lock pointer refers to the original PI mutex, not the prepared fake lock.
This disproves the earlier conclusion in item 50: the equal-priority control
could exit because the old and requested priorities were both 120 and did not
prove that PTRACE_SETREGSET overlapped the stale waiter.

58. A full 0x210-byte ptrace priority carpet with value 139 produced the same
panic. That run still had an effective priority of 120 because the nice 0
waiter donated priority through the owner chain, so it did not provide a
valid overlap oracle. A valid oracle must remove the owner's donation before
the vulnerable waiter leaves FUTEX_WAIT_REQUEUE_PI.

59. The first owner-chain diagnostic attempted to release the owner after the
waiter returned from FUTEX_WAIT_REQUEUE_PI. The persistent log and panic show
that this ordering is impossible: FUTEX_CMP_REQUEUE_PI returned -1/EDEADLK,
the main thread signaled the waiter and the kernel panicked during waiter
cleanup before the post-wait marker. The owner must be removed first while
the waiter's stack object is still live.

60. Signaling the owner before the waiter does not remove the donation on
this kernel. FUTEX_LOCK_PI is restartable here. The signal was handled and
the owner returned to futex_lock_pi with normal nice 19 while the main thread
waited. Added a one-second absolute CLOCK_REALTIME timeout to the owner's
FUTEX_LOCK_PI call. The next diagnostic waits for that timeout and only then
signals the vulnerable waiter.

61. Added GHOSTLOCK_SKIP_FOPS_PAGE_PREP for the priority-carpet diagnostic.
It supplies nonzero placeholder state and skips KernelSnitch, mm_struct slab
preparation and socket reclaim. A successful priority-carpet overlap exits
before any placeholder can be dereferenced, so this removes unrelated
allocator variance from the stack-placement test.

62. Rechecked the exported aiservice control surfaces. Every binder method in
AiInternalControlService and SmartCameraInternalControlService enforces the
smart-camera signature permission for cross-UID callers. AI session
properties expose only voice_activity_detection. The sound-preprocessing
debug dialog writes two shared preferences for WebRTC software AGC and
hardware AGC. It does not call AEC_ENABLE and its hardware AGC preference is
consumed by the calling engine rather than the system capture path. No
exported bridge to setAudioProcessingParam was found.

Current result: hardware echo cancellation remains enabled. The timeout-based
owner-chain diagnostic is built but cannot be deployed until network ADB is
restored after the intentional reboot.

63. The clean timeout-based carpet reached the decisive state and still
panicked. Exact call-chain reconstruction from the installed disassembly
explains why. The dangling waiter reported in pstore belongs to the owner
thread's rt_mutex_slowlock frame, whose waiter is at syscall-entry S-0x368.
The earlier ptrace call ran on the WAIT_REQUEUE_PI thread and therefore wrote
to a different kernel stack. On the owner thread, fpr_set's 0x210-byte buffer
starts at S-0x3a0, so the complete dangling waiter begins at buffer offset
0x38 and fits through offset 0x88. Added GHOSTLOCK_PTRACE_OWNER_STACK to run
PTRACE_SETREGSET on the owner immediately after its controlled timeout, use
offset 0x38 and skip the later waiter-thread stamp.

Current result: hardware echo cancellation remains enabled. The owner-stack
priority-carpet build is ready for the next clean-boot run.

64. The owner-stack priority carpet at ptrace-buffer offset 0x38 changed the
persistent panic from a dereference at 0x23e to a dereference at 0x38 in the
same rt_mutex_adjust_prio_chain+0x1c0 instruction. This proves the ptrace
copy reaches the dangling owner-thread waiter far enough to change its
priority and enter the stale chain. The stale waiter's lock pointer was still
the original PI lock. The route had an unintended 50 ms delay between the
ptrace syscall and sched_setattr, during which interrupts could reuse the
owner's kernel stack and overwrite parts of the forged waiter.

65. Retried with that delay and the spin delay both set to zero, a fully
prepared reclaimed page, a forged waiter priority of 139 and the no-child
scratch graph. The mm_struct page leak and full order-2 reclaim completed. The
owner timed out and logged the intended fake lock fffffffa933b1350 and scratch
parent fffffffa933b3000. The scheduler transition then stopped making progress.
The Portal remained reachable briefly before going offline and rebooting,
consistent with a kernel lockup and watchdog reset rather than the immediate
page fault seen in earlier runs. The next persistent log should identify which
raw spinlock or tree operation stalled.

Current result: hardware echo cancellation remains enabled. Network ADB needs
USB enablement after this watchdog restart so the persistent kernel log can be
collected.

66. Persistent log from the supposed lockup is another immediate
rt_mutex_adjust_prio_chain+0x1c0 null dereference. x20 is the original PI
lock, not the prepared fake lock fffffffa933b1350. The prior interpretation
that the dangling waiter belonged to the owner thread was wrong. The task
being reprioritized is the WAIT_REQUEUE_PI thread, and its pi_blocked_on must
point to that thread's local rt_waiter. Installed disassembly confirms its
placement: sys_futex 0x80, do_futex 0x140 and
futex_wait_requeue_pi.constprop.23 0x1a0 with rt_waiter at frame+0xd8. This is
syscall SP-0x288. The ptrace fpr_set buffer begins at syscall SP-0x3a0, so
the correct input offset remains 0x118 on the WAIT_REQUEUE_PI thread. The
owner timeout only removes priority donation before the waiter is released.
It does not change which stack holds the dangling object.

A scheduler-disabled diagnostic is prepared to report the actual
PTRACE_SETREGSET return value at offset 0x118. Network ADB went offline after
the bugreport and now refuses connections, so USB enablement is required
before running it.

Current result: hardware echo cancellation remains enabled.

67. A scheduler-disabled run proved PTRACE_SETREGSET succeeds on the
WAIT_REQUEUE_PI thread: ret=0, errno=0, iov_len=0x210 and input offset 0x118.
The corrected real run then reclaimed an order-2 page at ffffffc3c95f8000,
stamped fake lock ffffffc3c95f9350 and scratch parent ffffffc3c95fb000, and
completed sched_setattr with ret=0. The forged waiter returned, the route child
exited with status 0 and the parent reached the scratch-only route checkpoint.
This proves the full trigger can return without crashing but does not by itself
prove that rb_erase performed its constrained write.

Current result: hardware echo cancellation remains enabled.



68. The first scratch completion used a forged waiter priority of 139, which
could match the WAIT_REQUEUE_PI task after nice 19 and let rt_mutex_adjust_pi
return before rb_erase. A live fops attempt with priority 139 confirmed that
PTRACE_SETREGSET succeeded but ashmem_misc.fops was unchanged. Retrying the
no-child scratch route with waiter priority 130 also completed cleanly. A live
fops attempt with priority 130 again left ashmem_misc.fops unchanged. The
installed rb_erase path would write the forged parent value if it received the
forged tree node, so either an earlier chain condition is still exiting or a
forged waiter field is not landing at the assumed stack offset. The next run
will log the post-sched_setattr task priority and use the direct-map alias of
ashmem_misc.fops to separate those cases.

Current result: hardware echo cancellation remains enabled.
69. The in-flight ptrace scheduler race eliminated the silent early exit and
caused a controlled kernel panic in rt_mutex_adjust_prio_chain. The panic task
was the scheduler consumer. x28 held the exact expected stale waiter address
ending in 0x3c38, proving the 0x118 overlap calculation. The forged priority
had landed and started the chain, but waiter->lock at x20 contained unrelated
kernel-stack data instead of the fake lock. The normal 0x210-byte arm64
copy_from_user implementation copies in increasing address order, so a fault
after offset 0x1c0 can expose a fully written 0x118..0x168 waiter without ever
exposing a partial pointer set. CONFIG_USERFAULTFD is disabled. The next route
uses a two-page input with the second page PROT_NONE, causing the copy to fault
only after the complete forged waiter is live while the remote scheduler
consumer is already looping.

Current result: hardware echo cancellation remains enabled.

70. The PROT_NONE fault-tail run still panicked at
rt_mutex_adjust_prio_chain+0x1c0. The scheduler consumer saw the expected stale
waiter at fffffff853283c38 and the forged priority forced the chain walk, but
the waiter lock register was fffffff8592ef000 instead of the prepared fake
lock fffffff89b639350. The task and next-lock registers both held that same
value. This means ordinary kernel-stack reuse replaced the lock field before
the consumer reached it while the forged priority remained live. A synchronous
PROT_NONE fault returns too quickly to preserve the coherent copied waiter.
The next variant places the byte immediately after the complete waiter on a
cold file-backed page. Its major page fault should hold copy_from_user inside
the syscall while the scheduler consumer uses the fully written waiter.

Current result: hardware echo cancellation remains enabled.

71. The first cold file-backed tail run confirmed the second page was absent
from the page cache before PTRACE_SETREGSET, but the scheduler consumer entered
too early. The panic moved to _raw_spin_trylock+0x18 with x20 equal to the
waiter thread's user-stack area rather than the prepared fake lock. This is a
ptrace call-frame local written over the stale waiter before copy_from_user
replaces the complete object. Added a gated mode that opens the waiter thread's
/proc stat file before the race and makes the consumer wait until that thread
enters uninterruptible D state on the cold page fault. If the page fault is too
short to observe, the consumer performs no second scheduler call and the run
returns safely. The next live checkpoint also uses an ownerless fake mutex so
a successful rb_erase write returns without walking a fake task_struct.

Current result: hardware echo cancellation remains enabled.

72. The matching-priority D-state control still panicked in
_raw_spin_trylock+0x18. The scheduler reached the stale waiter only after the
cold file page became ready and the ptrace frame unwound. x20 was zero, not
the placeholder lock value 1. Waiting for D state therefore identifies the
right page fault but does not keep it blocked long enough. The installed ext4
source takes an inode-wide i_mmap_sem read lock for mapped-file faults and a
write lock while shrinking a file. A live probe showed that truncating warmed
page cache takes about 24 ms for 64 MiB, 47 ms for 128 MiB and 58 ms for
256 MiB. FALLOC_FL_ZERO_RANGE is unavailable on the encrypted userdata file.
The next route maps the ptrace tail from the first page of a file, warms a
separate 64 MiB range in that inode and truncates only the warm range while
copy_from_user faults on the retained first page.

Current result: hardware echo cancellation remains enabled.

73. Auditing the installed `pselect6` call chain ruled it out as a coherent
waiter carrier: its copied fd-set storage begins at syscall entry SP-0x1a8,
well above the stale WAIT_REQUEUE_PI waiter at SP-0x288. Native `sendmmsg`
provides an exact alternative. On this kernel, the nested `sockaddr_storage`
begins at SP-0x290, so an eight-byte prefix followed by the 0x50-byte waiter
lands precisely over the stale object. A connected loopback TCP socket with a
full send buffer keeps that copy live in `sk_stream_wait_memory`. The
equal-priority control observed that wchan, completed one `sched_setattr` call
with ret=0, unblocked through receiver shutdown, and exited cleanly. This
confirms deterministic placement and lifetime without a fault-window race.

Current result: hardware echo cancellation remains enabled.

74. The first live `ashmem_misc.fops` attempt used the default scheduler
transition to nice 1. The forged waiter was reinserted at priority 121 ahead
of the priority-130 sentinel, and the scheduler thread remained in kernel
context at 100% CPU. This matches the ownerless return branch attempting to
wake the new top waiter's forged task pointer. A second attempt changed the
task to priority 139 so the sentinel would remain top, but the device stopped
servicing shell requests and had to reboot before its final trace was
captured. The next build adds entry/return logging around `sched_setattr` and
a non-ashmem proof mode: the same constrained write redirects the boot-id
sysctl data pointer to the pinned fake table, whose first 16 bytes can be read
back through `/proc/sys/kernel/random/boot_id`. Output will be retained in a
file across reboot.

Current result: hardware echo cancellation remains enabled.

75. A reboot-persistent trace located the priority-139 attempt precisely. The
consumer entered `sched_setattr`, never returned, and consumed one CPU in
kernel context. Reading `/proc/sys/kernel/random/boot_id` concurrently still
returned the original UUID, proving the constrained `rb_erase` write had not
executed. The stall is therefore in acquisition of the reclaimed-page fake
mutex, before the tree operation. The next route no longer forges the waiter
lock pointer. `sendmmsg` copies only the eight-byte prefix and 0x18-byte
`rb_node`, preserving the stale waiter's legitimate task, priority and live
PI-mutex pointer. After the original owner-chain timeout, a helper thread at
priority 130 blocks on that real PI mutex and supplies a valid kernel-managed
sentinel. Changing the vulnerable task from priority 120 to 139 then forces
the forged dequeue while keeping the helper as the top waiter, allowing the
real owner and lock graph to provide the return path.

Current result: hardware echo cancellation remains enabled.

76. The first preserve-lock run reached the scheduler consumer despite its
retained userspace trace ending at the owner-timeout checkpoint. Ramoops shows
the expected stale waiter in x28, but waiter->lock in x20 was the userspace
pointer 0x7da29e5000. Signal delivery and rt_sigreturn therefore overwrite the
field before the partial sendmmsg copy; the real PI-mutex pointer cannot be
preserved this way. The panic occurred in _raw_spin_trylock before rb_erase,
so the boot-id pointer remained untouched.

The next route uses a deterministic kernel-owned lock instead of either the
overwritten real pointer or the reclaimed-page fake lock. The installed image
exports msm_bus_dbg_cllist_lock at image offset 0x22504f8. It is a statically
initialized rt_mutex in BSS and is used only by the optional MSM bus debug
interface. Its direct-map alias supplies a valid unlocked wait_lock and empty
waiter tree. The full sendmmsg copy points the forged waiter at this lock; an
ownerless requeue wakes init_task, which is already runnable, and returns.
This one-shot diagnostic dirties the debug lock's waiter tree and must be
followed by reboot unless the resulting kernel-write primitive restores it.

Current result: hardware echo cancellation remains enabled.

77. The static-mutex run did reach `rt_mutex_adjust_prio_chain` with both the
expected stale waiter and the requested `msm_bus_dbg_cllist_lock` direct-map
alias. It faulted in `_raw_spin_trylock` because that alias was unmapped. The
faulting alias was exactly 1 GiB below the alias reconstructed independently
from the panic task's valid direct-map stack pointer. This is consistent with
the leaked `mm_struct` slab page having fallen back from the nearly depleted
Normal zone into the upper half of DMA: the old reconstruction always assumed
that the slab page was in Normal, shifting `memstart_addr` by one 1-GiB
alignment unit when that assumption was false. Current Normal free pages sit
at approximately the zone low watermark, so this fallback is realistic during
the multi-process slab grooming run. The build now logs all three possible
2/3/4-GiB physical-zone reconstructions and has a diagnostic-only page leak
mode that performs no scheduler trigger. It also accepts an explicit zone or
verified `memstart_addr` for the eventual live route.

Current result: hardware echo cancellation remains enabled.

78. The five- and eight-collision diagnostic runs found timing candidates but
no `mm_struct`; a four-collision run completed twice and both independent
leaks produced the same three possible `memstart_addr` values. The ambiguity
is exactly the physical 2/3/4-GiB zone number, not a variable hash result.
The build can now precondition the Normal zone with a temporary anonymous
memory balloon before slab grooming. More significantly, a new release mode
uses the absolute timeout already supported by `FUTEX_WAIT_REQUEUE_PI` instead
of delivering SIGUSR1. This should leave the stale waiter's legitimate task
and PI-mutex pointers intact. The partial `sendmmsg` copy then replaces only
the vulnerable rb-node fields and can use the real kernel-owned mutex without
requiring any direct-map reconstruction for lock acquisition. This path still
needs a live non-writing scheduler control before a constrained write.

Current result: hardware echo cancellation remains enabled.

79. Reading the reboot bugreport's arm64 virtual-memory layout provides the
exact live linear-map range directly; it is no longer necessary to infer
`memstart_addr` from the physical zone of the leaked slab. With that exact
base, the static-lock route acquired `msm_bus_dbg_cllist_lock` and advanced
from `_raw_spin_trylock` to `rt_mutex_adjust_prio_chain+0x1c0`. It then
dereferenced address `0x38`: disassembly shows that instruction loads
`lock->waiters.rb_leftmost->lock`, and the idle static mutex has an empty
waiter tree. The next route uses `proc_uid_lock`, whose address is also known
from the exact image. A controlled cold ext4 page fault pauses one
`/proc/uid` enumeration while it owns that mutex, and a second enumeration
queues a legitimate priority-130 top waiter. This supplies the valid
kernel-managed owner and leftmost waiter that the constrained rb-tree removal
requires.

Current result: hardware echo cancellation remains enabled.

80. A second `/proc/uid` enumeration cannot serve as the real top waiter for
`proc_uid_lock`. `iterate_dir()` first takes the directory inode's write-side
`i_rwsem`, so the second enumeration blocks before reaching `proc_uid_lock`.
An app-process creation does reach the lock independently through UID
registration. Starting the debuggable `me.jxl.portalreadprobe` process while a
nice-19 holder is stopped in an ext4-backed `getdents64` copy boosts that holder
from kernel priority 139 to 120. This priority inheritance is definitive proof
that a normal-priority real waiter is queued on the mutex, unlike a nonzero
`wchan` alone.

81. The first app-process sentinel runs, with 64 and then 256 retained mappings,
still faulted at `rt_mutex_adjust_prio_chain+0x1c0`. Ramoops again showed the
correct `proc_uid_lock` alias in x20 but a NULL `lock->waiters.rb_leftmost`.
The retained timestamps identified the cause: panic-proof `O_SYNC` logging ran
after the PI check and before `sched_setattr`. A release log held the global log
mutex while ext4 completed the truncate, and the consumer's entry log then
waited behind it for roughly ten seconds. The real waiter had left before the
scheduler entered the chain walk. The consumer now performs no disk logging in
that interval and rechecks the holder's donated priority immediately before the
scheduler call. It also accepts only `sk_stream_wait_memory` as proof that
`sendmmsg` has copied the complete waiter; transient `avc_has_perm` and
`notif_lock` waits are no longer sufficient.

82. Moving signal return before the lock gate closes the remaining lifetime
race. The vulnerable waiter now completes its interrupted futex cleanup and
parks at a userspace barrier. The gate then starts the ext4 truncate, blocks the
nice-19 `/proc/uid` holder, and uses a pre-forked `run-as
me.jxl.portalreadprobe` process to queue directly through UID registration.
After the holder's kernel priority is observed at 120, the barrier releases the
waiter directly into `sendmmsg`. A scheduler-disabled control reached
`sk_stream_wait_memory` with holder priority 20 in `/proc` (kernel priority
120), nice 19, and both holder and truncate still active (`proc_done=0/0`).
This verifies the real top waiter survives at the exact scheduler boundary.

83. The first live run with the reordered gate used the exact current-boot
`memstart_addr` `0xffffffcdc0000000` and passed page reclaim and stale-waiter
setup. The ADB shell then disconnected and the device rebooted before a return
trace, rather than producing the previous userspace continuation. The reboot's
ramoops record has not yet been collected because network ADB came back
disabled. Its fault PC will determine whether the forged dequeue advanced past
the old `+0x1c0` NULL dereference into `rb_erase` or a later invariant.

Current result: hardware echo cancellation remains enabled.

84. The reordered proc-lock run's ramoops record showed a late panic in the
legitimate `run-as` waiter, not in the scheduler consumer. The forged scheduler
operation had returned zero. After the exploit child released its gates,
`run-as` entered `proc_register_uid`, attempted to take `proc_uid_lock`, and
faulted in `rb_next+0x1c` on a poisoned parent link. The forged waiter had used
the direct-map alias while the live lock graph used its canonical address; the
route now uses `canon_addr(SLIDE_PROC_UID_LOCK_IMAGE)` consistently.

85. Android's bundled `simpleperf` provides a repeatable KASLR disclosure on
this build even though kallsyms names are hidden. A one-second `cpu-clock`
record includes raw kernel callchain PCs. Samples ending in `0x3d7e` identify
`el0_svc_naked+0x34`, so subtracting `0x3d7e` yields the current runtime
`_text`. The exploit now validates and accepts that base through
`GHOSTLOCK_KASLR_BASE`. A separate ARM64 `PRFM` timing scan did not distinguish
the mapped 128 MiB kernel-module range from adjacent holes and is retained only
as a negative diagnostic.

86. With the canonical proc lock, the scheduler consumer again returned zero.
The child then exited and the real waiter later panicked in `rb_next`, proving
that cleanup, rather than the constrained write itself, caused the reboot. A
held mode now leaves the socket waiter and lock gate alive while another thread
performs immediate post-write work. Critical-window logging can be made
stderr-only with `GHOSTLOCK_VOLATILE_LOG`, avoiding `O_SYNC` delays on the same
ext4 filesystem used by the gate.

87. The held boot-ID run proved the constrained kernel write. It redirected
the boot-ID sysctl data pointer to the reclaimed-page candidate and returned
`11000000-0000-0000-70ea-8a0291ffffff`, decoded as `q0=0x11` and
`q1=0xffffff91028aea70`. The second word is the exact canonical write target
stored by the RB unlink. The device rebooted only after the finite ext4
truncate completed and released the legitimate waiter into the damaged tree.

88. The first in-child ashmem FOPS checkpoint also completed the scheduler
operation, then faulted in `try_module_get+0x2c` from `misc_open`; the fake
table's owner argument was `0xc`. This explains the earlier boot-ID `q0=0x11`:
the known slab address had not retained the sprayed file-operations payload.
The large proc-lock gate was allocating page tables and VMAs after the target
page reclaim and could reuse that page before the trigger.

89. The proc-lock gate is now preallocated inside page preparation while the
leaked `mm_struct` remains pinned. All page-preparation child processes already
exist at that point. Only after the 64 GiB mapping and page tables are complete
does the exploit free the order-2 target slab and spray it with the mixed
order-2/order-3 socket payload. The FOPS checkpoint also uses canonical
KASLR-adjusted addresses until it reads the real `memstart_addr` through the
configfs primitive and configures direct-map translation.

Current result: hardware echo cancellation remains enabled.

90. Preallocating the complete proc-lock gate did not change the FOPS-open
failure. The scheduler operation returned zero, but `misc_open()` again passed
`0xc` as the fake table's owner to `try_module_get()`. This disproves the
specific theory that the gate's later VMA and page-table allocations caused
the corrupt first word. A new held diagnostic uses `MSG_PEEK` on every reclaim
socket after the scheduler write. It searches for the canonical
`ashmem_misc.fops` target at the fake table's exact per-message offset and
reports the adjacent words without consuming or freeing the backing page. The
next run can therefore distinguish payload corruption from a later FOPS-open
effect without deliberately panicking the device.

Current result: hardware echo cancellation remains enabled.

91. The held payload inspection returned `table_hits=0` across 64 reclaim
socket pairs. This means the constrained write succeeded without the leaked
order-2 slab page being owned by any queued socket payload. The owner values
`0x11` and `0xc` were unrelated freed-page contents, not corruption after a
successful reclaim.

92. Exact allocator analysis found the mismatch. `unix_stream_sendmsg()` uses
the task page-fragment cache, whose refill is an order-3 compound allocation
with an order-0 fallback on this kernel. The 16 KiB data fragment merely uses
half of that order-3 page. It cannot directly reclaim the order-2
`mm_struct` slab page. The earlier `GHOSTLOCK_RECLAIM_ORDER2_ONLY` name
described message length, not the allocator order, and was therefore
misleading.

93. `/dev/kgsl-3d0` is available to the shell. A live
`KGSL_IOC_GPUMEM_ALLOC_ID` probe successfully allocated and mapped 16 KiB
buffers with alignment exponent 14. The exact KGSL implementation requests
an order-2 compound page for that geometry, and the installed live device
tree has no `qcom,gpu-mempools` node, so it uses the direct `alloc_pages()`
path rather than falling back through configured pool sizes. The exploit now
retains a pre-free drain set, performs the KGSL allocations immediately after
freeing the target, writes the payload through each userspace mapping, and
checks every mapped fake table after the constrained write. The first launch
selected the old sigreturn route because the stack-route environment variable
was omitted; it was interrupted before a scheduler write. A parent-death
signal now prevents future ADB interruptions from leaving the gate child
orphaned.

Current result: hardware echo cancellation remains enabled.

94. The corrected sendmmsg/KGSL run reached the vulnerable scheduler path and
`sched_setattr` returned zero. The child then spent about 0.38 seconds scanning
the legacy socket queue; the finite ext4 gate expired and the legitimate
waiter rebooted the device before the KGSL mapping scan began. The KGSL scan
now runs first and skips the socket queue by default. The proc_uid gate also
accepts a larger backing-file size so the held interval can be extended for
post-write verification.

Current result: hardware echo cancellation remains enabled.

95. A repeat with a 512 MiB proc_uid backing file showed that increasing the
gate size does not leave a useful post-write interval. It delays the scheduler
operation proportionally, but `sched_setattr` returns only when the ext4 gate
finishes; the damaged legitimate waiter can then reboot the device before a
different thread runs. Collision detection now executes in the scheduler
consumer itself immediately after the syscall returns. It reads only the
already populated KGSL mappings before logging, waking another thread, or
making another syscall, and reports the matching mapping as `kgsl_hit` in the
scheduler return line.

Current result: hardware echo cancellation remains enabled.
