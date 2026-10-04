#!/usr/bin/env python3
"""Inspect, provision, recover, and verify supported Meta Portal devices."""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import pathlib
import re
import select
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile

from portal_targets import PortalTarget, find_target


ROOT = pathlib.Path(__file__).resolve().parents[1]
HELPER_LOCAL = ROOT / "helper/build/libportal_audio_persist.so"
PRELOAD_REMOTE = "/data/local/tmp/preload-portal.so"
HELPER_REMOTE = "/data/local/tmp/libportal_audio_persist.so"
ACCOUNT_CTL_LOCAL = ROOT / "exploit/build/portal-account-ctl.jar"
ACCOUNT_CTL_REMOTE = "/data/local/tmp/portal-account-ctl.jar"
SHIZUKU_PACKAGE = "moe.shizuku.privileged.api"
SHIZUKU_HELPER_PACKAGE = "dev.portal.shizukuhelper"
SHIZUKU_HELPER_LOCAL = ROOT / "shizuku-helper/build/portal-shizuku-helper.apk"
SHIZUKU_KEY_REMOTE = "/data/local/tmp/portal-shizuku-adbkey.pub"
SHIZUKU_SAVED_KEY_REMOTE = "/data/local/tmp/portal-shizuku-adbkey-v1.pub"
SHIZUKU_VERSION = "13.6.0.r1086.2650830c"
SHIZUKU_APK_NAME = "shizuku-v13.6.0.r1086.2650830c-release.apk"
SHIZUKU_APK_URL = (
    "https://github.com/RikkaApps/Shizuku/releases/download/v13.6.0/"
    + SHIZUKU_APK_NAME
)
SHIZUKU_APK_SHA256 = (
    "6e273ab0e991c4e79bc8b1bbb9b9dd739ccac1a8712a541a214078886b7b790f"
)
STATE_REMOTE = "/data/local/tmp/portal-provision-state-v1.json"
PRIVACY_BACKUP_REMOTE = "/data/local/tmp/portal-private-dns-before-v1.json"
KIOSK_COMPONENT = "me.jxl.kiosk_satellite/.KioskAdminReceiver"
KIOSK_OWNER_COMPONENTS = (
    "admin=me.jxl.kiosk_satellite/.KioskAdminReceiver",
    "admin=ComponentInfo{me.jxl.kiosk_satellite/"
    "me.jxl.kiosk_satellite.KioskAdminReceiver}",
)
DEBLOAT_BACKUP_REMOTE = "/data/local/tmp/portal-debloat-backup-v1.tsv"
PACKAGE_STATE_SETTLE_SECONDS = 15
DEBLOAT_PACKAGES = (
    "com.facebook.aloha.analytics",
    "com.facebook.aloha.app.messenger",
    "com.facebook.aloha.app.whatsapp",
    "com.facebook.aloha.app.portalfeed",
    "com.facebook.alohaapps.superframe",
    "com.facebook.alohaapps.contacts",
)
META_ACCOUNT_BACKUP_REMOTE = "/data/local/tmp/portal-meta-accounts-before-v1.tsv"
META_ACCOUNT_TYPES = (
    "com.facebook.aloha.sso",
    "com.facebook.aloha.pl",
    "com.facebook.aloha.hw",
    "com.facebook.aloha.privowner",
)
META_AUTHENTICATOR_COMPONENTS = (
    "com.facebook.aloha.system.alohausers.services.AuthenticationService",
    "com.facebook.aloha.system.alohausers.services2.PLAuthenticatorService",
    "com.facebook.aloha.system.alohausers.services2.HWAuthenticatorService",
    "com.facebook.aloha.system.alohausers.services2."
    "PrivOwnerAccountsAuthenticatorService",
)
PRESENCE_PROFILE_KEYS = (
    "enable_cv_background_detector_v2",
    "enable_liveness_metric",
    "enable_color_based_reid",
    "enable_face_rec_based_reid_v3",
)
PRESENCE_LOG_MARKER = "Notify people presence"
PRESENCE_ANALYSIS_FRAME_MARKER = "Frame available for analysis stream"
PRESENCE_ROI_FRAME_MARKER = "Frame available for roi stream"
CAMERA_SERVICE_COMPONENT = (
    "com.facebook.portal.aiservice/"
    "com.facebook.alohaapp.app.services.CameraService"
)


class ProvisionError(RuntimeError):
    pass


class PortalProvisioner:
    def __init__(
        self,
        serial: str,
        attempts: int,
        log_dir: pathlib.Path,
        audio: bool = False,
        restore_audio: bool = False,
        device_owner: bool = False,
        disable_updates: bool = False,
        enable_updates: bool = False,
        debloat: bool = False,
        restore_bloat: bool = False,
        remove_meta_accounts: bool = False,
        optimize_presence: bool = False,
        restore_presence_profile: bool = False,
        privacy_dns: str | None = None,
        restore_privacy_dns: bool = False,
        shizuku: bool = False,
        remove_shizuku: bool = False,
        shizuku_apk: pathlib.Path | None = None,
        status_only: bool = False,
        dry_run: bool = False,
        backup_path: pathlib.Path | None = None,
        recover: bool = False,
        skip_build: bool = False,
    ):
        self.serial = serial
        self.attempts = attempts
        self.log_dir = log_dir
        self.audio = audio
        self.restore_audio = restore_audio
        self.device_owner = device_owner
        self.disable_updates = disable_updates
        self.enable_updates = enable_updates
        self.debloat = debloat
        self.restore_bloat = restore_bloat
        self.remove_meta_accounts = remove_meta_accounts
        self.optimize_presence = optimize_presence
        self.restore_presence_profile = restore_presence_profile
        self.privacy_dns = privacy_dns
        self.restore_privacy_dns = restore_privacy_dns
        self.shizuku = shizuku
        self.remove_shizuku = remove_shizuku
        self.shizuku_apk = shizuku_apk
        self.shizuku_public_key: pathlib.Path | None = None
        self.shizuku_verifier_initially_disabled: bool | None = None
        self.status_only = status_only
        self.dry_run = dry_run
        self.backup_path = backup_path
        self.recover = recover
        self.skip_build = skip_build
        self.adb = ["adb", "-s", serial]
        self.target: PortalTarget | None = None

    @staticmethod
    def run(
        args: list[str], timeout: float | None = None, check: bool = False
    ) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(
                args,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ProvisionError(f"command timed out: {shlex.join(args)}") from exc
        if check and result.returncode != 0:
            raise ProvisionError(
                f"command failed ({result.returncode}): {shlex.join(args)}\n"
                f"{result.stdout[-2000:]}"
            )
        return result

    def adb_run(
        self, args: list[str], timeout: float | None = None, check: bool = False
    ) -> subprocess.CompletedProcess[str]:
        return self.run(self.adb + args, timeout=timeout, check=check)

    def connect(self, wait_seconds: int = 150) -> None:
        try:
            self.run(["adb", "disconnect", self.serial], timeout=5)
        except ProvisionError:
            pass
        deadline = time.monotonic() + wait_seconds
        while time.monotonic() < deadline:
            try:
                self.run(["adb", "connect", self.serial], timeout=5)
                state = self.adb_run(["get-state"], timeout=5)
                completed = self.adb_run(
                    ["shell", "getprop", "sys.boot_completed"], timeout=5
                )
                if state.returncode == 0 and completed.stdout.strip() == "1":
                    return
            except ProvisionError:
                pass
            time.sleep(3)
        raise ProvisionError(f"{self.serial} did not reconnect after {wait_seconds}s")

    def reboot(self) -> tuple[str, str]:
        before = self.adb_run(
            ["shell", "cat", "/proc/sys/kernel/random/boot_id"],
            timeout=5,
            check=True,
        ).stdout.strip()
        try:
            self.adb_run(["reboot"], timeout=8)
        except ProvisionError:
            # adbd can disappear before acknowledging a successful reboot.
            pass
        after = self.connect_after_reboot(before)
        return before, after

    def connect_after_reboot(self, before: str, wait_seconds: int = 180) -> str:
        try:
            self.run(["adb", "disconnect", self.serial], timeout=5)
        except ProvisionError:
            pass
        deadline = time.monotonic() + wait_seconds
        last_boot_id = ""
        while time.monotonic() < deadline:
            try:
                self.run(["adb", "connect", self.serial], timeout=5)
                state = self.adb_run(["get-state"], timeout=5)
                completed = self.adb_run(
                    ["shell", "getprop", "sys.boot_completed"], timeout=5
                )
                boot = self.adb_run(
                    ["shell", "cat", "/proc/sys/kernel/random/boot_id"], timeout=5
                )
                last_boot_id = boot.stdout.strip()
                if (
                    state.returncode == 0
                    and completed.stdout.strip() == "1"
                    and last_boot_id
                    and last_boot_id != before
                ):
                    return last_boot_id
            except ProvisionError:
                pass
            time.sleep(3)
        raise ProvisionError(
            f"{self.serial} did not complete a new boot after {before}; "
            f"last boot ID was {last_boot_id!r}"
        )

    def verify_target(self, require_supported: bool = True) -> PortalTarget | None:
        fingerprint = self.adb_run(
            ["shell", "getprop", "ro.build.fingerprint"], timeout=5, check=True
        ).stdout.strip()
        device = self.adb_run(
            ["shell", "getprop", "ro.product.device"], timeout=5, check=True
        ).stdout.strip()
        target = find_target(device, fingerprint)
        self.target = target
        if target is None and require_supported:
            raise ProvisionError(
                "unsupported firmware; refusing build-specific kernel writes\n"
                f"device: {device}\nfingerprint: {fingerprint}"
            )
        if target is None:
            print(
                f"TARGET_UNSUPPORTED serial={self.serial} device={device} "
                f"fingerprint={fingerprint}"
            )
        else:
            print(
                f"TARGET_OK serial={self.serial} target={target.key} "
                f"device={device} fingerprint={fingerprint}"
            )
        return target

    def stage(self) -> None:
        if self.target is None:
            raise ProvisionError("target must be selected before staging")
        files = [(self.target.preload_path(ROOT), PRELOAD_REMOTE)]
        if self.audio:
            files.append((HELPER_LOCAL, HELPER_REMOTE))
        if self.remove_meta_accounts:
            files.append((ACCOUNT_CTL_LOCAL, ACCOUNT_CTL_REMOTE))
        if self.shizuku:
            if self.shizuku_public_key is None:
                raise ProvisionError("Shizuku helper key was not prepared")
            files.append((self.shizuku_public_key, SHIZUKU_KEY_REMOTE))
        for local, remote in files:
            if not local.is_file() or local.stat().st_size == 0:
                raise ProvisionError(f"missing build output: {local}")
            self.adb_run(["push", str(local), remote], timeout=30, check=True)
            mode = "0644" if remote == SHIZUKU_KEY_REMOTE else "0755"
            self.adb_run(["shell", "chmod", mode, remote], timeout=5, check=True)
        staged = f"preload={PRELOAD_REMOTE}"
        if self.audio:
            staged += f" helper={HELPER_REMOTE}"
        if self.remove_meta_accounts:
            staged += f" account_ctl={ACCOUNT_CTL_REMOTE}"
        if self.shizuku:
            staged += f" shizuku_key={SHIZUKU_KEY_REMOTE}"
        print(f"STAGED {staged}")

    def requested_actions(self) -> dict[str, object]:
        actions: dict[str, object] = {}
        for name in (
            "audio",
            "restore_audio",
            "device_owner",
            "disable_updates",
            "enable_updates",
            "debloat",
            "restore_bloat",
            "remove_meta_accounts",
            "optimize_presence",
            "restore_presence_profile",
            "restore_privacy_dns",
            "shizuku",
            "remove_shizuku",
        ):
            if getattr(self, name):
                actions[name] = True
        if self.privacy_dns:
            actions["privacy_dns"] = self.privacy_dns
        return actions

    def tool_revision(self) -> str:
        result = self.run(
            ["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"], timeout=5
        )
        if result.returncode != 0:
            return "unknown"
        revision = result.stdout.strip()
        dirty = self.run(
            ["git", "-C", str(ROOT), "status", "--porcelain"], timeout=5
        )
        if dirty.returncode == 0 and dirty.stdout.strip():
            revision += "-dirty"
        return revision

    def selected_artifact_hashes(self) -> dict[str, str]:
        candidates = [pathlib.Path(__file__).resolve(), ROOT / "tools/portal_targets.py"]
        if self.target:
            candidates.append(self.target.preload_path(ROOT))
        if self.audio:
            candidates.append(HELPER_LOCAL)
        if self.remove_meta_accounts:
            candidates.append(ACCOUNT_CTL_LOCAL)
        if self.shizuku:
            candidates.append(SHIZUKU_HELPER_LOCAL)
            if self.shizuku_apk:
                candidates.append(self.shizuku_apk)
        hashes: dict[str, str] = {}
        for path in candidates:
            if path.is_file():
                try:
                    name = str(path.relative_to(ROOT))
                except ValueError:
                    name = str(path)
                hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        return hashes

    def read_state(self) -> dict[str, object] | None:
        result = self.adb_run(["shell", "cat", STATE_REMOTE], timeout=5)
        if result.returncode != 0:
            return None
        try:
            state = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ProvisionError(f"invalid device state manifest: {exc}") from exc
        if not isinstance(state, dict) or state.get("schema") != 1:
            raise ProvisionError("unrecognized device state manifest")
        return state

    def write_state(
        self,
        state_status: str,
        first_boot: str | None = None,
        second_boot: str | None = None,
    ) -> None:
        fingerprint = self.adb_run(
            ["shell", "getprop", "ro.build.fingerprint"], timeout=5, check=True
        ).stdout.strip()
        state = {
            "schema": 1,
            "status": state_status,
            "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "serial": self.serial,
            "target": self.target.key if self.target else None,
            "fingerprint": fingerprint,
            "tool_revision": self.tool_revision(),
            "artifact_sha256": self.selected_artifact_hashes(),
            "actions": self.requested_actions(),
            "verification": {
                "first_boot": first_boot,
                "second_boot": second_boot,
            },
        }
        self.log_dir.mkdir(parents=True, exist_ok=True)
        local = self.log_dir / "portal-provision-state-v1.json"
        local.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
        local.chmod(0o600)
        remote_tmp = STATE_REMOTE + ".tmp"
        self.adb_run(["push", str(local), remote_tmp], timeout=15, check=True)
        self.adb_run(
            [
                "shell",
                f"chmod 0600 {shlex.quote(remote_tmp)} && "
                f"mv {shlex.quote(remote_tmp)} {shlex.quote(STATE_REMOTE)}",
            ],
            timeout=10,
            check=True,
        )
        print(f"STATE_MANIFEST status={state_status} path={STATE_REMOTE}")

    def collect_status(self) -> dict[str, object]:
        def shell(*arguments: str, timeout: int = 15) -> str:
            return self.adb_run(
                ["shell", *arguments], timeout=timeout
            ).stdout.strip()

        def exists(path: str) -> bool:
            return self.adb_run(
                ["shell", "test", "-f", path], timeout=5
            ).returncode == 0

        fingerprint = shell("getprop", "ro.build.fingerprint", timeout=5)
        device = shell("getprop", "ro.product.device", timeout=5)
        target = find_target(device, fingerprint)
        disabled_output = shell("pm", "list", "packages", "-d")
        disabled = {
            line.removeprefix("package:").strip()
            for line in disabled_output.splitlines()
            if line.startswith("package:")
        }
        installed_output = shell("pm", "list", "packages")
        installed = {
            line.removeprefix("package:").strip()
            for line in installed_output.splitlines()
            if line.startswith("package:")
        }
        policy = shell("dumpsys", "device_policy")
        owner = "Device Owner:" in policy and any(
            marker in policy for marker in KIOSK_OWNER_COMPONENTS
        )
        kiosk_dump = shell("dumpsys", "package", "me.jxl.kiosk_satellite")
        version_name = re.search(r"\bversionName=([^\s]+)", kiosk_dump)
        version_code = re.search(r"\bversionCode=(\d+)", kiosk_dump)
        logs = shell("logcat", "-d", "-v", "brief", timeout=20)
        audio_logs = shell("logcat", "-d", "-s", "PortalAudioPersist:*", timeout=10)
        camera = shell("dumpsys", "media.camera", timeout=20)
        webview = shell("dumpsys", "webviewupdate", timeout=15)
        accounts = self.meta_accounts()
        authenticators = self.disabled_meta_authenticators()
        ota_dump = shell("dumpsys", "facebook.aloha.otaservice", timeout=15)
        private_dns_mode = shell("settings", "get", "global", "private_dns_mode")
        private_dns_host = shell(
            "settings", "get", "global", "private_dns_specifier"
        )
        manifest: object
        try:
            manifest = self.read_state()
        except ProvisionError as exc:
            manifest = {"error": str(exc)}
        profile_keys = sorted(
            key
            for key in PRESENCE_PROFILE_KEYS
            if any(
                "settings_config.xml" in line
                and key in line
                and re.search(r"\bfalse\b", line, re.IGNORECASE)
                for line in logs.splitlines()
            )
        )
        audio_installed = exists(
            "/data/local/tmp/portal-audio-backup/installed-v1"
        )
        audio_restored = exists(
            "/data/local/tmp/portal-audio-backup/restored-v1"
        )
        ota_installed = exists("/data/local/tmp/portal-ota-backup/installed-v1")
        ota_restored = exists("/data/local/tmp/portal-ota-backup/restored-v1")
        presence_installed = exists(
            "/data/local/tmp/portal-presence-backup/installed-v1"
        )
        presence_restored = exists(
            "/data/local/tmp/portal-presence-backup/restored-v1"
        )
        shizuku_dump = shell("dumpsys", "package", SHIZUKU_PACKAGE)
        shizuku_version = re.search(r"\bversionName=([^\s]+)", shizuku_dump)
        process_list = shell("ps", "-A")
        shizuku_process = next(
            (line for line in process_list.splitlines() if "shizuku_server" in line),
            "",
        )
        return {
            "schema": 1,
            "serial": self.serial,
            "target": {
                "supported": target is not None,
                "key": target.key if target else None,
                "device": device,
                "fingerprint": fingerprint,
            },
            "runtime": {
                "boot_id": shell("cat", "/proc/sys/kernel/random/boot_id", timeout=5),
                "selinux": shell("getenforce", timeout=5),
                "wireless_adb_port": shell("getprop", "persist.adb.tcp.port", timeout=5),
                "aiservice_pid": shell(
                    "pidof", "com.facebook.portal.aiservice", timeout=5
                ),
                "cameras": 2 if "Number of camera devices: 2" in camera else None,
                "webview_ready": "(com.facebook.portal.webview," in webview,
            },
            "kiosk_satellite": {
                "installed": "me.jxl.kiosk_satellite" in installed,
                "version_name": version_name.group(1) if version_name else None,
                "version_code": int(version_code.group(1)) if version_code else None,
                "admin_active": f"    {KIOSK_COMPONENT}:" in policy,
                "device_owner": owner,
            },
            "audio": {
                "state": (
                    "installed"
                    if audio_installed
                    else "restored"
                    if audio_restored
                    else "observed_this_boot"
                    if "persistent audio watchdog started" in audio_logs
                    else "unknown"
                ),
                "installed_marker": audio_installed,
                "watchdog_observed": "persistent audio watchdog started" in audio_logs,
                "processing_zero_observed": (
                    "audio processing verified aec=0 ns=0" in audio_logs
                ),
                "restored_marker": audio_restored,
            },
            "updates": {
                "state": (
                    "blocked"
                    if ota_installed
                    or (
                        all(
                            package in disabled
                            for package in (
                                "com.facebook.aloha.otaui",
                                "com.facebook.aloha.alohaotasetup",
                            )
                        )
                        and "getBool(kFirmwareOtaUpdateEnable): false" in ota_dump
                    )
                    else "restored"
                    if ota_restored
                    else "unknown"
                ),
                "installed_marker": ota_installed,
                "packages_disabled": all(
                    package in disabled
                    for package in (
                        "com.facebook.aloha.otaui",
                        "com.facebook.aloha.alohaotasetup",
                    )
                ),
                "firmware_gate_false": (
                    "getBool(kFirmwareOtaUpdateEnable): false" in ota_dump
                ),
                "restored_marker": ota_restored,
            },
            "debloat": {
                "disabled": sorted(set(DEBLOAT_PACKAGES) & disabled),
                "complete": all(
                    package not in installed or package in disabled
                    for package in DEBLOAT_PACKAGES
                ),
            },
            "meta_accounts": {
                "remaining": len(accounts),
                "authenticators_disabled": len(
                    set(META_AUTHENTICATOR_COMPONENTS) & authenticators
                ),
            },
            "presence": {
                "state": (
                    "optimized"
                    if presence_installed or len(profile_keys) == len(PRESENCE_PROFILE_KEYS)
                    else "restored"
                    if presence_restored
                    else "unknown"
                ),
                "installed_marker": presence_installed,
                "restored_marker": presence_restored,
                "profile_keys_loaded": profile_keys,
                "analysis_frames_observed": PRESENCE_ANALYSIS_FRAME_MARKER in logs,
                "roi_frames_observed": PRESENCE_ROI_FRAME_MARKER in logs,
                "presence_event_observed": PRESENCE_LOG_MARKER in logs,
            },
            "privacy_dns": {
                "mode": None if private_dns_mode == "null" else private_dns_mode,
                "hostname": None if private_dns_host == "null" else private_dns_host,
                "backup_present": self.adb_run(
                    ["shell", "test", "-f", PRIVACY_BACKUP_REMOTE], timeout=5
                ).returncode
                == 0,
            },
            "shizuku": {
                "installed": SHIZUKU_PACKAGE in installed,
                "version_name": (
                    shizuku_version.group(1) if shizuku_version else None
                ),
                "boot_helper_installed": SHIZUKU_HELPER_PACKAGE in installed,
                "key_authorized_by_provisioner": exists(SHIZUKU_SAVED_KEY_REMOTE),
                "server_running": bool(shizuku_process),
                "server_user": (
                    shizuku_process.split()[0] if shizuku_process else None
                ),
            },
            "provision_manifest": manifest,
        }

    def print_status(self) -> dict[str, object]:
        status = self.collect_status()
        rendered = json.dumps(status, indent=2, sort_keys=True)
        print(rendered)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        (self.log_dir / "status.json").write_text(rendered + "\n")
        return status

    def privileged_requested(self) -> bool:
        return any(
            (
                self.audio,
                self.restore_audio,
                self.device_owner,
                self.disable_updates,
                self.enable_updates,
                self.remove_meta_accounts,
                self.optimize_presence,
                self.restore_presence_profile,
                self.shizuku,
                self.remove_shizuku,
            )
        )

    def dry_run_report(self, status: dict[str, object]) -> None:
        actions = self.requested_actions()
        kiosk = status.get("kiosk_satellite", {})
        audio = status.get("audio", {})
        updates = status.get("updates", {})
        debloat = status.get("debloat", {})
        accounts = status.get("meta_accounts", {})
        presence = status.get("presence", {})
        privacy = status.get("privacy_dns", {})
        shizuku = status.get("shizuku", {})
        current = {
            "audio": audio.get("state") if isinstance(audio, dict) else None,
            "device_owner": (
                kiosk.get("device_owner") if isinstance(kiosk, dict) else None
            ),
            "updates": updates.get("state") if isinstance(updates, dict) else None,
            "debloat": debloat.get("complete") if isinstance(debloat, dict) else None,
            "meta_accounts_remaining": (
                accounts.get("remaining") if isinstance(accounts, dict) else None
            ),
            "presence": presence.get("state") if isinstance(presence, dict) else None,
            "privacy_dns": privacy if isinstance(privacy, dict) else None,
            "shizuku": shizuku if isinstance(shizuku, dict) else None,
        }
        required_outputs = []
        if self.target:
            required_outputs.append(str(self.target.preload_path(ROOT)))
        if self.audio:
            required_outputs.append(str(HELPER_LOCAL))
        if self.remove_meta_accounts:
            required_outputs.append(str(ACCOUNT_CTL_LOCAL))
        if self.shizuku:
            required_outputs.append(str(SHIZUKU_HELPER_LOCAL))
        report = {
            "actions": actions,
            "current": current,
            "requires_exploit": self.privileged_requested(),
            "minimum_reboots": 3 if self.privileged_requested() else 2,
            "host_tools": {
                name: shutil.which(name) is not None
                for name in ("adb", "git", "make", "python3")
            },
            "build_outputs": {
                path: pathlib.Path(path).is_file() for path in required_outputs
            },
            "will_modify_device": False,
        }
        print("DRY_RUN " + json.dumps(report, sort_keys=True))

    def create_backup_bundle(self, destination: pathlib.Path) -> pathlib.Path:
        if destination.suffixes[-2:] != [".tar", ".gz"]:
            destination.mkdir(parents=True, exist_ok=True)
            destination = destination / (
                "portal-backup-" + dt.datetime.now().strftime("%Y%m%d-%H%M%S") + ".tar.gz"
            )
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="portal-backup-") as temporary:
            root = pathlib.Path(temporary) / "portal-backup"
            root.mkdir()
            status = self.collect_status()
            (root / "status.json").write_text(
                json.dumps(status, indent=2, sort_keys=True) + "\n"
            )
            commands = {
                "getprop.txt": ["shell", "getprop"],
                "packages.txt": ["shell", "dumpsys", "package", "packages"],
                "device-policy.txt": ["shell", "dumpsys", "device_policy"],
                "accounts.txt": ["shell", "dumpsys", "account"],
                "ota.txt": ["shell", "dumpsys", "facebook.aloha.otaservice"],
                "webview.txt": ["shell", "dumpsys", "webviewupdate"],
            }
            for filename, arguments in commands.items():
                result = self.adb_run(arguments, timeout=30)
                (root / filename).write_text(result.stdout, errors="replace")
            device_files = root / "device-files"
            device_files.mkdir()
            for remote in (
                STATE_REMOTE,
                DEBLOAT_BACKUP_REMOTE,
                META_ACCOUNT_BACKUP_REMOTE,
                PRIVACY_BACKUP_REMOTE,
                "/data/local/tmp/portal-ota-backup",
                "/data/local/tmp/portal-presence-backup",
                "/data/local/tmp/portal-device-owner-backup",
                "/data/local/tmp/portal-audio-backup",
                "/data/local/tmp/portal-audio-snapshot",
            ):
                self.adb_run(
                    ["pull", remote, str(device_files)], timeout=30
                )
            manifest = {
                "schema": 1,
                "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "serial": self.serial,
                "tool_revision": self.tool_revision(),
                "sha256": {},
            }
            hashes = manifest["sha256"]
            assert isinstance(hashes, dict)
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    hashes[str(path.relative_to(root))] = hashlib.sha256(
                        path.read_bytes()
                    ).hexdigest()
            (root / "manifest.json").write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n"
            )
            with tarfile.open(destination, "w:gz") as archive:
                archive.add(root, arcname="portal-backup")
        destination.chmod(0o600)
        print(f"BACKUP_OK path={destination}")
        return destination

    def apply_privacy_dns(self) -> None:
        if not self.privacy_dns:
            return
        hostname = self.privacy_dns.strip().lower()
        if not re.fullmatch(
            r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
            hostname,
        ):
            raise ProvisionError(f"invalid Private DNS hostname: {self.privacy_dns!r}")
        existing = self.adb_run(["shell", "cat", PRIVACY_BACKUP_REMOTE], timeout=5)
        if existing.returncode != 0:
            backup = {
                "schema": 1,
                "mode": self.adb_run(
                    ["shell", "settings", "get", "global", "private_dns_mode"],
                    timeout=5,
                    check=True,
                ).stdout.strip(),
                "hostname": self.adb_run(
                    [
                        "shell",
                        "settings",
                        "get",
                        "global",
                        "private_dns_specifier",
                    ],
                    timeout=5,
                    check=True,
                ).stdout.strip(),
            }
            with tempfile.TemporaryDirectory(prefix="portal-private-dns-") as temp:
                local = pathlib.Path(temp) / "private-dns.json"
                local.write_text(json.dumps(backup, indent=2) + "\n")
                self.adb_run(
                    ["push", str(local), PRIVACY_BACKUP_REMOTE],
                    timeout=15,
                    check=True,
                )
            self.adb_run(
                ["shell", "chmod", "0600", PRIVACY_BACKUP_REMOTE],
                timeout=5,
                check=True,
            )
        self.adb_run(
            ["shell", "settings", "put", "global", "private_dns_mode", "hostname"],
            timeout=10,
            check=True,
        )
        self.adb_run(
            [
                "shell",
                "settings",
                "put",
                "global",
                "private_dns_specifier",
                hostname,
            ],
            timeout=10,
            check=True,
        )
        self.privacy_dns = hostname
        self.verify_privacy_dns()

    def restore_private_dns(self) -> None:
        result = self.adb_run(
            ["shell", "cat", PRIVACY_BACKUP_REMOTE], timeout=5, check=True
        )
        try:
            backup = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ProvisionError(f"invalid Private DNS backup: {exc}") from exc
        if not isinstance(backup, dict) or backup.get("schema") != 1:
            raise ProvisionError("unrecognized Private DNS backup")
        for key, setting in (
            ("mode", "private_dns_mode"),
            ("hostname", "private_dns_specifier"),
        ):
            value = backup.get(key)
            if not isinstance(value, str):
                raise ProvisionError("Private DNS backup is incomplete")
            action = "delete" if value in {"", "null"} else "put"
            command = ["shell", "settings", action, "global", setting]
            if action == "put":
                command.append(value)
            self.adb_run(command, timeout=10, check=True)
        print("PRIVACY_DNS_RESTORE_OK")

    def verify_privacy_dns(self) -> None:
        mode = self.adb_run(
            ["shell", "settings", "get", "global", "private_dns_mode"],
            timeout=5,
            check=True,
        ).stdout.strip()
        hostname = self.adb_run(
            ["shell", "settings", "get", "global", "private_dns_specifier"],
            timeout=5,
            check=True,
        ).stdout.strip()
        expected_mode = "hostname"
        expected_hostname = self.privacy_dns
        if self.restore_privacy_dns:
            result = self.adb_run(
                ["shell", "cat", PRIVACY_BACKUP_REMOTE], timeout=5, check=True
            )
            try:
                backup = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                raise ProvisionError(f"invalid Private DNS backup: {exc}") from exc
            if not isinstance(backup, dict) or backup.get("schema") != 1:
                raise ProvisionError("unrecognized Private DNS backup")
            expected_mode = backup.get("mode")
            expected_hostname = backup.get("hostname")
            if not isinstance(expected_mode, str) or not isinstance(
                expected_hostname, str
            ):
                raise ProvisionError("Private DNS backup is incomplete")
            if expected_mode in {"", "null"}:
                expected_mode = "null"
            if expected_hostname in {"", "null"}:
                expected_hostname = "null"
        if mode != expected_mode or hostname != expected_hostname:
            raise ProvisionError(
                "Private DNS did not persist: "
                f"mode={mode!r}/{expected_mode!r} "
                f"hostname={hostname!r}/{expected_hostname!r}"
            )
        action = "restored" if self.restore_privacy_dns else "configured"
        print(f"PRIVACY_DNS_OK action={action} mode={mode} hostname={hostname}")

    def resolve_shizuku_apk(self) -> pathlib.Path:
        if self.shizuku_apk is not None:
            path = self.shizuku_apk.expanduser().resolve()
            if not path.is_file():
                raise ProvisionError(f"Shizuku APK does not exist: {path}")
        else:
            cache = pathlib.Path.home() / ".cache" / "portal-root"
            cache.mkdir(parents=True, exist_ok=True)
            path = cache / SHIZUKU_APK_NAME
            valid = path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == (
                SHIZUKU_APK_SHA256
            )
            if not valid:
                temporary = path.with_suffix(path.suffix + ".tmp")
                temporary.unlink(missing_ok=True)
                print(
                    f"SHIZUKU_DOWNLOAD version={SHIZUKU_VERSION} "
                    f"source={SHIZUKU_APK_URL}",
                    flush=True,
                )
                try:
                    urllib.request.urlretrieve(SHIZUKU_APK_URL, temporary)
                except OSError as exc:
                    temporary.unlink(missing_ok=True)
                    raise ProvisionError(f"Shizuku download failed: {exc}") from exc
                digest = hashlib.sha256(temporary.read_bytes()).hexdigest()
                if digest != SHIZUKU_APK_SHA256:
                    temporary.unlink(missing_ok=True)
                    raise ProvisionError(
                        "official Shizuku APK checksum mismatch: "
                        f"{digest} != {SHIZUKU_APK_SHA256}"
                    )
                temporary.replace(path)
            self.shizuku_apk = path
        try:
            with zipfile.ZipFile(path) as archive:
                if "AndroidManifest.xml" not in archive.namelist():
                    raise ProvisionError(f"invalid Shizuku APK: {path}")
                bad = archive.testzip()
                if bad:
                    raise ProvisionError(f"corrupt Shizuku APK member: {bad}")
        except zipfile.BadZipFile as exc:
            raise ProvisionError(f"invalid Shizuku APK: {path}") from exc
        return path

    def install_shizuku_payload(self) -> None:
        apk = self.resolve_shizuku_apk()
        self.install_apk_preserving_verifier(apk, "shizuku")
        self.install_apk_preserving_verifier(SHIZUKU_HELPER_LOCAL, "shizuku-helper")
        self.settle_package_state()
        self.verify_shizuku_verifier_state()
        package_dump = self.adb_run(
            ["shell", "dumpsys", "package", SHIZUKU_PACKAGE],
            timeout=20,
            check=True,
        ).stdout
        if f"versionName={SHIZUKU_VERSION}" not in package_dump and (
            self.shizuku_apk.name == SHIZUKU_APK_NAME
        ):
            raise ProvisionError(
                f"installed Shizuku version is not {SHIZUKU_VERSION}"
            )

        private_key = self.adb_run(
            [
                "exec-out",
                "run-as",
                SHIZUKU_HELPER_PACKAGE,
                "cat",
                "files/adbkey",
            ],
            timeout=10,
        ).stdout
        existing_public = self.adb_run(
            [
                "exec-out",
                "run-as",
                SHIZUKU_HELPER_PACKAGE,
                "cat",
                "files/adbkey.pub",
            ],
            timeout=10,
        ).stdout.strip()
        key_exists = (
            "-----BEGIN PRIVATE KEY-----" in private_key
            and "-----END PRIVATE KEY-----" in private_key
            and re.fullmatch(r"[A-Za-z0-9+/=]+ [^\r\n]+", existing_public)
            is not None
        )
        if not key_exists:
            with tempfile.TemporaryDirectory(prefix="portal-shizuku-key-") as temp:
                key = pathlib.Path(temp) / "adbkey"
                self.run(["adb", "keygen", str(key)], timeout=30, check=True)
                for source, remote, destination in (
                    (key, "/data/local/tmp/portal-shizuku-key.tmp", "files/adbkey"),
                    (
                        pathlib.Path(str(key) + ".pub"),
                        "/data/local/tmp/portal-shizuku-key.pub.tmp",
                        "files/adbkey.pub",
                    ),
                ):
                    self.adb_run(["push", str(source), remote], timeout=15, check=True)
                    self.adb_run(["shell", "chmod", "0644", remote], timeout=5, check=True)
                    self.adb_run(
                        ["shell", "run-as", SHIZUKU_HELPER_PACKAGE, "mkdir", "-p", "files"],
                        timeout=10,
                        check=True,
                    )
                    self.adb_run(
                        ["shell", "run-as", SHIZUKU_HELPER_PACKAGE, "cp", remote, destination],
                        timeout=10,
                        check=True,
                    )
                    self.adb_run(
                        ["shell", "run-as", SHIZUKU_HELPER_PACKAGE, "chmod", "0600", destination],
                        timeout=10,
                        check=True,
                    )
                    self.adb_run(["shell", "rm", "-f", remote], timeout=5)

        public = self.adb_run(
            [
                "exec-out",
                "run-as",
                SHIZUKU_HELPER_PACKAGE,
                "cat",
                "files/adbkey.pub",
            ],
            timeout=10,
            check=True,
        ).stdout.strip()
        if not re.fullmatch(r"[A-Za-z0-9+/=]+ [^\r\n]+", public):
            raise ProvisionError("Portal Shizuku helper returned an invalid ADB public key")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.shizuku_public_key = self.log_dir / "portal-shizuku-adbkey.pub"
        self.shizuku_public_key.write_text(public + "\n", encoding="ascii")
        self.shizuku_public_key.chmod(0o600)
        print(
            f"SHIZUKU_PAYLOAD_OK version={SHIZUKU_VERSION} "
            f"helper={SHIZUKU_HELPER_PACKAGE} key_reused={int(key_exists)}"
        )

    def install_apk_preserving_verifier(self, apk: pathlib.Path, tag: str) -> None:
        """Install an APK while restoring Meta's certificate verifier state."""
        remote = f"/data/local/tmp/portal-{tag}-install.apk"
        self.adb_run(["push", str(apk), remote], timeout=60, check=True)
        disabled = self.adb_run(
            ["shell", "pm", "list", "packages", "-d"], timeout=15, check=True
        ).stdout
        verifier_was_disabled = "package:com.facebook.appverifier" in disabled
        if self.shizuku_verifier_initially_disabled is None:
            self.shizuku_verifier_initially_disabled = verifier_was_disabled
        if verifier_was_disabled:
            command = f"pm install -r {shlex.quote(remote)}; rc=$?; " \
                f"rm -f {shlex.quote(remote)}; exit $rc"
        else:
            command = (
                "cleanup() { pm enable --user 0 com.facebook.appverifier "
                f">/dev/null; rm -f {shlex.quote(remote)}; }}; "
                "trap cleanup EXIT HUP INT TERM; "
                "pm disable-user --user 0 com.facebook.appverifier >/dev/null || exit 1; "
                f"pm install -r {shlex.quote(remote)}"
            )
        result = self.adb_run(["shell", command], timeout=120)
        if result.returncode != 0 or "Success" not in result.stdout:
            raise ProvisionError(
                f"APK installation failed for {apk}: {result.stdout.strip()}"
            )
        print(
            f"APK_INSTALL_OK package_source={apk.name} "
            f"verifier_state={'disabled' if verifier_was_disabled else 'enabled'}"
        )

    def verify_shizuku_verifier_state(self) -> None:
        if self.shizuku_verifier_initially_disabled is None:
            return
        disabled = self.adb_run(
            ["shell", "pm", "list", "packages", "-d"], timeout=15, check=True
        ).stdout
        actual = "package:com.facebook.appverifier" in disabled
        if actual != self.shizuku_verifier_initially_disabled:
            raise ProvisionError(
                "Meta package verifier state was not restored: "
                f"disabled={int(actual)} expected="
                f"{int(self.shizuku_verifier_initially_disabled)}"
            )
        print(
            "SHIZUKU_VERIFIER_OK state="
            + ("disabled" if actual else "enabled")
        )

    def uninstall_shizuku_payload(self) -> None:
        self.adb_run(["shell", "pkill", "-f", "shizuku_server"], timeout=10)
        for package in (SHIZUKU_HELPER_PACKAGE, SHIZUKU_PACKAGE):
            result = self.adb_run(["uninstall", package], timeout=60)
            if result.returncode != 0 and "Unknown package" not in result.stdout:
                raise ProvisionError(
                    f"failed to uninstall {package}: {result.stdout.strip()}"
                )
        print("SHIZUKU_REMOVE_APPS_OK")

    def verify_shizuku(self, wait_seconds: int = 120) -> None:
        self.verify_shizuku_verifier_state()
        package_state = self.adb_run(
            ["shell", "dumpsys", "package", SHIZUKU_HELPER_PACKAGE],
            timeout=15,
            check=True,
        ).stdout
        if re.search(r"\bstopped=true\b", package_state):
            self.adb_run(
                [
                    "shell",
                    "am",
                    "broadcast",
                    "-f",
                    "0x20",
                    "-a",
                    "dev.portal.shizukuhelper.START",
                    "-p",
                    SHIZUKU_HELPER_PACKAGE,
                ],
                timeout=15,
                check=True,
            )
            print("SHIZUKU_HELPER_ACTIVATED first_install=1")
        deadline = time.monotonic() + wait_seconds
        process = ""
        logs = ""
        while time.monotonic() < deadline:
            packages = self.adb_run(
                ["shell", "pm", "list", "packages"], timeout=15, check=True
            ).stdout
            process = self.adb_run(
                ["shell", "ps", "-A"], timeout=10, check=True
            ).stdout
            logs = self.adb_run(
                ["shell", "logcat", "-d", "-s", "PortalShizuku:*"],
                timeout=15,
            ).stdout
            process_line = next(
                (line for line in process.splitlines() if "shizuku_server" in line),
                "",
            )
            if (
                f"package:{SHIZUKU_PACKAGE}" in packages
                and f"package:{SHIZUKU_HELPER_PACKAGE}" in packages
                and process_line
                and process_line.split()[0] == "shell"
            ):
                print(
                    "SHIZUKU_OK privilege=shell startup=device-local "
                    f"process={process_line.strip()!r} "
                    f"helper_log={int('Shizuku started through loopback ADB' in logs)}"
                )
                return
            time.sleep(3)
        raise ProvisionError(
            "Shizuku did not start as Android shell after boot; "
            f"process_observed={int('shizuku_server' in process)} "
            f"helper_log={logs[-500:]!r}"
        )

    def verify_shizuku_removed(self) -> None:
        packages = self.adb_run(
            ["shell", "pm", "list", "packages"], timeout=15, check=True
        ).stdout
        process = self.adb_run(["shell", "ps", "-A"], timeout=10, check=True).stdout
        remaining = [
            package
            for package in (SHIZUKU_PACKAGE, SHIZUKU_HELPER_PACKAGE)
            if f"package:{package}" in packages
        ]
        if remaining or "shizuku_server" in process:
            raise ProvisionError(
                "Shizuku removal did not persist: "
                f"packages={','.join(remaining) or 'none'} "
                f"server={int('shizuku_server' in process)}"
            )
        print("SHIZUKU_REMOVED_OK packages=absent server=absent")

    def recover_actions(self) -> bool:
        state = self.read_state()
        self.adb_run(
            [
                "shell",
                "rm",
                "-f",
                PRELOAD_REMOTE,
                HELPER_REMOTE,
                ACCOUNT_CTL_REMOTE,
                SHIZUKU_KEY_REMOTE,
            ],
            timeout=10,
        )
        if state is None:
            print("RECOVER_NO_STATE staged_files=cleaned")
            self.print_status()
            return False
        if state.get("status") != "pending":
            print(f"RECOVER_STATE status={state.get('status')} action=status")
            self.print_status()
            return False
        actions = state.get("actions")
        if not isinstance(actions, dict):
            raise ProvisionError("pending state has no action map")
        allowed = set(self.requested_actions()) | {
            "audio",
            "restore_audio",
            "device_owner",
            "disable_updates",
            "enable_updates",
            "debloat",
            "restore_bloat",
            "remove_meta_accounts",
            "optimize_presence",
            "restore_presence_profile",
            "privacy_dns",
            "restore_privacy_dns",
            "shizuku",
            "remove_shizuku",
        }
        for name, value in actions.items():
            if name not in allowed:
                raise ProvisionError(f"unsupported recovery action: {name}")
            if name == "privacy_dns":
                if not isinstance(value, str):
                    raise ProvisionError("invalid privacy_dns recovery value")
                self.privacy_dns = value
            elif value is True:
                setattr(self, name, True)
            else:
                raise ProvisionError(f"invalid recovery value for {name}: {value!r}")
        print("RECOVER_RESUME actions=" + ",".join(sorted(actions)))
        return True

    def meta_accounts(self) -> list[tuple[str, str]]:
        output = self.adb_run(
            ["shell", "dumpsys", "account"], timeout=20, check=True
        ).stdout
        accounts = re.findall(
            r"Account \{name=([^,}]+), type=([^}]+)\}", output
        )
        return [
            (name, account_type)
            for name, account_type in accounts
            if account_type in META_ACCOUNT_TYPES
        ]

    def disabled_meta_authenticators(self) -> set[str]:
        output = self.adb_run(
            ["shell", "dumpsys", "package", "com.facebook.alohaservices.alohausers"],
            timeout=20,
            check=True,
        ).stdout
        match = re.search(
            r"disabledComponents:\s*(.*?)(?:\n\s*\w[^:\n]*:|\Z)",
            output,
            re.DOTALL,
        )
        return set() if match is None else set(match.group(1).split())

    def meta_accounts_preflight(self) -> bool:
        accounts = self.meta_accounts()
        disabled = self.disabled_meta_authenticators()
        already_clean = not accounts and set(META_AUTHENTICATOR_COMPONENTS) <= disabled
        existing = self.adb_run(
            ["shell", "cat", META_ACCOUNT_BACKUP_REMOTE], timeout=5
        )
        if existing.returncode != 0:
            contents = "# portal-meta-accounts-before-v1\n" + "".join(
                f"{account_type}\t{name}\n" for name, account_type in accounts
            )
            with tempfile.TemporaryDirectory(prefix="portal-meta-accounts-") as tmp:
                local = pathlib.Path(tmp) / "accounts.tsv"
                local.write_text(contents, encoding="utf-8")
                self.adb_run(
                    ["push", str(local), META_ACCOUNT_BACKUP_REMOTE],
                    timeout=15,
                    check=True,
                )
            self.adb_run(
                ["shell", "chmod", "0600", META_ACCOUNT_BACKUP_REMOTE],
                timeout=5,
                check=True,
            )
        else:
            contents = existing.stdout
        host_backup = self.log_dir / "meta-accounts-before.tsv"
        if not host_backup.exists():
            host_backup.write_text(contents, encoding="utf-8")
            host_backup.chmod(0o600)
        print(
            f"META_ACCOUNT_PREFLIGHT accounts={len(accounts)} "
            f"authenticators_disabled={len(disabled & set(META_AUTHENTICATOR_COMPONENTS))} "
            f"already_clean={int(already_clean)} backup={META_ACCOUNT_BACKUP_REMOTE}"
        )
        return already_clean

    def device_owner_preflight(self) -> bool:
        policy = self.adb_run(
            ["shell", "dumpsys", "device_policy"], timeout=15, check=True
        ).stdout
        component = KIOSK_COMPONENT
        is_owner = "Device Owner:" in policy and any(
            owner_component in policy for owner_component in KIOSK_OWNER_COMPONENTS
        )
        is_admin = (
            "Enabled Device Admins (User 0" in policy
            and f"    {component}:" in policy
        )
        if "Device Owner:" in policy and not is_owner:
            raise ProvisionError("another Device Owner is already registered")
        if not is_admin:
            raise ProvisionError(f"Kiosk Satellite admin is not active: {component}")
        print(
            f"DEVICE_OWNER_PREFLIGHT component={component} "
            f"active_admin=1 already_owner={int(is_owner)}"
        )
        return is_owner

    def kaslr_base(self, tag: str) -> int:
        offsets = (
            0x3D7E,
            0x3D54,
            0x153C,
            0x11756DC,
            0x1175724,
            0x363C6,
            0xAF90E,
            0x136E,
            0x3A72,
        )
        for sample_try in range(3):
            remote = f"/data/local/tmp/portal-perf-{tag}-{sample_try}.data"
            command = (
                "simpleperf record -g -e cpu-clock -f 4000 --duration 2 "
                f"-o {shlex.quote(remote)} -- /system/bin/dd if=/dev/zero "
                "of=/dev/null bs=4096"
            )
            self.adb_run(["shell", command], timeout=20)
            report = self.adb_run(
                ["shell", "simpleperf", "report-sample", "-i", remote],
                timeout=30,
            )
            self.adb_run(["shell", "rm", "-f", remote], timeout=5)
            values = [
                int(value, 16)
                for value in re.findall(
                    r"vaddr_in_file: (ffffff[0-9a-f]+)", report.stdout
                )
            ]
            candidates: collections.Counter[int] = collections.Counter()
            for value in values:
                for offset in offsets:
                    base = value - offset
                    if (
                        base >= 0xFFFFFF8000000000
                        and (base - 0xFFFFFF8008080000) & 0x1FFFFF == 0
                    ):
                        candidates[base] += 1
            if candidates:
                return candidates.most_common(1)[0][0]
        raise ProvisionError("simpleperf did not expose a recognized kernel PC")

    def memstart(self, tag: str) -> int:
        result = self.adb_run(["shell", "bugreportz", "-p"], timeout=180)
        match = re.search(r"OK:(\S+\.zip)", result.stdout)
        if not match:
            raise ProvisionError(f"bugreportz failed: {result.stdout[-500:]}")
        remote = match.group(1)
        with tempfile.TemporaryDirectory(prefix=f"portal-{tag}-") as temporary:
            local = pathlib.Path(temporary) / "bugreport.zip"
            self.adb_run(["pull", remote, str(local)], timeout=60, check=True)
            self.adb_run(["shell", "rm", "-f", remote], timeout=5)
            with zipfile.ZipFile(local) as archive:
                report_name = next(
                    (
                        name
                        for name in archive.namelist()
                        if pathlib.PurePosixPath(name).name.startswith("bugreport-")
                        and name.endswith(".txt")
                    ),
                    None,
                )
                if report_name is None:
                    raise ProvisionError("bugreport text is absent from archive")
                report = archive.read(report_name).decode(errors="replace")
        match = re.search(r"memory\s+: (0x[0-9a-f]+) -", report)
        if not match:
            raise ProvisionError("kernel virtual memory range is absent from bugreport")
        virtual_start = int(match.group(1), 16)
        return (
            0x80000000 - (virtual_start - 0xFFFFFFC000000000)
        ) & 0xFFFFFFFFFFFFFFFF

    def exploit(self, base: int, memstart: int, attempt: int) -> bool:
        environment = {
            "GHOSTLOCK_KASLR_BASE": hex(base),
            "GHOSTLOCK_P0_MEMSTART": hex(memstart),
            "GHOSTLOCK_TRUST_EXTERNAL_KASLR": "1",
            "GHOSTLOCK_MM_PARTIALS": "14",
            "GHOSTLOCK_PAGE_COLLISIONS": "5",
            "GHOSTLOCK_BUDDY_HOLD_PAIRS": "64",
            "GHOSTLOCK_BUDDY_HOLD_SENDS": "1024",
            "GHOSTLOCK_RECLAIM_PAIRS": "64",
            "GHOSTLOCK_RECLAIM_SENDS": "64",
            "GHOSTLOCK_SOCKET_WATCH": "1",
            "GHOSTLOCK_WATCH_CFI": "1",
            "GHOSTLOCK_SENDMMSG_PROC_UID_LOCK": "1",
            "GHOSTLOCK_PROC_UID_APP_SENTINEL": "1",
            "GHOSTLOCK_PROC_UID_RUNAS_SENTINEL": "1",
            "GHOSTLOCK_SLIDE_BREAK_OWNER_CHAIN": "1",
            "GHOSTLOCK_HOLD_AFTER_SCHED": "1",
            "GHOSTLOCK_MAIN_ROUTE": "slide-sendmmsg",
            "GHOSTLOCK_FOPS_STACK_ROUTE": "sendmmsg",
            "GHOSTLOCK_PROC_UID_WARM_MB": "256",
            "GHOSTLOCK_ADBD_ROOT_CONFIGFS": "1",
            "GHOSTLOCK_ROOT_SELF_CONFIGFS": "1",
            "GHOSTLOCK_VOLATILE_LOG": "1",
            "LD_PRELOAD": PRELOAD_REMOTE,
        }
        if self.audio:
            environment.update(
                {
                    "GHOSTLOCK_AUDIO_CTL": "1",
                    "GHOSTLOCK_AUDIO_PERSIST": "1",
                    "GHOSTLOCK_AUDIO_PERSIST_SO": HELPER_REMOTE,
                }
            )
        if self.restore_audio:
            environment.update(
                {
                    "GHOSTLOCK_RESTORE_AUDIO_PERSIST": "1",
                    "GHOSTLOCK_AUDIO_RESTORE_CTL": "1",
                }
            )
        if self.device_owner:
            environment["GHOSTLOCK_KIOSK_DEVICE_OWNER"] = "1"
        if self.disable_updates:
            environment["GHOSTLOCK_OTA_BLOCK"] = "1"
        if self.enable_updates:
            environment["GHOSTLOCK_RESTORE_OTA_BLOCK"] = "1"
        if self.optimize_presence:
            environment["GHOSTLOCK_PRESENCE_PROFILE"] = "1"
        if self.restore_presence_profile:
            environment["GHOSTLOCK_RESTORE_PRESENCE_PROFILE"] = "1"
        if self.remove_meta_accounts:
            environment.update(
                {
                    "GHOSTLOCK_REMOVE_META_ACCOUNTS": "1",
                    "GHOSTLOCK_META_ACCOUNT_CTL_JAR": ACCOUNT_CTL_REMOTE,
                }
            )
        if self.shizuku:
            environment["GHOSTLOCK_SHIZUKU_AUTHORIZE_KEY"] = "1"
        if self.remove_shizuku:
            environment["GHOSTLOCK_SHIZUKU_REMOVE_KEY"] = "1"
        self.adb_run(
            ["shell", "am", "force-stop", "--user", "0", "com.facebook.aloha.analytics"],
            timeout=10,
        )
        self.adb_run(["shell", "logcat", "-c"], timeout=5)
        shell = "env " + " ".join(
            f"{name}={shlex.quote(value)}" for name, value in environment.items()
        ) + " /system/bin/true"
        log_path = self.log_dir / f"attempt-{attempt}.log"
        success = False
        failed = False
        failure_markers = (
            "WATCH_CFI_OK=0",
            "pre-signal FOPS check miss",
            "held reclaim payload inspection complete clean=0",
            "held child CFI complete ok=0",
        )
        expected_markers: dict[str, tuple[str, bool]] = {}
        if self.audio:
            expected_markers.update(
                {
                    "audio_parameters": (
                        "PORTAL_AUDIO_NATIVE_OK mode=disabled",
                        False,
                    ),
                    "audio_persistence": ("audio persistence install", True),
                }
            )
        if self.restore_audio:
            expected_markers.update(
                {
                    "audio_defaults": (
                        "PORTAL_AUDIO_NATIVE_OK mode=firmware-defaults",
                        False,
                    ),
                    "audio_restore": ("audio persistence restore", True),
                }
            )
        if self.device_owner:
            expected_markers["device_owner"] = ("kiosk device owner install", True)
        if self.disable_updates:
            expected_markers["ota_block"] = ("OTA block file install", True)
        if self.enable_updates:
            expected_markers["ota_restore"] = ("OTA block restore", True)
        if self.optimize_presence:
            expected_markers["presence_profile"] = (
                "presence profile install",
                True,
            )
        if self.restore_presence_profile:
            expected_markers["presence_restore"] = (
                "presence profile restore",
                True,
            )
        if self.remove_meta_accounts:
            expected_markers["meta_accounts"] = ("Meta account removal", True)
        if self.shizuku:
            expected_markers["shizuku_key"] = (
                "Shizuku ADB key authorize",
                True,
            )
        if self.remove_shizuku:
            expected_markers["shizuku_key_remove"] = (
                "Shizuku ADB key remove",
                True,
            )
        observed_markers: set[str] = set()
        with log_path.open("w", encoding="utf-8") as output:
            process = subprocess.Popen(
                self.adb + ["shell", shell],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
            )
            assert process.stdout is not None
            deadline = time.monotonic() + 300
            while time.monotonic() < deadline:
                ready, _, _ = select.select([process.stdout], [], [], 1)
                if not ready:
                    if process.poll() is not None:
                        break
                    continue
                line = process.stdout.readline()
                if not line:
                    break
                sys.stdout.write(line)
                sys.stdout.flush()
                output.write(line)
                output.flush()
                for name, (marker, require_ok) in expected_markers.items():
                    if marker in line and (not require_ok or "ok=1" in line):
                        observed_markers.add(name)
                if expected_markers and observed_markers == set(expected_markers):
                    print(
                        "NATIVE_ACTIONS_OK actions="
                        + ",".join(sorted(observed_markers)),
                        flush=True,
                    )
                    success = True
                    break
                success_marker = "provision actions complete "
                if success_marker in line and "ok=1" in line:
                    success = True
                    break
                if any(marker in line for marker in failure_markers):
                    failed = True
                    break

            print(
                f"INSTALL_ATTEMPT_RESULT attempt={attempt} "
                f"success={int(success)} early_failure={int(failed)}"
            )
            try:
                self.adb_run(["reboot"], timeout=8)
            except ProvisionError:
                pass
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        return success

    def verify_watchdog(self, wait_seconds: int = 25) -> str:
        deadline = time.monotonic() + wait_seconds
        last_log = ""
        while time.monotonic() < deadline:
            result = self.adb_run(
                ["shell", "logcat", "-d", "-s", "PortalAudioPersist:*"],
                timeout=10,
            )
            last_log = result.stdout
            started = "persistent audio watchdog started" in last_log
            verified = "audio processing verified aec=0 ns=0" in last_log
            aec = re.search(r"param=3001 .*after=0 .*ok=1", last_log)
            ns = re.search(r"param=4001 .*after=0 .*ok=1", last_log)
            if started and (verified or (aec and ns)):
                pid = self.adb_run(
                    ["shell", "pidof", "com.facebook.portal.aiservice"],
                    timeout=5,
                    check=True,
                ).stdout.strip()
                boot_id = self.adb_run(
                    ["shell", "cat", "/proc/sys/kernel/random/boot_id"],
                    timeout=5,
                    check=True,
                ).stdout.strip()
                print(f"WATCHDOG_OK boot_id={boot_id} aiservice_pid={pid}")
                print(last_log.rstrip())
                return boot_id
            time.sleep(2)
        raise ProvisionError(
            "watchdog did not verify after boot; recent log follows:\n"
            + last_log[-4000:]
        )

    def verify_audio_restored(self, wait_seconds: int = 20) -> None:
        marker = "/data/local/tmp/portal-audio-backup/restored-v1"
        if self.adb_run(["shell", "test", "-f", marker], timeout=5).returncode != 0:
            raise ProvisionError("audio restore marker is absent")
        deadline = time.monotonic() + wait_seconds
        logs = ""
        pid = ""
        while time.monotonic() < deadline:
            pid = self.adb_run(
                ["shell", "pidof", "com.facebook.portal.aiservice"], timeout=5
            ).stdout.strip()
            logs = self.adb_run(
                ["shell", "logcat", "-d", "-s", "PortalAudioPersist:*"],
                timeout=10,
            ).stdout
            if pid:
                time.sleep(3)
                break
            time.sleep(2)
        logs = self.adb_run(
            ["shell", "logcat", "-d", "-s", "PortalAudioPersist:*"], timeout=10
        ).stdout
        if not pid or "persistent audio watchdog started" in logs:
            raise ProvisionError(
                "audio persistence restore did not verify: "
                f"aiservice_pid={pid!r} watchdog_started="
                f"{int('persistent audio watchdog started' in logs)}"
            )
        print(f"AUDIO_RESTORE_OK aiservice_pid={pid} watchdog=absent")

    def verify_device_owner(self) -> None:
        component = KIOSK_COMPONENT
        policy = self.adb_run(
            ["shell", "dumpsys", "device_policy"], timeout=15, check=True
        ).stdout
        owner_block = re.search(
            r"Device Owner:\s+(.*?)(?:\n\s*Profile Owner|\n\S|\Z)",
            policy,
            re.DOTALL,
        )
        if (
            owner_block is None
            or not any(
                owner_component in owner_block.group(1)
                for owner_component in KIOSK_OWNER_COMPONENTS
            )
            or "User ID: 0" not in owner_block.group(1)
        ):
            raise ProvisionError(
                "Kiosk Satellite is not the loaded Device Owner; "
                "dumpsys excerpt follows:\n" + policy[:5000]
            )
        owner_property = self.adb_run(
            ["shell", "getprop", "ro.device_owner"], timeout=5, check=True
        ).stdout.strip()
        if owner_property != "true":
            raise ProvisionError(
                f"Device Owner loaded but ro.device_owner={owner_property!r}"
            )
        print(
            f"DEVICE_OWNER_OK component={component} user=0 "
            f"ro.device_owner={owner_property}"
        )

    def disable_ota_packages(self) -> None:
        for package in (
            "com.facebook.aloha.otaui",
            "com.facebook.aloha.alohaotasetup",
        ):
            result = self.adb_run(
                ["shell", "pm", "disable-user", "--user", "0", package],
                timeout=10,
            )
            if result.returncode != 0 or "new state: disabled-user" not in result.stdout:
                already_disabled = self.adb_run(
                    ["shell", "pm", "list", "packages", "-d"],
                    timeout=10,
                    check=True,
                ).stdout
                if f"package:{package}" not in already_disabled:
                    raise ProvisionError(
                        f"failed to disable OTA package {package}: {result.stdout}"
                    )

    def enable_ota_packages(self) -> None:
        for package in (
            "com.facebook.aloha.otaui",
            "com.facebook.aloha.alohaotasetup",
        ):
            result = self.adb_run(
                ["shell", "pm", "enable", "--user", "0", package], timeout=10
            )
            if result.returncode != 0:
                raise ProvisionError(
                    f"failed to enable OTA package {package}: {result.stdout}"
                )
        self.settle_package_state()

    def verify_ota_restored(self) -> None:
        marker = "/data/local/tmp/portal-ota-backup/restored-v1"
        if self.adb_run(["shell", "test", "-f", marker], timeout=5).returncode != 0:
            raise ProvisionError("OTA restore marker is absent")
        disabled = self.adb_run(
            ["shell", "pm", "list", "packages", "-d"], timeout=10, check=True
        ).stdout
        still_disabled = [
            package
            for package in (
                "com.facebook.aloha.otaui",
                "com.facebook.aloha.alohaotasetup",
            )
            if f"package:{package}" in disabled
        ]
        if still_disabled:
            raise ProvisionError(
                "OTA packages remain disabled: " + ", ".join(still_disabled)
            )
        print("OTA_RESTORE_OK packages=enabled override=restored")

    def verify_ota_block(self, wait_seconds: int = 30) -> None:
        disabled = self.adb_run(
            ["shell", "pm", "list", "packages", "-d"],
            timeout=10,
            check=True,
        ).stdout
        required = (
            "com.facebook.aloha.otaui",
            "com.facebook.aloha.alohaotasetup",
        )
        missing = [package for package in required if f"package:{package}" not in disabled]
        if missing:
            raise ProvisionError(f"OTA packages became enabled: {', '.join(missing)}")

        deadline = time.monotonic() + wait_seconds
        last_dump = ""
        last_log = ""
        while time.monotonic() < deadline:
            result = self.adb_run(
                ["shell", "dumpsys", "facebook.aloha.otaservice"], timeout=10
            )
            last_dump = result.stdout
            last_log = self.adb_run(
                ["shell", "logcat", "-d", "-v", "threadtime"], timeout=15
            ).stdout
            override_loaded = re.search(
                r"getLatestBooleanWithOptions \[18296358819858434\], "
                r"latestBoolean: false, source: OVERRIDE",
                last_log,
            )
            if (
                "getBool(kFirmwareOtaUpdateEnable): false" in last_dump
                and override_loaded
            ):
                print(
                    "OTA_BLOCK_OK packages=disabled "
                    "firmware_ota_update_enable=false source=OVERRIDE"
                )
                return
            time.sleep(2)
        raise ProvisionError(
            "OTA daemon did not report its firmware-update gate from the "
            "local override; recent dump/log follow:\n"
            + last_dump[-3000:]
            + "\n"
            + last_log[-3000:]
        )

    def package_sets(self) -> tuple[set[str], set[str]]:
        installed_result = self.adb_run(
            ["shell", "pm", "list", "packages"], timeout=15, check=True
        )
        disabled_result = self.adb_run(
            ["shell", "pm", "list", "packages", "-d"], timeout=15, check=True
        )

        def parse(output: str) -> set[str]:
            return {
                line.removeprefix("package:").strip()
                for line in output.splitlines()
                if line.startswith("package:")
            }

        return parse(installed_result.stdout), parse(disabled_result.stdout)

    @staticmethod
    def parse_debloat_backup(contents: str) -> dict[str, str]:
        lines = contents.splitlines()
        if not lines or lines[0] != "# portal-debloat-backup-v1":
            raise ProvisionError("unrecognized Portal debloat backup format")
        states: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            fields = line.split("\t")
            if len(fields) != 2:
                raise ProvisionError(f"invalid Portal debloat backup line: {line!r}")
            package, state = fields
            if package in states or package not in DEBLOAT_PACKAGES:
                raise ProvisionError(
                    f"unexpected package in Portal debloat backup: {package!r}"
                )
            if state not in {"enabled", "disabled", "absent"}:
                raise ProvisionError(
                    f"invalid state in Portal debloat backup: {state!r}"
                )
            states[package] = state
        missing = set(DEBLOAT_PACKAGES) - states.keys()
        if missing:
            raise ProvisionError(
                "Portal debloat backup is incomplete: " + ", ".join(sorted(missing))
            )
        return states

    def read_debloat_backup(self, required: bool = True) -> dict[str, str] | None:
        result = self.adb_run(
            ["shell", "cat", DEBLOAT_BACKUP_REMOTE], timeout=5
        )
        if result.returncode != 0:
            if required:
                raise ProvisionError(
                    f"debloat backup is absent: {DEBLOAT_BACKUP_REMOTE}"
                )
            return None
        return self.parse_debloat_backup(result.stdout)

    def ensure_debloat_backup(self) -> dict[str, str]:
        existing = self.read_debloat_backup(required=False)
        if existing is not None:
            print(f"DEBLOAT_BACKUP_OK existing=1 path={DEBLOAT_BACKUP_REMOTE}")
            return existing

        installed, disabled = self.package_sets()
        states = {
            package: (
                "absent"
                if package not in installed
                else "disabled"
                if package in disabled
                else "enabled"
            )
            for package in DEBLOAT_PACKAGES
        }
        contents = "# portal-debloat-backup-v1\n" + "".join(
            f"{package}\t{states[package]}\n" for package in DEBLOAT_PACKAGES
        )
        remote_tmp = DEBLOAT_BACKUP_REMOTE + ".tmp"
        with tempfile.TemporaryDirectory(prefix="portal-debloat-") as temporary:
            local = pathlib.Path(temporary) / "backup.tsv"
            local.write_text(contents, encoding="utf-8")
            self.adb_run(["push", str(local), remote_tmp], timeout=15, check=True)
        command = (
            f"chmod 0600 {shlex.quote(remote_tmp)} && "
            f"mv {shlex.quote(remote_tmp)} {shlex.quote(DEBLOAT_BACKUP_REMOTE)}"
        )
        self.adb_run(["shell", command], timeout=10, check=True)
        saved = self.read_debloat_backup(required=True)
        if saved != states:
            raise ProvisionError("debloat backup verification failed after write")
        print(f"DEBLOAT_BACKUP_OK existing=0 path={DEBLOAT_BACKUP_REMOTE}")
        return states

    def apply_debloat(self) -> None:
        self.ensure_debloat_backup()
        installed, _ = self.package_sets()
        for package in DEBLOAT_PACKAGES:
            if package not in installed:
                print(f"DEBLOAT_SKIP package={package} reason=absent")
                continue
            result = self.adb_run(
                ["shell", "pm", "disable-user", "--user", "0", package],
                timeout=15,
            )
            if result.returncode != 0:
                raise ProvisionError(
                    f"failed to disable debloat package {package}: {result.stdout}"
                )
            print(f"DEBLOAT_DISABLE package={package}")
        self.settle_package_state()
        self.verify_debloat()

    def restore_debloat(self) -> None:
        states = self.read_debloat_backup(required=True)
        assert states is not None
        installed, _ = self.package_sets()
        for package in DEBLOAT_PACKAGES:
            state = states[package]
            if state == "absent" or package not in installed:
                print(
                    f"DEBLOAT_RESTORE_SKIP package={package} "
                    f"original_state={state}"
                )
                continue
            action = "enable" if state == "enabled" else "disable-user"
            command = ["shell", "pm", action, "--user", "0", package]
            result = self.adb_run(command, timeout=15)
            if result.returncode != 0:
                raise ProvisionError(
                    f"failed to restore package {package} to {state}: {result.stdout}"
                )
            print(f"DEBLOAT_RESTORE package={package} state={state}")
        self.settle_package_state()
        self.verify_debloat_restored()

    def settle_package_state(self) -> None:
        # PackageManager writes package-restrictions.xml asynchronously. An
        # immediate reboot can discard a state that pm already reports live.
        print(
            f"PACKAGE_STATE_SETTLE seconds={PACKAGE_STATE_SETTLE_SECONDS}",
            flush=True,
        )
        time.sleep(PACKAGE_STATE_SETTLE_SECONDS)
        self.adb_run(["shell", "sync"], timeout=15, check=True)

    def verify_retained_platform(self, wait_seconds: int = 45) -> None:
        deadline = time.monotonic() + wait_seconds
        ai_pid = ""
        camera = ""
        webview = ""
        home = ""
        while time.monotonic() < deadline:
            ai_pid = self.adb_run(
                ["shell", "pidof", "com.facebook.portal.aiservice"],
                timeout=5,
            ).stdout.strip()
            camera = self.adb_run(
                ["shell", "dumpsys", "media.camera"], timeout=15
            ).stdout
            webview = self.adb_run(
                ["shell", "dumpsys", "webviewupdate"], timeout=15
            ).stdout
            home = self.adb_run(
                [
                    "shell",
                    "cmd",
                    "package",
                    "resolve-activity",
                    "--brief",
                    "-a",
                    "android.intent.action.MAIN",
                    "-c",
                    "android.intent.category.HOME",
                ],
                timeout=10,
            ).stdout.strip()
            if (
                ai_pid
                and "Number of camera devices: 2" in camera
                and "Current WebView package (name, version): "
                "(com.facebook.portal.webview," in webview
                and "/" in home
            ):
                print(
                    f"DEBLOAT_PLATFORM_OK aiservice_pid={ai_pid} cameras=2 "
                    f"home={home.splitlines()[-1]}"
                )
                return
            time.sleep(2)
        raise ProvisionError(
            "retained Portal services did not become ready after package-state change: "
            f"aiservice_pid={ai_pid!r} cameras_2="
            f"{int('Number of camera devices: 2' in camera)} webview="
            f"{int('(com.facebook.portal.webview,' in webview)} home={home!r}"
        )

    def verify_debloat(self) -> None:
        installed, disabled = self.package_sets()
        missing = [
            package
            for package in DEBLOAT_PACKAGES
            if package in installed and package not in disabled
        ]
        if missing:
            raise ProvisionError(
                "debloat packages became enabled: " + ", ".join(missing)
            )
        self.verify_retained_platform()
        print(f"DEBLOAT_OK disabled={len(set(DEBLOAT_PACKAGES) & installed)}")

    def verify_debloat_restored(self) -> None:
        states = self.read_debloat_backup(required=True)
        assert states is not None
        installed, disabled = self.package_sets()
        mismatches = []
        for package, state in states.items():
            if state == "absent":
                continue
            actual = "disabled" if package in disabled else "enabled"
            if package not in installed or actual != state:
                mismatches.append(f"{package}={actual}, expected {state}")
        if mismatches:
            raise ProvisionError("debloat restore mismatch: " + "; ".join(mismatches))
        self.verify_retained_platform()
        print("DEBLOAT_RESTORE_OK")

    def verify_presence_runtime(
        self, require_profile: bool, wait_seconds: int = 90
    ) -> None:
        deadline = time.monotonic() + wait_seconds
        pid = ""
        camera_active = False
        camera_allowed = False
        presence_event = False
        analysis_frames = False
        roi_frames = False
        pose_metrics = False
        frame_processor_loaded = False
        loaded_keys: set[str] = set()
        threads = ""
        while time.monotonic() < deadline:
            pid = self.adb_run(
                ["shell", "pidof", "com.facebook.portal.aiservice"], timeout=5
            ).stdout.strip()
            camera = self.adb_run(
                ["shell", "dumpsys", "media.camera"], timeout=15
            ).stdout
            camera_active = (
                "Active Camera Clients:" in camera
                and "Client Package Name: com.facebook.portal.aiservice" in camera
            )
            appops = self.adb_run(
                [
                    "shell",
                    "cmd",
                    "appops",
                    "get",
                    "com.facebook.portal.aiservice",
                    "CAMERA",
                ],
                timeout=10,
            ).stdout
            camera_allowed = "CAMERA: allow" in appops
            logs = self.adb_run(
                ["shell", "logcat", "-d", "-v", "brief"], timeout=20
            ).stdout
            presence_event = PRESENCE_LOG_MARKER in logs
            analysis_frames = PRESENCE_ANALYSIS_FRAME_MARKER in logs
            roi_frames = PRESENCE_ROI_FRAME_MARKER in logs
            loaded_keys = {
                key
                for key in PRESENCE_PROFILE_KEYS
                if any(
                    "settings_config.xml" in line
                    and key in line
                    and re.search(r"\bfalse\b", line, re.IGNORECASE)
                    for line in logs.splitlines()
                )
            }
            config_ready = not require_profile or loaded_keys == set(
                PRESENCE_PROFILE_KEYS
            )
            metrics = self.adb_run(
                [
                    "shell",
                    "dumpsys",
                    "activity",
                    "service",
                    CAMERA_SERVICE_COMPONENT,
                ],
                timeout=20,
            ).stdout
            pose_section = ""
            frame_section = ""
            if "[ PoseEstimatorManagerMetrics ]" in metrics:
                pose_section = metrics.split(
                    "[ PoseEstimatorManagerMetrics ]", 1
                )[1].split("[ AlohaFrameProcessor ]", 1)[0]
            if "[ AlohaFrameProcessor ]" in metrics:
                frame_section = metrics.split(
                    "[ AlohaFrameProcessor ]", 1
                )[1].split("[ AiCameramanController ]", 1)[0]
                frame_processor_loaded = bool(frame_section)
            latency_bucket = re.compile(r"\b\d+ ms - \d+ ms:\s+\d+\b")
            pose_metrics = bool(latency_bucket.search(pose_section))
            if (
                pid
                and camera_active
                and camera_allowed
                and analysis_frames
                and roi_frames
                and pose_metrics
                and frame_processor_loaded
                and config_ready
            ):
                threads = self.adb_run(
                    ["shell", "ps", "-T", "-p", pid.split()[0]], timeout=10
                ).stdout
                disabled_workers = [
                    name
                    for name in ("BackgroundDetec", "alohaLivenessMa")
                    if name not in threads
                ]
                print(
                    "PRESENCE_RUNTIME_OK "
                    f"pid={pid.split()[0]} camera=active appop=allow "
                    "pipeline=active analysis_frames=observed "
                    "roi_frames=observed pose_metrics=populated "
                    "frame_processor=loaded "
                    f"presence_event={'observed' if presence_event else 'not_observed'} "
                    f"profile_keys={len(loaded_keys)} "
                    f"workers_absent={','.join(disabled_workers) or 'none'}"
                )
                return
            time.sleep(2)
        raise ProvisionError(
            "presence pipeline did not pass its live compatibility check: "
            f"pid={pid!r} camera_active={int(camera_active)} "
            f"camera_allowed={int(camera_allowed)} "
            f"analysis_frames={int(analysis_frames)} "
            f"roi_frames={int(roi_frames)} "
            f"pose_metrics={int(pose_metrics)} "
            f"frame_processor_loaded={int(frame_processor_loaded)} "
            f"presence_event={int(presence_event)} "
            f"profile_keys={','.join(sorted(loaded_keys)) or 'none'}"
        )

    def verify_meta_accounts_removed(self) -> None:
        accounts = self.meta_accounts()
        if accounts:
            raise ProvisionError(
                "Meta accounts remain: "
                + ", ".join(f"{account_type}/{name}" for name, account_type in accounts)
            )
        disabled = self.disabled_meta_authenticators()
        missing = set(META_AUTHENTICATOR_COMPONENTS) - disabled
        if missing:
            raise ProvisionError(
                "Meta authenticators became enabled: " + ", ".join(sorted(missing))
            )
        package_state = self.adb_run(
            ["shell", "pm", "list", "packages", "-d"], timeout=15, check=True
        ).stdout
        if "package:com.facebook.alohaservices.alohausers" in package_state:
            raise ProvisionError("alohausers package was disabled instead of its authenticators")
        self.verify_retained_platform()
        print(
            "META_ACCOUNTS_REMOVED_OK accounts=0 authenticators=disabled "
            "alohausers=enabled"
        )

    def verify_requested_state(self) -> None:
        if self.audio:
            self.verify_watchdog()
        if self.restore_audio:
            self.verify_audio_restored()
        if self.device_owner:
            self.verify_device_owner()
        if self.disable_updates:
            self.disable_ota_packages()
            self.verify_ota_block()
        if self.enable_updates:
            self.verify_ota_restored()
        if self.debloat:
            self.verify_debloat()
        if self.restore_bloat:
            self.verify_debloat_restored()
        if self.remove_meta_accounts:
            self.verify_meta_accounts_removed()
        if self.optimize_presence:
            self.verify_presence_runtime(require_profile=True)
        if self.restore_presence_profile:
            self.verify_presence_runtime(require_profile=False)
        if self.privacy_dns or self.restore_privacy_dns:
            self.verify_privacy_dns()
        if self.shizuku:
            self.verify_shizuku()
        if self.remove_shizuku:
            self.verify_shizuku_removed()

    def verify_across_two_reboots(self, first_boot: str | None = None) -> None:
        if first_boot is None:
            _, first_boot = self.reboot()
        self.verify_requested_state()
        print("VERIFY_REBOOT starting", flush=True)
        before, second_boot = self.reboot()
        if before != first_boot:
            raise ProvisionError(
                f"unexpected boot changed before verification: {first_boot} -> {before}"
            )
        self.verify_requested_state()
        self.write_state("complete", first_boot, second_boot)
        print(
            f"PROVISION_OK first_boot={first_boot} second_boot={second_boot} "
            f"logs={self.log_dir}"
        )

    def provision(self) -> None:
        self.connect(wait_seconds=30)
        if self.status_only:
            self.verify_target(require_supported=False)
            self.print_status()
            if self.backup_path:
                self.create_backup_bundle(self.backup_path)
            return
        if self.recover:
            self.verify_target(require_supported=False)
            if not self.recover_actions():
                return
            self.recover = False
        if self.dry_run:
            self.verify_target(require_supported=False)
            status = self.print_status()
            self.dry_run_report(status)
            if self.backup_path:
                self.create_backup_bundle(self.backup_path)
            return
        self.verify_target()
        if self.backup_path:
            self.create_backup_bundle(self.backup_path)
        self.write_state("pending")
        already_owner = self.device_owner_preflight() if self.device_owner else False
        already_meta_clean = (
            self.meta_accounts_preflight() if self.remove_meta_accounts else False
        )
        if self.debloat:
            self.apply_debloat()
        if self.restore_bloat:
            self.restore_debloat()
        if self.disable_updates:
            self.disable_ota_packages()
        if self.privacy_dns:
            self.apply_privacy_dns()
        if self.restore_privacy_dns:
            self.restore_private_dns()

        privileged_action = (
            self.audio
            or self.restore_audio
            or self.disable_updates
            or self.enable_updates
            or self.optimize_presence
            or self.restore_presence_profile
            or (self.device_owner and not already_owner)
            or (self.remove_meta_accounts and not already_meta_clean)
            or self.shizuku
            or self.remove_shizuku
        )
        if not privileged_action:
            self.verify_across_two_reboots()
            return

        if not self.skip_build:
            build(
                target=self.target,
                build_audio=self.audio,
                build_account=self.remove_meta_accounts,
                build_shizuku=self.shizuku,
            )
        if self.shizuku:
            self.install_shizuku_payload()
        self.stage()
        clean_boot_id: str | None = None
        for attempt in range(1, self.attempts + 1):
            if clean_boot_id is None:
                print(f"INSTALL_ATTEMPT={attempt} preparing clean boot", flush=True)
                _, boot_id = self.reboot()
            else:
                boot_id = clean_boot_id
                clean_boot_id = None
                print(
                    f"INSTALL_ATTEMPT={attempt} using post-attempt clean boot "
                    f"boot_id={boot_id}",
                    flush=True,
                )
            try:
                base = self.kaslr_base(str(attempt))
                memstart = self.memstart(str(attempt))
            except ProvisionError as exc:
                print(f"ADDRESS_DISCOVERY_RETRY attempt={attempt} error={exc}")
                continue
            print(
                f"RUNTIME_ADDRESSES attempt={attempt} boot_id={boot_id} "
                f"kaslr={base:#x} memstart={memstart:#x}",
                flush=True,
            )
            exploit_ok = self.exploit(base, memstart, attempt)
            post_attempt_boot = self.connect_after_reboot(boot_id)
            if not exploit_ok:
                clean_boot_id = post_attempt_boot
                continue
            if self.enable_updates:
                self.enable_ota_packages()
            if self.remove_shizuku:
                self.uninstall_shizuku_payload()
            self.verify_across_two_reboots(first_boot=post_attempt_boot)
            return
        raise ProvisionError(f"provisioning failed after {self.attempts} attempts")


def build(
    target: PortalTarget | None,
    build_audio: bool,
    build_account: bool,
    build_shizuku: bool,
) -> None:
    if target is None:
        raise ProvisionError("target must be selected before building")
    commands = [
        ["make", "-C", str(ROOT / "exploit"), "-j2", target.make_target]
    ]
    if build_audio:
        commands.append(["make", "-C", str(ROOT / "helper"), "native"])
    if build_account:
        commands.append(["make", "-C", str(ROOT / "exploit"), "account-ctl"])
    if build_shizuku:
        commands.append(["make", "-C", str(ROOT / "shizuku-helper"), "all"])
    for command in commands:
        result = subprocess.run(command, cwd=ROOT, check=False)
        if result.returncode != 0:
            raise ProvisionError(f"build failed: {shlex.join(command)}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Inspect, back up, provision, recover, and verify supported Meta "
            "Portal devices."
        )
    )
    parser.add_argument("--serial", default="192.168.1.72:5555")
    parser.add_argument("--attempts", type=int, default=12)
    parser.add_argument(
        "--profile",
        choices=("kiosk",),
        help="select the complete, tested Kiosk Satellite provisioning profile",
    )
    audio_group = parser.add_mutually_exclusive_group()
    audio_group.add_argument(
        "--audio",
        action="store_true",
        help=(
            "install the persistent hardware AEC/NS watchdog; this remains "
            "the default action when no provisioning action is specified"
        ),
    )
    audio_group.add_argument(
        "--restore-audio",
        action="store_true",
        help="restore AIService's original native loader and remove the audio watchdog",
    )
    parser.add_argument(
        "--device-owner",
        action="store_true",
        help=(
            "install Kiosk Satellite as Device Owner and verify it "
            "across both reboots"
        ),
    )
    parser.add_argument(
        "--skip-build", action="store_true", help="use existing build outputs"
    )
    shizuku_group = parser.add_mutually_exclusive_group()
    shizuku_group.add_argument(
        "--shizuku",
        action="store_true",
        help=(
            "install official Shizuku and a device-local boot helper that "
            "starts it with Android shell privileges through loopback ADB"
        ),
    )
    shizuku_group.add_argument(
        "--remove-shizuku",
        action="store_true",
        help="remove Shizuku, its boot helper, and the helper's authorized ADB key",
    )
    parser.add_argument(
        "--shizuku-apk",
        type=pathlib.Path,
        metavar="PATH",
        help=(
            "use a local Shizuku APK with --shizuku instead of downloading "
            f"the pinned official {SHIZUKU_VERSION} release"
        ),
    )
    update_group = parser.add_mutually_exclusive_group()
    update_group.add_argument(
        "--disable-updates",
        action="store_true",
        help=(
            "disable Meta's OTA UI/test packages and install a persistent "
            "MobileConfig override for the native OTA daemon"
        ),
    )
    update_group.add_argument(
        "--enable-updates",
        action="store_true",
        help="restore the original MobileConfig override and re-enable OTA packages",
    )
    debloat_group = parser.add_mutually_exclusive_group()
    debloat_group.add_argument(
        "--debloat",
        action="store_true",
        help=(
            "persistently disable the conservative Meta app/telemetry "
            "profile and save each package's original state"
        ),
    )
    debloat_group.add_argument(
        "--restore-bloat",
        action="store_true",
        help="restore package states saved by the first --debloat run",
    )
    parser.add_argument(
        "--remove-meta-accounts",
        action="store_true",
        help=(
            "remove the four Portal Meta accounts locally and persistently "
            "disable only their authenticator service components"
        ),
    )
    presence_group = parser.add_mutually_exclusive_group()
    presence_group.add_argument(
        "--optimize-presence",
        action="store_true",
        help=(
            "disable Smart Camera background segmentation, liveness scoring, "
            "and re-identification while requiring AIService's analysis and "
            "pose pipeline to remain live"
        ),
    )
    privacy_group = parser.add_mutually_exclusive_group()
    privacy_group.add_argument(
        "--privacy-dns",
        metavar="HOSTNAME",
        help=(
            "persistently use the specified DNS-over-TLS filtering resolver; "
            "the resolver controls the actual domain block list"
        ),
    )
    privacy_group.add_argument(
        "--restore-privacy-dns",
        action="store_true",
        help="restore the Private DNS settings saved by --privacy-dns",
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--status",
        action="store_true",
        help="print a read-only JSON health report without exploiting or rebooting",
    )
    mode_group.add_argument(
        "--dry-run",
        action="store_true",
        help="inspect the device and print the requested plan without changing it",
    )
    mode_group.add_argument(
        "--recover",
        action="store_true",
        help="clean stale staging and resume actions from a pending state manifest",
    )
    parser.add_argument(
        "--backup",
        type=pathlib.Path,
        metavar="PATH",
        help="create a timestamped diagnostic and configuration backup archive",
    )
    presence_group.add_argument(
        "--restore-presence-profile",
        action="store_true",
        help=(
            "restore the AIService settings file saved by the first "
            "--optimize-presence run"
        ),
    )
    parser.add_argument(
        "--log-dir",
        type=pathlib.Path,
        help="directory for exploit attempt logs (default: a timestamp under /tmp)",
    )
    args = parser.parse_args()
    if not 1 <= args.attempts <= 100:
        parser.error("--attempts must be between 1 and 100")
    if args.profile == "kiosk":
        conflicting = [
            flag
            for enabled, flag in (
                (args.restore_audio, "--restore-audio"),
                (args.enable_updates, "--enable-updates"),
                (args.restore_bloat, "--restore-bloat"),
                (args.restore_presence_profile, "--restore-presence-profile"),
            )
            if enabled
        ]
        if conflicting:
            parser.error(
                "--profile kiosk cannot be combined with rollback actions: "
                + ", ".join(conflicting)
            )
        args.audio = True
        args.device_owner = True
        args.disable_updates = True
        args.debloat = True
        args.remove_meta_accounts = True
        args.optimize_presence = True
    selected = any(
        (
            args.audio,
            args.restore_audio,
            args.device_owner,
            args.disable_updates,
            args.enable_updates,
            args.debloat,
            args.restore_bloat,
            args.remove_meta_accounts,
            args.optimize_presence,
            args.restore_presence_profile,
            args.privacy_dns,
            args.restore_privacy_dns,
            args.shizuku,
            args.remove_shizuku,
        )
    )
    if args.shizuku_apk and not args.shizuku:
        parser.error("--shizuku-apk requires --shizuku")
    if args.recover and (selected or args.profile):
        parser.error("--recover resumes its saved action set and cannot take action flags")
    if args.recover and args.backup:
        parser.error("--recover cannot be combined with --backup")
    if args.status and selected:
        parser.error("--status cannot be combined with provisioning actions")
    args.backup_only = (
        args.backup is not None
        and not selected
        and not any((args.status, args.dry_run, args.recover))
    )
    if not selected and not any((args.status, args.dry_run, args.recover, args.backup)):
        args.audio = True
    return args


def main() -> int:
    args = parse_args()
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    log_dir = args.log_dir or pathlib.Path(f"/tmp/portal-provision-{stamp}")
    log_dir.mkdir(parents=True, exist_ok=True)
    try:
        PortalProvisioner(
            args.serial,
            args.attempts,
            log_dir,
            audio=args.audio,
            restore_audio=args.restore_audio,
            device_owner=args.device_owner,
            disable_updates=args.disable_updates,
            enable_updates=args.enable_updates,
            debloat=args.debloat,
            restore_bloat=args.restore_bloat,
            remove_meta_accounts=args.remove_meta_accounts,
            optimize_presence=args.optimize_presence,
            restore_presence_profile=args.restore_presence_profile,
            privacy_dns=args.privacy_dns,
            restore_privacy_dns=args.restore_privacy_dns,
            shizuku=args.shizuku,
            remove_shizuku=args.remove_shizuku,
            shizuku_apk=args.shizuku_apk,
            status_only=args.status or args.backup_only,
            dry_run=args.dry_run,
            backup_path=args.backup,
            recover=args.recover,
            skip_build=args.skip_build,
        ).provision()
    except (ProvisionError, OSError, zipfile.BadZipFile) as exc:
        print(f"PROVISION_ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
