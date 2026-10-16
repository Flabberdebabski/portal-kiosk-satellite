from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from provision_portal import (  # noqa: E402
    ADB_AUTH_TIMEOUT_BACKUP_REMOTE,
    KIOSK_RELEASE_DOWNLOAD_PREFIX,
    REMOTE_WIPE_COMPONENTS,
    PortalProvisioner,
    ProvisionError,
    parse_args,
)


class PersistentWirelessAdbCliTest(unittest.TestCase):
    def test_standalone_flag_does_not_enable_the_default_audio_action(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--persistent-wireless-adb"],
        ):
            arguments = parse_args()

        self.assertTrue(arguments.persistent_wireless_adb)
        self.assertFalse(arguments.audio)

        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                persistent_wireless_adb=True,
            )
            self.assertEqual(
                provisioner.requested_actions(),
                {
                    "persistent_wireless_adb": True,
                    "disable_adb_auth_timeout": True,
                },
            )
            self.assertTrue(provisioner.privileged_requested())

    def test_cli_pairs_persistent_wireless_adb_with_non_expiring_auth(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--persistent-wireless-adb"],
        ):
            arguments = parse_args()

        self.assertTrue(arguments.disable_adb_auth_timeout)

    def test_persistent_wireless_adb_rejects_timeout_restore(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            [
                "provision_portal.py",
                "--persistent-wireless-adb",
                "--restore-adb-auth-timeout",
            ],
        ):
            with self.assertRaises(SystemExit):
                parse_args()


class AdbAuthorizationTimeoutCliTest(unittest.TestCase):
    def test_standalone_flag_needs_no_root_action(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--disable-adb-auth-timeout"],
        ):
            arguments = parse_args()

        self.assertTrue(arguments.disable_adb_auth_timeout)
        self.assertFalse(arguments.audio)
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                disable_adb_auth_timeout=True,
            )
            self.assertEqual(
                provisioner.requested_actions(),
                {"disable_adb_auth_timeout": True},
            )
            self.assertFalse(provisioner.privileged_requested())

    def test_disable_and_restore_preserve_an_absent_original_setting(self) -> None:
        current = {"value": "null"}
        saved: list[str] = []

        def adb_run(
            arguments: list[str],
            timeout: float | None = None,
            check: bool = False,
        ) -> subprocess.CompletedProcess[str]:
            del timeout, check
            if arguments[:2] == ["shell", "cat"]:
                if not saved:
                    return subprocess.CompletedProcess(arguments, 1, "")
                return subprocess.CompletedProcess(arguments, 0, saved[0])
            if arguments[:5] == [
                "shell", "settings", "get", "global", "adb_allowed_connection_time"
            ]:
                return subprocess.CompletedProcess(
                    arguments, 0, current["value"] + "\n"
                )
            if arguments[1:4] == ["settings", "put", "global"]:
                current["value"] = arguments[-1]
            elif arguments[1:4] == ["settings", "delete", "global"]:
                current["value"] = "null"
            return subprocess.CompletedProcess(arguments, 0, "")

        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                disable_adb_auth_timeout=True,
            )
            with (
                mock.patch.object(provisioner, "adb_run", side_effect=adb_run),
                mock.patch.object(
                    provisioner,
                    "push_text_atomic",
                    side_effect=lambda contents, remote: (
                        self.assertEqual(remote, ADB_AUTH_TIMEOUT_BACKUP_REMOTE),
                        saved.append(contents),
                    ),
                ),
            ):
                provisioner.disable_adb_authorization_timeout()
                self.assertEqual(current["value"], "0")
                provisioner.disable_adb_auth_timeout = False
                provisioner.restore_adb_auth_timeout = True
                provisioner.restore_adb_authorization_timeout()

        self.assertEqual(current["value"], "null")

    def test_kiosk_profile_includes_non_expiring_adb_authorization(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--profile", "kiosk"],
        ):
            arguments = parse_args()

        self.assertTrue(arguments.disable_adb_auth_timeout)


class ShizukuCliTest(unittest.TestCase):
    def test_download_failure_is_reported_before_any_reboot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                shizuku=True,
            )
            with (
                mock.patch.object(provisioner, "connect"),
                mock.patch.object(provisioner, "verify_target"),
                mock.patch.object(
                    provisioner,
                    "resolve_shizuku_apk",
                    side_effect=ProvisionError(
                        "Shizuku APK download failed on the host computer"
                    ),
                ),
                mock.patch.object(provisioner, "reboot") as reboot,
            ):
                with self.assertRaisesRegex(ProvisionError, "host computer"):
                    provisioner.provision()

            reboot.assert_not_called()


class RemoteWipeCliTest(unittest.TestCase):
    def test_combined_component_actions_are_a_single_bootstrap_phase(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                debloat=True,
                block_remote_wipe=True,
            )

            self.assertTrue(provisioner.only_component_actions_requested())

            provisioner.audio = True
            self.assertFalse(provisioner.only_component_actions_requested())

    def test_completed_component_profiles_are_not_reapplied(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                debloat=True,
                block_remote_wipe=True,
            )
            provisioner.debloat_already_configured = True
            provisioner.remote_wipe_already_configured = True

            self.assertFalse(provisioner.needs_component_ctl())

            provisioner.remote_wipe_already_configured = False
            self.assertTrue(provisioner.needs_component_ctl())

            provisioner.remote_wipe_already_configured = True
            provisioner.debloat_already_configured = False
            self.assertTrue(provisioner.needs_component_ctl())

    def test_standalone_block_targets_only_the_two_receivers(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--block-remote-wipe"],
        ):
            arguments = parse_args()

        self.assertTrue(arguments.block_remote_wipe)
        self.assertFalse(arguments.audio)

        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                block_remote_wipe=True,
            )
            captured: list[str] = []
            states = {component: "default" for component in REMOTE_WIPE_COMPONENTS}
            with (
                mock.patch.object(
                    provisioner,
                    "ensure_remote_wipe_backup",
                    return_value=states,
                ),
                mock.patch.object(
                    provisioner,
                    "push_text_atomic",
                    side_effect=lambda contents, remote: captured.append(contents),
                ),
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess([], 0, ""),
                ),
            ):
                provisioner.prepare_component_actions()

        self.assertEqual(
            provisioner.requested_actions(), {"block_remote_wipe": True}
        )
        self.assertTrue(provisioner.privileged_requested())
        self.assertEqual(len(captured), 1)
        action_lines = captured[0].splitlines()[1:]
        self.assertEqual(
            action_lines,
            [f"disable\t{component}" for component in REMOTE_WIPE_COMPONENTS],
        )

    def test_kiosk_profile_includes_remote_wipe_block(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--profile", "kiosk"],
        ):
            arguments = parse_args()

        self.assertTrue(arguments.block_remote_wipe)

    def test_restore_preserves_each_saved_component_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                restore_remote_wipe=True,
            )
            states = {
                REMOTE_WIPE_COMPONENTS[0]: "default",
                REMOTE_WIPE_COMPONENTS[1]: "enabled",
            }
            captured: list[str] = []
            with (
                mock.patch.object(
                    provisioner,
                    "read_remote_wipe_backup",
                    return_value=states,
                ),
                mock.patch.object(
                    provisioner,
                    "push_text_atomic",
                    side_effect=lambda contents, remote: captured.append(contents),
                ),
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess([], 0, ""),
                ),
            ):
                provisioner.prepare_component_actions()

        self.assertEqual(
            captured[0].splitlines()[1:],
            [
                f"default\t{REMOTE_WIPE_COMPONENTS[0]}",
                f"enable\t{REMOTE_WIPE_COMPONENTS[1]}",
            ],
        )


class KioskPermissionsCliTest(unittest.TestCase):
    def test_standalone_permission_action_does_not_select_root_or_audio(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--kiosk-permissions"],
        ):
            arguments = parse_args()

        self.assertTrue(arguments.kiosk_permissions)
        self.assertFalse(arguments.audio)

        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                kiosk_permissions=True,
            )
            self.assertEqual(
                provisioner.requested_actions(),
                {"kiosk_permissions": True},
            )
            self.assertFalse(provisioner.privileged_requested())

    def test_kiosk_profile_includes_permissions(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--profile", "kiosk"],
        ):
            arguments = parse_args()

        self.assertTrue(arguments.kiosk_permissions)
        self.assertTrue(arguments.install_kiosk_satellite)

    def test_permission_action_never_changes_accessibility_services(self) -> None:
        calls: list[list[str]] = []

        def adb_run(
            arguments: list[str],
            timeout: float | None = None,
            check: bool = False,
        ) -> subprocess.CompletedProcess[str]:
            del timeout, check
            calls.append(arguments)
            output = "Events injected: 1\n" if "monkey" in arguments else ""
            return subprocess.CompletedProcess(arguments, 0, output)

        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                kiosk_permissions=True,
            )
            with (
                mock.patch.object(provisioner, "adb_run", side_effect=adb_run),
                mock.patch.object(provisioner, "verify_kiosk_permissions"),
            ):
                provisioner.apply_kiosk_permissions()

        rendered = [" ".join(command) for command in calls]
        self.assertEqual(
            sum(command.startswith("shell pm grant ") for command in rendered),
            7,
        )
        self.assertEqual(
            sum(command.startswith("shell appops set ") for command in rendered),
            3,
        )
        self.assertTrue(
            any("dumpsys deviceidle whitelist +me.jxl.kiosk_satellite" in command
                for command in rendered)
        )
        self.assertFalse(
            any("enabled_accessibility_services" in command for command in rendered)
        )


class KioskSatelliteInstallCliTest(unittest.TestCase):
    def test_standalone_install_does_not_select_root_or_audio(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--install-kiosk-satellite"],
        ):
            arguments = parse_args()

        self.assertTrue(arguments.install_kiosk_satellite)
        self.assertFalse(arguments.audio)

        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                install_kiosk_satellite=True,
            )
            self.assertEqual(
                provisioner.requested_actions(),
                {"install_kiosk_satellite": True},
            )
            self.assertFalse(provisioner.privileged_requested())

    def test_release_selection_prefers_first_supported_device_abi(self) -> None:
        tag = "2026.10.23"
        arm64_name = f"kiosk-satellite-{tag}.arm64-v8a.apk"
        universal_name = f"kiosk-satellite-{tag}.apk"
        release = {
            "tag_name": tag,
            "assets": [
                {
                    "name": universal_name,
                    "browser_download_url": (
                        f"{KIOSK_RELEASE_DOWNLOAD_PREFIX}{tag}/{universal_name}"
                    ),
                    "digest": "sha256:" + "a" * 64,
                    "size": 200,
                },
                {
                    "name": arm64_name,
                    "browser_download_url": (
                        f"{KIOSK_RELEASE_DOWNLOAD_PREFIX}{tag}/{arm64_name}"
                    ),
                    "digest": "sha256:" + "b" * 64,
                    "size": 100,
                },
            ],
        }

        selected = PortalProvisioner.select_kiosk_release_asset(
            release, ("arm64-v8a", "armeabi-v7a")
        )

        self.assertEqual(
            selected,
            (tag, arm64_name, 100, "b" * 64, "arm64-v8a"),
        )

    def test_release_selection_rejects_asset_without_github_digest(self) -> None:
        tag = "2026.10.23"
        name = f"kiosk-satellite-{tag}.arm64-v8a.apk"
        release = {
            "tag_name": tag,
            "assets": [
                {
                    "name": name,
                    "browser_download_url": (
                        f"{KIOSK_RELEASE_DOWNLOAD_PREFIX}{tag}/{name}"
                    ),
                    "digest": None,
                    "size": 100,
                }
            ],
        }

        with self.assertRaisesRegex(ProvisionError, "SHA-256"):
            PortalProvisioner.select_kiosk_release_asset(
                release, ("arm64-v8a",)
            )

    def test_existing_install_is_preserved_without_release_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                install_kiosk_satellite=True,
            )
            with (
                mock.patch.object(
                    provisioner,
                    "kiosk_satellite_version",
                    return_value="2026.10.22",
                ),
                mock.patch.object(
                    provisioner, "resolve_kiosk_satellite_apk"
                ) as resolve,
            ):
                provisioner.ensure_kiosk_satellite()

        resolve.assert_not_called()

    def test_missing_install_is_installed_and_launched(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            apk = pathlib.Path(temporary) / "kiosk-satellite.apk"
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                install_kiosk_satellite=True,
            )
            with (
                mock.patch.object(
                    provisioner,
                    "kiosk_satellite_version",
                    side_effect=(None, "2026.10.23"),
                ),
                mock.patch.object(
                    provisioner,
                    "resolve_kiosk_satellite_apk",
                    return_value=(apk, "2026.10.23", "arm64-v8a"),
                ),
                mock.patch.object(
                    provisioner, "install_apk_preserving_verifier"
                ) as install,
                mock.patch.object(provisioner, "settle_package_state"),
                mock.patch.object(provisioner, "verify_package_verifier_state"),
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess(
                        [], 0, "Events injected: 1\n"
                    ),
                ) as adb_run,
            ):
                provisioner.ensure_kiosk_satellite()

        install.assert_called_once_with(apk, "kiosk-satellite")
        self.assertIn("monkey", adb_run.call_args.args[0])

    def test_each_apk_install_records_its_own_verifier_baseline(self) -> None:
        verifier_states = iter(
            ("", "package:com.facebook.appverifier\n")
        )

        def adb_run(
            arguments: list[str],
            timeout: float | None = None,
            check: bool = False,
        ) -> subprocess.CompletedProcess[str]:
            del timeout, check
            if arguments[:5] == ["shell", "pm", "list", "packages", "-d"]:
                return subprocess.CompletedProcess(
                    arguments, 0, next(verifier_states)
                )
            if arguments[0] == "push":
                return subprocess.CompletedProcess(arguments, 0, "1 file pushed\n")
            return subprocess.CompletedProcess(arguments, 0, "Success\n")

        with tempfile.TemporaryDirectory() as temporary:
            apk = pathlib.Path(temporary) / "payload.apk"
            apk.touch()
            provisioner = PortalProvisioner(
                "192.0.2.1:5555", 1, pathlib.Path(temporary)
            )
            with mock.patch.object(provisioner, "adb_run", side_effect=adb_run):
                provisioner.install_apk_preserving_verifier(apk, "first")
                self.assertFalse(
                    provisioner.package_verifier_before_install_disabled
                )
                provisioner.install_apk_preserving_verifier(apk, "second")
                self.assertTrue(
                    provisioner.package_verifier_before_install_disabled
                )


if __name__ == "__main__":
    unittest.main()
