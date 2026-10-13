from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from provision_portal import PortalProvisioner, parse_args  # noqa: E402


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
                {"persistent_wireless_adb": True},
            )
            self.assertTrue(provisioner.privileged_requested())


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


if __name__ == "__main__":
    unittest.main()
