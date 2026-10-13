from __future__ import annotations

import pathlib
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


if __name__ == "__main__":
    unittest.main()
