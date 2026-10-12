#!/usr/bin/env python3

import pathlib
import sys
import unittest


REPOSITORY = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY / "tools"))

from portal_targets import TARGETS, find_target  # noqa: E402


class PortalTargetSelectionTest(unittest.TestCase):
    def test_every_supported_build_selects_only_its_exact_target(self) -> None:
        self.assertEqual(len(TARGETS), 4)
        for target in TARGETS:
            selected = find_target(
                target.device,
                target.fingerprint,
                target.product_models[0] if target.product_models else None,
            )
            self.assertIs(selected, target)
            self.assertIsNone(
                find_target(
                    target.device,
                    target.fingerprint + ".different",
                    target.product_models[0] if target.product_models else None,
                )
            )

    def test_portal_go_and_first_generation_portal_plus_are_unchanged(self) -> None:
        targets = {target.device: target for target in TARGETS}
        terry = targets["terry"]
        cipher = targets["cipher"]
        omni = targets["omni"]
        aloha = targets["aloha"]
        self.assertEqual(terry.key, "portal-go-terry-5051355900018050")
        self.assertEqual(terry.stack_route, "sendmmsg")
        self.assertFalse(terry.bundled_simpleperf)
        self.assertFalse(terry.shell_root_package_actions)
        self.assertEqual(terry.reclaim_pairs, 64)
        self.assertEqual(terry.reclaim_sends, 64)
        self.assertEqual(terry.exploit_timeout_seconds, 300)
        self.assertFalse(terry.recover_watch_result_after_disconnect)
        self.assertEqual(
            terry.uid1000_host_package,
            "com.facebook.alohasdk.platformbatterystate",
        )

        self.assertEqual(aloha.key, "portal-plus-aloha-1041515800015050")
        self.assertEqual(aloha.stack_route, "ptrace")
        self.assertTrue(aloha.bundled_simpleperf)
        self.assertTrue(aloha.shell_root_package_actions)
        self.assertEqual(aloha.reclaim_pairs, 256)
        self.assertEqual(aloha.reclaim_sends, 256)
        self.assertEqual(aloha.exploit_timeout_seconds, 300)
        self.assertFalse(aloha.recover_watch_result_after_disconnect)
        self.assertEqual(
            aloha.uid1000_host_package,
            "com.facebook.alohasdk.virtualcameramanager",
        )
        self.assertEqual(aloha.uid1000_host_label, "virtualcameramanager")
        self.assertTrue(aloha.buffer_root_staged_sources)
        self.assertEqual(
            aloha.uid1000_data_directory, "/data/misc/adb/portal-uid1000"
        )
        self.assertEqual(aloha.uid1000_helper_make_target, "aloha")
        self.assertEqual(
            aloha.uid1000_helper_artifact, "portal-camera-led-watch-aloha"
        )
        self.assertEqual(
            aloha.uid1000_hook_artifact, "portal-uid1000-hook-aloha.bin"
        )
        self.assertTrue(aloha.uid1000_embedded_helper)
        self.assertTrue(aloha.uid1000_installer_credentials)

        self.assertEqual(cipher.key, "portal-plus-cipher-4051355900018050")
        self.assertEqual(cipher.stack_route, "sendmmsg")
        self.assertFalse(cipher.shell_root_package_actions)
        self.assertEqual(cipher.reclaim_pairs, 256)
        self.assertEqual(cipher.reclaim_sends, 256)
        self.assertEqual(cipher.exploit_timeout_seconds, 120)
        self.assertTrue(cipher.recover_watch_result_after_disconnect)
        self.assertEqual(
            cipher.uid1000_host_package,
            "com.facebook.alohasdk.platformsecurestate",
        )

        self.assertEqual(omni.key, "portal-10-omni-3051355900018050")
        self.assertEqual(omni.stack_route, "sendmmsg")
        self.assertFalse(omni.shell_root_package_actions)
        self.assertEqual(omni.reclaim_pairs, 256)
        self.assertEqual(omni.reclaim_sends, 256)
        self.assertEqual(omni.exploit_timeout_seconds, 120)
        self.assertTrue(omni.recover_watch_result_after_disconnect)
        self.assertEqual(omni.address_discovery_settle_seconds, 15)
        self.assertTrue(omni.address_discovery_reboot_on_failure)
        self.assertEqual(
            omni.wireless_adb_file_property,
            "service.adb.tcp.port",
        )
        self.assertTrue(omni.wireless_adb_uid1000_boot)
        self.assertTrue(omni.audio_java_fallback)
        self.assertTrue(omni.audio_deferred_ctl)
        self.assertEqual(
            omni.uid1000_host_package,
            "com.facebook.alohasdk.platformsecurestate",
        )

    def test_portal_plus_model_guard_is_enforced(self) -> None:
        for target in TARGETS:
            if target.product_models:
                self.assertIsNone(
                    find_target(target.device, target.fingerprint, "Portal Go")
                )

    def test_cipher_cleanup_guard_does_not_change_other_targets(self) -> None:
        cipher_header = (
            REPOSITORY
            / "exploit/targets/portal-cipher-4051355900018050/target.h"
        ).read_text()
        omni_header = (
            REPOSITORY
            / "exploit/targets/portal-omni-3051355900018050/target.h"
        ).read_text()
        terry_header = (
            REPOSITORY
            / "exploit/targets/portal-terry-5051355900018050/target.h"
        ).read_text()
        aloha_header = (
            REPOSITORY
            / "exploit/targets/portal-aloha-1041515800015050/target.h"
        ).read_text()
        self.assertIn("#define CONFIGFS_ZERO_GUARD_SIZE 32", cipher_header)
        self.assertIn("#define CONFIGFS_BINARY_CLEANUP 1", cipher_header)
        self.assertNotIn("#define CONFIGFS_ZERO_GUARD_SIZE", terry_header)
        self.assertNotIn("#define CONFIGFS_BINARY_CLEANUP", terry_header)
        self.assertIn("#define CONFIGFS_ZERO_GUARD_SIZE 32", aloha_header)
        self.assertNotIn("#define CONFIGFS_BINARY_CLEANUP", aloha_header)
        self.assertIn("PlatformSecureStateService.apk@classes.dex", cipher_header)
        self.assertIn("PlatformSecureStateService.apk@classes.dex", omni_header)
        self.assertIn("#define CONFIGFS_ZERO_GUARD_SIZE 32", omni_header)
        self.assertIn("#define CONFIGFS_BINARY_CLEANUP 1", omni_header)
        self.assertNotIn("PlatformSecureStateService", terry_header)
        self.assertNotIn("PlatformSecureStateService", aloha_header)
        self.assertIn("#define UID1000_ART_APPEND_SEGMENT 1", aloha_header)
        self.assertIn("VirtualCameraManagerService.apk@classes.dex", aloha_header)
        self.assertIn("#define UID1000_ART_ONCREATE_OFFSET 0x00004780", aloha_header)
        self.assertIn("#define UID1000_ART_HOOK_OFFSET 0x0000e000", aloha_header)
        self.assertIn("#define UID1000_ART_EXPECTED_MAGIC \"oat\\n138\\0\"", aloha_header)
        self.assertIn("#define CONFIGFS_BUFFER_HELPER_KEYS 1", aloha_header)
        self.assertIn("#define CONFIGFS_BUFFER_UID1000_SOURCES 1", aloha_header)
        self.assertIn("#define UID1000_EMBEDDED_HELPER 1", aloha_header)
        self.assertIn(
            '#define UID1000_DATA_DIRECTORY "/data/misc/adb/portal-uid1000"',
            aloha_header,
        )


if __name__ == "__main__":
    unittest.main()
