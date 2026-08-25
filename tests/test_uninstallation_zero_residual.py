import json
import tempfile
import unittest
from pathlib import Path

from opensight.core.constants import APP_VERSION, APP_NAME, INSTALL_MANIFEST_FILE
from opensight.core.safety import PortablePaths
from opensight.packaging.install_manifest import (
    InstallManifest,
    generate_install_manifest,
    load_install_manifest,
)


class TestUninstallationZeroResidual(unittest.TestCase):
    def test_install_manifest_generation_and_validation(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            manifest = generate_install_manifest(tmp_path)
            self.assertTrue((tmp_path / INSTALL_MANIFEST_FILE).is_file())
            self.assertEqual(manifest.application_name, APP_NAME)

            loaded = load_install_manifest(tmp_path / INSTALL_MANIFEST_FILE)
            self.assertEqual(loaded.application_name, APP_NAME)
            self.assertEqual(loaded.application_version, APP_VERSION)
            self.assertIn("OpenSight.exe", loaded.owned_binaries)
            self.assertIn("openvpn/openvpn.exe", loaded.owned_binaries)
            self.assertIn("singbox/sing-box.exe", loaded.owned_binaries)
            self.assertIn("OpenSight-TUN", loaded.owned_network_resources.adapters)
            self.assertTrue(loaded.is_owned_firewall_rule("OpenSight-KillSwitch-abc123-LAN"))
            self.assertFalse(loaded.is_owned_firewall_rule("Core-Windows-Defender-Rule"))
            self.assertTrue(loaded.is_owned_adapter("OpenSight-TUN"))
            self.assertFalse(loaded.is_owned_adapter("Ethernet"))
            self.assertFalse(loaded.is_owned_adapter("Wi-Fi"))

    def test_powershell_uninstaller_script_structure(self):
        script_path = Path(__file__).resolve().parent.parent / "scripts" / "uninstall_opensight_windows.ps1"
        self.assertTrue(script_path.is_file(), "uninstall_opensight_windows.ps1 脚本必须存在")

        content = script_path.read_text(encoding="utf-8")
        self.assertIn("[switch]$PurgeData", content, "必须支持 -PurgeData 参数")
        self.assertIn("[switch]$VerifyOnly", content, "必须支持 -VerifyOnly 参数")
        self.assertIn("Invoke-ResidualCheck", content, "必须包含自检逻辑")
        self.assertIn("OpenSight-TUN", content, "必须针对性清理 OpenSight-TUN 虚拟网卡")
        self.assertIn("OpenSight-*", content, "必须针对性清理 OpenSight-* 防火墙规则")
        self.assertIn("SKIPPED_EXTERNAL_COMPONENT", content, "必须有防误删外部组件的保护逻辑")

    def test_anti_misdeletion_logic(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            manifest = generate_install_manifest(tmp_path)

            external_openvpn = "C:/Program Files/OpenVPN/bin/openvpn.exe"
            opensight_openvpn = "openvpn/openvpn.exe"

            self.assertTrue(manifest.is_owned_binary(opensight_openvpn))
            self.assertFalse(manifest.is_owned_binary(external_openvpn))


if __name__ == "__main__":
    unittest.main()
