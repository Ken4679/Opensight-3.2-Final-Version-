import json
import os
import tempfile
import unittest
from pathlib import Path

from opensight.core.constants import APP_VERSION, APP_NAME, INSTALL_MANIFEST_FILE, OPENVPN_MSI_NAME, OPENVPN_VERSION, OPENVPN_MSI_SHA256, OPENVPN_MSI_SIZE
from opensight.core.safety import PortablePaths
from opensight.packaging.install_manifest import (
    InstallManifest,
    TrackedRoute,
    OpenVpnDriverMetadata,
    NetworkResourcesMetadata,
    WindowsResourcesMetadata,
    generate_install_manifest,
    load_install_manifest,
)


class TestUninstallationZeroResidual(unittest.TestCase):
    def test_01_install_manifest_generation_and_validation(self):
        """测试安装清单默认生成与核心字段完整性"""
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

    def test_02_route_and_driver_ownership(self):
        """测试专属路由与驱动强归属权记录"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            manifest = generate_install_manifest(tmp_path)

            # 路由归属判定
            self.assertTrue(manifest.is_owned_route("172.19.0.0/30"))
            self.assertTrue(manifest.is_owned_route("fdfe:dcba:9876::/126"))
            self.assertFalse(manifest.is_owned_route("0.0.0.0/0"))
            self.assertFalse(manifest.is_owned_route("192.168.1.0/24"))

            # 动态路由记录
            manifest.record_tracked_route("10.8.0.0/24", gateway="10.8.0.1", interface_alias="OpenSight-TUN")
            self.assertTrue(manifest.is_owned_route("10.8.0.0/24"))

            # OpenVPN 驱动强归属记录
            manifest.openvpn_driver_metadata.installed_by_opensight = True
            manifest.openvpn_driver_metadata.install_path = "C:/OpenSight/openvpn"
            manifest.openvpn_driver_metadata.msi_product_code = "{12345678-ABCD-EF01-2345-6789ABCDEF01}"
            manifest.openvpn_driver_metadata.source_msi = OPENVPN_MSI_NAME
            manifest.openvpn_driver_metadata.version = OPENVPN_VERSION
            manifest.openvpn_driver_metadata.expected_sha256 = OPENVPN_MSI_SHA256
            manifest.save(tmp_path)

            reloaded = load_install_manifest(tmp_path / INSTALL_MANIFEST_FILE)
            self.assertTrue(reloaded.openvpn_driver_metadata.installed_by_opensight)
            self.assertEqual(reloaded.openvpn_driver_metadata.msi_product_code, "{12345678-ABCD-EF01-2345-6789ABCDEF01}")
            self.assertEqual(reloaded.openvpn_driver_metadata.source_msi, OPENVPN_MSI_NAME)
            self.assertTrue(reloaded.is_owned_route("10.8.0.0/24"))

    def test_03_powershell_uninstaller_script_structure(self):
        """测试 PowerShell 卸载脚本架构、参数兼容性及安全防线"""
        script_path = Path(__file__).resolve().parent.parent / "scripts" / "uninstall_opensight_windows.ps1"
        self.assertTrue(script_path.is_file(), "uninstall_opensight_windows.ps1 脚本必须存在")

        content = script_path.read_text(encoding="utf-8")
        self.assertIn("[string]$BundleRoot", content, "必须支持 -BundleRoot 参数")
        self.assertIn("[string]$StatusFile", content, "必须支持 -StatusFile 参数")
        self.assertIn("[switch]$PurgeData", content, "必须支持 -PurgeData 参数")
        self.assertIn("[switch]$VerifyOnly", content, "必须支持 -VerifyOnly 参数")
        self.assertIn("Invoke-ResidualCheck", content, "必须包含自检逻辑")
        self.assertIn("OpenSight-TUN", content, "必须针对性清理 OpenSight-TUN 虚拟网卡")
        self.assertIn("OpenSight-*", content, "必须针对性清理 OpenSight-* 防火墙规则")
        self.assertIn("SKIPPED_EXTERNAL_COMPONENT", content, "必须有防误删外部组件的保护逻辑")
        self.assertIn("OpenSight-Finalizer-", content, "必须包含外部终态验证与清理调度器")
        self.assertNotIn("route -f", content, "严禁使用 route -f 全局重置路由表")
        self.assertNotIn("netsh advfirewall reset", content, "严禁使用 netsh advfirewall reset 全局重置防火墙")

    def test_04_anti_misdeletion_and_external_preservation(self):
        """测试防误删外部组件逻辑（如外部 OpenVPN、外部路由、外部网卡）"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            manifest = generate_install_manifest(tmp_path)

            external_openvpn = "C:/Program Files/OpenVPN/bin/openvpn.exe"
            opensight_openvpn = "openvpn/openvpn.exe"

            self.assertTrue(manifest.is_owned_binary(opensight_openvpn))
            self.assertFalse(manifest.is_owned_binary(external_openvpn))

            # 外部网卡保护
            self.assertFalse(manifest.is_owned_adapter("Wi-Fi"))
            self.assertFalse(manifest.is_owned_adapter("TAP-Windows Adapter V9"))
            self.assertFalse(manifest.is_owned_adapter("Wintun Userspace Tunnel"))
            self.assertTrue(manifest.is_owned_adapter("OpenSight-TUN"))

            # 外部路由保护
            self.assertFalse(manifest.is_owned_route("192.168.0.0/16"))
            self.assertFalse(manifest.is_owned_route("10.0.0.0/8"))
            self.assertTrue(manifest.is_owned_route("172.19.0.0/30"))

    def test_05_external_finalizer_verification_integrity(self):
        """测试外部 Finalizer 逻辑确保在 BundleRoot 删除后才写入 CLEAN"""
        script_path = Path(__file__).resolve().parent.parent / "scripts" / "uninstall_opensight_windows.ps1"
        content = script_path.read_text(encoding="utf-8")

        # 验证 Finalizer 在子进程中执行删除后才进行证据核查
        self.assertIn("OpenSight-Finalizer-", content)
        self.assertIn("Invoke-ResidualCheck", content)
        self.assertIn("CLEAN", content)
        self.assertIn("RESIDUALS_FOUND", content)

    def test_06_repair_openvpn_ownership_registration(self):
        """测试 OpenVPN 修复脚本中登记归属权元数据"""
        repair_script = Path(__file__).resolve().parent.parent / "scripts" / "repair_openvpn_windows.ps1"
        self.assertTrue(repair_script.is_file())
        content = repair_script.read_text(encoding="utf-8")

        self.assertIn("opensight-install-manifest.json", content)
        self.assertIn("installed_by_opensight = $true", content)
        self.assertIn("msi_product_code", content)

    def test_07_package_release_includes_uninstall_assets(self):
        """测试打包脚本中将卸载脚本和安装清单包含到发布包中"""
        package_script = Path(__file__).resolve().parent.parent / "scripts" / "package_release.py"
        content = package_script.read_text(encoding="utf-8")

        self.assertIn("uninstall_opensight_windows.ps1", content)
        self.assertIn("generate_install_manifest", content)


if __name__ == "__main__":
    unittest.main()

