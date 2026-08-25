from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from opensight.core.constants import (
    APP_NAME,
    APP_VERSION,
    INSTALL_MANIFEST_FILE,
    OPENVPN_MSI_NAME,
    OPENVPN_MSI_SHA256,
    OPENVPN_MSI_SIZE,
    OPENVPN_VERSION,
)
from opensight.core.safety import validate_subpath, PortablePaths


@dataclass
class OpenVpnDriverMetadata:
    msi_name: str = OPENVPN_MSI_NAME
    version: str = OPENVPN_VERSION
    expected_sha256: str = OPENVPN_MSI_SHA256
    file_size_bytes: int = OPENVPN_MSI_SIZE
    msi_product_code: Optional[str] = None
    installed_by_opensight: bool = False
    install_timestamp: Optional[int] = None
    install_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "msi_name": self.msi_name,
            "version": self.version,
            "expected_sha256": self.expected_sha256,
            "file_size_bytes": self.file_size_bytes,
            "msi_product_code": self.msi_product_code,
            "installed_by_opensight": self.installed_by_opensight,
            "install_timestamp": self.install_timestamp,
            "install_path": self.install_path,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> OpenVpnDriverMetadata:
        return cls(
            msi_name=data.get("msi_name", OPENVPN_MSI_NAME),
            version=data.get("version", OPENVPN_VERSION),
            expected_sha256=data.get("expected_sha256", OPENVPN_MSI_SHA256),
            file_size_bytes=int(data.get("file_size_bytes", OPENVPN_MSI_SIZE)),
            msi_product_code=data.get("msi_product_code"),
            installed_by_opensight=bool(data.get("installed_by_opensight", False)),
            install_timestamp=data.get("install_timestamp"),
            install_path=data.get("install_path"),
        )


@dataclass
class NetworkResourcesMetadata:
    adapters: List[str] = field(default_factory=lambda: ["OpenSight-TUN"])
    pnp_devices: List[str] = field(default_factory=lambda: ["*OpenSight-TUN*"])
    firewall_rule_prefixes: List[str] = field(
        default_factory=lambda: ["OpenSight-", "OpenSight-KillSwitch-"]
    )
    route_destinations: List[str] = field(
        default_factory=lambda: ["172.19.0.0/30", "fdfe:dcba:9876::/126"]
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "adapters": list(self.adapters),
            "pnp_devices": list(self.pnp_devices),
            "firewall_rule_prefixes": list(self.firewall_rule_prefixes),
            "route_destinations": list(self.route_destinations),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> NetworkResourcesMetadata:
        return cls(
            adapters=list(data.get("adapters", ["OpenSight-TUN"])),
            pnp_devices=list(data.get("pnp_devices", ["*OpenSight-TUN*"])),
            firewall_rule_prefixes=list(
                data.get("firewall_rule_prefixes", ["OpenSight-", "OpenSight-KillSwitch-"])
            ),
            route_destinations=list(
                data.get("route_destinations", ["172.19.0.0/30", "fdfe:dcba:9876::/126"])
            ),
        )


@dataclass
class WindowsResourcesMetadata:
    registry_keys: List[str] = field(
        default_factory=lambda: [
            "HKCU\\Software\\OpenSight",
            "HKLM\\Software\\OpenSight",
        ]
    )
    services: List[str] = field(default_factory=list)
    scheduled_tasks: List[str] = field(default_factory=list)
    startup_shortcuts: List[str] = field(default_factory=lambda: ["OpenSight.lnk"])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "registry_keys": list(self.registry_keys),
            "services": list(self.services),
            "scheduled_tasks": list(self.scheduled_tasks),
            "startup_shortcuts": list(self.startup_shortcuts),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WindowsResourcesMetadata:
        return cls(
            registry_keys=list(
                data.get("registry_keys", ["HKCU\\Software\\OpenSight", "HKLM\\Software\\OpenSight"])
            ),
            services=list(data.get("services", [])),
            scheduled_tasks=list(data.get("scheduled_tasks", [])),
            startup_shortcuts=list(data.get("startup_shortcuts", ["OpenSight.lnk"])),
        )


@dataclass
class InstallManifest:
    manifest_version: str = "1.0"
    application_name: str = APP_NAME
    application_version: str = APP_VERSION
    created_at: int = field(default_factory=lambda: int(time.time()))
    owned_binaries: List[str] = field(
        default_factory=lambda: [
            "OpenSight.exe",
            "opensight-core.exe",
            "openvpn/openvpn.exe",
            f"openvpn/{OPENVPN_MSI_NAME}",
            "singbox/sing-box.exe",
        ]
    )
    owned_directories: List[str] = field(
        default_factory=lambda: [
            "data",
            "logs",
            "profiles",
            "licenses",
            "openvpn",
            "singbox",
        ]
    )
    owned_network_resources: NetworkResourcesMetadata = field(
        default_factory=NetworkResourcesMetadata
    )
    openvpn_driver_metadata: OpenVpnDriverMetadata = field(
        default_factory=OpenVpnDriverMetadata
    )
    owned_windows_resources: WindowsResourcesMetadata = field(
        default_factory=WindowsResourcesMetadata
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "manifest_version": self.manifest_version,
            "application_name": self.application_name,
            "application_version": self.application_version,
            "created_at": self.created_at,
            "owned_binaries": list(self.owned_binaries),
            "owned_directories": list(self.owned_directories),
            "owned_network_resources": self.owned_network_resources.to_dict(),
            "openvpn_driver_metadata": self.openvpn_driver_metadata.to_dict(),
            "owned_windows_resources": self.owned_windows_resources.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> InstallManifest:
        return cls(
            manifest_version=data.get("manifest_version", "1.0"),
            application_name=data.get("application_name", APP_NAME),
            application_version=data.get("application_version", APP_VERSION),
            created_at=int(data.get("created_at", int(time.time()))),
            owned_binaries=list(data.get("owned_binaries", [])),
            owned_directories=list(data.get("owned_directories", [])),
            owned_network_resources=NetworkResourcesMetadata.from_dict(
                data.get("owned_network_resources", {})
            ),
            openvpn_driver_metadata=OpenVpnDriverMetadata.from_dict(
                data.get("openvpn_driver_metadata", {})
            ),
            owned_windows_resources=WindowsResourcesMetadata.from_dict(
                data.get("owned_windows_resources", {})
            ),
        )

    def is_owned_binary(self, rel_path: str) -> bool:
        normalized = rel_path.replace("\\", "/").strip().lstrip("/")
        return any(
            normalized.lower() == b.replace("\\", "/").lower()
            for b in self.owned_binaries
        )

    def is_owned_firewall_rule(self, rule_name: str) -> bool:
        return any(
            rule_name.startswith(p)
            for p in self.owned_network_resources.firewall_rule_prefixes
        )

    def is_owned_adapter(self, adapter_name: str) -> bool:
        return any(
            adapter_name.lower() == a.lower()
            for a in self.owned_network_resources.adapters
        )

    def is_owned_route(self, destination_prefix: str) -> bool:
        norm = destination_prefix.strip().lower()
        return any(
            norm == r.strip().lower()
            for r in self.owned_network_resources.route_destinations
        )

    def save(self, base_dir: Path) -> Path:
        manifest_path = validate_subpath(base_dir, base_dir / INSTALL_MANIFEST_FILE)
        manifest_path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return manifest_path


def generate_install_manifest(base_dir: Path) -> InstallManifest:
    manifest = InstallManifest()
    manifest_path = validate_subpath(base_dir, base_dir / INSTALL_MANIFEST_FILE)
    manifest_path.write_text(
        json.dumps(manifest.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return manifest


def load_install_manifest(manifest_path: Path) -> InstallManifest:
    if not manifest_path.is_file():
        raise FileNotFoundError(f"未找到安装清单文件: {manifest_path}")
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    return InstallManifest.from_dict(raw)
