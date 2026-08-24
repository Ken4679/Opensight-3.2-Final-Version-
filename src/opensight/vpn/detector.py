import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional, Final
from opensight.core.safety import is_reparse_point_or_symlink, safe_clean_directory, PortablePaths

_STANDARD_SYSTEM_PATHS: Final[tuple[str, ...]] = (
    r"C:\Program Files\OpenVPN\bin\openvpn.exe",
    r"C:\Program Files (x86)\OpenVPN\bin\openvpn.exe",
)

class RuntimeType(str, Enum):
    BUNDLED = "bundled"
    SYSTEM = "system"
    NONE = "none"

@dataclass(frozen=True)
class RuntimeInfo:
    runtime_type: RuntimeType
    executable_path: Optional[Path]
    display_name: str
    is_valid: bool
    verification_status: str = "已就绪"

class OpenVPNDetector:
    def __init__(self, portable_paths: PortablePaths):
        self._paths = portable_paths

    def detect_bundled_runtime(self) -> RuntimeInfo:
        exe = self._paths.openvpn_dir / ("openvpn.exe" if sys.platform == "win32" else "openvpn")
        if not exe.exists() or is_reparse_point_or_symlink(exe) or not exe.is_file():
            return RuntimeInfo(RuntimeType.BUNDLED, None, "OpenSight 内置 OpenVPN", False, "未安装")
        return RuntimeInfo(RuntimeType.BUNDLED, exe, "OpenSight 内置 OpenVPN", True, "便携组件就绪")

    def detect_system_runtime(self) -> RuntimeInfo:
        for p_str in _STANDARD_SYSTEM_PATHS:
            p = Path(p_str)
            if p.is_file() and not is_reparse_point_or_symlink(p):
                return RuntimeInfo(RuntimeType.SYSTEM, p, "系统 OpenVPN", True, "标准路径就绪")
        return RuntimeInfo(RuntimeType.SYSTEM, None, "系统 OpenVPN", False, "未检测到")

    def detect_driver_ready(self) -> bool:
        if sys.platform != "win32":
            return True
        import subprocess
        try:
            value = subprocess.check_output([
                "powershell.exe", "-NoProfile", "-Command",
                "@(Get-PnpDevice -PresentOnly:$false -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'OK' -and $_.FriendlyName -match 'OpenVPN|TAP|TUN' }).Count"
            ], text=True, stderr=subprocess.DEVNULL, timeout=8).strip()
            return int(value or "0") > 0
        except Exception:
            return False

    def resolve_best_runtime(self) -> RuntimeInfo:
        b = self.detect_bundled_runtime()
        if b.is_valid:
            return b
        s = self.detect_system_runtime()
        if s.is_valid:
            return s
        return RuntimeInfo(RuntimeType.NONE, None, "未找到 OpenVPN 引擎", False, "请安装官方组件")

    def delete_bundled_runtime(self) -> bool:
        if not self._paths.openvpn_dir.exists():
            return True
        try:
            safe_clean_directory(self._paths.base_dir, self._paths.openvpn_dir, ["openvpn"])
            if self._paths.openvpn_dir.exists():
                self._paths.openvpn_dir.rmdir()
            return True
        except Exception:
            return False
