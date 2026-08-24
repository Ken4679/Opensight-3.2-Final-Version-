from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Final

from opensight.core.safety import is_reparse_point_or_symlink

_CRITICAL_PROCESSES: Final[set[str]] = {
    "svchost.exe", "services.exe", "lsass.exe", "csrss.exe",
    "explorer.exe", "dwm.exe", "smss.exe", "wininit.exe"
}

@dataclass(frozen=True)
class ValidatedApp:
    app_name: str
    executable_path: str
    canonical_name: str
    is_valid: bool
    rejection_reason: Optional[str] = None

@dataclass(frozen=True)
class InstalledApp:
    app_name: str
    executable_path: str
    publisher: str = ""
    version: str = ""
    install_location: str = ""

class AppSelector:
    @classmethod
    def validate_executable(cls, path_str: str, custom_name: Optional[str] = None) -> ValidatedApp:
        if not path_str or not path_str.strip():
            return ValidatedApp("", "", "", False, "没有找到可执行文件")
        p = Path(path_str.strip()).resolve()
        if not p.exists() or is_reparse_point_or_symlink(p) or not p.is_file():
            return ValidatedApp(p.name, str(p), p.name.lower(), False, "应用文件不存在或不安全")
        if sys.platform == "win32" and p.suffix.lower() != ".exe":
            return ValidatedApp(p.name, str(p), p.name.lower(), False, "应用主程序必须是 EXE 文件")
        if p.name.lower() in _CRITICAL_PROCESSES:
            return ValidatedApp(p.name, str(p), p.name.lower(), False, "系统关键程序不能配置分流")
        return ValidatedApp(
            custom_name.strip() if custom_name and custom_name.strip() else p.stem,
            str(p),
            p.name.lower(),
            True,
        )

    @classmethod
    def list_installed_applications(cls) -> list[InstalledApp]:
        if sys.platform != "win32":
            return []
        try:
            import winreg
        except ImportError:
            return []

        locations = (
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        )
        views = [0]
        if hasattr(winreg, "KEY_WOW64_64KEY"):
            views.extend([winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY])

        found: dict[str, InstalledApp] = {}

        for hive, subpath in locations:
            for view in views:
                try:
                    root = winreg.OpenKey(hive, subpath, 0, winreg.KEY_READ | view)
                except OSError:
                    continue
                try:
                    count = winreg.QueryInfoKey(root)[0]
                    for idx in range(count):
                        try:
                            child_name = winreg.EnumKey(root, idx)
                            with winreg.OpenKey(root, child_name, 0, winreg.KEY_READ | view) as key:
                                name = cls._read_value(key, "DisplayName")
                                if not name:
                                    continue
                                if cls._looks_like_system_component(name, cls._read_value(key, "SystemComponent")):
                                    continue
                                publisher = cls._read_value(key, "Publisher")
                                version = cls._read_value(key, "DisplayVersion")
                                install_location = cls._read_value(key, "InstallLocation")
                                display_icon = cls._read_value(key, "DisplayIcon")
                                exe = cls._pick_main_executable(
                                    name=name,
                                    display_icon=display_icon,
                                    install_location=install_location,
                                )
                                if exe:
                                    key_id = exe.lower()
                                    found.setdefault(
                                        key_id,
                                        InstalledApp(
                                            name.strip(),
                                            exe,
                                            publisher.strip(),
                                            version.strip(),
                                            install_location.strip(),
                                        ),
                                    )
                        except OSError:
                            continue
                finally:
                    try:
                        winreg.CloseKey(root)
                    except OSError:
                        pass

        return sorted(found.values(), key=lambda item: (item.app_name.lower(), item.executable_path.lower()))

    @staticmethod
    def _read_value(key, name: str) -> str:
        try:
            value, _ = __import__("winreg").QueryValueEx(key, name)
        except OSError:
            return ""
        return str(value or "")

    @staticmethod
    def _looks_like_system_component(name: str, system_component: str) -> bool:
        if str(system_component).strip() not in ("1", "True", "true"):
            return False
        return True

    @staticmethod
    def _pick_main_executable(name: str, display_icon: str, install_location: str) -> Optional[str]:
        candidates: list[Path] = []

        def add_candidate(raw: str):
            raw = raw.strip().strip('"')
            if "," in raw and Path(raw.split(",", 1)[0]).suffix.lower() == ".exe":
                raw = raw.split(",", 1)[0].strip().strip('"')
            p = Path(raw)
            if p.suffix.lower() == ".exe" and p.is_file() and not is_reparse_point_or_symlink(p):
                candidates.append(p.resolve())

        if display_icon:
            add_candidate(display_icon)

        root = Path(install_location.strip().strip('"')) if install_location else None
        if root and root.is_dir() and not is_reparse_point_or_symlink(root):
            try:
                for p in root.glob("*.exe"):
                    if p.is_file() and not is_reparse_point_or_symlink(p):
                        candidates.append(p.resolve())
                for p in root.glob("*/*.exe"):
                    if p.is_file() and not is_reparse_point_or_symlink(p):
                        candidates.append(p.resolve())
            except OSError:
                pass

        if not candidates:
            return None

        unique = {str(p).lower(): p for p in candidates}

        def score(path: Path) -> tuple[int, str]:
            stem = re.sub(r"[^a-z0-9]", "", path.stem.lower())
            app = re.sub(r"[^a-z0-9]", "", name.lower())
            score_value = 0
            if stem and (stem == app or stem in app or app in stem):
                score_value += 100
            if any(token in stem for token in ("uninstall", "update", "updater", "helper", "crash", "setup")):
                score_value -= 80
            if path.parent == root:
                score_value += 20
            return (-score_value, str(path).lower())

        return str(sorted(unique.values(), key=score)[0])