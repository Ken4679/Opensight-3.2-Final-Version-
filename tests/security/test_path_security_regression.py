import os
import sys
import pytest
from pathlib import Path
from opensight.core.safety import (
    validate_subpath,
    safe_clean_directory,
    is_reparse_point_or_symlink,
    SecurityViolationError,
    PortablePaths,
)
from opensight.vpn.routing.app_selector import AppSelector, ValidatedApp


def test_subpath_validation_traversal_attempts(tmp_path: Path):
    """Ensure various path traversal syntax combinations are blocked by validate_subpath."""
    base = tmp_path / "portable_root"
    base.mkdir(parents=True, exist_ok=True)

    escape_attempts = [
        base.parent / "escape.txt",
        base / ".." / "escape.txt",
        base / "sub" / ".." / ".." / "escape.txt",
        Path("/etc/passwd"),
        Path("C:\\Windows\\System32\\calc.exe"),
    ]

    for attempt in escape_attempts:
        with pytest.raises(SecurityViolationError, match="安全越界违规"):
            validate_subpath(base, attempt)


def test_subpath_validation_valid_cases(tmp_path: Path):
    """Ensure legitimate subpaths inside base directory resolve and validate cleanly."""
    base = tmp_path / "portable_root"
    base.mkdir(parents=True, exist_ok=True)
    child_dir = base / "data" / "subfolder"
    child_dir.mkdir(parents=True, exist_ok=True)
    child_file = child_dir / "test.db"
    child_file.write_text("dummy", encoding="utf-8")

    res = validate_subpath(base, child_file)
    assert res == child_file.resolve()


def test_safe_clean_directory_prevents_cleaning_base_dir(tmp_path: Path):
    """Ensure safe_clean_directory blocks attempts to clean the root base directory itself."""
    base = tmp_path / "portable_root"
    base.mkdir(parents=True, exist_ok=True)

    with pytest.raises(SecurityViolationError, match="禁止清除便携根目录本身"):
        safe_clean_directory(base, base)


def test_safe_clean_directory_prevents_cleaning_outside_target(tmp_path: Path):
    """Ensure safe_clean_directory blocks cleaning paths outside base directory."""
    base = tmp_path / "portable_root"
    base.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside_dir"
    outside.mkdir(parents=True, exist_ok=True)

    with pytest.raises(SecurityViolationError, match="安全越界违规"):
        safe_clean_directory(base, outside)


def test_safe_clean_directory_enforces_allowed_subdirs(tmp_path: Path):
    """Ensure safe_clean_directory strictly respects allowed_subdirs whitelist."""
    base = tmp_path / "portable_root"
    base.mkdir(parents=True, exist_ok=True)
    unauthorized = base / "system_core"
    unauthorized.mkdir(parents=True, exist_ok=True)

    with pytest.raises(SecurityViolationError, match="不在允许的清理列表内"):
        safe_clean_directory(base, unauthorized, allowed_subdirs=["data", "logs", "profiles"])


def test_symlink_reparse_point_detection(tmp_path: Path):
    """Test detection of symlinks and prevent traversing through symlinks."""
    target_file = tmp_path / "real_file.txt"
    target_file.write_text("hello", encoding="utf-8")

    symlink_file = tmp_path / "symlink_file.txt"
    try:
        symlink_file.symlink_to(target_file)
        assert is_reparse_point_or_symlink(symlink_file) is True
    except (OSError, NotImplementedError):
        # Platform might not permit symlink creation without admin privs
        pass


def test_app_selector_rejects_unc_and_device_paths():
    """Ensure AppSelector rejects UNC paths and DOS device namespaces."""
    unc_cases = [
        "\\\\server\\share\\app.exe",
        "//server/share/app.exe",
        "\\\\?\\C:\\Windows\\notepad.exe",
        "\\\\.\\PhysicalDrive0\\app.exe",
    ]
    for p in unc_cases:
        res = AppSelector.validate_executable(p)
        assert not res.is_valid
        assert "不支持 UNC" in (res.rejection_reason or "")


def test_app_selector_rejects_null_bytes_and_control_chars():
    """Ensure AppSelector rejects null bytes and non-printable control characters."""
    bad_paths = [
        "C:\\Windows\\notepad.exe\x00extra",
        "C:\\Windows\\\x07beep.exe",
        "C:\\Windows\\\nmalicious.exe",
    ]
    for p in bad_paths:
        res = AppSelector.validate_executable(p)
        assert not res.is_valid
        assert "非法字符" in (res.rejection_reason or "")


def test_app_selector_rejects_windows_reserved_names():
    """Ensure AppSelector rejects Windows DOS device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)."""
    reserved_cases = [
        "CON.exe",
        "PRN.exe",
        "AUX.exe",
        "NUL.exe",
        "COM1.exe",
        "COM9.exe",
        "LPT1.exe",
        "C:\\Windows\\CON.exe",
        "C:\\Windows\\nul.exe",
    ]
    for r in reserved_cases:
        res = AppSelector.validate_executable(r)
        assert not res.is_valid
        assert "系统保留设备名称" in (res.rejection_reason or "") or not res.is_valid


def test_app_selector_rejects_critical_system_processes(tmp_path: Path):
    """Ensure critical Windows system processes (svchost, lsass, etc.) are barred from routing."""
    critical = ["svchost.exe", "services.exe", "lsass.exe", "csrss.exe", "explorer.exe", "dwm.exe"]
    for c in critical:
        fake_crit = tmp_path / c
        fake_crit.write_text("fake", encoding="utf-8")
        res = AppSelector.validate_executable(str(fake_crit))
        assert not res.is_valid
        assert "系统关键程序不能配置分流" in (res.rejection_reason or "")
