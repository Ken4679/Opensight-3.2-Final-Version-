import os
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import Final, Iterable, Optional
from opensight.core.constants import (
    DEFAULT_DATA_DIR,
    DEFAULT_LOGS_DIR,
    DEFAULT_PROFILES_DIR,
    DEFAULT_LICENSES_DIR,
    DEFAULT_OPENVPN_DIR,
    DEFAULT_SINGBOX_DIR,
)

FILE_ATTRIBUTE_REPARSE_POINT: Final[int] = 0x0400

class SecurityViolationError(Exception):
    pass

@dataclass(frozen=True)
class PortablePaths:
    base_dir: Path
    data_dir: Path
    logs_dir: Path
    profiles_dir: Path
    licenses_dir: Optional[Path] = None
    openvpn_dir: Optional[Path] = None
    singbox_dir: Optional[Path] = None
    is_isolated: bool = False

def is_reparse_point_or_symlink(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        if sys.platform == "win32" and path.exists():
            st = os.stat(path, follow_symlinks=False)
            attrs = getattr(st, "st_file_attributes", 0)
            if attrs & FILE_ATTRIBUTE_REPARSE_POINT:
                return True
    except (OSError, ValueError):
        return False
    return False

def get_base_directory() -> Path:
    env_override = os.environ.get("OPENSIGHT_PORTABLE_ROOT")
    if env_override:
        p = Path(env_override).resolve()
        if p.exists() and p.is_dir():
            return p
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    curr = Path(__file__).resolve().parent
    for _ in range(6):
        if (curr / "pyproject.toml").is_file() or (curr / "src" / "opensight").is_dir():
            return curr
        curr = curr.parent
    return Path.cwd().resolve()

def validate_subpath(base_dir: Path, target_path: Path) -> Path:
    resolved_base = base_dir.resolve()
    resolved_target = target_path.resolve()
    try:
        resolved_target.relative_to(resolved_base)
    except ValueError as exc:
        raise SecurityViolationError(f"安全越界违规: 路径 '{target_path}' 超出便携基准目录 '{base_dir}'") from exc
    return resolved_target

def safe_clean_directory(base_dir: Path, target_dir: Path, allowed_subdirs: Optional[Iterable[str]] = None) -> int:
    resolved_base = base_dir.resolve()
    valid_dir = validate_subpath(resolved_base, target_dir)
    if valid_dir == resolved_base:
        raise SecurityViolationError("安全违规: 禁止清除便携根目录本身")
    if is_reparse_point_or_symlink(valid_dir):
        valid_dir.unlink(missing_ok=True)
        return 1
    if allowed_subdirs is not None:
        rel_parts = valid_dir.relative_to(resolved_base).parts
        if not rel_parts or rel_parts[0] not in allowed_subdirs:
            raise SecurityViolationError(f"安全违规: 目录 '{valid_dir}' 不在允许的清理列表内")
    if not valid_dir.exists():
        return 0
    deleted_count = 0
    for root, dirs, files in os.walk(valid_dir, topdown=False, followlinks=False):
        current_root = Path(root)
        validate_subpath(resolved_base, current_root)
        for fname in files:
            fpath = current_root / fname
            fpath.unlink(missing_ok=True)
            deleted_count += 1
        for dname in dirs:
            dpath = current_root / dname
            try:
                dpath.rmdir()
            except OSError:
                dpath.unlink(missing_ok=True)
            deleted_count += 1
    return deleted_count

def ensure_portable_environment() -> PortablePaths:
    base_dir = get_base_directory()
    data_dir = base_dir / DEFAULT_DATA_DIR
    logs_dir = base_dir / DEFAULT_LOGS_DIR
    profiles_dir = base_dir / DEFAULT_PROFILES_DIR
    licenses_dir = base_dir / DEFAULT_LICENSES_DIR
    openvpn_dir = base_dir / DEFAULT_OPENVPN_DIR
    singbox_dir = base_dir / DEFAULT_SINGBOX_DIR

    for folder in (data_dir, logs_dir, profiles_dir, licenses_dir, openvpn_dir, singbox_dir):
        validate_subpath(base_dir, folder)
        folder.mkdir(parents=True, exist_ok=True)

    return PortablePaths(base_dir, data_dir, logs_dir, profiles_dir, licenses_dir, openvpn_dir, singbox_dir)