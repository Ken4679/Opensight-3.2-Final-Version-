import os
from dataclasses import dataclass
from pathlib import Path
from typing import Final
from opensight.core.models import ParsedProfile
from opensight.core.parser import OvpnParser
from opensight.core.safety import validate_subpath, is_reparse_point_or_symlink

SUPPORTED_EXTENSIONS: Final[tuple[str, ...]] = (".ovpn", ".conf")

@dataclass(frozen=True)
class ImportReport:
    total_found: int
    imported_count: int
    skipped_count: int
    error_count: int
    profiles: tuple[ParsedProfile, ...]
    errors: tuple[tuple[str, str], ...]

class ProfileImporter:
    @classmethod
    def import_from_directory(cls, directory_path: Path, recursive: bool = False) -> ImportReport:
        if not directory_path.exists() or not directory_path.is_dir() or is_reparse_point_or_symlink(directory_path):
            return ImportReport(0, 0, 0, 1, (), ((str(directory_path), "目录不存在或为符号链接"),))

        resolved_root = directory_path.resolve()
        discovered_files = []
        seen = set()

        def scan_dir(curr: Path):
            with os.scandir(curr) as it:
                for entry in it:
                    p = Path(entry.path)
                    try:
                        validate_subpath(resolved_root, p)
                    except Exception:
                        continue
                    if entry.is_symlink() or is_reparse_point_or_symlink(p):
                        continue
                    if entry.is_file(follow_symlinks=False) and p.suffix.lower() in SUPPORTED_EXTENSIONS:
                        if p.resolve() not in seen:
                            seen.add(p.resolve())
                            discovered_files.append(p)
                    elif recursive and entry.is_dir(follow_symlinks=False):
                        scan_dir(p)

        scan_dir(resolved_root)
        profiles = []
        errors = []
        for f in sorted(discovered_files, key=lambda x: x.name.lower()):
            try:
                profiles.append(OvpnParser.parse_file(f, relative_to=resolved_root))
            except Exception as e:
                errors.append((f.name, str(e)))

        return ImportReport(len(discovered_files), len(profiles), 0, len(errors), tuple(profiles), tuple(errors))