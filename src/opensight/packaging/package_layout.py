from pathlib import Path
from opensight.core.safety import validate_subpath, is_reparse_point_or_symlink

class PortableStructureError(Exception):
    pass

class PackageLayout:
    @classmethod
    def validate_layout(cls, base_dir: Path) -> bool:
        res = base_dir.resolve()
        if not res.is_dir() or is_reparse_point_or_symlink(res):
            raise PortableStructureError("便携根目录无效或为符号链接")
        for sub in ("data", "logs", "profiles", "licenses", "openvpn", "singbox"):
            p = validate_subpath(res, res / sub)
            if not p.is_dir() or is_reparse_point_or_symlink(p):
                raise PortableStructureError(f"必需子目录缺失或异常: {sub}")
        return True