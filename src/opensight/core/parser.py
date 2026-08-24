import hashlib
import re
from pathlib import Path
from typing import Final, Optional
from opensight.core.models import ParsedProfile, ParsedRemote, ProtocolType
from opensight.core.country_resolver import CountryResolver
from opensight.core.safety import is_reparse_point_or_symlink
from opensight.core.ovpn_security import validate_ovpn_security

MAX_OVPN_FILE_SIZE_BYTES: Final[int] = 2 * 1024 * 1024
_SUPPORTED_ENCODINGS = ("utf-8-sig", "utf-8", "cp1252", "gb18030", "latin-1")

class ParseError(Exception):
    pass

class OvpnParser:
    @classmethod
    def parse_file(cls, file_path: Path, relative_to: Optional[Path] = None) -> ParsedProfile:
        if not file_path.exists() or is_reparse_point_or_symlink(file_path) or not file_path.is_file():
            raise ParseError(f"文件无效或为符号链接: {file_path}")
        with open(file_path, "rb") as f:
            raw_bytes = f.read(MAX_OVPN_FILE_SIZE_BYTES + 1)
        if len(raw_bytes) > MAX_OVPN_FILE_SIZE_BYTES:
            raise ParseError("文件超出 2MB 大小限制")

        file_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        content = cls._decode_bytes(raw_bytes)
        if relative_to:
            rel_path = str(file_path.resolve().relative_to(relative_to.resolve())).replace("\\", "/")
        else:
            rel_path = file_path.name

        return cls.parse_text(content, file_path.name, rel_path, file_sha256, len(raw_bytes))

    @classmethod
    def parse_text(
        cls,
        text: str,
        filename: str = "profile.ovpn",
        relative_path: str = "profile.ovpn",
        file_sha256: Optional[str] = None,
        file_size_bytes: int = 0
    ) -> ParsedProfile:
        is_safe, sec_reason = validate_ovpn_security(text, filename)
        if not is_safe:
            raise ParseError(f"安全策略拦截: {sec_reason}")

        if file_sha256 is None:
            file_sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()

        warnings = []
        raw_remotes = []
        global_proto = None
        global_port = None
        in_tag = None

        for line_num, line in enumerate(text.splitlines(), start=1):
            clean = line.strip()
            if not clean:
                continue
            if in_tag:
                if clean.startswith(f"</{in_tag}>"):
                    in_tag = None
                continue
            if clean.startswith("<") and clean.endswith(">") and not clean.startswith("</"):
                in_tag = clean[1:-1].strip().split()[0]
                continue
            if clean.startswith("#") or clean.startswith(";"):
                continue
            clean = re.split(r"\s+[#;]", clean, maxsplit=1)[0].strip()
            tokens = clean.split()
            if not tokens:
                continue
            directive = tokens[0].lower()
            args = tokens[1:]

            if directive == "proto" and args:
                global_proto = "tcp" if "tcp" in args[0].lower() else "udp"
            elif directive == "port" and args:
                try:
                    global_port = int(args[0])
                except ValueError:
                    pass
            elif directive == "remote" and args:
                host = args[0]
                port = int(args[1]) if len(args) > 1 and args[1].isdigit() else None
                proto = "tcp" if len(args) > 2 and "tcp" in args[2].lower() else None
                raw_remotes.append({"host": host, "port": port, "proto": proto})

        eff_proto: ProtocolType = "tcp" if (global_proto == "tcp" or not global_proto) else "udp"
        eff_port = global_port or (443 if eff_proto == "tcp" else 1194)
        remotes = []
        seen = set()
        for r in raw_remotes:
            p_port = r["port"] or eff_port
            p_proto = r["proto"] or eff_proto
            key = (r["host"].lower(), p_port, p_proto)
            if key not in seen:
                seen.add(key)
                remotes.append(ParsedRemote(r["host"], p_port, p_proto))

        server_name = Path(filename).stem.upper()
        loc = CountryResolver.resolve(server_name, remotes[0].host if remotes else None, filename)
        pid = hashlib.sha256(f"{relative_path}:{file_sha256}".encode("utf-8")).hexdigest()[:16]

        return ParsedProfile(
            pid, filename, relative_path, file_sha256, file_size_bytes,
            "ProtonVPN", server_name, loc.country, loc.country_code, loc.city,
            "free" in filename.lower(), tuple(remotes),
            remotes[0].protocol if remotes else eff_proto,
            eff_proto == "tcp", tuple(warnings)
        )

    @staticmethod
    def _decode_bytes(raw: bytes) -> str:
        for enc in _SUPPORTED_ENCODINGS:
            try:
                return raw.decode(enc)
            except UnicodeDecodeError:
                continue
        return raw.decode("latin-1", errors="replace")
