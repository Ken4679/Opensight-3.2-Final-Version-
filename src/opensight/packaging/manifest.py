import json
import time
from dataclasses import dataclass
from pathlib import Path
from opensight.core.constants import APP_NAME, APP_VERSION, SECURITY_MANIFEST_FILE, SHA256SUMS_FILE
from opensight.core.safety import validate_subpath, PortablePaths
from opensight.packaging.provenance import ArtifactProvenance
import hashlib

@dataclass(frozen=True)
class SecurityManifest:
    application_name: str
    application_version: str
    manifest_version: str
    created_at: int
    artifacts: list[ArtifactProvenance]
    build_provenance: dict

    def to_dict(self) -> dict:
        return {
            "application_name": self.application_name,
            "application_version": self.application_version,
            "manifest_version": self.manifest_version,
            "created_at": self.created_at,
            "artifacts": [a.to_dict() for a in self.artifacts],
            "build_provenance": self.build_provenance,
        }

class ManifestGenerator:
    def __init__(self, portable_paths: PortablePaths):
        self._paths = portable_paths

    def generate_manifest(self, artifacts: list[ArtifactProvenance], build_commit: str = "LOCAL") -> SecurityManifest:
        now = int(time.time())
        m = SecurityManifest(APP_NAME, APP_VERSION, "1.0", now, list(artifacts), {"commit": build_commit, "timestamp": now})
        p = validate_subpath(self._paths.base_dir, self._paths.base_dir / SECURITY_MANIFEST_FILE)
        p.write_text(json.dumps(m.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        return m

    def generate_sha256sums(self, files: list[Path]) -> Path:
        sums_file = validate_subpath(self._paths.base_dir, self._paths.base_dir / SHA256SUMS_FILE)
        lines = [f"{hashlib.sha256(f.read_bytes()).hexdigest().lower()}  {f.name}" for f in files if f.is_file()]
        sums_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return sums_file