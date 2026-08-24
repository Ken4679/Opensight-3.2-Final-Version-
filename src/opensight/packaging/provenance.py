from dataclasses import dataclass
from enum import Enum
from typing import Optional

class VerificationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    HASH_MISMATCH = "HASH_MISMATCH"
    BUILT_ARTIFACT = "BUILT_ARTIFACT"

@dataclass(frozen=True)
class ArtifactProvenance:
    artifact_name: str
    version: str
    source_url: str
    source_domain: str
    expected_sha256: Optional[str]
    actual_sha256: Optional[str]
    verification_status: VerificationStatus
    file_size_bytes: int
    local_path: Optional[str]
    downloaded_at: int
    opensight_owned: bool = True

    def to_dict(self) -> dict:
        return {
            "artifact_name": self.artifact_name,
            "version": self.version,
            "source_url": self.source_url,
            "source_domain": self.source_domain,
            "expected_sha256": self.expected_sha256,
            "actual_sha256": self.actual_sha256,
            "verification_status": self.verification_status.value,
            "file_size_bytes": self.file_size_bytes,
            "local_path": self.local_path,
            "downloaded_at": self.downloaded_at,
            "opensight_owned": self.opensight_owned,
        }