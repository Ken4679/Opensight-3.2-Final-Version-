import hashlib
import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(ROOT_DIR / "scripts"))

from opensight.core.constants import APP_VERSION, OPENVPN_MSI_SHA256, OPENVPN_VERSION, SINGBOX_VERSION
from opensight.packaging.provenance import ArtifactProvenance, VerificationStatus
from opensight.packaging.manifest import ManifestGenerator
from generate_sbom import generate_cyclonedx_sbom
from verify_manifest import verify_manifest



def test_sbom_generation(tmp_path: Path):
    sbom_file = tmp_path / "SBOM.cdx.json"
    sbom = generate_cyclonedx_sbom(APP_VERSION, sbom_file)

    assert sbom_file.is_file()
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["metadata"]["component"]["version"] == APP_VERSION

    component_names = {c["name"] for c in sbom["components"]}
    assert "fastapi" in component_names
    assert "uvicorn" in component_names
    assert "openvpn" in component_names
    assert "sing-box" in component_names


def test_manifest_verification_pass(tmp_path: Path):
    dummy_exe = tmp_path / "OpenSight.exe"
    dummy_exe.write_bytes(b"MZ_DUMMY_BINARY_DATA_FOR_TEST")
    exe_sha = hashlib.sha256(dummy_exe.read_bytes()).hexdigest().lower()

    dummy_msi = tmp_path / "OpenVPN.msi"
    dummy_msi.write_bytes(b"MSI_PACKAGE_DATA")
    msi_sha = hashlib.sha256(dummy_msi.read_bytes()).hexdigest().lower()

    artifacts = [
        # 自构建产物：expected_sha256 为 None, status 为 BUILT_ARTIFACT
        ArtifactProvenance(
            artifact_name="OpenSight.exe",
            version=APP_VERSION,
            source_url="build://OpenSight",
            source_domain="build",
            expected_sha256=None,
            actual_sha256=exe_sha,
            verification_status=VerificationStatus.BUILT_ARTIFACT,
            file_size_bytes=dummy_exe.stat().st_size,
            local_path="OpenSight.exe",
            downloaded_at=12345678,
            opensight_owned=True,
        ),
        # 外部固化产物：包含预期哈希与实际哈希
        ArtifactProvenance(
            artifact_name="OpenVPN.msi",
            version="2.7.5",
            source_url="https://build.openvpn.net/OpenVPN.msi",
            source_domain="build.openvpn.net",
            expected_sha256=msi_sha,
            actual_sha256=msi_sha,
            verification_status=VerificationStatus.VERIFIED,
            file_size_bytes=dummy_msi.stat().st_size,
            local_path="OpenVPN.msi",
            downloaded_at=12345678,
            opensight_owned=False,
        ),
    ]

    gen = ManifestGenerator(type("Paths", (), {"base_dir": tmp_path})())
    gen.generate_manifest(artifacts, build_commit="TEST_COMMIT")
    gen.generate_sha256sums([dummy_exe, dummy_msi])

    assert verify_manifest(tmp_path) is True


def test_manifest_verification_fail_on_hash_mismatch(tmp_path: Path):
    dummy_exe = tmp_path / "OpenSight.exe"
    dummy_exe.write_bytes(b"ORIGINAL_DATA")
    original_sha = hashlib.sha256(dummy_exe.read_bytes()).hexdigest().lower()

    artifacts = [
        ArtifactProvenance(
            artifact_name="OpenSight.exe",
            version=APP_VERSION,
            source_url="build://OpenSight",
            source_domain="build",
            expected_sha256=original_sha,
            actual_sha256=original_sha,
            verification_status=VerificationStatus.VERIFIED,
            file_size_bytes=dummy_exe.stat().st_size,
            local_path="OpenSight.exe",
            downloaded_at=12345678,
            opensight_owned=True,
        )
    ]

    gen = ManifestGenerator(type("Paths", (), {"base_dir": tmp_path})())
    gen.generate_manifest(artifacts, build_commit="TEST_COMMIT")

    # 模拟篡改文件
    dummy_exe.write_bytes(b"TAMPERED_DATA")

    assert verify_manifest(tmp_path) is False
