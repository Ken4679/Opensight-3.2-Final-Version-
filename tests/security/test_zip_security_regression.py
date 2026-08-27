import io
import zipfile
import pytest
from pathlib import Path
from scripts.fetch_components import extract_singbox
from tests.malicious_inputs.sample_zip_generator import (
    create_zip_slip_archive,
    create_absolute_path_archive,
    create_unc_path_archive,
    create_device_path_archive,
    create_reserved_name_archive,
    create_zip_bomb_archive,
    create_huge_file_count_archive,
    create_nested_archive,
    create_malformed_corrupted_zip,
)


def test_zip_slip_relative_traversal_rejected(tmp_path: Path):
    """Ensure zip files containing relative path traversal (../) are rejected immediately."""
    zip_bytes = create_zip_slip_archive("../../../../escape_attempt.exe", b"MZ" + b"\x00" * 1024)
    zip_file = tmp_path / "evil_slip.zip"
    zip_file.write_bytes(zip_bytes)

    dest_dir = tmp_path / "extracted_singbox"
    dest_dir.mkdir(parents=True, exist_ok=True)

    with pytest.raises(RuntimeError, match="Unsafe archive member"):
        extract_singbox(zip_file, dest_dir)

    # Confirm no files were written outside destination directory
    assert not (tmp_path.parent / "escape_attempt.exe").exists()


def test_zip_absolute_path_rejected(tmp_path: Path):
    """Ensure zip files containing absolute unix or windows paths are rejected."""
    zip_bytes = create_absolute_path_archive("/tmp/absolute_evil.exe", b"MZ" + b"\x00" * 1024)
    zip_file = tmp_path / "evil_abs.zip"
    zip_file.write_bytes(zip_bytes)

    dest_dir = tmp_path / "extracted_singbox"
    dest_dir.mkdir(parents=True, exist_ok=True)

    with pytest.raises(RuntimeError, match="Unsafe archive member"):
        extract_singbox(zip_file, dest_dir)


def test_zip_unc_path_rejected(tmp_path: Path):
    """Ensure zip files containing UNC network paths (\\\\server\\share) are rejected."""
    zip_bytes = create_unc_path_archive("\\\\evil.attacker.com\\share\\evil.exe", b"MZ" + b"\x00" * 1024)
    zip_file = tmp_path / "evil_unc.zip"
    zip_file.write_bytes(zip_bytes)

    dest_dir = tmp_path / "extracted_singbox"
    dest_dir.mkdir(parents=True, exist_ok=True)

    with pytest.raises(RuntimeError, match="Unsafe archive member"):
        extract_singbox(zip_file, dest_dir)


def test_zip_device_namespace_path_rejected(tmp_path: Path):
    """Ensure zip files containing device namespace paths (\\\\.\\PhysicalDrive) are rejected."""
    zip_bytes = create_device_path_archive("\\\\.\\PhysicalDrive0\\payload.exe", b"MZ" + b"\x00" * 1024)
    zip_file = tmp_path / "evil_dev.zip"
    zip_file.write_bytes(zip_bytes)

    dest_dir = tmp_path / "extracted_singbox"
    dest_dir.mkdir(parents=True, exist_ok=True)

    with pytest.raises(RuntimeError, match="Unsafe archive member"):
        extract_singbox(zip_file, dest_dir)


def test_corrupted_malformed_zip_raises_gracefully(tmp_path: Path):
    """Ensure corrupted / truncated zip bytes fail gracefully without crash or hang."""
    bad_bytes = create_malformed_corrupted_zip()
    bad_zip = tmp_path / "corrupt.zip"
    bad_zip.write_bytes(bad_bytes)

    dest_dir = tmp_path / "extracted_singbox"
    dest_dir.mkdir(parents=True, exist_ok=True)

    with pytest.raises(zipfile.BadZipFile):
        extract_singbox(bad_zip, dest_dir)


def test_nested_archive_does_not_execute_or_extract_uncontrolled(tmp_path: Path):
    """Ensure nested archives are treated as normal files and do not cause recursive uncontrolled extraction."""
    nested_bytes = create_nested_archive()
    nested_zip = tmp_path / "nested.zip"
    nested_zip.write_bytes(nested_bytes)

    dest_dir = tmp_path / "extracted_singbox"
    dest_dir.mkdir(parents=True, exist_ok=True)

    # extract_singbox only extracts sing-box.exe, .dll, or license*
    # An archive named archive.zip inside should be ignored and if no sing-box.exe exists, verify_pe will fail
    with pytest.raises(RuntimeError):
        extract_singbox(nested_zip, dest_dir)


def test_safe_singbox_zip_extracts_whitelisted_files_only(tmp_path: Path):
    """Ensure a valid zip file extracts only whitelisted sing-box.exe, dll, and license files."""
    valid_buf = io.BytesIO()
    # Create fake valid sing-box.exe with PE MZ header and >= 1MB size
    fake_pe = b"MZ" + b"\x00" * (1024 * 1024 + 100)
    with zipfile.ZipFile(valid_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("sing-box-1.9.0-windows-amd64/sing-box.exe", fake_pe)
        zf.writestr("sing-box-1.9.0-windows-amd64/LICENSE", b"Apache-2.0 License Text")
        zf.writestr("sing-box-1.9.0-windows-amd64/unrelated_script.sh", b"#!/bin/bash\necho evil")

    valid_zip = tmp_path / "valid_singbox.zip"
    valid_zip.write_bytes(valid_buf.getvalue())

    dest_dir = tmp_path / "extracted_singbox"
    dest_dir.mkdir(parents=True, exist_ok=True)

    exe_path = extract_singbox(valid_zip, dest_dir)
    assert exe_path.is_file()
    assert (dest_dir / "sing-box.exe").exists()
    assert (dest_dir / "LICENSE").exists()
    # Unrelated script should NOT have been extracted
    assert not (dest_dir / "unrelated_script.sh").exists()
