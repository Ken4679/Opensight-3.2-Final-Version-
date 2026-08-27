# OpenSight Malicious and Edge-Case ZIP Archive Generators

import io
import zipfile
from pathlib import Path


def create_zip_slip_archive(target_filename: str = "../../../../tmp/evil.txt", content: bytes = b"EVIL") -> bytes:
    """Create a zip archive containing directory traversal paths (Zip-Slip)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(target_filename, content)
    return buf.getvalue()


def create_absolute_path_archive(target_filename: str = "/etc/passwd_evil", content: bytes = b"EVIL") -> bytes:
    """Create a zip archive containing absolute path entries."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(target_filename, content)
    return buf.getvalue()


def create_unc_path_archive(target_filename: str = "\\\\remote\\share\\evil.exe", content: bytes = b"EVIL") -> bytes:
    """Create a zip archive containing Windows UNC network share paths."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(target_filename, content)
    return buf.getvalue()


def create_device_path_archive(target_filename: str = "\\\\.\\PhysicalDrive0\\evil.exe", content: bytes = b"EVIL") -> bytes:
    """Create a zip archive containing Windows device namespace paths."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(target_filename, content)
    return buf.getvalue()


def create_reserved_name_archive(target_filename: str = "CON.exe", content: bytes = b"EVIL") -> bytes:
    """Create a zip archive containing Windows DOS reserved device names."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(target_filename, content)
    return buf.getvalue()


def create_zip_bomb_archive(uncompressed_size_mb: int = 10) -> bytes:
    """Create a highly compressed archive (ZIP bomb style with repeating zero bytes)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr("huge_sparse_file.dat", b"\x00" * (uncompressed_size_mb * 1024 * 1024))
    return buf.getvalue()


def create_huge_file_count_archive(file_count: int = 1000) -> bytes:
    """Create a zip archive with an excessive number of tiny member files."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(file_count):
            zf.writestr(f"nested/dir/sub/file_{i}.txt", b"x")
    return buf.getvalue()


def create_nested_archive() -> bytes:
    """Create a nested zip archive (zip within a zip)."""
    inner_buf = io.BytesIO()
    with zipfile.ZipFile(inner_buf, "w", zipfile.ZIP_DEFLATED) as inner_zf:
        inner_zf.writestr("inner_payload.exe", b"MZ" + b"\x00" * 1024)

    outer_buf = io.BytesIO()
    with zipfile.ZipFile(outer_buf, "w", zipfile.ZIP_DEFLATED) as outer_zf:
        outer_zf.writestr("archive.zip", inner_buf.getvalue())
    return outer_buf.getvalue()


def create_malformed_corrupted_zip() -> bytes:
    """Create truncated/corrupted bytes with an invalid zip header."""
    return b"PK\x03\x04" + b"\xff" * 64 + b"corrupted_zip_payload_data"
