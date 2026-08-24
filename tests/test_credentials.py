import json
import pytest
from unittest.mock import patch
from pathlib import Path
from opensight.core.safety import PortablePaths
from opensight.vpn.credentials import CredentialVault, OpenVPNCredentials, CredentialStorageMode, DPAPIVault
from opensight.core.logger import CredentialSanitizer

@pytest.fixture
def temp_paths(tmp_path):
    base = tmp_path / "opensight_portable"
    base.mkdir(parents=True, exist_ok=True)
    profiles = base / "profiles"
    profiles.mkdir(parents=True, exist_ok=True)
    data = base / "data"
    data.mkdir(parents=True, exist_ok=True)
    logs = base / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    return PortablePaths(
        base_dir=base,
        profiles_dir=profiles,
        data_dir=data,
        logs_dir=logs,
        licenses_dir=base / "licenses",
        openvpn_dir=base / "openvpn",
        singbox_dir=base / "singbox",
        is_isolated=True,
    )

def test_session_credentials(temp_paths):
    vault = CredentialVault(temp_paths)
    vault.set_session_credentials("user_test", "super_secret_pass")
    creds = vault.load_credentials()
    assert creds is not None
    assert creds.username == "user_test"
    assert creds.password == "super_secret_pass"
    assert creds.storage_mode == CredentialStorageMode.SESSION

    # Session credentials shouldn't create credentials.enc
    assert not (temp_paths.data_dir / "credentials.enc").exists()

def test_sanitizer_masks_registered_credentials():
    sanitizer = CredentialSanitizer.get_instance()
    sanitizer.register("secret_password_999")
    masked = sanitizer.sanitize("Connecting with password: secret_password_999 now")
    assert "secret_password_999" not in masked
    assert "[REDACTED]" in masked

def test_corrupted_encrypted_file_recovery(temp_paths):
    # Corrupt credentials.enc file
    enc_file = temp_paths.data_dir / "credentials.enc"
    enc_file.write_bytes(b"CORRUPTED_GARBAGE_BYTES_THAT_CANNOT_DECRYPT")

    vault = CredentialVault(temp_paths)
    with patch.object(DPAPIVault, "is_supported", return_value=True):
        with patch.object(DPAPIVault, "decrypt", side_effect=RuntimeError("Decryption error")):
            creds = vault.load_credentials()
            # Must safely return None without throwing or crashing
            assert creds is None

def test_clear_credentials(temp_paths):
    enc_file = temp_paths.data_dir / "credentials.enc"
    enc_file.write_bytes(b"some_encrypted_data")

    vault = CredentialVault(temp_paths)
    vault.set_session_credentials("u", "p")
    vault.clear_saved_credentials()

    assert vault.load_credentials() is None
    assert not enc_file.exists()
