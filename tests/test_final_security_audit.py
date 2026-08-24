from pathlib import Path
from opensight.core.logger import CredentialSanitizer

def test_credential_sanitizer_masks_secrets():
    sanitizer = CredentialSanitizer.get_instance()
    sanitizer.register("MySecretPassword_999")
    text = "Connecting with pass MySecretPassword_999"
    assert "MySecretPassword_999" not in sanitizer.sanitize(text)
    assert "[REDACTED]" in sanitizer.sanitize(text)

def test_icon_source_and_payload_exist():
    root = Path(__file__).resolve().parent.parent
    assert (root / "opensight.svg").is_file()
    payload = (root / "opensight.ico.b64").read_text(encoding="utf-8-sig").strip()
    assert len(payload) > 100
    assert "eye" not in (root / "opensight.svg").read_text(encoding="utf-8-sig").lower()
