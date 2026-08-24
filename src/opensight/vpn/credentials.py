import ctypes
import ctypes.wintypes
import json
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Optional
from opensight.core.safety import validate_subpath, PortablePaths
from opensight.core.logger import CredentialSanitizer

class CredentialStorageMode(str, Enum):
    SESSION = "session"
    PERSISTENT = "persistent"

@dataclass(frozen=True)
class OpenVPNCredentials:
    username: str
    password: str
    storage_mode: CredentialStorageMode = CredentialStorageMode.SESSION

class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

class DPAPIVault:
    @staticmethod
    def is_supported() -> bool:
        return sys.platform == "win32"

    @classmethod
    def encrypt(cls, data: bytes) -> bytes:
        raw_buf = ctypes.create_string_buffer(data)
        blob_in = DATA_BLOB(len(data), ctypes.cast(raw_buf, ctypes.POINTER(ctypes.c_byte)))
        blob_out = DATA_BLOB()
        if not ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(blob_in), "OpenSight", None, None, None, 0, ctypes.byref(blob_out)
        ):
            raise RuntimeError("Windows DPAPI 数据加密失败")
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)

    @classmethod
    def decrypt(cls, data: bytes) -> bytes:
        raw_buf = ctypes.create_string_buffer(data)
        blob_in = DATA_BLOB(len(data), ctypes.cast(raw_buf, ctypes.POINTER(ctypes.c_byte)))
        blob_out = DATA_BLOB()
        if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
        ):
            raise RuntimeError("Windows DPAPI 数据解密失败")
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)

class CredentialVault:
    def __init__(self, portable_paths: PortablePaths):
        self._paths = portable_paths
        self._enc_file = portable_paths.data_dir / "credentials.enc"
        self._session: Optional[OpenVPNCredentials] = None
        self._sanitizer = CredentialSanitizer.get_instance()

    def set_session_credentials(self, u: str, p: str):
        self._session = OpenVPNCredentials(u.strip(), p.strip(), CredentialStorageMode.SESSION)
        self._sanitizer.register(u.strip())
        self._sanitizer.register(p.strip())

    def save_persistent_credentials(self, u: str, p: str) -> bool:
        if not DPAPIVault.is_supported():
            self.set_session_credentials(u, p)
            return False
        try:
            cipher = DPAPIVault.encrypt(json.dumps({"u": u.strip(), "p": p.strip()}).encode("utf-8"))
            validate_subpath(self._paths.base_dir, self._enc_file).write_bytes(cipher)
            self._session = OpenVPNCredentials(u.strip(), p.strip(), CredentialStorageMode.PERSISTENT)
            self._sanitizer.register(u.strip())
            self._sanitizer.register(p.strip())
            return True
        except Exception:
            return False

    def load_credentials(self) -> Optional[OpenVPNCredentials]:
        if self._session:
            return self._session
        if not self._enc_file.exists() or not DPAPIVault.is_supported():
            return None
        try:
            raw = DPAPIVault.decrypt(validate_subpath(self._paths.base_dir, self._enc_file).read_bytes())
            d = json.loads(raw.decode("utf-8"))
            self._session = OpenVPNCredentials(d["u"], d["p"], CredentialStorageMode.PERSISTENT)
            self._sanitizer.register(d["u"])
            self._sanitizer.register(d["p"])
            return self._session
        except Exception:
            return None

    def clear_saved_credentials(self):
        self._session = None
        if self._enc_file.exists():
            try:
                validate_subpath(self._paths.base_dir, self._enc_file).unlink(missing_ok=True)
            except Exception:
                pass
