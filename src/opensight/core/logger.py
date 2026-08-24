import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Final

_STATIC_SENSITIVE_PATTERNS: Final[list[re.Pattern]] = [
    re.compile(r"(password\s+)[^\s\r\n]+", re.IGNORECASE),
    re.compile(r"(auth-user-pass\s+)[^\s\r\n]+", re.IGNORECASE),
    re.compile(r"(token\s*[:=]\s*)[^\s\r\n]+", re.IGNORECASE),
    re.compile(r"(secret\s*[:=]\s*)[^\s\r\n]+", re.IGNORECASE),
    re.compile(r"(bearer\s+)[a-zA-Z0-9_\-\.]+", re.IGNORECASE),
]

class CredentialSanitizer:
    _instance = None
    def __init__(self) -> None:
        self._registered_secrets: set[str] = set()

    @classmethod
    def get_instance(cls) -> "CredentialSanitizer":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def register(self, secret: str) -> None:
        clean = secret.strip()
        if len(clean) >= 3:
            self._registered_secrets.add(clean)

    def unregister(self, secret: str) -> None:
        self._registered_secrets.discard(secret.strip())

    def clear(self) -> None:
        self._registered_secrets.clear()

    def sanitize(self, text: str) -> str:
        if not text:
            return ""
        result = text
        for secret in self._registered_secrets:
            if secret in result:
                result = result.replace(secret, "[REDACTED]")
        for pattern in _STATIC_SENSITIVE_PATTERNS:
            result = pattern.sub(r"\1[REDACTED]", result)
        return result

class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        return CredentialSanitizer.get_instance().sanitize(original)

def setup_logging(logs_dir: Path, log_level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("opensight")
    logger.setLevel(log_level)
    logger.handlers.clear()
    log_file = logs_dir / "opensight.log"

    file_handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
    file_formatter = RedactingFormatter("[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_formatter = RedactingFormatter("[%(levelname)s] %(name)s: %(message)s")
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    return logger

def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"opensight.{name}")