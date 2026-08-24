import asyncio
import http.client
import ipaddress
import re
import time
import urllib.parse
from typing import Optional

from opensight.core.constants import (
    DEFAULT_DOMESTIC_PUBLIC_IP_SERVICES,
    DEFAULT_OVERSEAS_PUBLIC_IP_SERVICES,
    DEFAULT_PUBLIC_IP_SERVICES,
    DEFAULT_IP_CHECKPOINT_INTERVAL_SEC,
)

_ALLOWED_HOSTS = frozenset({
    "myip.ipip.net",
    "icanhazip.com",
    "api.ipify.org",
    "checkip.amazonaws.com",
})


class PublicIPGuard:
    """公网 IP 检测器。每次请求都重新读取；服务顺序随 VPN 状态切换。"""

    def __init__(
        self,
        service_urls: Optional[tuple[str, ...]] = None,
        timeout: float = 3.5,
        checkpoint_interval_sec: float = DEFAULT_IP_CHECKPOINT_INTERVAL_SEC,
        domestic_service_urls: tuple[str, ...] = DEFAULT_DOMESTIC_PUBLIC_IP_SERVICES,
        overseas_service_urls: tuple[str, ...] = DEFAULT_OVERSEAS_PUBLIC_IP_SERVICES,
    ):
        self._custom_services = tuple(self._validate_services(service_urls)) if service_urls is not None else None
        self._domestic_services = tuple(self._validate_services(domestic_service_urls))
        self._overseas_services = tuple(self._validate_services(overseas_service_urls))
        if not self._custom_services and not self._domestic_services and not self._overseas_services:
            self._custom_services = tuple(self._validate_services(DEFAULT_PUBLIC_IP_SERVICES))
        self._timeout = timeout
        self._interval = checkpoint_interval_sec
        self._initial_ip: Optional[str] = None
        self._last_time = 0.0
        self._vpn_connected = False

    @staticmethod
    def _validate_services(urls: Optional[tuple[str, ...]]) -> list[str]:
        valid: list[str] = []
        for url in urls or ():
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme == "https" and parsed.hostname in _ALLOWED_HOSTS:
                valid.append(url)
        return valid

    def set_vpn_connected(self, connected: bool) -> None:
        self._vpn_connected = bool(connected)

    def _services(self) -> tuple[str, ...]:
        if self._custom_services is not None:
            return self._custom_services
        return self._overseas_services if self._vpn_connected else self._domestic_services

    async def fetch_current_ip(self) -> Optional[str]:
        loop = asyncio.get_running_loop()
        for url in self._services():
            try:
                ip = await loop.run_in_executor(None, self._http_get_ip, url)
                if ip:
                    return ip
            except Exception:
                continue
        return None

    async def record_baseline(self) -> Optional[str]:
        self._initial_ip = await self.fetch_current_ip()
        self._last_time = time.time()
        return self._initial_ip

    async def check_periodic_drift(self) -> tuple[bool, Optional[str]]:
        if not self._initial_ip or time.time() - self._last_time < self._interval:
            return True, self._initial_ip
        self._last_time = time.time()
        current = await self.fetch_current_ip()
        return current == self._initial_ip, current

    async def verify_integrity(self) -> tuple[bool, Optional[str]]:
        if not self._initial_ip:
            return True, None
        current = await self.fetch_current_ip()
        return current == self._initial_ip, current

    @staticmethod
    def _extract_ip(body: str) -> Optional[str]:
        body = body.strip()
        try:
            return str(ipaddress.ip_address(body))
        except ValueError:
            match = re.search(r"(?:\d{1,3}\.){3}\d{1,3}", body)
            if not match:
                return None
            try:
                return str(ipaddress.ip_address(match.group(0)))
            except ValueError:
                return None

    def _http_get_ip(self, url: str) -> Optional[str]:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https" or parsed.hostname not in _ALLOWED_HOSTS:
            return None
        conn = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=self._timeout)
        try:
            conn.request("GET", parsed.path or "/", headers={"User-Agent": "OpenSight/3.1", "Connection": "close"})
            response = conn.getresponse()
            if response.status != 200:
                return None
            return self._extract_ip(response.read(512).decode("utf-8", errors="ignore"))
        finally:
            conn.close()
